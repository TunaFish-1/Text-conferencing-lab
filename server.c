#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <time.h>
#include <pthread.h>
#include <stdbool.h>
#include "packet.h"

int totalClients = 0;
int totalSessions = 0;

struct Clients{
    int clientSocket;
    char* sessionName;
    char* clientUsername;
    int clientID;
    bool joinedSession;
    int sessionIndex;
    bool loggedIn;
};

struct Session{
    int sessionIndex;
    char* sessionName;
    int numClients;
}



#define SERVER_CAPACITY 20
#define SESSION_CAPACITY 20
#define INACTIVE_CLIENT -1
#define INACTIVE_SESSION -1
#define MAXCHAR 1000

struct Clients clientList[SERVER_CAPACITY];
struct Session sessionList[SESSION_CAPACITY];


pthread_mutex_t clientsMutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t sessionsMutex = PTHREAD_MUTEX_INITIALIZER;

void * handleConnection(void * newClientArg){

    struct Clients newClient = *(struct Clients *) newClientArg;
    int clientID = newClient.clientID;
    newClient.joinedSession = false;
    newClient.loggedIn = false;

    struct message* clientMessage = (struct message*) malloc(sizeof(struct message));
    struct message* sendMessage = (struct message*) malloc(sizeof(struct message));

    int clientSocket = newClient.clientSocket;
    int numbytes = 0;
    char buf[MAXBUFLEN];

    char* reasonForFailure = "Incorrect username or password"; //default reason for failure

    bool notLoggedIn = true;
    while(notLoggedIn){
        
        // empty the messages
        clientMessage->source = "";
        clientMessage->data = "";
        sendMessage->source = "";
        sendMessage->data = "";

        
        //receive a message from the client
        memset(buf, 0, MAXBUFLEN); 
        while(numbytes == 0){
            if ((numbytes = recv(clientSocket, buf, MAXBUFLEN-1 , 0)) == -1) {
                perror("Error in receiving from client");
                exit(1);
            }
            sleep(0.7);
        }


        // message format of buffer received-  <type>:<size of data>:<source>:<data>
        // printf("%s\n", buf);
        
        PacketToData(buf, clientMessage);

        // Check if first command sent by client is invalid
        if(clientMessage->type != LOGIN && clientMessage->type != EXIT){
            printf("You have to login before you do anything else. Please try again\n");
            reasonForFailure = "You have to login first!";
            goto INVALID_LOGIN;
        }

        // Early exit, edit clientList to reflect that
        if(clientMessage->type == EXIT){
            pthread_mutex_lock(&clientsMutex);
            clientList[clientID].clientID = INACTIVE_CLIENT;
            pthread_mutex_unlock(&clientsMutex);
            return NULL;
        }
        if(clientMessage->type == LOGIN){
            unsigned char * username = clientMessage->source;
            unsigned char * password = clientMessage->data;

            // Get usernames and passwords to check with packet
            FILE *fp;
            char str[MAXCHAR];
            char* filename = "users.txt";
        
            fp = fopen(filename, "r");
            if (fp == NULL){
                printf("Could not open file %s",filename);
                exit(1);
            }
            while (fgets(str, MAXCHAR, fp) != NULL){

                // Get username and password of one line of file
                char *token = strtok(str, ";");
                unsigned char * usernameFromFile = token;
                token = strtok(NULL, "\n");
                unsigned char * passwordFromFile = token;

                bool usernameLegal = strcmp(usernameFromFile, username) == 0? true:false;
                bool passwordLegal = strcmp(passwordFromFile,password) == 0? true:false;

                // Check for match
                if(usernameLegal && passwordLegal){
                    notLoggedIn = false;
                    newClient.clientUsername = usernameLegal;
                    newClient.loggedIn = true;
                    break;
                }
            }
            fclose(fp);
        }

        INVALID_LOGIN:
        if(notLoggedIn){
            printf("I m not logged in, sending packet\n");
            sendMessage->type = LO_NAK;
            sendMessage->size = sizeof(reasonForFailure);
            strcpy(sendMessage->source, "server");
            strcpy(sendMessage->data, reasonForFailure);

            DataToPacket(buf, sendMessage);
            
            if ((numbytes = send(clientSocket, buf, MAXBUFLEN-1 , 0)) == -1) {
                perror("Error in sending to client\n");
                exit(1);
            }
        }
        // //TESING PURPOSES
        // memset(buf, 0, MAXBUFLEN); 
        // if ((numbytes = recv(clientSocket, buf, MAXBUFLEN-1 , 0) == -1)) {
        //     perror("Error in receiving from client");
        //     exit(1);
        // }
        bzero(buf, sizeof(buf));
    }
    sendMessage->type = LO_ACK;
    sendMessage->size = sizeof("no-data");
    strcpy(sendMessage->source, "server");
    strcpy(sendMessage->data, "no-data");
    
    DataToPacket(buf, sendMessage);
    if ((numbytes = send(clientSocket, buf, MAXBUFLEN-1 , 0)) == -1) {
        perror("Error in sending to client\n");
        exit(1);
    }
    
    printf("Login successful ack sent!\n");



    // --- Check command other than login now ---

    while(loggedIn){
        // receive a message from the client
        memset(buf, 0, MAXBUFLEN); 
        while(numbytes == 0){
            if ((numbytes = recv(clientSocket, buf, MAXBUFLEN-1 , 0)) == -1) {
                perror("Error in receiving from client");
                exit(1);
            }
            sleep(0.7);
        }

        // empty the messages
        clientMessage->source = "";
        clientMessage->data = "";
        sendMessage->source = "";
        sendMessage->data = "";

        PacketToData(buf, clientMessage);

        if(clientMessage->type == LOGIN){
            sendMessage->type = LO_NAK;
            sendMessage->size = sizeof("You are already logged in. Logout first");
            strcpy(sendMessage->source, "server");
            strcpy(sendMessage->data, "You are already logged in. Logout first");

            DataToPacket(buf, sendMessage);
            
            if ((numbytes = send(clientSocket, buf, MAXBUFLEN-1 , 0)) == -1) {
                perror("Error in sending to client\n");
                exit(1);
            }
        }

        // exit the session, delete the session if the last thread
        // make itself inactive in list of clients
        // logout before exiting?
        else if(clientMessage->type == EXIT){

            pthread_mutex_lock(&sessionsMutex);
            if(newClient.joinedSession){
                int sessionIndex = newClient.sessionIndex;
                sessionList[sessionIndex].numClients-= 1; 

                // if no clients, inactivate the session
                if(sessionList[sessionIndex].numClients == 0){
                    sessionList[sessionIndex].sessionIndex = INACTIVE_SESSION;
                }
            }
            pthread_mutex_unlock(&sessionsMutex);
            pthread_mutex_lock(&clientsMutex);
            clientList[clientID].clientID = INACTIVE_CLIENT;
            pthread_mutex_unlock(&clientsMutex);
            return NULL;
        }

        else if(clientMessage->type == NEW_SESS){
            if(newClient.joinedSession)
                goto LEAVESESSION;
            

            pthread_mutex_lock(&sessionsMutex);

            // create session and add name to list
            Session newSession;
            newSession.sessionIndex = totalSessions;
            newSession.sessionName = clientMessage->data;
            newSession.numClients = 0; // join session will increment count
            // maybe not set numClients correctly?
            sessionList[totalSessions] = newSession;
            totalSessions++;

            // send ack for new session
            sendMessage->type = NEW_SESS;
            sendMessage->size = sizeof("New session created succefully!");
            sendMessage->source = "server";
            sendMessage->data = "New session created succefully!";

            DataToPacket(buf, sendMessage);
            if ((numbytes = send(clientSocket, buf, MAXBUFLEN-1 , 0)) == -1) {
                perror("Error in sending to client\n");
                exit(1);
            }

            pthread_mutex_unlock(&sessionsMutex);

            goto JOINSESSION;
        }

        else if(clientMessage->type == JOIN){
            JOINSESSION:
            pthread_mutex_lock(&sessionsMutex);
            
            pthread_mutex_unlock(&sessionsMutex);


        }

        else if(clientMessage->type == LEAVE_SESS){
            LEAVESESSION:

        }


    }


    return NULL;

    
}

int main(int argc, char const *argv[])
{
	int sockfd;
	struct addrinfo hints, *servinfo, *p;
	int rv;
	int numbytes;
	struct sockaddr_storage their_addr;
	char buf[MAXBUFLEN];
	socklen_t addr_len;
	char s[INET_ADDRSTRLEN];

    if (argc != 2) {
		fprintf(stderr,"usage: server <TCP port number to listen on>\n");
		exit(1);
	}

    int MYPORT = atoi(argv[1]);

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_INET; // set to AF_INET6 to use IPv6
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE; // use my IP

	if ((rv = getaddrinfo(NULL, argv[1], &hints, &servinfo)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
		return 1;
	}

	// loop through all the results and bind to the first we can
	for(p = servinfo; p != NULL; p = p->ai_next) {
		if ((sockfd = socket(p->ai_family, p->ai_socktype,
				p->ai_protocol)) == -1) {
			perror("listener: socket");
			continue;
		}

		if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
			close(sockfd);
			perror("listener: bind");
			continue;
		}
		break;
	}

	if (p == NULL) {
		fprintf(stderr, "listener: failed to bind socket\n");
		return 2;
	}

	freeaddrinfo(servinfo);

	printf("listener: waiting to recvfrom...\n");

    if(listen(sockfd, SERVER_CAPACITY) == -1){// 8 clients limit for listening
        perror("Too many connections");
        exit(1);
    }  

    char addrstlen[INET6_ADDRSTRLEN];

    while(1){
        
        struct sockaddr_storage newClientAddr;
        int newClientSocket;
        socklen_t newAddrSize = sizeof(newClientAddr);

        pthread_t newClientThread;
        // Accept an incoming connection: blocking
        if((newClientSocket = accept(sockfd, (struct sockaddr *) &newClientAddr, &newAddrSize)) < 0){
            printf("newClientSocket: %d\n", newClientSocket);
            perror("Error in creating new socket for client");
            exit(1);
        }
        // printf("newClientSocket: %d\n", newClientSocket);
        inet_ntop(newClientAddr.ss_family, get_in_addr((struct sockaddr *)&newClientAddr), addrstlen, sizeof(addrstlen));

        // Add a client to the list of clients with socketfd and address
        clientList[totalClients].clientSocket = newClientSocket;
        clientList[totalClients].clientID = totalClients;
        
        // Create a thread that uses the socket and handles connection
        pthread_create(&newClientThread, NULL, handleConnection, &clientList[totalClients]);
        totalClients++;
    }
}
