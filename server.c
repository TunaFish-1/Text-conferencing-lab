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
    int clientIndex;
    bool joinedSession;
    int sessionIndex;
    bool loggedIn;
};

struct Session{
    int sessionIndex;
    char* sessionName;
    int numClients;
};



#define SERVER_CAPACITY 30
#define SESSION_CAPACITY 20
#define INACTIVE_CLIENT -1
#define INACTIVE_SESSION -1
#define MAXCHAR 1000

struct Clients clientList[SERVER_CAPACITY];
struct Session sessionList[SESSION_CAPACITY];


pthread_mutex_t clientsMutex = PTHREAD_MUTEX_INITIALIZER;

void * handleConnection(void * newClientArg){

    struct Clients * newClient = (struct Clients *) malloc (sizeof(struct Clients));
    newClient->clientIndex = * (int *) newClientArg;
    int clientIndex = newClient->clientIndex;
    newClient->joinedSession = false;
    newClient->loggedIn = false;

    struct message* clientMessage = (struct message*) malloc(sizeof(struct message));
    struct message* sendMessage = (struct message*) malloc(sizeof(struct message));

    pthread_mutex_lock(&clientsMutex);
    newClient->clientSocket = clientList[clientIndex].clientSocket;
    pthread_mutex_unlock(&clientsMutex);
    int clientSocket = newClient->clientSocket;
    int numbytes = 0;
    

    
    
    // --- Login code, exit if wrong username or password ---

    char* reasonForFailure = "Incorrect username or password"; //default reason for failure
    bool notLoggedIn = true;
    
    //receive a message from the client
    {
        char buf[MAXBUFLEN];
        memset(buf, 0, MAXBUFLEN); 
        if ((numbytes = recv(clientSocket, buf, MAXBUFLEN-1 , 0)) == -1) {
            perror("Error in receiving from client");
            exit(1);
        }
        if(numbytes == 0)
            goto EXIT_EARLY;

        // message format of buffer received-  <type>:<size of data>:<source>:<data>
        // printf("%s\n", buf);
        
        PacketToData(buf, clientMessage);
    }

    // Check if first command sent by client is invalid
    if(clientMessage->type != LOGIN && clientMessage->type != EXIT){
        printf("You have to login before you do anything else. Please try again\n");
        reasonForFailure = "You have to login first!";
        goto INVALID_LOGIN;
    }

    // Early exit, edit clientList to reflect that
    if(clientMessage->type == EXIT){
        EXIT_EARLY:
        pthread_mutex_lock(&clientsMutex);
        clientList[clientIndex].clientIndex = INACTIVE_CLIENT;
        pthread_mutex_unlock(&clientsMutex);
        free(clientMessage);
        free(sendMessage);
        free(newClient);
        close(clientSocket);
        return NULL;
    }

    if(clientMessage->type == LOGIN){
        unsigned char * username = (unsigned char *) malloc(strlen(clientMessage->source));
        strcpy(username, clientMessage->source);
        unsigned char * password = (unsigned char *) malloc(clientMessage->size);
        strncpy(password, clientMessage->data, clientMessage->size);
        *(password + clientMessage->size) = 0;

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
                newClient->clientUsername = (char *) malloc(strlen(username));
                strcpy(newClient->clientUsername, username);
                newClient->loggedIn = true;
                break;
            }
        }
        fclose(fp);
    }

    INVALID_LOGIN:
    if(notLoggedIn){
        printf("I m not logged in, sending packet\n");

        pthread_mutex_lock(&clientsMutex);
        clientList[clientIndex].clientIndex = INACTIVE_CLIENT;
        pthread_mutex_unlock(&clientsMutex);

        sendMessage->type = LO_NAK;
        sendMessage->size = strlen(reasonForFailure);
        strcpy(sendMessage->source, "server");
        strcpy(sendMessage->data, reasonForFailure);

        {
            char buf[MAXBUFLEN];
            DataToPacket(buf, sendMessage);
            
            if ((numbytes = send(clientSocket, buf, MAXBUFLEN-1 , 0)) == -1) {
                perror("Error in sending to client\n");
                exit(1);
            }
        }

        free(clientMessage);
        free(sendMessage);
        free(newClient);
        close(clientSocket);
        return NULL;
    }

    pthread_mutex_lock(&clientsMutex);
    clientList[clientIndex] = *newClient;
    pthread_mutex_unlock(&clientsMutex);
    
    sendMessage->type = LO_ACK;
    sendMessage->size = sizeof("no-data");
    strcpy(sendMessage->source, "server");
    strcpy(sendMessage->data, "no-data");

    {
        char buf[MAXBUFLEN];
        DataToPacket(buf, sendMessage);
        if ((numbytes = send(clientSocket, buf, MAXBUFLEN-1 , 0)) == -1) {
            perror("Error in sending to client\n");
            exit(1);
        }
    }
    
    printf("Login successful ack sent!\n");

    // bool loggedIn = true;
    // --- Check command other than login now ---

    while(1){

        // empty the messages
        free(clientMessage);
        free(sendMessage);
        clientMessage = (struct message*) malloc(sizeof(struct message));
        sendMessage = (struct message*) malloc(sizeof(struct message));

        // Helper variables
        bool joiningSessionHelp = false;
        bool createSessionHelp = false;

        // receive a message from the client
        {
            char buf[MAXBUFLEN];
            if ((numbytes = recv(clientSocket, buf, MAXBUFLEN-1 , 0)) == -1) {
                perror("Error in receiving from client");
                exit(1);
            }
            if(numbytes == 0)
                goto EXIT_AFTER_LOGIN;

            PacketToData(buf, clientMessage);
        }

        if(clientMessage->type == LOGIN){
            sendMessage->type = LO_NAK;
            sendMessage->size = sizeof("You are already logged in. Logout first");
            strcpy(sendMessage->source, "server");
            strcpy(sendMessage->data, "You are already logged in. Logout first");
            
            {
                char buf[MAXBUFLEN];
                DataToPacket(buf, sendMessage);
                
                if ((numbytes = send(clientSocket, buf, MAXBUFLEN-1 , 0)) == -1) {
                    perror("Error in sending to client\n");
                    exit(1);
                }
            }
        }

        // exit the session, delete the session if the last thread
        // make itself inactive in list of clients
        // logout before exiting? 
        if(clientMessage->type == EXIT){
            EXIT_AFTER_LOGIN:
            printf("Please dont leave %s!!!\n", newClient->clientUsername);
            pthread_mutex_lock(&clientsMutex);
            if(newClient->joinedSession){
                int sessionIndex = newClient->sessionIndex;
                sessionList[sessionIndex].numClients-= 1; 

                // if no clients, inactivate the session
                if(sessionList[sessionIndex].numClients == 0){
                    sessionList[sessionIndex].sessionIndex = INACTIVE_SESSION;
                }
            }
            clientList[clientIndex].clientIndex = INACTIVE_CLIENT;
            pthread_mutex_unlock(&clientsMutex);

            // free malloced data
            free(clientMessage);
            free(sendMessage);
            free(newClient->clientUsername);
            free(newClient);
            close(clientSocket);
            return NULL;
        }

        if(clientMessage->type == NEW_SESS){
            if(newClient->joinedSession){
                createSessionHelp = true; // helps to return back after leaving session
                goto LEAVESESSION;
            }

            BACKTOCREATESESSION: 
            createSessionHelp = false;
            pthread_mutex_lock(&clientsMutex);

            // create session and add name to list
            struct Session newSession;
            newSession.sessionIndex = totalSessions;
            newSession.sessionName = (char *) malloc(clientMessage->size);
            strncpy(newSession.sessionName, clientMessage->data, clientMessage->size);
            *(newSession.sessionName + clientMessage->size) = 0;
            newSession.numClients = 1; 
            sessionList[totalSessions] = newSession;
            

            // join the session
            newClient->sessionIndex = totalSessions;
            newClient->sessionName = (char *) malloc(clientMessage->size);
            strncpy(newClient->sessionName,clientMessage->data, clientMessage->size);
            *(newClient->sessionName + clientMessage->size) = 0;
            newClient->joinedSession = true;

            // increment count for sessions array
            totalSessions++;

            // update the client list with client information
            clientList[clientIndex] = *newClient;
            pthread_mutex_unlock(&clientsMutex);

            // send ack for new session
            sendMessage->type = NS_ACK;
            sendMessage->size = sizeof("New session created succefully!");
            strcpy(sendMessage->source, "server");
            strcpy(sendMessage->data,"New session created succefully!");

            {
                char buf[MAXBUFLEN];
                DataToPacket(buf, sendMessage);
                if ((numbytes = send(clientSocket, buf, MAXBUFLEN-1 , 0)) == -1) {
                    perror("Error in sending to client\n");
                    exit(1);
                }
            }
        }

        if(clientMessage->type == JOIN){
            JOINSESSION:

            if(newClient->joinedSession){
                joiningSessionHelp = true;
                goto LEAVESESSION;
            }

            BACKTOJOINSESSION:
            joiningSessionHelp = false;
            pthread_mutex_lock(&clientsMutex);

            for(int i =0; i<totalSessions; i++){
                if(sessionList[i].sessionIndex != INACTIVE_SESSION){
                    if(strcmp(sessionList[i].sessionName,clientMessage->data) == 0){
                        newClient->sessionIndex = i;
                        newClient->sessionName = (char *) malloc(clientMessage->size);
                        strncpy(newClient->sessionName, clientMessage->data, clientMessage->size);
                        *(newClient->sessionName + clientMessage->size) = 0;
                        newClient->joinedSession = true;
                        sessionList[i].numClients+= 1;
                        break;
                    }
                }
            }

            // update the client list with client information
            clientList[clientIndex] = *newClient;
            pthread_mutex_unlock(&clientsMutex);

            if(newClient->joinedSession){
                // send ack for join session
                sendMessage->type = JN_ACK;
                sendMessage->size = sizeof("Joined session succefully!");
                strcpy(sendMessage->source, "server");
                strcpy(sendMessage->data,"Joined session succefully!");

                {
                    char buf[MAXBUFLEN];
                    DataToPacket(buf, sendMessage);
                    if ((numbytes = send(clientSocket, buf, MAXBUFLEN-1 , 0)) == -1) {
                        perror("Error in sending to client\n");
                        exit(1);
                    }
                }
            }
            else if(!newClient->joinedSession){
                // send nak for join session
                sendMessage->type = JN_NAK;
                sendMessage->size = sizeof("The session you entered is invalid");
                strcpy(sendMessage->source, "server");
                strcpy(sendMessage->data, "The session you entered is invalid");

                {
                    char buf[MAXBUFLEN];
                    DataToPacket(buf, sendMessage);
                    if ((numbytes = send(clientSocket, buf, MAXBUFLEN-1 , 0)) == -1) {
                        perror("Error in sending to client\n");
                        exit(1);
                    }
                }
            }
        }

        if(clientMessage->type == LEAVE_SESS){
            LEAVESESSION:
            pthread_mutex_lock(&clientsMutex);

            if(newClient->joinedSession){
                newClient->joinedSession = false;
                sessionList[newClient->sessionIndex].numClients-=1;
            }

            else{
                 // We do nothing
                 printf("Trying to leave session but we client never joined one\n");
            }

            int sessionIndex = newClient->sessionIndex;
            printf("%s has left session %s\n", newClient->clientUsername, sessionList[sessionIndex].sessionName);

            // if no clients, inactivate the session
            if(sessionList[sessionIndex].numClients == 0){
                printf("Everyone has left session %s : Deactivating", sessionList[sessionIndex].sessionName);
                sessionList[sessionIndex].sessionIndex = INACTIVE_SESSION;
            }

            // update the client list with client information
            clientList[clientIndex] = *newClient;
            pthread_mutex_unlock(&clientsMutex);
            
            if(createSessionHelp == true){
                goto BACKTOCREATESESSION;
            }
            if(joiningSessionHelp == true){
                goto BACKTOJOINSESSION;
            }
        }

        if(clientMessage->type == MESSAGE){
            
            pthread_mutex_lock(&clientsMutex);
            if(newClient->joinedSession == true){
                int i;
                for(i = 0; i<totalClients; i++){
                    
                    // check the client list item if it is a part of same session
                    if(clientList[i].clientIndex!= INACTIVE_CLIENT){
                        if(clientList[i].sessionIndex == newClient->sessionIndex){
                            
                            // empty client message
                            free(sendMessage);
                            sendMessage = (struct message*) malloc(sizeof(struct message));

                            // send message to all clients connected
                            sendMessage->type = MESSAGE;
                            sendMessage->size = clientMessage->size;
                            strcpy(sendMessage->source, newClient->clientUsername);
                            strncpy(sendMessage->data, clientMessage->data, clientMessage->size);
                            *(sendMessage->data + clientMessage->size) = 0;
                            {
                                char buf[MAXBUFLEN];
                                DataToPacket(buf, sendMessage);
                                if ((numbytes = send(clientList[i].clientSocket, buf, MAXBUFLEN-1 , 0)) == -1) {
                                    perror("Error in sending to client\n");
                                    exit(1);
                                }
                            }

                            // potential bug: case of unexpected closed connection here, numbytes = 0
                        }
                    }
                }
            }
            pthread_mutex_unlock(&clientsMutex);
        }

        if(clientMessage->type == QUERY){
            pthread_mutex_lock(&clientsMutex);

            char * result = (char*) malloc(1000);
            int i;
            int cursor = 0;
            for(i = 0; i<totalClients; i++){
                // add every active user and its session name to the list
                if(clientList[i].clientIndex!= INACTIVE_CLIENT && clientList[i].joinedSession){                      
                    cursor+= sprintf(result+cursor, "%s: %s\n", clientList[i].clientUsername, clientList[i].sessionName);
                }
            }
            printf("%s\n",result);
            int resultLen = strlen(result);
            sendMessage->type = QU_ACK;
            sendMessage->size = resultLen;
            strcpy(sendMessage->source, newClient->clientUsername);
            strncpy(sendMessage->data, result, resultLen);
            free(result);

            {
                char buf[MAXBUFLEN];
                DataToPacket(buf, sendMessage);
                if ((numbytes = send(clientList[clientIndex].clientSocket, buf, MAXBUFLEN-1 , 0)) == -1) {
                    perror("Error in sending to client\n");
                    exit(1);
                }
            }
            
            pthread_mutex_unlock(&clientsMutex);
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

        pthread_mutex_lock(&clientsMutex);
        // Add a client to the list of clients with socketfd and address
        clientList[totalClients].clientSocket = newClientSocket;
        clientList[totalClients].clientIndex = totalClients;
        pthread_mutex_unlock(&clientsMutex);
        // Create a thread that uses the socket and handles connection
        pthread_create(&newClientThread, NULL, handleConnection, (void*) &clientList[totalClients].clientIndex);
        totalClients++;
    }
}
