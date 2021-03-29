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

struct Clients{
    int clientSocket;
    int session_id;
    char* clientUsername;
    int clientID;
};



#define SERVER_CAPACITY 10
#define INACTIVE_CLIENT -1
#define MAXCHAR 1000

struct Clients clientList[SERVER_CAPACITY];

pthread_mutex_t clientsMutex = PTHREAD_MUTEX_INITIALIZER;

void * handleConnection(void * newClientArg){

    struct Clients newClient = *(struct Clients *) newClientArg;
    int clientID = newClient.clientID;

    struct message* clientMessage = (struct message*) malloc(sizeof(struct message));
    struct message* sendMessage = (struct message*) malloc(sizeof(struct message));

    int clientSocket = newClient.clientSocket;
    // struct addrinfo hints, *servinfo, *p;
    int numbytes;
    char buf[MAXBUFLEN];
    // socklen_t addr_len;

    bool notLoggedIn = true;
    while(notLoggedIn){
        
        //receive a message from the client
        memset(buf, 0, MAXBUFLEN); 
        if ((numbytes = recv(clientSocket, buf, MAXBUFLEN-1 , 0) == -1)) {
            perror("Error in receiving from client");
            exit(1);
        }

        // message format of buffer received-  <type>:<size of data>:<source>:<data>
        printf("%s\n", buf);
        
        PacketToData(buf, clientMessage);

        // Check if first command sent by client is invalid
        if(clientMessage->type != LOGIN && clientMessage->type != EXIT){
            printf("You have to login before you do anything else. Please try again\n");
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
                    break;
                }
            }
            fclose(fp);
        }

        INVALID_LOGIN:
        if(notLoggedIn){
            printf("I m not logged in, sending packet\n");
            sendMessage->type = LO_NAK;
            sendMessage->size = sizeof("Incorrect password");
            strcpy(sendMessage->source, "server");
            strcpy(sendMessage->data, "Incorrect password");

            DataToPacket(buf, sendMessage);
            
            if ((numbytes = send(clientSocket, buf, MAXBUFLEN-1 , 0) == -1)) {
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
    }
    sendMessage->type = LO_ACK;
    sendMessage->size = 1;
    strcpy(sendMessage->source, "server");
    strcpy(sendMessage->data, "no-data");
    
    DataToPacket(buf, sendMessage);
    if ((numbytes = send(clientSocket, buf, MAXBUFLEN-1 , 0)) == -1) {
        perror("Error in sending to client\n");
        exit(1);
    }

    printf("Login successful ack sent!\n");
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
        printf("newClientSocket: %d\n", newClientSocket);
        inet_ntop(newClientAddr.ss_family, get_in_addr((struct sockaddr *)&newClientAddr), addrstlen, sizeof(addrstlen));

        // Add a client to the list of clients with socketfd and address
        clientList[totalClients].clientSocket = newClientSocket;
        clientList[totalClients].clientID = totalClients;
        
        // Create a thread that uses the socket and handles connection
        pthread_create(&newClientThread, NULL, handleConnection, &clientList[totalClients]);
        totalClients++;
    }
}
