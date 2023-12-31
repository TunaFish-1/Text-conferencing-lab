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
    char* admin;
};



#define SERVER_CAPACITY 30
#define SESSION_CAPACITY 20
#define INACTIVE_CLIENT -1
#define INACTIVE_SESSION -1
#define MAXCHAR 1000

char *noMoreAdmin = "NO_MORE_ADMIN";

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
        

        // check if user has already logged in
        pthread_mutex_lock(&clientsMutex);
        int i;
        for(i = 0; i<totalClients; i++){

            if(clientList[i].clientIndex!= INACTIVE_CLIENT){
                if(clientList[i].clientUsername !=NULL && strcmp(clientList[i].clientUsername, username) == 0){
                    reasonForFailure = "Another client with same username already logged in";
                    pthread_mutex_unlock(&clientsMutex);
                    goto INVALID_LOGIN;
                }
            }
        }
        pthread_mutex_unlock(&clientsMutex);


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
            DataToPacketSafe(buf, sendMessage);
            
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
        DataToPacketSafe(buf, sendMessage);
        if ((numbytes = send(clientSocket, buf, MAXBUFLEN-1 , 0)) == -1) {
            perror("Error in sending to client\n");
            exit(1);
        }
    }
    
    free(clientMessage);
    free(sendMessage);
    printf("Login successful ack sent!\n");

    // bool loggedIn = true;
    // --- Check command other than login now ---

    while(1){

        struct message* clientMessaging = (struct message*) malloc(sizeof(struct message));
        struct message* sendMessaging = (struct message*) malloc(sizeof(struct message));

        // Helper variables
        bool joiningSessionHelp = false;
        bool createSessionHelp = false;

        // //timeout
        struct timeval timeout;
        timeout.tv_sec = 120;
        timeout.tv_usec = 0;
        int timeover = 0;
        if (setsockopt(clientSocket, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout)) < 0) {
            perror("setsockopt failed\n");
            exit(1);
        }

        // receive a message from the client
        {
            char buf[MAXBUFLEN];
            numbytes = recv(clientSocket, buf, MAXBUFLEN-1 , 0);
            if (numbytes == -1){
                timeover = 1;
                goto EXIT_AFTER_LOGIN;

            }
            if(numbytes == 0)
                goto EXIT_AFTER_LOGIN;

            PacketToData(buf, clientMessaging);
        }

        if(clientMessaging->type == LOGIN){
            sendMessaging->type = LO_NAK;
            sendMessaging->size = sizeof("You are already logged in. Logout first");
            strcpy(sendMessaging->source, "server");
            strcpy(sendMessaging->data, "You are already logged in. Logout first");
            
            {
                char buf[MAXBUFLEN];
                DataToPacketSafe(buf, sendMessaging);
                
                if ((numbytes = send(clientSocket, buf, MAXBUFLEN-1 , 0)) == -1) {
                    perror("Error in sending to client\n");
                    exit(1);
                }
            }
        }

        // exit the session, delete the session if the last thread
        // make itself inactive in list of clients
        // logout before exiting? 
        if(clientMessaging->type == EXIT){
            EXIT_AFTER_LOGIN:
            if(timeover){
                sendMessaging->type = TIME;
                sendMessaging->size = sizeof("You are being logged out, TIMEOUT\n");
                strcpy(sendMessaging->source, "server");
                strcpy(sendMessaging->data, "You are being logged out, TIMEOUT\n");
                
                {
                    char buf[MAXBUFLEN];
                    DataToPacketSafe(buf, sendMessaging);
                    
                    if ((numbytes = send(clientSocket, buf, MAXBUFLEN-1 , 0)) == -1) {
                        perror("Error in sending to client\n");
                        exit(1);
                    }
                }
                printf("Kicking %s!!!\n", newClient->clientUsername);
            }else{
                printf("Please dont leave %s!!!\n", newClient->clientUsername);
            }
            pthread_mutex_lock(&clientsMutex);
            if(newClient->joinedSession){
                int sessionIndex = newClient->sessionIndex;
                sessionList[sessionIndex].numClients-= 1; 

                //if admin and not transfered, transfer to someone still in session
                sessionList[sessionIndex].admin = noMoreAdmin;
                printf("ADMIN left without having a successor, no more admins, all are equal\n");

                // if no clients, inactivate the session
                if(sessionList[sessionIndex].numClients == 0){
                    printf("Everyone has left session %s : Deactivating\n", sessionList[sessionIndex].sessionName);
                    sessionList[sessionIndex].sessionIndex = INACTIVE_SESSION;
                }
            }
            clientList[clientIndex].clientIndex = INACTIVE_CLIENT;
            pthread_mutex_unlock(&clientsMutex);

            // free malloced data
            free(clientMessaging);
            free(sendMessaging);
            free(newClient->clientUsername);
            free(newClient);
            close(clientSocket);
            return NULL;
        }

        if(clientMessaging->type == NEW_SESS){
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
            newSession.sessionName = (char *) malloc(clientMessaging->size);
            strncpy(newSession.sessionName, clientMessaging->data, clientMessaging->size);
            *(newSession.sessionName + clientMessaging->size) = 0;
            newSession.numClients = 1; 
            newSession.admin = newClient->clientUsername;
            sessionList[totalSessions] = newSession;
            

            // join the session
            newClient->sessionIndex = totalSessions;
            newClient->sessionName = (char *) malloc(clientMessaging->size);
            strncpy(newClient->sessionName,clientMessaging->data, clientMessaging->size);
            *(newClient->sessionName + clientMessaging->size) = 0;
            newClient->joinedSession = true;

            // increment count for sessions array
            totalSessions++;

            // update the client list with client information
            clientList[clientIndex] = *newClient;
            pthread_mutex_unlock(&clientsMutex);

            // send ack for new session
            sendMessaging->type = NS_ACK;
            sendMessaging->size = sizeof("New session created succefully!");
            strcpy(sendMessaging->source, "server");
            strcpy(sendMessaging->data,"New session created succefully!");

            {
                char buf[MAXBUFLEN];
                DataToPacketSafe(buf, sendMessaging);
                if ((numbytes = send(clientSocket, buf, MAXBUFLEN-1 , 0)) == -1) {
                    perror("Error in sending to client\n");
                    exit(1);
                }
            }
        }

        if(clientMessaging->type == JOIN){
            JOINSESSION:

            // if(newClient->joinedSession){
            //     joiningSessionHelp = true;
            //     goto LEAVESESSION;
            // }

            BACKTOJOINSESSION:
            joiningSessionHelp = false;
            pthread_mutex_lock(&clientsMutex);

            char * sessionToJoin = (char *) malloc(clientMessaging->size);
            strncpy(sessionToJoin, clientMessaging->data, clientMessaging->size);
            *(sessionToJoin + clientMessaging->size) = 0;

            for(int i =0; i<totalSessions; i++){
                if(sessionList[i].sessionIndex != INACTIVE_SESSION){
                    if(strcmp(sessionList[i].sessionName,sessionToJoin) == 0){
                        newClient->sessionIndex = i;
                        newClient->sessionName = (char *) malloc(clientMessaging->size);
                        strncpy(newClient->sessionName, sessionToJoin, clientMessaging->size);
                        *(newClient->sessionName + clientMessaging->size) = 0;
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
                sendMessaging->type = JN_ACK;
                sendMessaging->size = sizeof("Joined session succefully!");
                strcpy(sendMessaging->source, "server");
                strcpy(sendMessaging->data,"Joined session succefully!");

                {
                    char buf[MAXBUFLEN];
                    DataToPacketSafe(buf, sendMessaging);
                    if ((numbytes = send(clientSocket, buf, MAXBUFLEN-1 , 0)) == -1) {
                        perror("Error in sending to client\n");
                        exit(1);
                    }
                }
            }
            else if(!newClient->joinedSession){
                // send nak for join session
                sendMessaging->type = JN_NAK;
                sendMessaging->size = sizeof("The session you entered is invalid");
                strcpy(sendMessaging->source, "server");
                strcpy(sendMessaging->data, "The session you entered is invalid");

                {
                    char buf[MAXBUFLEN];
                    DataToPacketSafe(buf, sendMessaging);
                    if ((numbytes = send(clientSocket, buf, MAXBUFLEN-1 , 0)) == -1) {
                        perror("Error in sending to client\n");
                        exit(1);
                    }
                }
            }
        }

        if(clientMessaging->type == LEAVE_SESS){
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

            //if admin and not transfered, transfer to someone still in session
            sessionList[sessionIndex].admin = noMoreAdmin;
            printf("ADMIN left without having a successor, no more admins, all are equal\n");

            // if no clients, inactivate the session
            if(sessionList[sessionIndex].numClients == 0){
                printf("Everyone has left session %s : Deactivating\n", sessionList[sessionIndex].sessionName);
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

        if(clientMessaging->type == MESSAGE){
            
            pthread_mutex_lock(&clientsMutex);
            if(newClient->joinedSession == true){
                int i;
                for(i = 0; i<totalClients; i++){
                    
                    // check the client list item if it is a part of same session
                    if(clientList[i].clientIndex!= INACTIVE_CLIENT){
                        if(clientList[i].joinedSession && clientList[i].sessionIndex == newClient->sessionIndex){
                            
                            struct message* sendText = (struct message*) malloc(sizeof(struct message));

                            // send message to all clients connected
                            sendText->type = MESSAGE;
                            sendText->size = clientMessaging->size;
                            strcpy(sendText->source, newClient->clientUsername);
                            strncpy(sendText->data, clientMessaging->data, clientMessaging->size);
                            *(sendText->data + clientMessaging->size) = 0;
                            {
                                char buf[MAXBUFLEN];
                                DataToPacketSafe(buf, sendText);
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

        if(clientMessaging->type == KICK){
            
            pthread_mutex_lock(&clientsMutex);
            if(newClient->joinedSession == true){
                int i;
                for(i = 0; i<totalClients; i++){
                    
                    // check the client list item if it is a part of same session
                    if(clientList[i].clientIndex!= INACTIVE_CLIENT){
                        if(clientList[i].joinedSession && clientList[i].sessionIndex == newClient->sessionIndex){
                            if(strcmp(clientList[i].clientUsername, clientMessaging->data) == 0){
                                if(clientList[i].joinedSession){
                                    clientList[i].joinedSession = false;
                                    sessionList[clientList[i].sessionIndex].numClients-=1;
                                }

                                int sessionIndex = clientList[i].sessionIndex;
                                //int sessionIndex = newClient->sessionIndex;
                                printf("%s has been kicked from session %s\n", clientList[i].clientUsername, sessionList[sessionIndex].sessionName);

                                // update the client list with client information
                                //clientList[clientIndex] = clientList[i];

                                struct message* sendText = (struct message*) malloc(sizeof(struct message));

                                // send message to all clients connected
                                sendText->type = K_ACK;
                                sendText->size = strlen("Has kicked you from the session");
                                strcpy(sendText->source, newClient->clientUsername);
                                strcpy(sendText->data, "Has kicked you from the session");
                                {
                                    char buf[MAXBUFLEN];
                                    DataToPacketSafe(buf, sendText);
                                    if ((numbytes = send(clientList[i].clientSocket, buf, MAXBUFLEN-1 , 0)) == -1) {
                                        perror("Error in sending to client\n");
                                        exit(1);
                                    }
                                }
                                break;
                            }

                            // potential bug: case of unexpected closed connection here, numbytes = 0
                        }
                    }
                }
                if(i == totalClients){
                    //NOT FOUND
                    // send nak for join session
                    sendMessaging->type = K_NACK;
                    sendMessaging->size = sizeof("The client you entered is invalid");
                    strcpy(sendMessaging->source, "server");
                    strcpy(sendMessaging->data, "The client you entered is invalid");

                    {
                        char buf[MAXBUFLEN];
                        DataToPacketSafe(buf, sendMessaging);
                        if ((numbytes = send(clientSocket, buf, MAXBUFLEN-1 , 0)) == -1) {
                            perror("Error in sending to client\n");
                            exit(1);
                        }
                    }
                }
            }
            pthread_mutex_unlock(&clientsMutex);
        }

        if(clientMessaging->type == ADMIN){
            
            pthread_mutex_lock(&clientsMutex);
            if(newClient->joinedSession == true){
                int i;
                for(i = 0; i<totalClients; i++){
                    
                    // check the client list item if it is a part of same session
                    if(clientList[i].clientIndex!= INACTIVE_CLIENT){
                        if(clientList[i].joinedSession && clientList[i].sessionIndex == newClient->sessionIndex){
                            if(strcmp(clientList[i].clientUsername, clientMessaging->data) == 0){
                                int sessionIndex = newClient->sessionIndex;
                                if(clientList[i].joinedSession){
                                    sessionList[sessionIndex].admin = clientList[i].clientUsername;
                                }

                                printf("%s has been made admin of session %s\n", clientList[i].clientUsername, sessionList[sessionIndex].sessionName);

                                struct message* sendText = (struct message*) malloc(sizeof(struct message));

                                // send message to all clients connected
                                sendText->type = AD_ACK;
                                sendText->size = strlen("Has made you admin of the session");
                                strcpy(sendText->source, newClient->clientUsername);
                                strcpy(sendText->data, "Has made you admin of the session");
                                {
                                    char buf[MAXBUFLEN];
                                    DataToPacketSafe(buf, sendText);
                                    if ((numbytes = send(clientList[i].clientSocket, buf, MAXBUFLEN-1 , 0)) == -1) {
                                        perror("Error in sending to client\n");
                                        exit(1);
                                    }
                                }
                                break;
                            }

                            // potential bug: case of unexpected closed connection here, numbytes = 0
                        }
                    }
                }
                if(i == totalClients){
                    //NOT FOUND
                    // send nak for join session
                    sendMessaging->type = AD_NACK;
                    sendMessaging->size = sizeof("The client you entered is invalid");
                    strcpy(sendMessaging->source, "server");
                    strcpy(sendMessaging->data, "The client you entered is invalid");

                    {
                        char buf[MAXBUFLEN];
                        DataToPacketSafe(buf, sendMessaging);
                        if ((numbytes = send(clientSocket, buf, MAXBUFLEN-1 , 0)) == -1) {
                            perror("Error in sending to client\n");
                            exit(1);
                        }
                    }
                }
            }
            pthread_mutex_unlock(&clientsMutex);
        }

        if(clientMessaging->type == QUERY){
            pthread_mutex_lock(&clientsMutex);

            // empty client message
            free(sendMessaging);
            sendMessaging = (struct message*) malloc(sizeof(struct message));

            char * result = (char*) malloc(1000);
            int i;
            int cursor = 0;
            for(i = 0; i<totalClients; i++){
                // add every active user and its session name to the list
                if(clientList[i].clientIndex!= INACTIVE_CLIENT){                      
                    cursor+= sprintf(result+cursor, "%s: ", clientList[i].clientUsername);
                    if(clientList[i].joinedSession){
                        if(strcmp(sessionList[clientList[i].sessionIndex].admin, clientList[i].clientUsername)==0){
                            cursor+= sprintf(result+cursor, "ADMIN of "); 
                        }
                        cursor+= sprintf(result+cursor, "%s\n", clientList[i].sessionName);
                    }else{
                        cursor+= sprintf(result+cursor, "not in a session\n");
                    }
                }
            }
            printf("%s\n",result);
            int resultLen = strlen(result);
            sendMessaging->type = QU_ACK;
            sendMessaging->size = resultLen;
            strcpy(sendMessaging->source, newClient->clientUsername);
            strncpy(sendMessaging->data, result, resultLen);
            *(sendMessaging->data + resultLen) = 0;
            free(result);

            {
                char buf[MAXBUFLEN];
                DataToPacketSafe(buf, sendMessaging);
                if ((numbytes = send(clientList[clientIndex].clientSocket, buf, MAXBUFLEN-1 , 0)) == -1) {
                    perror("Error in sending to client\n");
                    exit(1);
                }
            }
            
            pthread_mutex_unlock(&clientsMutex);
        }
        free(clientMessaging);
        free(sendMessaging);
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