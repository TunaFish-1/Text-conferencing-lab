/*
	client.c 
	Made by Anthony Fakhoury and Romil Jain
	Inspired by snipets of code from Beej's Guide to Network Programming
*/

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

#include "packet.h"

//forward declarations
void askInput(char *buf, char *command, char *arg1, char *arg2, char *arg3, char *arg4, char *extra);
void *client_receiver(void *socketfd);
void login(char *arg1, char *arg2, char *arg3, char *arg4, int *sockfd, pthread_t *clientThread);
int logout(int *sockfd, pthread_t *clientThread);
void joinsession(char *arg1, int *sockfd);
void leavesession(int *sockfd);
void createsession(char *arg1, int *sockfd);
void list(int *sockfd);
void quit(int *sockfd, pthread_t *clientThread);
void messageTransfer(char *message, int *sockfd);

//global variables
char *sessionID = NULL;
char *clientID = NULL;

int main(int argc, char *argv[])
{
	int sockfd = 0;
	char buf[MAXBUFLEN];
	char command[MAX_NAME];
	char arg1[MAX_NAME];
	char arg2[MAX_NAME];
	char arg3[MAX_NAME];
	char arg4[MAX_NAME];
	char extra[MAX_NAME];
	pthread_t clientThread;


	if (argc != 1) {
		fprintf(stderr,"usage\n");
		exit(1);
	}

	while(1){
		//ask the user to input a message 
		ask_input:
		askInput(buf, command, arg1, arg2, arg3, arg4, extra);
		//check input length
		if (command[0] == '\0') {
			perror("too few arguments or too long\n");
			goto ask_input;
		} else if (extra[0] != '\0') {
			perror("too many arguments\n");
			goto ask_input;
		}

		//check command
		if (strcmp(command, "/login")==0){
			if (arg1[0] == '\0' || arg2[0] == '\0' || arg3[0] == '\0' || arg4[0] == '\0') {
				perror("too few arguments or too long\n");
				goto ask_input;
			} else if (extra[0] != '\0') {
				perror("too many arguments\n");
				goto ask_input;
			}
			login(arg1, arg2, arg3, arg4, &sockfd, &clientThread);
		}else if (strcmp(command, "/logout")==0){ 
			if (arg1[0] != '\0') {
				perror("too many arguments\n");
				goto ask_input;
			}
			logout(&sockfd, &clientThread);
		}else if (strcmp(command, "/joinsession")==0){ 
			if (arg1[0] == '\0') {
				perror("too few arguments or too long\n");
				goto ask_input;
			} else if (arg2[0] != '\0') {
				perror("too many arguments\n");
				goto ask_input;
			}
			joinsession(arg1, &sockfd);
		}else if (strcmp(command, "/leavesession")==0){
			if (arg1[0] != '\0') {
				perror("too many arguments\n");
				goto ask_input;
			}
			leavesession(&sockfd);
		}else if (strcmp(command, "/createsession")==0){
			if (arg1[0] != '\0') {
				perror("too many arguments\n");
				goto ask_input;
			}
			createsession(arg1, &sockfd);
		}else if (strcmp(command, "/list")==0){
			if (arg1[0] != '\0') {
				perror("too many arguments\n");
				goto ask_input;
			}
			list(&sockfd);
		}else if (strcmp(command, "/quit")==0){
			if (arg1[0] != '\0') {
				perror("too many arguments\n");
				goto ask_input;
			}
			quit(&sockfd, &clientThread);
			fprintf(stdout, "EXIT\n");
			return 0;
		}else{ //command is the message to be sent
			messageTransfer(buf, &sockfd);
		}
	}
	fprintf(stdout, "EXIT\n");
	return 0;
}

void login(char *arg1, char *arg2, char *arg3, char *arg4, int *sockfd, pthread_t *clientThread){
	//initiaite connection
	if (*sockfd){
		fprintf(stdout, "Client already connected\n");
		return;
	}

	struct addrinfo hints, *servinfo, *p;
	int rv;
	int numbytes;
	char s[INET_ADDRSTRLEN]; 

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_INET; // set to AF_INET6 to use IPv6
	hints.ai_socktype = SOCK_STREAM; // TCP

	if ((rv = getaddrinfo(arg3, arg4, &hints, &servinfo)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
		return;
	}

	// loop through all the results and make a socket
	for(p = servinfo; p != NULL; p = p->ai_next) {
		if ((*sockfd = socket(p->ai_family, p->ai_socktype,
				p->ai_protocol)) == -1) {
			perror("talker: socket\n");
			continue;
		}
		if (connect(*sockfd, p->ai_addr, p->ai_addrlen) == -1) { 
			close(*sockfd);
			perror("talker: connect\n");
			continue;
		}

		break;
	}

	if (p == NULL) {
		fprintf(stderr, "talker: failed to create socket\n");
		close(*sockfd);
		*sockfd = 0;
		return;
	}

	inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr),
				s, sizeof s);
	printf("talker: connecting to %s\n", s);

	freeaddrinfo(servinfo);

	//create packet
	struct message* newPacket = (struct message*) malloc(sizeof(struct message));
	clientID = arg1;
	//populate packet
	newPacket->type = LOGIN;
	newPacket->size = sizeof(*arg2);
	strcpy(newPacket->source, arg1);
	strcpy(newPacket->data, arg2);

	//format packet
	char buffer[MAXBUFLEN];
	DataToPacket(buffer, newPacket);

	//send packet
	if ((numbytes = send(*sockfd, buffer, strlen(buffer), 0)) == -1) {
		perror("talker: send");
		close(*sockfd);
		*sockfd = 0;
		free(newPacket);
		return;
	}

	//receive a message from the server
	memset(buffer, 0, MAXBUFLEN); // first empty the buffer
	if ((numbytes = recv(*sockfd, buffer, MAXBUFLEN-1 , 0)) == -1) {
		perror("recv");
		close(*sockfd);
		*sockfd = 0;
		free(newPacket);
		return;
	}

	//format message
	PacketToData(buffer, newPacket);

	//check info
	if (newPacket->type == LO_ACK){
		//create a thread for active user logging in a session to receive messages from server
		numbytes = pthread_create(clientThread, NULL, client_receiver, sockfd);
		if (numbytes){
			fprintf(stderr, "talker: %s failed to log in, thread_create error\n", arg1);
			close(*sockfd);
			*sockfd = 0;
			free(newPacket);
			return;
		}
		fprintf(stdout, "talker: %s successfully logged in to %s on port %s\n", arg1, arg3, arg4);
	}else if (newPacket->type == LO_NAK){
		fprintf(stderr, "talker: %s failed logged in to %s on port %s due to %s\n", arg1, arg3, arg4, newPacket->data);
		close(*sockfd);
		*sockfd = 0;
		free(newPacket);
		return;
	}else{
		fprintf(stderr, "talker: %s failed to log in, unexpected response from server\n", arg1);
		close(*sockfd);
		*sockfd = 0;
		free(newPacket);
		return;
	}

	//free packet space allocated by malloc
    free(newPacket);
}

int logout(int *sockfd, pthread_t *clientThread){
	if (*sockfd == 0){
		fprintf(stdout, "Client not logged in\n");
		return -1;
	}

	//create packet
	struct message* newPacket = (struct message*) malloc(sizeof(struct message));
	//populate packet
	newPacket->type = EXIT;
	newPacket->size = 0;
	strcpy(newPacket->source, clientID);
	strcpy(newPacket->data, NULL);

	//format packet
	char buffer[MAXBUFLEN];
	int numbytes;
	DataToPacket(buffer, newPacket);

	//send packet
	if ((numbytes = send(*sockfd, buffer, strlen(buffer), 0)) == -1) {
		perror("talker: send");
		free(newPacket);
		return -1;
	}

	numbytes = pthread_cancel(*clientThread);
	if(numbytes){
		fprintf(stderr, "talker: failed to delete thread during log out\n");
		free(newPacket);
		return -1;
	}

	fprintf(stdout, "talker: client successfully logged out\n");
	close(*sockfd);
	*sockfd = 0;
	sessionID = NULL;
	free(newPacket);
	return 1;
}

void joinsession(char *arg1, int *sockfd){

}

void leavesession(int *sockfd){

}

void createsession(char *arg1, int *sockfd){

}

void list(int *sockfd){
	if (*sockfd == 0){
		fprintf(stdout, "Client not logged in\n");
		return;
	}

	//create packet
	struct message* newPacket = (struct message*) malloc(sizeof(struct message));
	//populate packet
	newPacket->type = QUERY;
	newPacket->size = 0;
	strcpy(newPacket->source, clientID);
	strcpy(newPacket->data, NULL);

	//format packet
	char buffer[MAXBUFLEN];
	int numbytes;
	DataToPacket(buffer, newPacket);

	//send packet
	if ((numbytes = send(*sockfd, buffer, strlen(buffer), 0)) == -1) {
		perror("talker: send");
		free(newPacket);
		return;
	}

	free(newPacket);
	return;
}

void quit(int *sockfd, pthread_t *clientThread){
	if (logout(sockfd, clientThread) == 1){
		fprintf(stdout, "talker: terminating program\n");
		exit(1);
	}else{
		return;
	}
}

void messageTransfer(char *message, int *sockfd){
	if (*sockfd == 0){
		fprintf(stdout, "Client not logged in\n");
		return;
	}else if (sessionID == NULL){
		fprintf(stdout, "Client not in a session\n");
		return;
	}

	//create packet
	struct message* newPacket = (struct message*) malloc(sizeof(struct message));
	//populate packet
	newPacket->type = MESSAGE;
	newPacket->size = sizeof(*message);
	strcpy(newPacket->source, clientID);
	strcpy(newPacket->data, message);

	//format packet
	char buffer[MAXBUFLEN];
	int numbytes;
	DataToPacket(buffer, newPacket);

	//send packet
	if ((numbytes = send(*sockfd, buffer, strlen(buffer), 0)) == -1) {
		perror("talker: send");
		free(newPacket);
		return;
	}

	free(newPacket);
	return;

}

void askInput(char *buf, char *command, char *arg1, char *arg2, char *arg3, char *arg4, char *extra){

	printf("User: insert command\n");
	memset(buf, 0, MAXBUFLEN); // first empty the buffer
	fgets(buf, MAXBUFLEN, stdin);
	fflush(stdin);

	//extract user input (instead of using scanf as requested by TA)
	int count = 0;
	while (buf[count]==' ') {
		if (count >= MAXBUFLEN) {
			break;
		}
		count++;
	}
	int index = 0;
	while (buf[count]!=' ') {
		if (buf[count]=='\0' || buf[count]=='\n' || count >= MAXBUFLEN) {
			break;
		}
		command[index] = buf[count];
		count++;
		index++;
	}
	command[index] = '\0';
	index = 0;
	while (buf[count]==' ') {
		if (count >= MAXBUFLEN) {
			break;
		}
		count++;
	}
	while (buf[count]!=' ') {
		if (buf[count]=='\0' || buf[count]=='\n' || count >= MAXBUFLEN) {
			break;
		}
		arg1[index] = buf[count];
		count++;
		index++;
	}
	arg1[index] = '\0';
	index = 0;
	while (buf[count]==' ') {
		if (count >= MAXBUFLEN) {
			break;
		}
		count++;
	}
	while (buf[count]!=' ') {
		if (buf[count]=='\0' || buf[count]=='\n' || count >= MAXBUFLEN) {
			break;
		}
		arg2[index] = buf[count];
		count++;
		index++;
	}
	arg2[index] = '\0';
	index = 0;
	while (buf[count]==' ') {
		if (count >= MAXBUFLEN) {
			break;
		}
		count++;
	}
	while (buf[count]!=' ') {
		if (buf[count]=='\0' || buf[count]=='\n' || count >= MAXBUFLEN) {
			break;
		}
		arg3[index] = buf[count];
		count++;
		index++;
	}
	arg3[index] = '\0';
	index = 0;
	while (buf[count]==' ') {
		if (count >= MAXBUFLEN) {
			break;
		}
		count++;
	}
	while (buf[count]!=' ') {
		if (buf[count]=='\0' || buf[count]=='\n' || count >= MAXBUFLEN) {
			break;
		}
		arg4[index] = buf[count];
		count++;
		index++;
	}
	arg4[index] = '\0';
	index = 0;
	while (buf[count]==' ') {
		if (count >= MAXBUFLEN) {
			break;
		}
		count++;
	}
	while (buf[count]!=' ') {
		if (buf[count]=='\0' || buf[count]=='\n' || count >= MAXBUFLEN) {
			break;
		}
		extra[index] = buf[count];
		count++;
		index++;
	}
	extra[index] = '\0';
	while (buf[count]==' ') {
		if (buf[count]=='\0' || count >= MAXBUFLEN) {
			break;
		}
		count++;
	}
}

void *client_receiver(void *socketfd){
	char buffer[MAXBUFLEN];
	int numbytes;
	struct message* newPacket = (struct message*) malloc(sizeof(struct message));
	int *sockfd = socketfd;

	while(1){
		//receive a message from the server
		memset(buffer, 0, MAXBUFLEN); // first empty the buffer
		if ((numbytes = recv(*sockfd, buffer, MAXBUFLEN-1 , 0)) == -1) {
			perror("recv");
			return NULL;
		}

		//format
		PacketToData(buffer, newPacket);

		//check info
		switch (newPacket->type)
		{
		case JN_ACK:
			sessionID = newPacket->data;
			fprintf(stdout, "talker: server acknowledge join of session %s\n", newPacket->data);
			break;
		case JN_NAK:
			sessionID = NULL;
			fprintf(stderr, "talker: can't join session %s\n", newPacket->data);
			break;
		case NS_ACK:
			sessionID = newPacket->data;
			fprintf(stdout, "talker: server acknowledge new session %s\n", newPacket->data);
			break;
		case QU_ACK:
			fprintf(stdout, "talker: List of users and sessions:\n %s\n", newPacket->data);
			break;
		case MESSAGE:
			fprintf(stdout, "%s: %s\n", newPacket->source, newPacket->data);
			break;
		default: //cannot receive LO_ACK or LO_NAK as this takes places before reaching this point
			fprintf(stderr, "talker: erronous response from server, packet is of type %d and data is %s\n", newPacket->type, newPacket->data);
			break;
		}
	}
	return NULL;
}
