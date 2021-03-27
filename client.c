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
void login(char *arg1, char *arg2, char *arg3, char *arg4, int *sockfd, pthread_t *clientThread);
void logout(int *sockfd, pthread_t *clientThread);
void joinsession(char *arg1, int *sockfd);
void leavesession(int *sockfd);
void createsession(char *arg1, int *sockfd);
void list(int *sockfd);
void quit(int *sockfd, pthread_t *clientThread);
void messageTransfer(char *message, int *sockfd);

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
			if (arg1[0] != '\0') {
				perror("too many arguments\n");
				goto ask_input;
			}
			messageTransfer(command, &sockfd);
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
	hints.ai_socktype = SOCK_DGRAM;

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
		*sockfd = 0;
		return;
	}

	inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr),
				s, sizeof s);
	printf("talker: connecting to %s\n", s);

	freeaddrinfo(servinfo);

	//send packet
	struct message* newPacket = (struct message*) malloc(sizeof(struct message));
	//populate packet
	newPacket->type = LOGIN;
	newPacket->size = sizeof(*arg2);
	strcpy(newPacket->source, arg1);
	strcpy(newPacket->data, arg2);


	//free packet space allocated by malloc
    free(newPacket);
}

void logout(int *sockfd, pthread_t *clientThread){

}

void joinsession(char *arg1, int *sockfd){

}

void leavesession(int *sockfd){

}

void createsession(char *arg1, int *sockfd){

}

void list(int *sockfd){

}

void quit(int *sockfd, pthread_t *clientThread){

}

void messageTransfer(char *message, int *sockfd){

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
		command[index] = buf[count];
		count++;
		index++;
	}
	command[index] = '\0';
	index = 0;
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