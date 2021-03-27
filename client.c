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
void askInput(char buf[MAXBUFLEN], char command[MAX_NAME], char arg1[MAX_NAME], char arg2[MAX_NAME],
			  char arg3[MAX_NAME], char arg4[MAX_NAME], char extra[MAX_NAME]);
void login(char arg1[MAX_NAME], char arg2[MAX_NAME], char arg3[MAX_NAME], char arg4[MAX_NAME], int *sockfd, pthread_t *clientThread);
void logout(int *sockfd, pthread_t *clientThread);
void joinsession(char arg1[MAX_NAME], int *sockfd);
void leavesession(int *sockfd);
void createsession(char arg1[MAX_NAME], int *sockfd);
void list(int *sockfd);
void quit(int *sockfd, pthread_t *clientThread);
void messageTransfer(char message[MAX_NAME], int *sockfd);

int main(int argc, char *argv[])
{
	int sockfd;
	struct addrinfo hints, *servinfo, *p;
	int rv;
	int numbytes;
	char buf[MAXBUFLEN];
	char s[INET_ADDRSTRLEN];
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
			//check input length
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

void login(char arg1[MAX_NAME], char arg2[MAX_NAME], char arg3[MAX_NAME], char arg4[MAX_NAME], int *sockfd, pthread_t *clientThread){

}
void logout(int *sockfd, pthread_t *clientThread){

}
void joinsession(char arg1[MAX_NAME], int *sockfd){

}
void leavesession(int *sockfd){
	
}
void createsession(char arg1[MAX_NAME], int *sockfd){

}
void list(int *sockfd){

}
void quit(int *sockfd, pthread_t *clientThread){

}
void messageTransfer(char message[MAX_NAME], int *sockfd){

}

/*  
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_INET; // set to AF_INET6 to use IPv6
	hints.ai_socktype = SOCK_DGRAM;

	if ((rv = getaddrinfo(argv[1], argv[2], &hints, &servinfo)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
		return 1;
	}

	// loop through all the results and make a socket
	for(p = servinfo; p != NULL; p = p->ai_next) {
		if ((sockfd = socket(p->ai_family, p->ai_socktype,
				p->ai_protocol)) == -1) {
			perror("talker: socket");
			continue;
		}

		break;
	}

	if (p == NULL) {
		fprintf(stderr, "talker: failed to create socket\n");
		return 2;
	}

	inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr),
				s, sizeof s);
	printf("talker: connecting to %s\n", s);

	freeaddrinfo(servinfo);
*/

void askInput(char buf[MAXBUFLEN], char command[MAX_NAME], char arg1[MAX_NAME], char arg2[MAX_NAME],
			  char arg3[MAX_NAME], char arg4[MAX_NAME], char extra[MAX_NAME]){

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