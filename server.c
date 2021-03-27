/*
	server.c 
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
		fprintf(stderr,"usage: server <UDP listen port>\n");
		exit(1);
	}

    //int MYPORT = atoi(argv[1]);

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_INET; // set to AF_INET6 to use IPv6
	hints.ai_socktype = SOCK_DGRAM;
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

	//receive a message from the client
	memset(buf, 0, MAXBUFLEN); // first empty the buffer
	addr_len = sizeof their_addr;
	if ((numbytes = recvfrom(sockfd, buf, MAXBUFLEN-1 , 0,
		(struct sockaddr *)&their_addr, &addr_len)) == -1) {
		perror("recvfrom");
		exit(1);
	}

	// printf("listener: got packet from %s\n",
	// inet_ntop(their_addr.ss_family, get_in_addr((struct sockaddr *)&their_addr),
	// 			s, sizeof s));
	// printf("listener: packet is %d bytes long\n", numbytes);
	// buf[numbytes] = '\0';
	// printf("listener: packet contains \"%s\"\n", buf);

	// reply with a message to the client based on the message recieved from the client (if "ftp")
    if (strcmp(buf, "ftp") == 0) {
        if ((numbytes = sendto(sockfd, "yes", strlen("yes"), 0,
			(struct sockaddr *) &their_addr, addr_len)) == -1) {
            perror("listener: sendto");
            exit(1);
        }
    } else {
        if ((numbytes = sendto(sockfd, "no", strlen("no"), 0, 
			(struct sockaddr *) &their_addr, addr_len)) == -1) {
            perror("listener: sendto");
            exit(1);
        }
    }
}
