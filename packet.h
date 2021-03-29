#ifndef PACKET_H
#define PACKET_H

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_DATA 1000
#define MAX_NAME 100
#define MAXBUFLEN 1000
#define MAXPACKLEN 1100

struct message {
    unsigned int type;
    unsigned int size;
    unsigned char source[MAX_NAME];
    unsigned char data[MAX_DATA];
};

enum type {
    LOGIN,
    LO_ACK,
    LO_NAK,
    EXIT,
    JOIN,
    JN_ACK,
    JN_NAK,
    LEAVE_SESS,
    NEW_SESS,
    NS_ACK,
    MESSAGE,
    QUERY,
    QU_ACK
};

void DataToPacket(char* buffer, struct message * Packet){
	memset(buffer, 0, MAXPACKLEN); // first empty the buffer
    int buffer_size = sizeof(buffer);
	int header = sprintf(buffer, "%d:%d:%s:", Packet->type, Packet->size, Packet->source);
    printf("This is the output of buffer: %s\n", buffer);
    memcpy( buffer + header, Packet->data, Packet->size);
}

void PacketToData(char* buffer, struct message * Packet){

    int i = 0, j = 0;
    char * type = (char *) malloc(sizeof(char) * 100);

    while(buffer[i]!=':'){
		type[j] = buffer[i];
		i++, j++;
    }
	type[j] = '\0';
	Packet->type = atoi(type);

	j = 0;
	i++; // go to the character after the :
    char * size = (char *) malloc(sizeof(char) * 100);

    while(buffer[i]!=':'){
		size[j] = buffer[i];
		i++, j++;
    }
	size[j] = '\0';
	Packet->size = atoi(size);

	j = 0;
	i++; // go to the character after the :
    char * source = (char *) malloc(sizeof(char) * 100);

    while(buffer[i]!=':'){
		source[j] = buffer[i];
        Packet->source[j] = source[j];
		i++, j++;
    }
	source[j] = '\0';
    Packet->source[j] = source[j];

	//printf("%d %d %d %s \n", Packet->total_frag, Packet->frag_no, Packet->size, Packet->filename);
	i++;
	memcpy(Packet->data, buffer+i, Packet->size);

}

// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
	if (sa->sa_family == AF_INET) {
		return &(((struct sockaddr_in*)sa)->sin_addr);
	}

	return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

#endif /* PACKET_H */