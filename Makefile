CFLAGS = -lpthread

all: server deliver

server: server.c 
	gcc server.c -o server ${CFLAGS}

deliver: client.c 
	gcc client.c -o client ${CFLAGS}

clean:
	rm -f server client