CFLAGS = -lpthread

all: server deliver

debug: sever_debug deliver_debug

server: server.c 
	gcc server.c -o server ${CFLAGS}

deliver: client.c 
	gcc client.c -o client ${CFLAGS}

sever_debug: server.c
	gcc -g server.c -o server ${CFLAGS}

deliver_debug: client.c
	gcc -g client.c -o client ${CFLAGS}

clean:
	rm -f server client