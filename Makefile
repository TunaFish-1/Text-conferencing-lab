all: server deliver

server: server.c 
	gcc server.c -o server

deliver: client.c 
	gcc client.c -o client

clean:
	rm -f server client