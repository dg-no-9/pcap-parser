#include "sender.h"
char* d_ip;
int port;
Sender::Sender(){
	clientfd = 0;
    struct sockaddr_in server;
    socklen_t addr_size;

    clientfd = socket(PF_INET, SOCK_STREAM, 0);

    if(clientfd == -1){
        printf("Error creating socket.");
    }
    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    server.sin_addr.s_addr = inet_addr(d_ip);
    memset(server.sin_zero, '\0', sizeof(server.sin_zero));

    if( connect(clientfd, (struct sockaddr *) &server, sizeof(server)) == 0) printf("Connected to server\n");

    else printf("Failed to connect to server\n");
}

void Sender::sendjson(const char* json, int len){
	//esprintf(buffer,json);
	if (send(clientfd, json,len, 0) > 0 ){
	    printf("OK.\n");
	}

	usleep(500);

}

void Sender::finish(){
	close(clientfd);
}