#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>

#define DST 		"127.0.0.1"
#define PORT 	9999

class Sender{
	private:
		int clientfd;
		char buffer[5120];
	public:
		Sender();
		void sendjson(const char*, int);
		void finish();
};