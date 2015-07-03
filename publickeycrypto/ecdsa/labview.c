/*
 * Client.c
 *
 *  Created on: Apr 28, 2015
 *      Author: ugurcil
 */

#include <stdio.h>
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <netdb.h>
#include <unistd.h>

#ifdef WIN32
#include <windows.h>
#elif _POSIX_C_SOURCE >= 199309L
#include <time.h>   // for nanosleep
#else
#include <unistd.h> // for usleep
#endif

#define PMU_PORT 5000

void error(const char *msg) {
	perror(msg);
	exit(0);
}

void rand_string(char *str, size_t size)
{
	int n;
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJK?!.@#$%&";
    if (size) {
        --size;
        for (n = 0; n < size; n++) {
            int key = rand() % (int) (sizeof charset - 1);
            str[n] = charset[key];
        }
        str[size] = '\0';
    }
}

int main(int argc, char *argv[]) 
{
	int clientSocket;
	//int msgLen = 1024;
	//char buffer[msgLen];
	unsigned char  buffer[] = "Hello, world!";
	size_t msgLen = sizeof(buffer);

	struct sockaddr_in serverAddr;
	size_t sentlen;
	/*Create UDP socket*/
	clientSocket = socket(AF_INET, SOCK_DGRAM, 0);
	if (clientSocket < 0)
		error("ERROR opening socket");

	/*Configure settings in address struct*/
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons(PMU_PORT);
	serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
	//memset(serverAddr.sin_zero, '\0', sizeof serverAddr.sin_zero);

	while (1) 
	{
		//rand_string(buffer, msgLen);

		if ((sentlen = sendto(clientSocket, buffer, msgLen, 0, (struct sockaddr *) &serverAddr, sizeof serverAddr)) < 0)
			error("ERROR writing to socket");
		 printf("sent %zu bytes\n", sentlen);

//		sleep_ms(20);
//		sleep(1);
	}

	close(clientSocket);

	return 0;
}
