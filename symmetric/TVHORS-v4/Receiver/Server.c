/*
 * Server.c
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
#include <inttypes.h>
#include <pthread.h>

#include "verification.h"
#include "RSA.h"

#define NUMBER_OF_THREAD	2

void sendLabView(char *buffer, int sock, struct sockaddr_in serAddr);
int openConnection(int port, int flag, struct sockaddr_in *serAddr);
void* handleMsg(void* ptr);
void RSAVerif(char *data);
void error(const char *msg);
void InitMsg(char *buffer, saltType *fS, lightType *fL, uint32_t *eD, double *sT);
void NormalMsg(char *buffer, uint32_t *a, char *recvMsg, uint32_t *cE, saltType *cS, lightType * signatures, int size);
void printLightChain(lightType * key);

int main(int argc, char *argv[]) {
	pthread_t threads[NUMBER_OF_THREAD];
	int rc, t;

	for (t = 0; t < NUMBER_OF_THREAD; t++) {
		rc = pthread_create(&threads[t], NULL, handleMsg, (void *) (PMU_PDC_PORT + t));
		if (rc) {
			printf("ERROR; return code from pthread_create() is %d\n", rc);
			exit(-1);
		}
	}
	pthread_exit(NULL);
}

/*
 * 1 for writing, 0 for listening
 */
int openConnection(int port, int flag, struct sockaddr_in *serAddr) {
	int sock;
	uint32_t yes = 1;
	struct ip_mreq mreq;
	struct sockaddr_in serverAddr;

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0)
		error("ERROR opening socket");

	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons(port);
	memset(serverAddr.sin_zero, '\0', sizeof serverAddr.sin_zero);
	if (flag == 0) {
		serverAddr.sin_addr.s_addr = INADDR_ANY;
		if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) < 0) {
			perror("ERROR Reusing ADDR failed");
			exit(1);
		}
		if (bind(sock, (struct sockaddr *) &serverAddr, sizeof(serverAddr)) < 0)
			error("ERROR on binding");
		mreq.imr_multiaddr.s_addr = inet_addr(MULTICAST_GROUP);
		mreq.imr_interface.s_addr = htonl(INADDR_ANY);
		if (setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq))
				< 0) {
			perror("ERROR setsockopt");
			exit(1);
		}
	}
	else if (flag == 1) {
		serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
		memcpy(serAddr, &serverAddr, sizeof serverAddr);
	}

	return sock;
}

void* handleMsg(void* ptr) {
	saltType firstSalt;						// The first salt
	lightType firstLight[NUMBER_OF_KEYS];	// The first SAGE
	saltType lastSalt[SESSION_DURATION / EPOCH_DURATION];	// The last verified salt
	lightType lastLight[NUMBER_OF_KEYS];	// The last verified SAGE

	uint32_t epoch_duration = 0;
	uint32_t currEpoch;			// Index of the current epoch
	uint32_t a;					// Index of the msg to be sent
	saltType currSalt;			// Received salt k(c)
	char recvMsg[MSG_LENGTH];
	lightType * signatures = NULL;
	uint32_t signatureSize = SHA_DIGEST_LENGTH / ((uint32_t) log2(NUMBER_OF_KEYS));
	signatures = (lightType *) malloc(sizeof(lightType) * signatureSize);
	double senderTimeSecond = 0;

	int port = (int) ptr;
	int recvSock, sendSock;
	char buffer[BUFF_SIZE];
	struct sockaddr_in serAddr;

	recvSock = openConnection(port, 0, NULL);
	sendSock = openConnection(port + 1000, 1, &serAddr);
	uint32_t msgType = 0;

	while (1) {

		if (recvfrom(recvSock, buffer, BUFF_SIZE, 0,
				NULL, NULL) < 0)
			error("ERROR reading from socket");

		bcopy(buffer, &msgType, sizeof(uint32_t));

		if (msgType == INITIAL_MSG) {
			RSAVerif(buffer);
			InitMsg(buffer, &firstSalt, firstLight, &epoch_duration, &senderTimeSecond);
			printLightChain(firstLight);

			memcpy(lastLight, firstLight, sizeof(struct lightType) * NUMBER_OF_KEYS);
			memcpy(&lastSalt[0], &firstSalt, sizeof(struct saltType));
		} else if (msgType == NORMAL_MSG) {
			NormalMsg(buffer, &a, recvMsg, &currEpoch, &currSalt, signatures, signatureSize);

			if (Verification(recvMsg, signatures, a, currSalt, currEpoch, senderTimeSecond, lastSalt, lastLight) == 0) {
				printf("Signature is OK. Epoch: %3" PRIu32 ". Msg No: %3" PRIu32 "\n", currEpoch, a);
				sendLabView(recvMsg, sendSock, serAddr);
			} else {
				printf("Signature is failed. Epoch: %3" PRIu32 ". Msg No: %3" PRIu32 "\n", currEpoch, a);
			}
		}
	}

	pthread_exit(NULL);
}

void sendLabView(char *buffer, int sock, struct sockaddr_in serAddr) {
	if (sendto(sock, buffer, MSG_LENGTH, 0, (struct sockaddr *) &serAddr,
			sizeof serAddr) < 0 )
		error("ERROR writing to socket");
}

void RSAVerif(char *data) {
	EVP_PKEY *pkey;
	char *buffer1[BUFF_SIZE - sizeof(struct signInfo)];
	struct signInfo MD;

	memcpy(buffer1, data, BUFF_SIZE - sizeof(struct signInfo));
	memcpy(&MD, data + BUFF_SIZE - sizeof(struct signInfo), sizeof(struct signInfo));

	pkey = readPublicKey("Alice.pem");
	doVerification(buffer1, BUFF_SIZE - sizeof(struct signInfo), pkey, MD.md_ctx, MD.data, MD.sig_len);
}

void error(const char *msg) {
	perror(msg);
	exit(1);
}

/*
 * Set the variables for the INITIAL MESSAGE
 */
void InitMsg(char *buffer, saltType *fS, lightType *fL, uint32_t *eD, double *sT) {
	bcopy(buffer + sizeof(uint32_t), fS, sizeof(saltType));
	bcopy(buffer + sizeof(uint32_t) + sizeof(saltType), fL, sizeof(lightType) * NUMBER_OF_KEYS);
	bcopy(buffer + sizeof(uint32_t) + sizeof(saltType) + sizeof(lightType) * NUMBER_OF_KEYS, eD, sizeof(uint32_t));
	bcopy(buffer + sizeof(uint32_t) * 2 + sizeof(saltType) + sizeof(lightType) * NUMBER_OF_KEYS, sT, sizeof(double));
	bcopy(buffer + sizeof(uint32_t) * 2 + sizeof(saltType) + sizeof(lightType) * NUMBER_OF_KEYS + sizeof(double), &number_of_epoches, sizeof(uint32_t));
}

/*
 * Set the variables for the NORMAL MESSAGE
 */
void NormalMsg(char *buffer, uint32_t *a, char *recvMsg, uint32_t *cE, saltType *cS, lightType * signatures, int size) {
	bcopy(buffer + sizeof(uint32_t), a, sizeof(uint32_t));
	bcopy(buffer + sizeof(uint32_t) * 2, recvMsg, sizeof(uint8_t) * MSG_LENGTH);
	bcopy(buffer + sizeof(uint32_t) * 2 + sizeof(uint8_t) * MSG_LENGTH, cE, sizeof(uint32_t));
	bcopy(buffer + sizeof(uint32_t) * 3 + sizeof(uint8_t) * MSG_LENGTH, cS, sizeof(saltType));
	bcopy(buffer + sizeof(uint32_t) * 3 + sizeof(uint8_t) * MSG_LENGTH + sizeof(saltType), signatures, sizeof(lightType) * size);
}

/*
 * Print the public keys
 */
void printLightChain(lightType * key) {
	int i, j;
	for (i=0; i<NUMBER_OF_KEYS; ++i) {
		for (j=0; j<sizeof(struct lightType); ++j) {
			printf("%d", (key + i)->SAGE[j]);
		}
		printf(".");
	}
	printf("\n");
}
