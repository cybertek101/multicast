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
#include <netinet/in.h>
#include <arpa/inet.h>

#include "verification.h"
#include "RSA.h"
#include "consts.h"

int openConnection(int port, int flag, struct sockaddr_in *serAddr);
int handleMsg(struct sockaddr_in srcAddr, char *buffer);
int addClient(struct sockaddr_in srcAddr);
int portIndex(struct sockaddr_in srcAddr);
void sendLabView(char *buffer, int sock, struct sockaddr_in serAddr);
void RSAVerif(char *data);
void error(const char *msg);
void InitMsg(char *buffer, struct pmuInfo *pmu);
void NormalMsg(char *buffer, char *recvMsg, struct pmuInfo *pmu, lightType * signatures, int size);
void printLightChain(lightType * key);

struct pmuInfo *pmuList = NULL;
int pmuNum = 0;

int main(int argc, char *argv[]) {
	int sockRecv, sockSend;
	struct sockaddr_in labviewAddr, srcAddr;
	socklen_t srcAddr_len;
	char buff[BUFF_SIZE], orgMsg[MSG_LENGTH];

	sockSend = openConnection(PDC_OUT_PORT, 1, &labviewAddr);
	sockRecv = openConnection(PDC_IN_PORT, 0, NULL);

	while (1) {
		if (recvfrom(sockRecv, buff, BUFF_SIZE, 0, (struct sockaddr *) &srcAddr, &srcAddr_len) < 0)
			error("ERROR reading from socket [PMU to PDC]");

		if (handleMsg(srcAddr, buff) == 1) {
			bcopy(buff + sizeof(uint32_t) * 2, orgMsg, sizeof(uint8_t) * MSG_LENGTH);
			sendLabView(orgMsg, sockSend, labviewAddr);
		}

	}
	return 0;
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
		if (setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
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

int handleMsg(struct sockaddr_in srcAddr, char *buffer) {
	char recvMsg[MSG_LENGTH];
	lightType * signatures = NULL;
	uint32_t signatureSize = SHA_DIGEST_LENGTH / ((uint32_t) log2(NUMBER_OF_KEYS));
	signatures = (lightType *) malloc(sizeof(lightType) * signatureSize);

	uint32_t msgType = 0;
	int index;

	index = addClient(srcAddr);
	pmuList[index].scrPort = (int) srcAddr.sin_port;
	pmuList[index].addr = srcAddr.sin_addr;

	bcopy(buffer, &msgType, sizeof(uint32_t));

	if (msgType == INITIAL_MSG) {
		RSAVerif(buffer);
		InitMsg(buffer, &pmuList[index]);
		printLightChain(pmuList[index].firstLight);

		memcpy(pmuList[index].lastLight, pmuList[index].firstLight, sizeof(struct lightType) * NUMBER_OF_KEYS);
		memcpy(&pmuList[index].lastSalt[0], &pmuList[index].firstSalt, sizeof(struct saltType));
	} else if (msgType == NORMAL_MSG) {
		NormalMsg(buffer, recvMsg, &pmuList[index], signatures, signatureSize);

		if (Verification(recvMsg, signatures, &pmuList[index]) == 0) {
			printf("Signature is OK. Epoch: %3" PRIu32 ". Msg No: %3" PRIu32 "\n", pmuList[index].currEpoch, pmuList[index].a);
			return 1;
		} else {
			printf("Signature is failed. Epoch: %3" PRIu32 ". Msg No: %3" PRIu32 "\n", pmuList[index].currEpoch, pmuList[index].a);
			return -1;
		}
	}

	free(signatures);
	return 0;
}

int addClient(struct sockaddr_in srcAddr) {
	int index;

	if (pmuList == NULL) {
		pmuList = (struct pmuInfo *) malloc(sizeof (struct pmuInfo));
		index = pmuNum++;
	} else {
		index = portIndex(srcAddr);
		if (index == -1) {
			index = pmuNum++;
			pmuList = (struct pmuInfo *) realloc(pmuList, sizeof (struct pmuInfo) * pmuNum);
		}
	}
	return index;
}

int portIndex(struct sockaddr_in srcAddr) {
	int i;

	for(i=0; i<pmuNum; ++i)
		if (strcmp(inet_ntoa(pmuList[i].addr), inet_ntoa(srcAddr.sin_addr)) == 0)
			return i;
	return -1;
}

void sendLabView(char *buffer, int sock, struct sockaddr_in serAddr) {
	if (sendto(sock, buffer, MSG_LENGTH, 0, (struct sockaddr *) &serAddr,
			sizeof serAddr) < 0 )
		error("ERROR writing to socket");
}

void RSAVerif(char *data) {
	EVP_PKEY *pkey;
	char buffer1[BUFF_SIZE - sizeof(struct signInfo)];
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
void InitMsg(char *buffer, struct pmuInfo *pmu) {
	bcopy(buffer + sizeof(uint32_t), &pmu->firstSalt, sizeof(saltType));
	bcopy(buffer + sizeof(uint32_t) + sizeof(saltType), pmu->firstLight, sizeof(lightType) * NUMBER_OF_KEYS);
	bcopy(buffer + sizeof(uint32_t) + sizeof(saltType) + sizeof(lightType) * NUMBER_OF_KEYS, &pmu->epoch_duration, sizeof(uint32_t));
	bcopy(buffer + sizeof(uint32_t) * 2 + sizeof(saltType) + sizeof(lightType) * NUMBER_OF_KEYS, &pmu->senderTimeSecond, sizeof(double));
	bcopy(buffer + sizeof(uint32_t) * 2 + sizeof(saltType) + sizeof(lightType) * NUMBER_OF_KEYS + sizeof(double), &number_of_epoches, sizeof(uint32_t));
}

/*
 * Set the variables for the NORMAL MESSAGE
 */
void NormalMsg(char *buffer, char *recvMsg, struct pmuInfo *pmu, lightType * signatures, int size) {
	bcopy(buffer + sizeof(uint32_t), &pmu->a, sizeof(uint32_t));
	bcopy(buffer + sizeof(uint32_t) * 2, recvMsg, sizeof(uint8_t) * MSG_LENGTH);
	bcopy(buffer + sizeof(uint32_t) * 2 + sizeof(uint8_t) * MSG_LENGTH, &pmu->currEpoch, sizeof(uint32_t));
	bcopy(buffer + sizeof(uint32_t) * 3 + sizeof(uint8_t) * MSG_LENGTH, &pmu->currSalt, sizeof(saltType));
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
