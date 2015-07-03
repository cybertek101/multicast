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

#include "consts.h"
#include "signing.h"
#include "keygeneration.h"
#include "shafunctions.h"
#include "RSA.h"

char buffer_LV[1024];

saltType saltChain[SESSION_DURATION / EPOCH_DURATION];
lightType lightChain[SESSION_DURATION / EPOCH_DURATION][NUMBER_OF_KEYS];
uint32_t currEpoch = 0;		// Index of the current epoch
uint32_t a = 0;				// Index of the msg to be sent
uint8_t sendMsg[MSG_LENGTH];
uint32_t vTimes = 0;

/*Set λm, TΔ, P=Tφ/TΔ, S's local starting time of the ith epoch*/
time_t senderTime, epochStart, epochStop;
uint32_t epoch_duration = EPOCH_DURATION;
uint32_t signatureSize = SHA_DIGEST_LENGTH / ((uint32_t) log2(NUMBER_OF_KEYS));
double senderTimeSecond = 0;

void epochTimeControl(uint32_t *msgType);
int openConnection(int port, int flag, struct sockaddr_in *serAddr);
void sendInitMsg (int clientSocket, struct sockaddr_in serverAddr, socklen_t addr_size);
void sendNormalMsg(int clientSocket, struct sockaddr_in serverAddr, socklen_t addr_size, lightType *signature);
struct signInfo RSASignBuff(char *data, int dataLen);
void cpInitValues(char *buffer);
void cpNormValues(char *buffer, lightType *signatures);
double timeSecons(time_t sT);

int main(int argc, char *argv[]) {
	int clientSocket, LVSock;
	struct sockaddr_in serverAddr;

	LVSock = openConnection(LV_PORT, 0, NULL);
	clientSocket = openConnection(PMU_PDC_PORT, 1, &serverAddr);

	lightType * signatures = (lightType *) malloc(sizeof(struct lightType) * signatureSize);
	uint32_t msgType = INITIAL_MSG;

	while (1) {
		bzero(buffer_LV, 1024);
		if (recvfrom(LVSock, buffer_LV, 1024, 0, NULL, NULL) < 0)
				error("ERROR reading from socket (LabView)");

		printf("received message\n");
			
		bcopy(buffer_LV, sendMsg, MSG_LENGTH);

		if (msgType == INITIAL_MSG) {
			sendInitMsg(clientSocket, serverAddr, sizeof serverAddr);
			msgType = NORMAL_MSG;
		} else if (msgType == NORMAL_MSG) {
			sendNormalMsg(clientSocket, serverAddr, sizeof serverAddr, signatures);
		}

		epochTimeControl(&msgType);

	}

  return 0;
}

void epochTimeControl(uint32_t *msgType) {
	if (currEpoch + 1 == number_of_epoches) {
		currEpoch = 0;
		a = 0;
		*msgType = INITIAL_MSG;
		time(&epochStart);
	} else {
		*msgType = NORMAL_MSG;
	}
}

/*
 * 1 for writing, 0 for listening
 */
int openConnection(int port, int flag, struct sockaddr_in *serAddr) {
	int sock;
	struct sockaddr_in serverAddr;

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0)
		error("ERROR opening socket");

	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons(port);
	memset(serverAddr.sin_zero, '\0', sizeof serverAddr.sin_zero);
	if (flag == 0) {
		serverAddr.sin_addr.s_addr = INADDR_ANY;

		if (bind(sock, (struct sockaddr *) &serverAddr, sizeof(serverAddr)) < 0)
			error("ERROR on binding");
	}
	else if (flag == 1) {
	    serverAddr.sin_addr.s_addr = inet_addr(MULTICAST_GROUP);
		memcpy(serAddr, &serverAddr, sizeof serverAddr);
	}

	return sock;
}

void sendInitMsg (int clientSocket, struct sockaddr_in serverAddr, socklen_t addr_size) {
	struct signInfo sig;
	char buffer1[BUFF_SIZE - sizeof(struct signInfo)];
	char buffer2[BUFF_SIZE];

	generateKeys(lightChain, saltChain);
	time(&senderTime);
	time(&epochStart);
	senderTimeSecond = timeSecons(senderTime);

	cpInitValues(buffer1);
	sig = RSASignBuff(buffer1, BUFF_SIZE - sizeof(struct signInfo));
	memcpy(buffer2, buffer1, BUFF_SIZE - sizeof(struct signInfo));
	memcpy(buffer2 + BUFF_SIZE - sizeof(struct signInfo), &sig, sizeof(struct signInfo));

	if (sendto(clientSocket, buffer2, BUFF_SIZE, 0, (struct sockaddr *) &serverAddr,
			addr_size) < 0 )
		error("ERROR writing to socket");
}

void sendNormalMsg(int clientSocket, struct sockaddr_in serverAddr, socklen_t addr_size, lightType *signatures) {
	char buffer[BUFF_SIZE];

	signing(lightChain, sendMsg, a, saltChain[currEpoch], currEpoch, signatures);
	cpNormValues(buffer, signatures);
	++a;
	++vTimes;
	time(&epochStop);
	if (vTimes == MAX_NUMBER_PACKETS || (uint32_t)difftime(epochStop, epochStart) > epoch_duration) {
		++currEpoch;
		vTimes = 0;
	}
	if (sendto(clientSocket, buffer, BUFF_SIZE, 0, (struct sockaddr *) &serverAddr,
			addr_size) < 0 )
		error("ERROR writing to socket");
}

struct signInfo RSASignBuff(char *data, int dataLen) {
	EVP_PKEY *pkey;
	struct signInfo sig;

	pkey = ReadPrivateKey("Alice.key");
	doSignature(data, dataLen, pkey, &sig.md_ctx, sig.data, &sig.sig_len);

	return sig;
}

void cpInitValues(char *buffer) {
	uint32_t msgType = INITIAL_MSG;
	bcopy(&msgType, buffer, sizeof(uint32_t));
	bcopy(&saltChain[0], buffer + sizeof(uint32_t), sizeof(struct saltType));																		// k0
	bcopy(lightChain[0], buffer + sizeof(uint32_t) + sizeof(struct saltType), sizeof(struct lightType) * NUMBER_OF_KEYS);							// {s(u,0)} u:[1,N]
	bcopy(&epoch_duration, buffer + sizeof(uint32_t) + sizeof(struct saltType) + sizeof(struct lightType) * NUMBER_OF_KEYS, sizeof(uint32_t));		// TΔ
	bcopy(&senderTimeSecond, buffer + sizeof(uint32_t) * 2 + sizeof(struct saltType) + sizeof(struct lightType) * NUMBER_OF_KEYS, sizeof(double));	// S's local starting time of the first epoch
	bcopy(&number_of_epoches, buffer + sizeof(uint32_t) * 2 + sizeof(struct saltType) + sizeof(struct lightType) * NUMBER_OF_KEYS + sizeof(double), sizeof(uint32_t));
}

void cpNormValues(char *buffer, lightType *signatures) {
	uint32_t msgType = NORMAL_MSG;
	bcopy(&msgType, buffer, sizeof(uint32_t));
	bcopy(&a, buffer + sizeof(uint32_t), sizeof(uint32_t));
	bcopy(sendMsg, buffer + sizeof(uint32_t) * 2, sizeof(uint8_t) * MSG_LENGTH);
	bcopy(&currEpoch, buffer + sizeof(uint32_t) * 2 + sizeof(uint8_t) * MSG_LENGTH, sizeof(uint32_t));
	bcopy(&saltChain[currEpoch], buffer + sizeof(uint32_t) * 3 + sizeof(uint8_t) * MSG_LENGTH, sizeof(struct saltType));
	bcopy(signatures, buffer + sizeof(uint32_t) * 3 + sizeof(uint8_t) * MSG_LENGTH + sizeof(struct saltType), sizeof(struct lightType) * signatureSize);
}

double timeSecons(time_t sT) {
	struct tm newyear;

	newyear = *localtime(&sT);

	newyear.tm_hour = 0;
	newyear.tm_min = 0;
	newyear.tm_sec = 0;
	newyear.tm_mon = 0;
	newyear.tm_mday = 1;

	return difftime(sT, mktime(&newyear));
}

//void recvLabView () {
//	/*Create UDP socket*/
//	sock_LV = socket(PF_INET, SOCK_DGRAM, 0);
//	if (sock_LV < 0)
//			error("ERROR opening socket");
//
//	/*Configure settings in address struct*/
//	serverAddr_LV.sin_family = AF_INET;
//	serverAddr_LV.sin_port = htons(7890);
//	serverAddr_LV.sin_addr.s_addr = inet_addr("127.0.0.1");
//	memset(serverAddr_LV.sin_zero, '\0', sizeof serverAddr_LV.sin_zero);
//
//	/*Bind socket with address struct*/
//	if (bind(sock_LV, (struct sockaddr *) &serverAddr_LV, sizeof(serverAddr_LV)) < 0)
//		error("ERROR on binding");
//
//	/*Initialize size variable to be used later on*/
//	addr_size_LV = sizeof serverStorage_LV;
//}
