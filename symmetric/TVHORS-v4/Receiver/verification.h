/*
 * verification.h
 *
 *  Created on: Apr 22, 2015
 *      Author: ugurcil
 */

#ifndef VERIFICATION_H_
#define VERIFICATION_H_

#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <openssl/sha.h>
#include <math.h>

#include "consts.h"
#include "shafunctions.h"

int CompareSalt(saltType *src1, saltType *src2, uint32_t len);
int CompareSAGE(lightType *src1, lightType *src2, uint32_t len);
int verifySALT(saltType *currSalt, int c, saltType lastSalt[]);
int verifySAGE(lightType *currLight, int index, int c, saltType lastSalt[], lightType lastLight[]);
int Verification(char *orgMsg, lightType *signatures,
		uint32_t a, saltType kc, uint32_t c, double senderTimeSecond, saltType lastSalt[], lightType lastLight[]);
uint32_t * splitHASH(uint8_t *hash, uint32_t *size);
double timeSecons(time_t localTime);

int CompareSalt(saltType *src1, saltType *src2, uint32_t len) {
	int i;

	for (i=0; i<len; ++i) {
		if (src1->salt[i] != src2->salt[i])
			return 0;
	}

	return 1;
}

int CompareSAGE(lightType *src1, lightType *src2, uint32_t len) {
	int i;

	for (i=0; i<len; ++i) {
		if (src1->SAGE[i] != src2->SAGE[i])
			return 0;
	}

	return 1;
}

int verifySALT(saltType *currSalt, int c, saltType lastSalt[]){
	int i;
	uint8_t hash[SHA_DIGEST_LENGTH];
	saltType temp = *currSalt;

	if (CompareSalt(currSalt, &lastSalt[c], SALT_LEN))
		return 1;

	if (c > 0) {
		for (i=c; i>0; --i) {
			generateSHA(&temp, sizeof(struct saltType), hash);
			memcpy(&temp, hash, SALT_LEN);
			if (CompareSalt(&temp, &lastSalt[i-1], SALT_LEN))
				return 1;
		}
	}
	return 0;
}

int verifySAGE(lightType *currLight, int index, int c, saltType lastSalt[], lightType lastLight[]) {
	int i;
	uint8_t hash[SHA_DIGEST_LENGTH];
	uint8_t conct[SAGE_LEN + SALT_LEN];
	lightType calculated;

	memcpy(&calculated, currLight, SAGE_LEN);

	if (CompareSAGE(&calculated, &lastLight[index], SAGE_LEN))
		return 1;

	if (c > 0) {
		for (i=c; i>0; --i) {
			memcpy(conct, &calculated, SAGE_LEN);
			memcpy(&conct[SAGE_LEN], &lastSalt[i-1], SALT_LEN);
			generateSHA(conct, SAGE_LEN + SALT_LEN, hash);
			memcpy(&calculated, hash, L);

			if (CompareSAGE(&calculated, &lastLight[index], SAGE_LEN))
				return 1;
		}
	}
	return 0;
}

int Verification(char *orgMsg, lightType *signatures,
		uint32_t a, saltType kc, uint32_t c, double senderTimeSecond, saltType lastSalt[], lightType lastLight[]) {
	int i;
	uint8_t hash[SHA_DIGEST_LENGTH];
	uint32_t *mappingSet = NULL;
	uint32_t *size = (uint32_t *) malloc(sizeof(uint32_t));
	uint8_t *newMsg = (uint8_t *) malloc(LEN_TO_BE_SIGNED + sizeof(uint32_t) + sizeof(struct saltType));

	/*
	 * Records the local time and decides whether discard or not the packet
	 */
	time_t local_recv_time;
	time(&local_recv_time);

	double diff = timeSecons(local_recv_time) - senderTimeSecond;
	double decTime = diff + ENDTOEND_DELAY - c * EPOCH_DURATION;

	if (decTime >= ADV_CALCULATION) {
		printf("Adversary could have found a second-preimage. "
				"Discarding the packet... "
				"decTime: %f\n", decTime);
		return -1;
	} else {
		memcpy(newMsg, &a, sizeof(uint32_t));
		memcpy((newMsg + sizeof(uint32_t)), orgMsg, MSG_LENGTH);
		memcpy((newMsg + sizeof(uint32_t) + MSG_LENGTH), &kc, sizeof(struct saltType));

		if (generateSHA(newMsg, LEN_TO_BE_SIGNED + sizeof(uint32_t) + sizeof(struct saltType), hash)) {
			printf("Error: computing hash.\n");
			return -1;
		}

		mappingSet = splitHASH(hash, size);

		for (i=0; i<*(size); ++i) {
			if (!verifySALT(&kc, c, lastSalt) || !verifySAGE(&signatures[i], *(mappingSet + i), c, lastSalt, lastLight))
				return -1;

			memcpy(&lastLight[*(mappingSet + i)], &signatures[i], sizeof(struct lightType));
		}
		lastSalt[c] = kc;
	}
	free(newMsg);
	free(size);

	return 0;
}

uint32_t * splitHASH(uint8_t *hash, uint32_t *size) {
	int i, j, index = 0;
	uint32_t subStrLength = 0;
	uint32_t subStrNumber = 0;
	uint8_t *subStrSet;
	uint32_t *mappingSet;

	subStrLength = (uint32_t) log2(NUMBER_OF_KEYS);
	if (subStrLength <= 0) {
		printf("Error: calculation of log2(N).\n");
		return NULL;
	}

	subStrNumber = SHA_DIGEST_LENGTH / subStrLength;
	*size = subStrNumber;

	subStrSet = (uint8_t *) malloc(subStrNumber * sizeof(uint8_t));
	mappingSet = (uint32_t *) malloc(subStrNumber * sizeof(uint32_t));

	for (i = 0; i < subStrNumber; ++i) {
		memcpy((subStrSet + i), (hash + i * subStrLength), subStrLength);
	}

	/*
	 * Mapping b_j to i_j. O(n2)
	 */
	for (i = 0; i < subStrNumber; ++i) {
		for (j = 0; j < subStrNumber; ++j) {
			if (*(subStrSet + j) < *(subStrSet + i))
				++index;
		}
		*(mappingSet + i) = index;
		index = 0;
	}

	free(subStrSet);
	return mappingSet;
}

double timeSecons(time_t localTime) {
	struct tm newyear;

	newyear = *localtime(&localTime);

	newyear.tm_hour = 0;
	newyear.tm_min = 0;
	newyear.tm_sec = 0;
	newyear.tm_mon = 0;
	newyear.tm_mday = 1;

	return difftime(localTime, mktime(&newyear));
}

#endif /* VERIFICATION_H_ */
