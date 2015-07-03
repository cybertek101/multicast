/*
 * signing.h
 *
 *  Created on: Apr 21, 2015
 *      Author: ugurcil
 */

#ifndef SIGNING_H_
#define SIGNING_H_

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <openssl/sha.h>
#include <math.h>

#include "consts.h"
#include "shafunctions.h"

void signing(lightType lightChain[][NUMBER_OF_KEYS], uint8_t *msg,
		uint32_t a, saltType kc, uint32_t c, lightType *signatures);
uint32_t * splitHASH(uint8_t *hash, uint32_t *size);
void generateSignature(lightType lightChain[][NUMBER_OF_KEYS],
		uint32_t *mappingSet, uint32_t size, uint32_t c, lightType *signatures);

void signing(lightType lightChain[][NUMBER_OF_KEYS], uint8_t *msg,
		uint32_t a, saltType kc, uint32_t c, lightType *signatures) {
	uint32_t *mappingSet;
	uint8_t hash[SHA_DIGEST_LENGTH];
	uint32_t *size = (uint32_t *) malloc(sizeof(uint32_t));
	uint8_t *newMsg = (uint8_t *) malloc(LEN_TO_BE_SIGNED + sizeof(uint32_t) + sizeof(struct saltType));

	memcpy(newMsg, &a, sizeof(uint32_t));
	memcpy((newMsg + sizeof(uint32_t)), msg, MSG_LENGTH);
	memcpy((newMsg + sizeof(uint32_t) + MSG_LENGTH), &kc, sizeof(struct saltType));

	generateSHA(newMsg, LEN_TO_BE_SIGNED + sizeof(uint32_t) + sizeof(struct saltType), hash);

	mappingSet = splitHASH(hash, size);
	free(newMsg);
	generateSignature(lightChain, mappingSet, *size, c, signatures);
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

void generateSignature(lightType lightChain[][NUMBER_OF_KEYS],
		uint32_t *mappingSet, uint32_t size, uint32_t c, lightType *signatures) {
	int i;

	for (i = 0; i < size; ++i)
		memcpy((signatures + i), &lightChain[c][*(mappingSet + i)], sizeof(struct lightType));
}

#endif /* SIGNING_H_ */
