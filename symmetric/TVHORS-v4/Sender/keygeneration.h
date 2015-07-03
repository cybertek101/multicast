/*
 * signing.h
 *
 *  Created on: Apr 21, 2015
 *      Author: ugurcil
 */

#ifndef KEYGENERATION_H_
#define KEYGENERATION_H_

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <openssl/sha.h>

#include "consts.h"
#include "shafunctions.h"

void generateKeys(lightType lightchain[][NUMBER_OF_KEYS], saltType saltchain[]);
void generateLightChain(lightType lightchain[][NUMBER_OF_KEYS], saltType saltchain[]);
void generateSaltChain(saltType chain[]);
void setLigth(lightType *key, uint8_t *value, int lenValue);
void setSalt(saltType *key, uint8_t *value, int lenValue);
void error(const char *msg);

void generateKeys(lightType lightchain[][NUMBER_OF_KEYS], saltType saltchain[]) {
	generateSaltChain(saltchain);
	generateLightChain(lightchain, saltchain);
}

void generateLightChain(lightType lightchain[][NUMBER_OF_KEYS], saltType saltchain[]) {
	int i, j;
	uint8_t hash[SHA_DIGEST_LENGTH];
	uint8_t conct[SAGE_LEN + SALT_LEN];
	uint32_t randomNumber;

	srand(time(NULL));
	for (i=0; i<NUMBER_OF_KEYS; ++i) {
		randomNumber = rand();
		generateSHA(&randomNumber, sizeof(uint32_t), hash);
		memcpy(&lightchain[number_of_epoches-1][i], hash, sizeof(struct lightType));
	}

	for (i=number_of_epoches-2; i>=0; --i) {
		for (j=0; j<NUMBER_OF_KEYS; ++j) {
			memcpy(conct, &lightchain[i+1][j], SAGE_LEN);
			memcpy(&conct[SAGE_LEN], &saltchain[i], SALT_LEN);
			generateSHA(conct, SAGE_LEN + SALT_LEN, hash);
			memcpy(&lightchain[i][j], hash, L);
		}
	}
}

void generateSaltChain(saltType chain[]) {
	int i, index = number_of_epoches - 1;
	uint8_t hash[SHA_DIGEST_LENGTH];
	uint32_t randomNumber;

	srand(time(NULL));
	randomNumber = rand();
	generateSHA(&randomNumber, sizeof(uint32_t), hash);
	memcpy(&chain[index], hash, sizeof(struct saltType));

	for (i=index-1; i>=0; --i) {
		generateSHA(&chain[i+1], sizeof(struct saltType), hash);
		memcpy(&chain[i], hash, sizeof(struct saltType));
	}
}

void setLigth(lightType *key, uint8_t *value, int lenValue) {
	int i;

	if (lenValue != SAGE_LEN)
		error("Provided Value does not equal to required length of SAGE.");

	for (i=0; i<lenValue; ++i)
		key->SAGE[i] = *(value + i);
}

void setSalt(saltType *key, uint8_t *value, int lenValue) {
	int i;

	if (lenValue != SALT_LEN)
		error("Provided Value does not equal to required length of SALT.");

	for (i=0; i<lenValue; ++i)
		key->salt[i] = *(value + i);
}

void error(const char *msg) {
	perror(msg);
	exit(0);
}
#endif /* KEYGENERATION_H_ */
