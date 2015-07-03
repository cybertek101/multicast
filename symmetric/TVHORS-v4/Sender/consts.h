/*
 * Consts.h
 *
 *  Created on: Apr 21, 2015
 *      Author: ugurcil
 */

#ifndef CONSTS_H_
#define CONSTS_H_

#include <openssl/sha.h>
#include <openssl/evp.h>

#define NUMBER_OF_KEYS			1000

#define MAX_SENDING_RATE		1000	// Number of packets sent per second - λm
#define MAX_NUMBER_PACKETS		10	 	// Maximum number of packets that can be signed in each epoch - v
#define SYNCH_ERROR				60		// Upper bound on synchronization error in seconds - σ
#define ENDTOEND_DELAY			360		// Desired upper bound on end-to-end delay in seconds - ε
#define EPOCH_DURATION			10		// Duration of each epoch - TΔ

#define ADV_CALCULATION			3600	// Lower bound on Adv's calculation time to find a second-preimage

#define SESSION_DURATION		3600	// Sender will estimate duration of session in seconds

#define INITIAL_MSG				1453
#define NORMAL_MSG				1876

#define MSG_LENGTH				512		// Length of the full msg
#define LEN_TO_BE_SIGNED		512		// Length of the msg to be signed
#define SAGE_LEN				6		// Length of the each SAGE - bytes - 48 bits
#define SALT_LEN				10		// Length of the salt - bytes - 80 bits
#define L						SAGE_LEN		// Number of bytes to be used in lightType
#define BUFF_SIZE				10000	// Buffer length to be send and received
#define SIGN_LEN				1024	// Buffer length of signature for the initial msg

#define LV_PORT					7890	// Port number for incoming msg from LabView
#define MULTICAST_GROUP			"239.0.0.1"
#define PMU_PDC_PORT			5000	// Port; from pdc to pmu
/*
 * Global Variables
 */
typedef struct lightType {
	uint8_t SAGE[SAGE_LEN];				// Means SAGE_LEN*8 bits for light chains - Public/Private Key
}lightType;

typedef struct saltType {
	uint8_t salt[SALT_LEN];				// Means SALT_LEN*8 bits for the salt.
}saltType;

typedef struct signInfo {
	char data[SIGN_LEN];
	EVP_MD_CTX md_ctx;
	uint32_t sig_len;
}signInfo;

uint32_t number_of_epoches = SESSION_DURATION / EPOCH_DURATION;

#define debug(fmt, ...) printf("%s:%d: " fmt, __FILE__, __LINE__, __VA_ARGS__);

#endif /* CONSTS_H_ */
