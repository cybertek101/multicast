/*
 * shafunctions.h
 *
 *  Created on: May 2, 2015
 *      Author: ugurcil
 */

#ifndef SHAFUNCTIONS_H_
#define SHAFUNCTIONS_H_

#include <openssl/sha.h>

int generateSHA(void *, unsigned long, unsigned char *);
int generateSHA224(void *, unsigned long, unsigned char *);
int generateSHA256(void *, unsigned long, unsigned char *);
int generateSHA384(void *, unsigned long, unsigned char *);
int generateSHA512(void *, unsigned long, unsigned char *);

int generateSHA(void *input, unsigned long length, unsigned char *hash) {
	SHA_CTX context;
	if (!SHA1_Init(&context))
		return -1;

	if (!SHA1_Update(&context, (unsigned char *)input, length))
		return -1;

	if (!SHA1_Final(hash, &context))
		return -1;

	return 0;
}

int generateSHA224(void *input, unsigned long length, unsigned char *hash) {
	SHA256_CTX context;
	if (!SHA224_Init(&context))
		return -1;

	if (!SHA224_Update(&context, (unsigned char *)input, length))
		return -1;

	if (!SHA224_Final(hash, &context))
		return -1;

	return 0;
}

int generateSHA256(void *input, unsigned long length, unsigned char *hash) {
	SHA256_CTX context;
	if (!SHA256_Init(&context))
		return -1;

	if (!SHA256_Update(&context, (unsigned char *)input, length))
		return -1;

	if (!SHA256_Final(hash, &context))
		return -1;

	return 0;
}

int generateSHA384(void *input, unsigned long length, unsigned char *hash) {
	SHA512_CTX context;
	if (!SHA384_Init(&context))
		return -1;

	if (!SHA384_Update(&context, (unsigned char *)input, length))
		return -1;

	if (!SHA384_Final(hash, &context))
		return -1;

	return 0;
}

int generateSHA512(void *input, unsigned long length, unsigned char *hash) {
	SHA512_CTX context;
	if (!SHA512_Init(&context))
		return -1;

	if (!SHA512_Update(&context, (unsigned char *)input, length))
		return -1;

	if (!SHA512_Final(hash, &context))
		return -1;

	return 0;
}

int generateSHA256File(char *path, unsigned char *hash) {
        FILE *file = fopen(path, "rb");
        if (!file) {
                printf("File open error.\n");
                return -1;
        }

        SHA256_CTX context;
        if (!SHA256_Init(&context))
                return -1;

        const int bufSize = 32768;
        char *buff = malloc(bufSize);
        if (!buff)
                return -1;

        int bytesRead = 0;
        while ((bytesRead = fread(buff, 1, bufSize, file))) {
                if(!SHA256_Update(&context, buff, bytesRead))
                        return -1;
        }

        if (!SHA256_Final(hash, &context))
                return -1;

        fclose(file);
        free(buff);

        return 0;
}


#endif /* SHAFUNCTIONS_H_ */
