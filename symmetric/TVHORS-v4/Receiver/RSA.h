/*
 * Exp01.c
 *
 *  Created on: Apr 21, 2015
 *      Author: ugurcil
 */

#include <stdio.h>
#include <inttypes.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>

EVP_PKEY* ReadPrivateKey(char *keyfile) {
	EVP_PKEY *pkey;
	ERR_load_crypto_strings();

	FILE *fp = fopen(keyfile, "r");
	if (fp == NULL)
		exit(1);
	pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
	fclose(fp);

	if (pkey == NULL) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}
	return pkey;
}

void doSignature(char *data, int dataLen, EVP_PKEY *pkey, EVP_MD_CTX *md_ctx,
		uint8_t *signBuff, uint32_t *signLen) {
	int err;

	ERR_load_crypto_strings();

	EVP_SignInit(md_ctx, EVP_sha1());
	EVP_SignUpdate(md_ctx, data, dataLen);
	err = EVP_SignFinal(md_ctx, signBuff, signLen, pkey);

	if (err != 1) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}

	EVP_PKEY_free(pkey);
}

EVP_PKEY* readPublicKey(char *certfile) {
	X509 *x509;
	EVP_PKEY *pkey;

	ERR_load_crypto_strings();

	FILE *fp = fopen(certfile, "r");
	if (fp == NULL)
		exit(1);
	x509 = PEM_read_X509(fp, NULL, NULL, NULL);
	fclose(fp);

	if (x509 == NULL) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}

	pkey = X509_get_pubkey(x509);
	if (pkey == NULL) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}
	return pkey;
}

void doVerification(char *data, int dataLen, EVP_PKEY *pkey, EVP_MD_CTX md_ctx,
		uint8_t *signBuff, uint32_t signLen) {
	int err;

	ERR_load_crypto_strings();

	EVP_VerifyInit(&md_ctx, EVP_sha1());
	EVP_VerifyUpdate(&md_ctx, data, dataLen);
	err = EVP_VerifyFinal(&md_ctx, signBuff, signLen, pkey);
	EVP_PKEY_free(pkey);

	if (err == -1) { //!=1
		ERR_print_errors_fp(stderr);
		exit(1);
	}
	printf("Signature verified.\n");
}
