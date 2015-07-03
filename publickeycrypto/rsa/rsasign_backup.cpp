
//cross-compile: arm-linux-gnueabi-g++ -g -L openssllibraries// -lssleay32 rsasign.cpp -leay32
//native compile: g++ -o rsasign -lssl rsasign.cpp -lcrypto
//testcases: different key sizes, clean code where key loading is done once, test on pmu, compare with ecdsa,

//to do: load keys from a file, read EVP rsa



#include <iostream>
#include <string>
#include <math.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <errno.h>
#include <sstream>
#include <stdexcept>
#include <sys/time.h>

#include <cstring>
#include <exception>
#include <fstream>

#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include <openssl/engine.h>

#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

using namespace std;

#define DEFAULT_SIG_KEYLEN 512 

void initialise_openssl();
bool generate_keys(string skey_file, string pkey_file, unsigned int len);

unsigned char* sign(string msg, RSA* rsa);
bool verify_signature(string msg, unsigned char* tag, RSA* rsa);
int sha256(unsigned char* msg, unsigned long length, unsigned char* digest);


//string load_key_bytes(string key_file); void generate_iv(unsigned
//char* iv); void generate_key(unsigned char* key,int length);

//string encrypt_rsa(string plaintext, string pk_file);
//string decrypt_rsa(string ciphertext, string sk_file);


//int encrypt_aes_cbc_openssl(const unsigned char* plain, const unsigned char* key, const unsigned char* iv, const int len, unsigned char *ciphertext);
//int decrypt_aes_cbc_openssl(const unsigned char* ciphertext, const unsigned char* key, const unsigned char* iv, const int len, unsigned char *plaintext);
//unsigned char* hmac_sha256(string msg, unsigned char* key);
//bool verify_hmac_sha256(string payload, unsigned char* mac, unsigned char* skey);



/*// For debuging purposes only
 void toHex(const unsigned char* s) 
{ 
	ostringstream ret;
 	bool upper_case = true;
 	for (string::size_type i = 0; i < s.length(); ++i)
 		ret << std::hex << std::setfill('0') << std::setw(2) << (upper_case ? std::uppercase : std::nouppercase) << (int) s[i];

 cout << ret.str()<<endl;
 }*/

/*
void generate_iv(unsigned char* iv) 
{

	if (!RAND_bytes(iv, MAX_IVLEN))
		abort();
}
*/

/*void generate_key(unsigned char* key, int length) {

    		abort();
OB
}


string load_key_bytes(string file) 
{

	string key;
	ifstream key_file;

	try 
	{
		//Save private key into a file
		key_file.open(file.c_str());
		string tmp = "";
		while (!key_file.eof()) 
		{
			getline(key_file, tmp);
			key += tmp;
		}
		key_file.close();

	} 
	catch (std::exception& e) 
	{
		cerr << e.what() << endl;
	}

	return key;
}

string encrypt_rsa(string plaintext, string pk_file) 
{

	string sciphertext;

	try 
	{
		//string key = load_key_bytes(pk_file);
		// Encrypt the message
		unsigned char *ciphertext = (unsigned char*) malloc(sizeof(unsigned char) * MAX_DATALEN);
		unsigned char *error = (unsigned char*) malloc(sizeof(unsigned char) * 512);

		FILE * file = fopen((const char*) pk_file.c_str(), "r");
		if (file != NULL) 
		{
			RSA *rsa = RSA_new();
			PEM_read_RSAPublicKey(file, &rsa, NULL, NULL);
			fclose(file);

			int ctxt_len = RSA_public_encrypt(plaintext.length() + 1,
					(unsigned char*) plaintext.c_str(),
					(unsigned char*) ciphertext, rsa,
					RSA_PKCS1_OAEP_PADDING);

			if (ctxt_len == -1) 
			{
				ERR_load_crypto_strings();
				ERR_error_string(ERR_get_error(), (char *) error);
				cout << "[CryptoBox] Error encrypting message:" << error<< endl;
			}

			sciphertext = string((const char *) ciphertext, ctxt_len);

		} 
		else 
		{
			cout << "[CryptoBox] Error encrypting the message:"
					<< " could not open public key file " << pk_file << endl;
		}

	} catch (std::exception& e) 
	{
		cerr << e.what() << endl;
	}
	return sciphertext;
}

string decrypt_rsa(string ciphertext, string sk_file) 
{

	string splaintext;
	try 
	{

		unsigned char *plaintext = (unsigned char*) malloc(
				sizeof(unsigned char) * MAX_DATALEN);
		unsigned char *error = (unsigned char*) malloc(
				sizeof(unsigned char) * 512);

		FILE * file = fopen((const char*) sk_file.c_str(), "r");
		if (file != NULL) 
		{
			RSA *rsa = RSA_new();
			PEM_read_RSAPrivateKey(file, &rsa, NULL, NULL);
			fclose(file);

			int ptxt_len = RSA_private_decrypt(
					ciphertext.length(), //FIXME
					(unsigned char*) ciphertext.c_str(),
					(unsigned char*) plaintext, rsa,
					RSA_PKCS1_OAEP_PADDING);
			if (ptxt_len == -1) 
			{
				ERR_load_crypto_strings();
				ERR_error_string(ERR_get_error(), (char*) error);
				cout << "[CryptoBox] Error decrypting message:" << error<< endl;
			}
			splaintext = string((const char *) plaintext, ptxt_len);
		} else 
		{
			cout << "[CryptoBox] Error decrypting the message:"
					<< " could not open secret key file " << sk_file << endl;
		}

	} catch (std::exception& e) 
	{
		cerr << e.what() << endl;
	}
	return splaintext;
}

void handleErrors(void) 
{
	ERR_print_errors_fp(stderr);
	//abort();
}

*/
/*
int encrypt_aes_cbc_openssl(const unsigned char* plaintext, const unsigned char* key, const unsigned char* iv, const int len, unsigned char *ciphertext) 
{

	EVP_CIPHER_CTX ctx;

	int ciphertext_len;
	int olen;

	// Initialise the context 
	EVP_CIPHER_CTX_init(&ctx);

	// AES-CBC-256 - key of 256bits and IV of 128bits
	// Encryption initialisation
	if (1 != EVP_EncryptInit_ex(&ctx, EVP_aes_256_cbc(), NULL, key, iv))
		handleErrors();

	// Providing plaintext to be encrypted
	// The output stored in cipertext variable
	if (1 != EVP_EncryptUpdate(&ctx, ciphertext, &olen, plaintext, len))
		handleErrors();
	ciphertext_len = olen;

	// Finalise the encryption
	if (1 != EVP_EncryptFinal_ex(&ctx, ciphertext + olen, &olen))
		handleErrors();
	ciphertext_len += olen;

	// Clean up 
	//EVP_CIPHER_CTX_free(ctx);
	EVP_CIPHER_CTX_cleanup(&ctx);

	return ciphertext_len;
}

int decrypt_aes_cbc_openssl(const unsigned char* ciphertext,
		const unsigned char* key, const unsigned char* iv, const int len,
		unsigned char *plaintext) {

	EVP_CIPHER_CTX ctx;

	int plen, tmplen;
	int plaintext_len;

	EVP_CIPHER_CTX_init(&ctx);

	EVP_DecryptInit_ex(&ctx, EVP_aes_256_cbc(), NULL, NULL, NULL);

	EVP_DecryptInit_ex(&ctx, NULL, NULL, (unsigned char *) key, iv);

	if (!EVP_DecryptUpdate(&ctx, (unsigned char *) plaintext, &plen,
			(const unsigned char *) ciphertext, len))
		handleErrors();

	plaintext_len = plen;

	if (!EVP_DecryptFinal_ex(&ctx, (unsigned char *) plaintext + plen, &tmplen))
		handleErrors();

	plaintext_len += tmplen;

	EVP_CIPHER_CTX_cleanup(&ctx);

	return plaintext_len;
}

unsigned char* hmac_sha256(string msg, unsigned char* key) 
{
	int len = msg.length();
	unsigned char *hash = (unsigned char*) malloc(
			sizeof(unsigned char) * MAX_MACLEN);
	hash = HMAC(EVP_sha256(), (const unsigned char*) key, MAX_TAGKEYLEN,
			(const unsigned char*) msg.c_str(), len, NULL, NULL);

	return hash;
}
bool verify_hmac_sha256(string payload, unsigned char* mac,
		unsigned char* skey) {

	return (memcmp((const void *) hmac_sha256(payload, skey),
			(const void *) mac, MAX_MACLEN) == 0);
}


*/

void initialise_openssl() 
{
	//Library initialisation
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();
	OPENSSL_config(NULL);
	OpenSSL_add_all_ciphers();
	OpenSSL_add_all_digests();

}


bool generate_keys(string skey_file, string pkey_file, unsigned int len) 
{

	bool saved = 0;
	try 
	{

		const int kExp = 65537;//3; //65537 should be used instead -- nevertheless for testing purposes 3 is enough

		int keylen;
		unsigned char *pem_key;
		ofstream key_file;

		//Generate RSA key pair
		RSA *rsa = RSA_generate_key(len, kExp, 0, 0);

		//Extract the private key
		BIO *bio = BIO_new(BIO_s_mem());
		PEM_write_bio_RSAPrivateKey(bio, rsa, NULL, NULL, 0, NULL, NULL);

		keylen = BIO_pending(bio);
		pem_key = (unsigned char *) calloc(keylen + 1, 1); /* Null-terminate */
		BIO_read(bio, pem_key, keylen);

		//Save private key into a file
		key_file.open(skey_file.c_str());
		key_file << pem_key;
		key_file.close();
		free(pem_key);


		//Extract the public key
		PEM_write_bio_RSAPublicKey(bio, rsa);

		keylen = BIO_pending(bio);
		pem_key = (unsigned char *) calloc(keylen + 1, 1); /* Null-terminate */
		BIO_read(bio, pem_key, keylen);

		//Save public key into a file
		key_file.open(pkey_file.c_str());
		key_file << pem_key;
		key_file.close();

		BIO_free_all(bio);
		RSA_free(rsa);
		free(pem_key);

		saved = 1;

	} 
	catch (std::exception& e) 
	{
		cerr << e.what() << endl;
	}
	return saved;
}


int sha256(unsigned char* msg, unsigned long length,
		unsigned char* digest) 
{
	SHA256_CTX context;
	if (!SHA256_Init(&context))
		return 0;

	if (!SHA256_Update(&context, (unsigned char*) msg, length))
		return 0;

	if (!SHA256_Final(digest, &context))
		return 0;
	return 1;
}


unsigned char* sign(string msg, RSA* rsa) 
{
	unsigned char *signature;
	try 
	{

		unsigned char* digest = (unsigned char*) malloc(sizeof(unsigned char) * SHA256_DIGEST_LENGTH);
		signature = (unsigned char*) malloc(sizeof(unsigned char) * DEFAULT_SIG_KEYLEN);
		//unsigned char * error = (unsigned char*) malloc(sizeof(unsigned char) * DEFAULT_SIG_KEYLEN);
		unsigned int slen; //signature length

		//Get key from the file
		/*FILE * file = fopen((const char*) skey_file.c_str(), "r");
		if (file != NULL) 
		{
			RSA *rsa = RSA_new();
			PEM_read_RSAPrivateKey(file, &rsa, NULL, NULL);
			fclose(file);

			//Verifying RSA Private keys
			if (RSA_check_key(rsa) != 1) {
				//ERR_load_crypto_strings();
				//ERR_error_string(ERR_get_error(), (char *) error);
				cout << "RSA keys are not valid." << error << endl;
			}
		*/
			//hashing the message
			sha256((unsigned char *) msg.c_str(), (unsigned long) msg.length(),digest);
			
			//Signing
			int out = RSA_sign(NID_sha256, digest, SHA256_DIGEST_LENGTH, signature, &slen, rsa);

			if (out != 1) 
			{
			//	ERR_load_crypto_strings();
			//	ERR_error_string(ERR_get_error(), (char *) error);
				cout << "Error signing the message:" << endl;
			}
		/*} 
		else 
		{
			cout << "Error signing the message:"
					<< " could not open secret key file " << skey_file << endl;
		}*/

	} 
	catch (std::exception& e) 
	{
		cerr << e.what() << endl;
	}
	return signature;
}

bool verify_signature(string msg, unsigned char* sig, RSA* rsa) 
{

	int output = 0;
	try 
	{

		unsigned char* digest = (unsigned char*) malloc(sizeof(unsigned char) * SHA256_DIGEST_LENGTH);

		/*//Get key from the file
		FILE * file = fopen((const char*) pkey_file.c_str(), "r");
		if (file != NULL) 
		{
			RSA *rsa = RSA_new();
			PEM_read_RSAPublicKey(file, &rsa, NULL, NULL);
			fclose(file);
		*/	
			//hashing the message
			sha256((unsigned char *) msg.c_str(), (unsigned long) msg.length(),digest);
			
			//verifying
			output = RSA_verify(NID_sha256, digest, SHA256_DIGEST_LENGTH, sig, RSA_size(rsa),rsa);
			cout<<"signature length:"<<RSA_size(rsa)<<endl;
		/*} 
		else 
		{
			cout << "[CryptoBox] Error verifying the message:"
					<< " could not open public key file " << pkey_file << endl;
		}*/

	} 
	catch (std::exception& e) 
	{
		cerr << e.what() << endl;
	}
	return output;
}


int main()
{
	
	string msg = "Hello World";
	string pk_file = "pk.txt";
	string sk_file = "sk.txt";
	//string tag;
	//unsigned char* tag;
	unsigned int key_len = 1024;
	unsigned char* signature;
	int N=100;
	
	clock_t begin, end;
	double time_spent;
    	RSA *rsa_sk = RSA_new();
	RSA *rsa_pk = RSA_new();
	
	initialise_openssl();
	
	//size_t length = msg.length();
	//cout <<"length: "<< length<<endl;
	
	if (generate_keys(sk_file, pk_file, key_len))
	{

		//Get private key from the file
		FILE * file = fopen((const char*) sk_file.c_str(), "r");
		if (file != NULL) 
		{
			PEM_read_RSAPrivateKey(file, &rsa_sk, NULL, NULL);
			fclose(file);

			//Verifying RSA Private keys
			if (RSA_check_key(rsa_sk) != 1) 
			{
				//ERR_load_crypto_strings();
				//ERR_error_string(ERR_get_error(), (char *) error);
				cout << "RSA keys are not valid."<< endl;
			}

		}

		//Get public key from the file
		file = fopen((const char*) pk_file.c_str(), "r");
		if (file != NULL) 
		{
			PEM_read_RSAPublicKey(file, &rsa_pk, NULL, NULL);
			fclose(file);
		}
		

		//begin signing and verifying

		begin = clock();	
		for(int i=0;i<N;i++)  
    		{
			signature =sign(msg, rsa_sk);
			
			if(verify_signature(msg, signature, rsa_pk))
			{
				//cout<<"Verification succeeded"<<endl;
			}
			else
			{
				cout<<"Verification failed"<<endl;
			}
			
			msg[msg.length()-2]=rand()%100;
			//printf("%s\n",data);
		}	
		
		end = clock();
		time_spent = (double)(end - begin) / CLOCKS_PER_SEC;
		//timesign =timesign/CLOCKS_PER_SEC;
		//timeverif =timeverif/CLOCKS_PER_SEC;
		printf("exec time:%fms\n",1000*time_spent/N);
		//printf("sign time:%fms\n",1000*timesign/N);
		//printf("verify time:%fms\n",1000*timeverif/N);
	}
	else
	{
		cout<<"Key generation failed"<<endl;

	}

	return 0;
}
