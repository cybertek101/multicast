
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


cryptoBoxOpenSSL() {
	// TODO Auto-generated constructor stub
	initialise_openssl();
}

void generate_iv(unsigned char* iv) 
{

	if (!RAND_bytes(iv, MAX_IVLEN))
		abort();

}


bool generate_keys(string skey_file, string pkey_file, unsigned int len) 
{

	bool saved = 0;
	try {

		const int kExp = 3; //65537 should be used instead -- nevertheless for testing purposes 3 is enough

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

	} catch (std::exception& e) {
		cerr << e.what() << endl;
	}
	return saved;
}

unsigned char* sign(string msg, string skey_file) 
{
	unsigned char *signature;
	try {

		unsigned char* digest = (unsigned char*) malloc(
				sizeof(unsigned char) * SHA256_DIGEST_LENGTH);
		signature = (unsigned char*) malloc(
				sizeof(unsigned char) * DEFAULT_SIG_KEYLEN);
		unsigned char * error = (unsigned char*) malloc(
				sizeof(unsigned char) * DEFAULT_SIG_KEYLEN);
		unsigned int slen; //signature length

		//Get key from the file
		FILE * file = fopen((const char*) skey_file.c_str(), "r");
		if (file != NULL) {
			RSA *rsa = RSA_new();
			PEM_read_RSAPrivateKey(file, &rsa, NULL, NULL);
			fclose(file);

			//Verifying RSA Private keys
			if (RSA_check_key(rsa) != 1) {
				ERR_load_crypto_strings();
				ERR_error_string(ERR_get_error(), (char *) error);
				cout << "RSA keys are not valid." << error << endl;
			}

			//hashing the message
			sha256((unsigned char *) msg.c_str(), (unsigned long) msg.length(),
					digest);

			//Signing
			int out = RSA_sign(NID_sha256, digest,
			SHA256_DIGEST_LENGTH, signature, &slen, rsa);

			if (out != 1) {
				ERR_load_crypto_strings();
				ERR_error_string(ERR_get_error(), (char *) error);
				cout << "Error signing the message:" << error
						<< endl;
			}
		} else {
			cout << "Error signing the message:"
					<< " could not open secret key file " << skey_file << endl;
		}

	} catch (std::exception& e) {
		cerr << e.what() << endl;
	}
	return signature;
}

bool verify_signature(string msg, string tag,
		string pkey_file) {

	int output = 0;
	try {

		unsigned char* digest = (unsigned char*) malloc(
				sizeof(unsigned char) * SHA256_DIGEST_LENGTH);

		//Get key from the file
		FILE * file = fopen((const char*) pkey_file.c_str(), "r");
		if (file != NULL) {
			RSA *rsa = RSA_new();
			PEM_read_RSAPublicKey(file, &rsa, NULL, NULL);
			fclose(file);

			//hashing the message
			sha256((unsigned char *) msg.c_str(), (unsigned long) msg.length(),
					digest);

			//Signing
			output = RSA_verify(NID_sha256, digest,
			SHA256_DIGEST_LENGTH, (unsigned char *) tag.c_str(), tag.length(),
					rsa);
		} else {
			cout << "Error verifying the message:"
					<< " could not open public key file " << pkey_file << endl;
		}

	} catch (std::exception& e) {
		cerr << e.what() << endl;
	}
	return output;
}

int main()
{

string file_name;


}














