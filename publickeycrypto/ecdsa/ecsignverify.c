/* How to generate EC public/private key pairs using openssl

*list ec parameters
$ openssl ecparam -list_curves

*generate private key:
$ openssl ecparam -genkey -name prime256v1 -out myeccprivatekey.pem [-param_enc explicit]

* generate public key from private key
$ openssl ec -in myeccprivatekey.pem -pubout -out myeccpubkey.pem  [-param_enc explicit]

* generating an EC certificate request
$ openssl req -new -key myeccprivatekey.pem -out csr.pem

*self signing a certificate request
$ openssl req -x509 -days 365 -key myeccprivatekey.pem -in csr.pem -out myecccertificate.pem

References:
* https://msol.io/blog/tech/2013/10/06/create-a-self-signed-ecc-certificate/
* https://wiki.openssl.org/index.php/Command_Line_Elliptic_Curve_Operations
* http://www.guyrutenberg.com/2013/12/28/creating-self-signed-ecdsa-ssl-certificate-using-openssl/
* https://wiki.openssl.org/index.php/Elliptic_Curve_Cryptography
*/


//different ecc parameters
//comparison of bitsize of rsa ecc ...
//crosscompiled
//finish scu
//certificate based implementation
//remember ecdsa algorithm

//arm-linux-gnueabi-gcc -g -o ecsignverifycross -L openssllibraries/  -lssleay32 ecdsasig.c -leay32
//native compule: gcc -g -o ecsignverify -lssl  signverify.c -lcrypto

#include <openssl/ec.h> // for EC_GROUP_new_by_curve_name, EC_GROUP_free, EC_KEY_new, EC_KEY_set_group, EC_KEY_generate_key, EC_KEY_free
#include <openssl/ecdsa.h>   // for ECDSA_do_sign, ECDSA_do_verify
#include <openssl/obj_mac.h> // for NID_secp192k1
#include <openssl/sha.h>  //for sha1
#include <time.h>  
#include <string.h>
#include <stdlib.h>
#include <openssl/pem.h>

//------------------------------------

EC_KEY* ecprivkey=NULL;
EC_KEY* ecpubkey=NULL;

//EC_GROUP *ecgroup=NULL;
//unsigned char* hash=NULL;
double timesign=0;
double timeverif=0;
clock_t begint, endt;
//------------------------------------
/*

static int generatekey()
{

    int function_status = -1;
    eckey=EC_KEY_new();
    if (NULL == eckey)
    {
        printf("Failed to create new EC Key\n");
        function_status = -1;
    }
    else
    {
        ecgroup= EC_GROUP_new_by_curve_name(NID_secp192k1);
        //ecgroup= EC_GROUP_new_by_curve_name(NID_secp521r1);
        //ecgroup= EC_GROUP_new_by_curve_name(NID_sect571r1);


        if (NULL == ecgroup)
        {
            printf("Failed to create new EC Group\n");
            function_status = -1;
        }
        else
        {
            int set_group_status = EC_KEY_set_group(eckey,ecgroup);
            const int set_group_success = 1;
            if (set_group_success != set_group_status)
            {
                printf("Failed to set group for EC Key\n");
                function_status = -1;
            }
            else
            {
                const int gen_success = 1;
                int gen_status = EC_KEY_generate_key(eckey);
                if (gen_success != gen_status)
                {
                    printf("Failed to generate EC Key\n");
                    function_status = -1;
                }
	     }
	}
    }
    return function_status;
}*/



int loadkeys()
{

	EVP_PKEY* pevpkey;
	//EC_KEY* ecprivkey;

	FILE *fp1 = fopen("keys/myeccprivkey.pem", "rb");
	FILE *fp2 = fopen("keys/myeccpubkey.pem", "rb");

	if (fp1 == NULL ||fp2 == NULL)
	{
		return -1;
	}
	pevpkey= PEM_read_PrivateKey(fp1, NULL, NULL, NULL); 
	ecprivkey= EVP_PKEY_get1_EC_KEY(pevpkey); 


	pevpkey= PEM_read_PUBKEY(fp2, NULL, NULL, NULL); 
	ecpubkey= EVP_PKEY_get1_EC_KEY(pevpkey); 

	return 1;
}

//------------------------------------
/*
//http://stackoverflow.com/questions/9284420/how-to-use-sha1-hashing-in-c-programming
unsigned char* computeHash(char* msg,size_t length)
{

	// The data to be hashed
	//char msg2[] = "Hello, world!";
	//size_t length2 = sizeof(msg2);	
	//size_t length = sizeof(msg);
	unsigned char hash2[SHA_DIGEST_LENGTH];
	SHA1(msg, length, hash2); // hash now contains the 20-byte SHA-1 hash
	
	printf("msg: %s, len: %d\n hash:%s",msg,length,hash2);
	return hash2; 
}
*/

//------------------------------------

static void signverify(unsigned char* msg, size_t length)
{
	int function_status = -1;
	int i;
	unsigned int siglen;

	unsigned char * sig; 
	unsigned char * buffer = NULL;
	begint = clock();
	unsigned char hash[SHA_DIGEST_LENGTH];
	SHA1(msg, length, hash); // hash now contains the 20-byte SHA-1 hash
	

	//printf("msg: %s, len: %d\n hash:%s",msg,length,hash);
	//printf("hash:%s\t %zd\n",hash,strlen(hash));


    //ECDSA_SIG *signature = ECDSA_do_sign(hash, strlen(hash), eckey);
 	//ECDSA_sign(int type, const unsigned char *dgst, int dgstlen, unsigned char *sig, unsigned int *siglen, EC_KEY *eckey);
	siglen = ECDSA_size(ecprivkey);
 	sig  = OPENSSL_malloc(siglen);

	int ret= ECDSA_sign(0, hash, SHA_DIGEST_LENGTH, sig, &siglen, ecprivkey); 

	buffer = OPENSSL_malloc(length+siglen+sizeof(unsigned int));

   	printf("Sig len: %d \t priv key len: %d \t puk key len: %d \n", siglen, ECDSA_size(ecprivkey), ECDSA_size(ecpubkey));
   	
   	//bcopy(msg, buffer, length);
   	//bcopy(sig, buffer + length, ECDSA_size(ecpubkey));

   	memcpy(buffer,&siglen, sizeof(siglen));
   	memcpy(buffer+sizeof(siglen),msg,length);
   	memcpy(buffer+sizeof(siglen)+length,sig,siglen);
   	
   	
   	
	for(i = 0; i < ECDSA_size(ecpubkey); i++) 
		printf("%02x", sig[i]);
 	printf("\n");

	//for(i = 0; i < siglen; i++) 
	//		printf("%02x", buffer[length+i]);
 	//printf("\n");

	free(sig);
	
	endt = clock();
	timesign = timesign + (double)(endt-begint);

    	if (NULL == sig)
    	{
    		printf("Failed to generate EC Signature\n");
        	function_status = -1;
    	}
        else
    	{
		begint = clock();
		//int verify_status = ECDSA_do_verify(hash, strlen(hash), signature, eckey);
		//
		// 					ECDSA_verify(int type, const unsigned char *dgst, int dgstlen, const unsigned char *sig, int siglen, EC_KEY *eckey);
		size_t lenlen = sizeof(buffer);
		printf("rcv len: %zu \n",lenlen);

		sig  = OPENSSL_malloc(ECDSA_size(ecpubkey));
		unsigned int siglenn;
		unsigned char* msgg;
		//bcopy(buffer-ECDSA_size(ecpubkey), sig,  ECDSA_size(ecpubkey));
   		memcpy(&siglenn, buffer,sizeof(siglenn));
   		//memcpy(msgg, buffer+sizeof(siglenn),length);
   		memcpy(sig, buffer+sizeof(siglenn)+length,siglenn);
		
		for(i = 0; i < siglenn; i++) 
			printf("%02x", sig[i]);
 		printf("\n");

		
		int verify_status = ECDSA_verify(0, hash, SHA_DIGEST_LENGTH, sig, siglenn, ecpubkey); 

		endt = clock();
		timeverif = timeverif + (double)(endt-begint);

        	const int verify_success = 1;
		if (verify_success != verify_status)
        	{
	           printf("Failed to verify EC Signature\n");
        	}
        	else
        	{
        		//printf("Verified!\n");
        	}
    	}
}

//------------------------------------
int main( int argc , char * argv[] )
{
	//unsigned char hash[] = "c7fbca202a95a570285e3d700eb04ca2";
	int i, N = 1;
	unsigned char  data[] = "Hell, world!";
	
    size_t length = sizeof(data);
	printf("msg len: %zu \n", length);
	//http://stackoverflow.com/questions/5248915/execution-time-of-c-program
	clock_t begin, end;
	double time_spent;
    
	//if(generatekey())
	if(loadkeys())
	{	begin = clock();	
		for(i=0;i<N;i++)  
    		{
					
			signverify(data,length);
			
			data[length-2]=rand()%100;
			//printf("%s\n",data);

    		}	
		
		end = clock();
		time_spent = (double)(end - begin) / CLOCKS_PER_SEC;
		timesign =timesign/CLOCKS_PER_SEC;
		timeverif =timeverif/CLOCKS_PER_SEC;
		printf("exec time:%fms\n",1000*time_spent/N);
		printf("sign time:%fms\n",1000*timesign/N);
		printf("verify time:%fms\n",1000*timeverif/N);
	}
	else
	{
		printf("Key generation failed\n");
	
	}
	
	//EC_GROUP_free(ecgroup);
    //EC_KEY_free(eckey);
    
    	return(0) ;
}
