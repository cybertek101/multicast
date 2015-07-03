
//different ecc parameters
//comparison of bitsize of rsa ecc ...
//crosscompiled
//finish scu
//certificate based implementation
//remember ecdsa algorithm

//arm-linux-gnueabi-gcc -g -L openssllibraries/  -lssleay32 ecdsasig.c -leay32
//native compule: gcc -g  -lssl  signverify.c -lcrypto

#include <openssl/ec.h> // for EC_GROUP_new_by_curve_name, EC_GROUP_free, EC_KEY_new, EC_KEY_set_group, EC_KEY_generate_key, EC_KEY_free
#include <openssl/ecdsa.h>   // for ECDSA_do_sign, ECDSA_do_verify
#include <openssl/obj_mac.h> // for NID_secp192k1
#include <openssl/sha.h>  //for sha1
#include <time.h>  
#include <string.h>
#include <stdlib.h>
//------------------------------------

EC_KEY* eckey=NULL;
EC_GROUP *ecgroup=NULL;
//unsigned char* hash=NULL;
//------------------------------------

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
        ecgroup= EC_GROUP_new_by_curve_name(NID_secp112r1);
        //ecgroup= EC_GROUP_new_by_curve_name(NID_secp192k1);
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

static void signverify(char* msg, size_t length)
{
	int function_status = -1;


	unsigned char hash[SHA_DIGEST_LENGTH];
	SHA1(msg, length, hash); // hash now contains the 20-byte SHA-1 hash
	
	//printf("msg: %s, len: %d\n hash:%s",msg,length,hash);
	//printf("hash:%s\t %zd\n",hash,strlen(hash));


    	ECDSA_SIG *signature = ECDSA_do_sign(hash, strlen(hash), eckey);
    	if (NULL == signature)
    	{
    		printf("Failed to generate EC Signature\n");
        	function_status = -1;
    	}
        else
    	{
		int verify_status = ECDSA_do_verify(hash, strlen(hash), signature, eckey);
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
	int i, N=100;
	char data[] = "Hello, world!";
	
    	size_t length = sizeof(data);
	
	//http://stackoverflow.com/questions/5248915/execution-time-of-c-program
	clock_t begin, end;
	double time_spent;
    
	if(generatekey())
	{	begin = clock();	
		for(i=0;i<N;i++)  
    		{
					
			signverify(data,length);
			
			data[length-2]=rand()%100;
			//printf("%s\n",data);

    		}	
		
		end = clock();
		time_spent = (double)(end - begin) / CLOCKS_PER_SEC;
		printf("exec time:%fms\n",1000*time_spent/N);
	}
	else
	{
		printf("Key generation failed\n");
	
	}
	
	EC_GROUP_free(ecgroup);
        EC_KEY_free(eckey);
    
    	return(0) ;
}
