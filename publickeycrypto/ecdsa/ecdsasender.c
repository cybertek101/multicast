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
#include <strings.h>
#include <stdlib.h>
#include <openssl/pem.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <stdio.h>

//------------------------------------

#define MULTICAST_GROUP "239.0.0.2"
#define RCVR_PORT 6000
#define PMU_PORT 3001
#define MAX_BUF_LENGTH 1500
#define HASH_LENGTH 20
//------------------------------------

EC_KEY* ecprivkey=NULL;
unsigned char * sig_buf;
unsigned char signed_msg[MAX_BUF_LENGTH];
unsigned char phasor_message[MAX_BUF_LENGTH];
size_t signed_msg_length;

//------------------------------------

int createSocket()
{
  int sockfd;
  struct sockaddr_in PMUAddr;

  //create  socket
  sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  if (sockfd <= 0)
  {
    perror("socket");
    return -1;
  }

  bzero(&PMUAddr,sizeof(PMUAddr));
  PMUAddr.sin_family = AF_INET;
  PMUAddr.sin_addr.s_addr = htonl(INADDR_ANY);
  PMUAddr.sin_port = htons(PMU_PORT); //htons(atoi(localPort));
 
  if(bind(sockfd,(struct sockaddr *)&PMUAddr, sizeof(PMUAddr)) != 0)
  {
    perror("ERROR: bind() failed.\n");
    return -1;
  }

  //printf("PORT = %d \n", PMUAddr.sin_port);

  return sockfd;
}

//------------------------------------
int Initialize()
{

	EVP_PKEY* pevpkey;

	FILE *fp = fopen("keys/myeccprivkey.pem", "rb");

	if (fp == NULL)
	{
		return -1;
	}
	pevpkey= PEM_read_PrivateKey(fp, NULL, NULL, NULL); 
	ecprivkey= EVP_PKEY_get1_EC_KEY(pevpkey); 

  sig_buf = OPENSSL_malloc(ECDSA_size(ecprivkey));

  close(fp);

  return 1;
}

//------------------------------------
void getSignedMessage(size_t msglength)
{

	int function_status = -1;
  int i;
  unsigned int siglen;
  unsigned char msg_hash[SHA_DIGEST_LENGTH];

  SHA1(phasor_message, msglength, msg_hash); // msg_hash now contains the 20-byte SHA-1 hash

  if(ECDSA_sign(0, (const unsigned char*) msg_hash, SHA_DIGEST_LENGTH, sig_buf, &siglen, ecprivkey))
  {
    memcpy(signed_msg, &siglen, sizeof(siglen));
    memcpy(signed_msg + sizeof(siglen), phasor_message, msglength);
    memcpy(signed_msg + sizeof(siglen) + msglength, sig_buf, siglen);
    
    signed_msg_length = sizeof(siglen) + msglength + siglen;

    //printf("bytes: %zu", sizeof(siglen));
    /*for(i = 0; i < ECDSA_size(ecpubkey); i++) 
      printf("%02x", sig_buf[i]);
    printf("\n");
    */
  }
  else
  {
    perror("signing failed\n");
  }
 
}


//------------------------------------
int main( int argc , char * argv[])
{

	struct sockaddr_in rcvr_addr, lv_addr;
	int addrlen, sock;
	char* buffer;
	//unsigned char data[] = "Hello, world!";
	ssize_t length;
  	
  sock = createSocket();
	if(sock <= 0) 
  {
    perror("socket");
    exit(1);
  }

  bzero((char *)&rcvr_addr, sizeof(rcvr_addr));
  rcvr_addr.sin_family = AF_INET;
  rcvr_addr.sin_addr.s_addr = inet_addr(MULTICAST_GROUP); 
  rcvr_addr.sin_port = htons(RCVR_PORT);
  addrlen = sizeof(rcvr_addr);

	Initialize();

  printf("Waiting to receive from LV\n");
   	/* receive + send */
	while (1) 
	{
  
    	//-------receive phasor_message
	  length = recvfrom(sock, phasor_message, MAX_BUF_LENGTH, 0, (struct sockaddr *) &lv_addr, &addrlen);
    printf("Received %zu bytes\n", length);
    getSignedMessage(length);

    //-- check conditions to update key if need b
   	//send returned value from securitybox to multicast address.
    
    int sent_cnt = sendto(sock, signed_msg, signed_msg_length, 0, (struct sockaddr *) &rcvr_addr, addrlen);
    if (sent_cnt != signed_msg_length) 
    {
      perror("sendto");
      exit(1);
    }
    printf("Sent %zu bytes \n", signed_msg_length);
  }
  free(sig_buf);
  close(sock);
    
	return(0) ;
}
