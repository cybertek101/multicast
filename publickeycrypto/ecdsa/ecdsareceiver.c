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
#define MY_PORT 6000
#define MAX_BUF_LENGTH 1500
//------------------------------------

EC_KEY* ecpubkey=NULL;
unsigned char * sig_buf;
unsigned char rcvd_msg[MAX_BUF_LENGTH];
unsigned char phasor_message[MAX_BUF_LENGTH];
size_t rcvd_msg_length, phasor_msg_length;

//------------------------------------
int createSocket()
{
  /* set up socket */
	struct sockaddr_in myAddr;
	struct ip_mreq mreq;

	int addrlen;
 	int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
 	if (sockfd < 0) 
  	{
    	perror("socket");
    	return -1;
  	}
  	bzero((char *)&myAddr, sizeof(myAddr));
  	myAddr.sin_family = AF_INET;
  	myAddr.sin_addr.s_addr = htonl(INADDR_ANY);
  	myAddr.sin_port = htons(MY_PORT);
  	addrlen = sizeof(myAddr);

  	/* receive */
  	if (bind(sockfd, (struct sockaddr *) &myAddr, sizeof(myAddr)) < 0) 
  	{        
    	perror("bind");
    	exit(1);
  	}    
  	mreq.imr_multiaddr.s_addr = inet_addr(MULTICAST_GROUP);         
  	mreq.imr_interface.s_addr = htonl(INADDR_ANY);         
  	if (setsockopt(sockfd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) 
  	{
    	perror("setsockopt mreq");
    	return -1;
  	}         
  	else
  	{
    	printf("PDC joined multicast group.\n");
  	}
  	return sockfd;
}


int Initialize()
{

	EVP_PKEY* pevpkey;
	FILE *fp = fopen("keys/myeccpubkey.pem", "rb");

	if (fp == NULL)
	{
		return -1;
	}

	pevpkey= PEM_read_PUBKEY(fp, NULL, NULL, NULL); 
	ecpubkey= EVP_PKEY_get1_EC_KEY(pevpkey); 
	
	close(fp);
	return 1;
}

//------------------------------------
int getVerifiedMessage()
{

	int function_status = -1;
  unsigned int siglen;
  unsigned char msg_hash[SHA_DIGEST_LENGTH];

  memcpy(&siglen, rcvd_msg, sizeof(siglen));
  sig_buf = OPENSSL_malloc(siglen);
	phasor_msg_length = rcvd_msg_length - (sizeof(siglen) + siglen);

	memcpy(phasor_message, rcvd_msg+sizeof(siglen), phasor_msg_length);
  memcpy(sig_buf, rcvd_msg+sizeof(siglen)+phasor_msg_length, siglen);

  SHA1(phasor_message, phasor_msg_length, msg_hash); // msg_hash now contains the 20-byte SHA-1 hash
    	
	int verify_status = ECDSA_verify(0, msg_hash, SHA_DIGEST_LENGTH, sig_buf, siglen, ecpubkey); 

	free(sig_buf);
	
	const int verify_success = 1;
	if (verify_success == verify_status)
  {
    //printf("success!\n");
		return 1;
	}
  else
  {
    //printf("Failed!\n");
    return -1;
  }
 }

//------------------------------------
int main( int argc , char * argv[])
{
	struct sockaddr_in srcaddr, lv_addr;

	int addrlen;
	int sock;

  /* set up socket */
  sock = createSocket();
	if(sock <= 0) 
  {
    perror("socket");
    exit(1);
  }

  bzero(&lv_addr,sizeof(lv_addr));
  lv_addr.sin_family = AF_INET;
  lv_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    	
	Initialize();
	
	/* receive + send */
	while (1) 
	{
	  if((rcvd_msg_length = recvfrom(sock, rcvd_msg, MAX_BUF_LENGTH, 0, (struct sockaddr *) &srcaddr, &addrlen))<=0)
		{   
			perror("socket");
      exit(1);
  	}
    	
    //printf("Received %zu bytes\n", rcvd_msg_length);
    if(getVerifiedMessage()==1)
    {
      
      lv_addr.sin_port = srcaddr.sin_port;//  htons(ntohs(srcaddr.sin_port)); //htons(atoi(localPort));
      printf("Verified! pmu port: %d \t msg: %s\n", srcaddr.sin_port,phasor_message);
      int sent_cnt = sendto(sock, phasor_message, phasor_msg_length, 0, (struct sockaddr *) &lv_addr, addrlen);

      if (sent_cnt != phasor_msg_length) 
      {
        perror("sendto");
        exit(1);
      }
    }
    else
    {
      printf("Failed to verify\n");
    }
		
		//-- check conditions to update key if need b
   		//send returned value from securitybox to multicast address.
    
    	//int sent_cnt = sendto(sock, signed_msg, signed_msg_length, 0, (struct sockaddr *) &rcvr_addr, addrlen);
    
    	//if (sent_cnt != signed_msg_length) 
    	//{
      	//	perror("sendto");
      	//	exit(1);
    	//}
    	//printf("sent %zu bytes \n", signed_msg_length);
  	}
  
  //free(sig_buf);
  close(sock);
 
    
	return(0) ;
}
