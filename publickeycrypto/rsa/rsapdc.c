/* How to generate RSA public/private key pairs using openssl
*
*
references:
-----------
* http://stuff.onse.fi/man?program=EVP_PKEY_sign_init&section=3
* https://www.openssl.org/docs/crypto/EVP_PKEY_verify.html
*/


//#include <openssl/ec.h> // for EC_GROUP_new_by_curve_name, EC_GROUP_free, EC_KEY_new, EC_KEY_set_group, EC_KEY_generate_key, EC_KEY_free
//#include <openssl/ecdsa.h>   // for ECDSA_do_sign, ECDSA_do_verify
//#include <openssl/obj_mac.h> // for NID_secp192k1
#include <openssl/sha.h>  //for SHA functions
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

#define NUM_MSGS = 100;
#define MULTICAST_GROUP "239.0.0.2"
#define MY_PORT 6000
#define MAX_BUF_LENGTH 1500

//------------------------------------

EVP_PKEY * rsapubkey=NULL;

unsigned char * sig_buf;
unsigned char rcvd_msg[MAX_BUF_LENGTH];
unsigned char phasor_message[MAX_BUF_LENGTH];
size_t rcvd_msg_length, phasor_msg_length;


//int createSocket(const char* Port, int flag)
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

  ERR_load_crypto_strings();

  FILE *fp = fopen("keys/rsapubkey.pem", "rb");
  if (fp == NULL)
    return -1;
  rsapubkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
  fclose(fp);

  if (rsapubkey == NULL) {
    ERR_print_errors_fp(stderr);
    return -1;
  }
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

int getVerifiedMessage()
{

  //EVP_PKEY *verify_key;
  /* NB: assumes verify_key, sig and siglen are already set up
  * and that verify_key is an RSA public key
  */

  EVP_PKEY_CTX *ctx;
  size_t mdlen=32, siglen; 
  unsigned char md[32];



  memcpy(&siglen, rcvd_msg, sizeof(siglen));
  sig_buf = OPENSSL_malloc(siglen);
  phasor_msg_length = rcvd_msg_length - (sizeof(siglen) + siglen);

  memcpy(phasor_message, rcvd_msg+sizeof(siglen), phasor_msg_length);
  memcpy(sig_buf, rcvd_msg + sizeof(siglen) + phasor_msg_length, siglen);

  phasor_msg_length = rcvd_msg_length - (sizeof(siglen) + siglen);

  SHA256(phasor_message, phasor_msg_length, md);

  //SHA1(phasor_message, phasor_msg_length, msg_hash); // msg_hash now contains the 20-byte SHA-1 hash

 //EVP_PKEY *verify_key;
 /* NB: assumes verify_key, sig, siglen md and mdlen are already set up
  * and that verify_key is an RSA public key
  */
  ctx = EVP_PKEY_CTX_new(rsapubkey, NULL/* no engine */);
  if (!ctx)
        /* Error occurred */
    return -1;
  if (EVP_PKEY_verify_init(ctx) <= 0)
        /* Error */
    return -1; 
  if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0)
        /* Error */
    return -1;
  if (EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) <= 0)
        /* Error */
    return -1;
  /* Perform operation */
  int ret;
  if((ret=EVP_PKEY_verify(ctx, sig_buf, siglen, md, mdlen))==1)  // ret == 1 indicates success, 0 verify failure and < 0 for some other error.
  {
    free(sig_buf);
    return 1;
  }
  else
  {
    free(sig_buf);
    return -1;
  }

/*
	int function_status = -1;
  	int i;
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
	if (verify_success != verify_status)
    {
		return -1;
	}
    else
    {
      return 1;
    }*/
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
  	
    printf("Received %zu bytes\n", rcvd_msg_length);
  
    if(getVerifiedMessage()==1)
    {
      
      lv_addr.sin_port = htons(ntohs(srcaddr.sin_port));//  htons(ntohs(srcaddr.sin_port)); //htons(atoi(localPort));
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

  }
  
  close(sock);
     
	return(0) ;
}
