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

#define NUM_MSGS = 100;
#define MULTICAST_GROUP "239.0.0.2"
#define RCVR_PORT 6000
#define LV_RCV_PORT 5000
#define MAX_BUF_LENGTH 1500

//------------------------------------


EVP_PKEY * rsaprivkey=NULL;

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
  PMUAddr.sin_port = htons(LV_RCV_PORT); //htons(atoi(localPort));
 
  if(bind(sockfd,(struct sockaddr *)&PMUAddr, sizeof(PMUAddr)) != 0)
  {
    perror("ERROR: bind() failed.\n");
    return -1;
  }
  //printf("PORT = %d \n", PMUAddr.sin_port);
  return sockfd;
}


int Initialize()
{
  ERR_load_crypto_strings();
  FILE *fp = fopen("keys/rsaprivkey.pem", "rb");
  if (fp == NULL)
    return -1;
  rsaprivkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
  fclose(fp);

  if (rsaprivkey == NULL) {
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

void getSignedMessage(size_t msglength)
{


EVP_PKEY_CTX *ctx;
 /* md is a SHA-256 digest in this example. */
 unsigned char *md, *sig;
 size_t mdlen = 32, siglen;
 //EVP_PKEY *signing_key;

  unsigned char msg_hash[32];
  SHA256(phasor_message, msglength, msg_hash);

 /*
  * NB: assumes signing_key and md are set up before the next
  * step. signing_key must be an RSA private key and md must
  * point to the SHA-256 digest to be signed.
  */
 ctx = EVP_PKEY_CTX_new(rsaprivkey, NULL /* no engine */);
 if (!ctx)
        /* Error occurred */
    perror("cannot create context\n");
 
 if (EVP_PKEY_sign_init(ctx) <= 0)
        /* Error */
    perror("Cannot initialize context\n");
 
 if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0)
        /* Error */
    perror("Problem with padding\n");
 
 if (EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) <= 0)
        /* Error */
    perror("Cannot set signature md\n");
 
 /* Determine buffer length */
 if (EVP_PKEY_sign(ctx, NULL, &siglen, msg_hash, mdlen) <= 0)
        /* Error */
    perror("signing problem\n");
 
 sig = OPENSSL_malloc(siglen);

 if (!sig)
        /* malloc failure */
    perror("Malloc error\n");

 if (EVP_PKEY_sign(ctx, sig, &siglen, msg_hash, mdlen) <= 0)
        /* Error */
    perror("Problem signing\n");
 
 /* Signature is siglen bytes written to buffer sig */


  memcpy(signed_msg, &siglen, sizeof(siglen));
  memcpy(signed_msg + sizeof(siglen), phasor_message, msglength);
  memcpy(signed_msg + sizeof(siglen) + msglength, sig, siglen);
    
  signed_msg_length = sizeof(siglen) + msglength + siglen;

  printf(" sig len: %zu\n", siglen);

  free(sig);

/*  int function_status = -1;
  int i;
  unsigned int siglen;
  unsigned char msg_hash[SHA_DIGEST_LENGTH];
  SHA1(phasor_message, msglength, msg_hash); // msg_hash now contains the 20-byte SHA-1 hash
  
  if(ECDSA_sign(0, msg_hash, SHA_DIGEST_LENGTH, sig_buf, &siglen, ecprivkey))
  {

    //printf("Sig len: %d \t priv key len: %d \t puk key len: %d \n", siglen, ECDSA_size(ecprivkey), ECDSA_size(ecpubkey));
    
    memcpy(signed_msg, &siglen, sizeof(siglen));
    memcpy(signed_msg + sizeof(siglen), phasor_message, msglength);
    memcpy(signed_msg + sizeof(siglen) + msglength, sig_buf, siglen);
    
    signed_msg_length = sizeof(siglen) + msglength + siglen;

    //printf("bytes: %zu", sizeof(siglen));
    /*for(i = 0; i < ECDSA_size(ecpubkey); i++) 
      printf("%02x", sig_buf[i]);
    printf("\n");
    */
  //}
  //else
  //{
  //  perror("signing failed\n");
  //}
 
}


//------------------------------------
int main( int argc , char * argv[])
{

  struct sockaddr_in rcvr_addr, lv_addr;
  int addrlen, sock;
  char* buffer;
  unsigned char data[] = "Hello, world!";
  ssize_t length;

  //http://stackoverflow.com/questions/5248915/execution-time-of-c-program
  //clock_t begin, end;
  //double time_spent;
    
  /* set up socket */
  //sock = socket(AF_INET, SOCK_DGRAM, 0);
    
  sock = createSocket();
  if(sock <= 0) 
  {
    perror("socket");
    exit(1);
  }

  bzero((char *)&rcvr_addr, sizeof(rcvr_addr));
  rcvr_addr.sin_family = AF_INET;
  rcvr_addr.sin_addr.s_addr = inet_addr(MULTICAST_GROUP); 
  //rcvr_addr.sin_addr.s_addr = htonl(INADDR_ANY);
  rcvr_addr.sin_port = htons(RCVR_PORT);
  addrlen = sizeof(rcvr_addr);


  /*if(Initialize())
  { 
  }*/
  
  Initialize();

 //printf("Waiting\n");
  /* receive + send */
  while (1) 
  {
      //-------receive phasor_message
    //length = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr *) &lv_addr, &addrlen);
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
    printf("sent %zu bytes \n", signed_msg_length);
  }
  //free(sig_buf);
  close(sock);
 
    
  return(0) ;
}
