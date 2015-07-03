#include <time.h>  
#include <string.h>
#include <strings.h>
#include <stdlib.h>
//#include <openssl/pem.h>
 #include <openssl/hmac.h>
#include <openssl/sha.h>  //for sha1
#include <openssl/evp.h>
#include <openssl/engine.h>

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
#define KEY_LENGTH 32 //256/8
//------------------------------------

unsigned char HMAC_buf[KEY_LENGTH];
unsigned char HMACed_msg[MAX_BUF_LENGTH];
unsigned char phasor_message[MAX_BUF_LENGTH];
unsigned char seret_key[KEY_LENGTH];
size_t HMACed_msg_length;

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


int Initialize()
{

  unsigned char seed[] = "my secret key";

  SHA256(seed, strlen(seed), seret_key);

  return 1;
}

//------------------------------------
/*
void generate_session_key()
{

  if (!seed_prng (8))
  {
    printf ("Fatal Error! Unable to seed the PRNG!\n");
    abort ();
  }

  select_random_key (key, key_length_bytes); 
  select_random_iv (iv, EVP_MAX_IV_LENGTH);

}
*/

//------------------------------------

void getHMACedMessage(size_t msglength)
{

  //unsigned char msg_hash[SHA_DIGEST_LENGTH];
  //unsigned char* phasor_hmac;
  int hmac_len;


  HMAC_CTX ctx;
  HMAC_CTX_init(&ctx);
 
  // Using sha1 hash engine here.
  // You may use other hash engines. e.g EVP_md5(), EVP_sha224, EVP_sha512, etc
  HMAC_Init_ex(&ctx, seret_key, KEY_LENGTH, EVP_sha256(), NULL);
  HMAC_Update(&ctx, (unsigned char*)phasor_message, msglength);
  HMAC_Final(&ctx, HMAC_buf, &hmac_len);
  HMAC_CTX_cleanup(&ctx);

  //printf("HMAC len: %d\n",hmac_len);


  memcpy(HMACed_msg, phasor_message, msglength);
  memcpy(HMACed_msg + msglength, HMAC_buf, hmac_len);
    
  HMACed_msg_length = msglength + hmac_len;


  //SHA1(phasor_message, msglength, msg_hash); // msg_hash now contains the 20-byte SHA-1 hash
  
  //if(ECDSA_sign(0, msg_hash, SHA_DIGEST_LENGTH, sig_buf, &siglen, ecprivkey))
  //{

    //printf("Sig len: %d \t priv key len: %d \t puk key len: %d \n", siglen, ECDSA_size(ecprivkey), ECDSA_size(ecpubkey));
    
    //memcpy(signed_msg, &siglen, sizeof(siglen));
    //memcpy(signed_msg + sizeof(siglen), phasor_message, msglength);
    //memcpy(signed_msg + sizeof(siglen) + msglength, sig_buf, siglen);
    
    //signed_msg_length = sizeof(siglen) + msglength + siglen;

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

  //send symmetric key 
  int cnt = sendto(sock, seret_key, KEY_LENGTH, 0, (struct sockaddr *) &rcvr_addr, addrlen);

  printf("sent %d bytes key \n", cnt);
	/* receive + send */
	while (1) 
	{
    	//-------receive phasor_message
		//length = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr *) &lv_addr, &addrlen);
    length = recvfrom(sock, phasor_message, MAX_BUF_LENGTH, 0, (struct sockaddr *) &lv_addr, &addrlen);
    //printf("Received %zu bytes\n", length);
    getHMACedMessage(length);

    //-- check conditions to update key if need b
   	//send returned value from securitybox to multicast address.
    
    int sent_cnt = sendto(sock, HMACed_msg, HMACed_msg_length, 0, (struct sockaddr *) &rcvr_addr, addrlen);
    if (sent_cnt != HMACed_msg_length) 
    {
      perror("sendto");
      exit(1);
    }
    //printf("sent %zu bytes \n", HMACed_msg_length);
  }
  //free(sig_buf);
  close(sock);
 
    
	return(0) ;
}
