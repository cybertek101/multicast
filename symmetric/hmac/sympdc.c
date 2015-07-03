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
#define MY_PORT 6000
#define MAX_BUF_LENGTH 1500
#define KEY_LENGTH 32 //256/8
//------------------------------------

unsigned char HMAC_buf[KEY_LENGTH];
unsigned char rcvd_msg[MAX_BUF_LENGTH];
unsigned char phasor_message[MAX_BUF_LENGTH];
unsigned char seret_key[KEY_LENGTH];
size_t rcvd_msg_length, phasor_msg_length;
//------------------------------------

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

  int hmac_len = KEY_LENGTH;
  unsigned char msg_dgst[KEY_LENGTH];

  HMAC_CTX ctx;

  phasor_msg_length = rcvd_msg_length - hmac_len;
  memcpy(phasor_message, rcvd_msg, phasor_msg_length);
  memcpy(HMAC_buf, rcvd_msg + phasor_msg_length, hmac_len);

  HMAC_CTX_init(&ctx);
  // Using sha1 hash engine here.
  // You may use other hash engines. e.g EVP_md5(), EVP_sha224, EVP_sha512, etc
  HMAC_Init_ex(&ctx, seret_key, KEY_LENGTH, EVP_sha256(), NULL);
  HMAC_Update(&ctx, (unsigned char*)phasor_message, phasor_msg_length);
  HMAC_Final(&ctx, msg_dgst, &hmac_len);
  HMAC_CTX_cleanup(&ctx);
 //printf("HMAC len: %d\n",hmac_len);


	if (strcmp(HMAC_buf, msg_dgst))
  {
		return 1;
	}
  else
  {
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
	
  int rcvd_key_length = recvfrom(sock, seret_key, KEY_LENGTH, 0, (struct sockaddr *) &srcaddr, &addrlen);
  if(rcvd_key_length ==KEY_LENGTH)
  {
    printf("%d bytes key received\n",rcvd_key_length);
  }

  sleep(10);
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

  }
  
  //free(sig_buf);
  close(sock);
 
    
	return(0) ;
}
