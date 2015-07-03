#include <time.h>  
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <stdio.h>

#include <sys/un.h>
#include <netinet/tcp.h>
#include <netdb.h>

//------------------------------------
#define MULTICAST_GROUP4 "239.0.0.2"
#define MULTICAST_GROUP6 "ffee::5"

#define MY_PORT "6000"
#define MAX_BUF_LENGTH 1500
#define PORT_MODIFIER 10000
#define IPv4 4
#define IPv6 6


//------------------------------------
//unsigned char rcvd_msg[MAX_BUF_LENGTH];
unsigned char phasor_message[MAX_BUF_LENGTH];
size_t phasor_msg_length;

int createSocket(int flag)
{
  /* //setup socket 
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

  	// 
  	if (bind(sockfd, (struct sockaddr *) &myAddr, sizeof(myAddr)) < 0) 
  	{        
    	perror("bind");
    	exit(1);
  	}    
  	mreq.imr_multiaddr.s_addr = inet_addr(MULTICAST_GROUP4);         
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
  */
  //----------

  int sockfd;
  struct addrinfo addrCriteria;                   // Criteria for address match

  memset(&addrCriteria, 0, sizeof(addrCriteria)); // Zero out structure
  addrCriteria.ai_family = AF_UNSPEC;             // v4 or v6 is OK
  addrCriteria.ai_socktype = SOCK_DGRAM;          // Only datagram sockets
  addrCriteria.ai_protocol = IPPROTO_UDP;         // Only UDP protocol
  addrCriteria.ai_flags |= AI_NUMERICHOST;        // Don't try to resolve address

  // Get address information
  struct addrinfo *multicastAddr;                 // List of server addresses
  int rtnVal;

  if(flag==4)
    rtnVal = getaddrinfo(MULTICAST_GROUP4, MY_PORT, &addrCriteria, &multicastAddr);
  else if(flag==6)
    rtnVal = getaddrinfo(MULTICAST_GROUP6, MY_PORT, &addrCriteria, &multicastAddr);
  else
    rtnVal=-1;


  if (rtnVal != 0)
  {
    perror("getaddrinfo() failed");
    return -1;
  }

  // Create socket to receive on
  sockfd = socket(multicastAddr->ai_family, multicastAddr->ai_socktype, multicastAddr->ai_protocol);
  if (sockfd < 0)
  {
    perror("socket() failed");
    return -1;
  }

  if (bind(sockfd, multicastAddr->ai_addr, multicastAddr->ai_addrlen) < 0)
  {
    perror("bind() failed");
    return -1;
  }

  // Unfortunately we need some address-family-specific pieces
  if (multicastAddr->ai_family == AF_INET6) 
  {
    // Now join the multicast "group" (address)
    struct ipv6_mreq joinRequest;
    memcpy(&joinRequest.ipv6mr_multiaddr, &((struct sockaddr_in6 *)multicastAddr->ai_addr)->sin6_addr,  sizeof(struct in6_addr));
    joinRequest.ipv6mr_interface = 0;   // Let system choose the i/f
   
    puts("Joining IPv6 multicast group...");
    if (setsockopt(sockfd, IPPROTO_IPV6, IPV6_JOIN_GROUP, &joinRequest, sizeof(joinRequest)) < 0)
    {
      perror("setsockopt(IPV6_JOIN_GROUP) failed");
      return -1;
    }

    /* lose the pesky "Address already in use" error message */
    int yes=1;
    if (setsockopt(sockfd,SOL_SOCKET,SO_REUSEADDR,(char*)&yes,sizeof(int)) == -1) 
    {
      perror("setsockopt:SO_REUSEADDR");
      return -1;
    }

  } 
  else if (multicastAddr->ai_family == AF_INET) 
  {
    // Now join the multicast "group"
    struct ip_mreq joinRequest;
    joinRequest.imr_multiaddr =((struct sockaddr_in *) multicastAddr->ai_addr)->sin_addr;
    joinRequest.imr_interface.s_addr = INADDR_ANY;  // Let the system choose the i/f
  
    printf("Joining IPv4 multicast group...\n");
    if (setsockopt(sockfd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &joinRequest, sizeof(joinRequest)) < 0)
    {
      perror("setsockopt(IPV4_ADD_MEMBERSHIP) failed");
      return -1;
    }
  } 
  else 
  {
    perror("Unknown address family");
    return -1;
  }

  // Free address structure(s) allocated by getaddrinfo()
  freeaddrinfo(multicastAddr);
  
  return sockfd;
}

//------------------------------------
int main( int argc , char * argv[])
{
	struct sockaddr_in lv_addr;
   struct sockaddr_in6 srcaddr6;
	int addrlen;
	int sock4,sock6;

  /* setup socket for ipv4*/
  sock4 = socket(AF_INET, SOCK_DGRAM, 0);
  if (sock4 < 0) 
  {
    perror("socket");
    return -1;
  }

  
  bzero(&lv_addr,sizeof(lv_addr));
  lv_addr.sin_family = AF_INET;
  lv_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

  
/*
  lv_addr.sin_port = htons(7000);//ntohs(srcaddr.sin_port)-PORT_MODIFIER); //srcaddr.sin_port; //htons(atoi(localPort));

  char* buffer ="hihi\n";
  int bufflen = strlen(buffer);


  int sent_cnt = sendto(sock4, buffer, bufflen, 0, (struct sockaddr *) &lv_addr, sizeof(lv_addr));

  if (sent_cnt <=0) 
  {
      perror("sendto");
      exit(1);
  }
  printf("sent: %d bytes\n",sent_cnt);
*/
  /* setup socket */
  sock6 = createSocket(6);
 
  if(sock6 < 0)//||sock4 < 0) 
  {
      perror("socket");
      exit(1);
  }


	/* receive + send */
	while (1) 
	{
  
    phasor_msg_length = recvfrom(sock6, phasor_message, MAX_BUF_LENGTH, 0, (struct sockaddr *) &srcaddr6, &addrlen);
    if (phasor_msg_length <= 0)
    {   
      perror("recvfrom() failed");
      exit(1);
    }
    //phasor_message[phasor_msg_length] = '\0';    // Terminate the received string // Note: sender did not send the terminal 0
    //printf("Received: %s\n", phasor_message);


      
    lv_addr.sin_port = htons(ntohs(srcaddr6.sin6_port)-PORT_MODIFIER); //srcaddr.sin_port; //htons(atoi(localPort));

    printf("Received %zu bytes,\t pmu port: %d  msg: %s\n", phasor_msg_length, ntohs(lv_addr.sin_port), phasor_message);


    int sent_cnt = sendto(sock4, phasor_message, phasor_msg_length, 0, (struct sockaddr *) &lv_addr, sizeof(lv_addr));

    if (sent_cnt != phasor_msg_length) 
    {
      perror("sendto");
      exit(1);
    }
    printf("sent %d bytes\n", sent_cnt);
  
    		
  }

  //close(sock4);
  close(sock6);
     
	return(0) ;
}
