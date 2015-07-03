/*PMU code not normal
non-blocking
radom output of recvfrom and sendto,
try by stoping and restarting with lv and without pdc
*/
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


/* Define IPV6_ADD_MEMBERSHIP for FreeBSD and Mac OS X */
#ifndef IPV6_ADD_MEMBERSHIP
#define IPV6_ADD_MEMBERSHIP IPV6_JOIN_GROUP
#endif

//------------------------------------
#define MULTICAST_GROUP4 "239.0.0.2"
#define MULTICAST_GROUP6 "ffee::5"

#define RCVR_PORT "6000"
#define MY_PORT "5000"
#define PORT_MODIFIER 10000

#define MAX_BUF_LENGTH 1500

#define IPv4 4
#define IPv6 6

//------------------------------------

struct addrinfo *multicastAddr;  
int multicastTTL=5;

unsigned char phasor_message[MAX_BUF_LENGTH];
size_t phasor_msg_length;

//------------------------------------
int createSocket(int flag)
{
  int sockfd;
 
  //create  socket
  if(flag==4)
  {
    struct sockaddr_in PMUAddr4;
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd <= 0)
    {
      perror("socket");
      return -1;
    }

    bzero(&PMUAddr4,sizeof(PMUAddr4));
    PMUAddr4.sin_family = AF_INET;
    PMUAddr4.sin_addr.s_addr = htonl(INADDR_ANY);
    PMUAddr4.sin_port = htons(atoi(MY_PORT)); //htons(atoi(localPort));
     
    if(bind(sockfd,(struct sockaddr *)&PMUAddr4, sizeof(PMUAddr4)) != 0)
    {
        perror("ERROR: bind() failed.\n");
        return -1;
    }
    //printf("PORT = %d \n", PMUAddr4.sin_port);
  }
  
  else if (flag==6)
  {
    struct sockaddr_in6 PMUAddr6;
    // Tell the system what kind(s) of address info we want
    struct addrinfo addrCriteria;                   // Criteria for address match

    memset(&addrCriteria, 0, sizeof(addrCriteria)); // Zero out structure
    addrCriteria.ai_family = AF_INET6;;             // v4 or v6 is OK
    addrCriteria.ai_socktype = SOCK_DGRAM;          // Only datagram sockets
    addrCriteria.ai_protocol = IPPROTO_UDP;         // Only UDP please
    addrCriteria.ai_flags |= AI_NUMERICHOST;        // Don't try to resolve address

    //struct addrinfo *multicastAddr;   // Holder for returned address
    int rtnVal= getaddrinfo(MULTICAST_GROUP6, RCVR_PORT, &addrCriteria, &multicastAddr);
    if (rtnVal != 0)
    {
      perror("getaddrinfo() failed");
      return -1;
    }
    // Create socket for sending datagrams
    sockfd = socket(multicastAddr->ai_family, multicastAddr->ai_socktype, multicastAddr->ai_protocol);
    if (sockfd < 0)
    {
      perror("socket() failed");
      return -1;
    }

    // Set TTL of multicast packet. Unfortunately this requires
    // address-family-specific code
    if (multicastAddr->ai_family == AF_INET6) 
    { // v6-specific
      // The v6 multicast TTL socket option requires that the value be
      // passed in as an integer
      if (setsockopt(sockfd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &multicastTTL, sizeof(multicastTTL)) < 0)
      {
        perror("setsockopt(IPV6_MULTICAST_HOPS) failed");
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
    /*else if (multicastAddr->ai_family == AF_INET) 
    { // v4 specific
      // The v4 multicast TTL socket option requires that the value be
      // passed in an unsigned char
      u_char mcTTL = (u_char) multicastTTL;
      if (setsockopt(sock, IPPROTO_IP, IP_MULTICAST_TTL, &mcTTL,sizeof(mcTTL)) < 0)
        DieWithSystemMessage("setsockopt(IP_MULTICAST_TTL) failed");

    } 
    */

    bzero(&PMUAddr6,sizeof(PMUAddr6));

    //PMUAddr6.sin6_len = sizeof(PMUAddr6);
    PMUAddr6.sin6_family = AF_INET6;
    PMUAddr6.sin6_flowinfo = 0;
    PMUAddr6.sin6_port = htons(atoi(MY_PORT)+ PORT_MODIFIER);
    PMUAddr6.sin6_addr = in6addr_any; //0;//IN6ADDR_ANY_INIT;

    printf("src port:%d \n",ntohs(PMUAddr6.sin6_port));
    
    if (bind(sockfd, (struct sockaddr *) &PMUAddr6, sizeof(PMUAddr6)) == -1)
    {
      perror("ERROR: ipv6 bind() failed.\n");
      return -1;
    }
  }
  else 
  {
    perror("Unknown address family");
    return -1;
  }   

  return sockfd;
}


//------------------------------------
int main( int argc , char * argv[])
{

  struct sockaddr_in rcvr_addr, lv_addr;
  int addrlen; 
  int sock4, sock6;
  //char* buffer;
  //ssize_t length;
  
  sock6 = createSocket(6);

  printf("sock6: %d\n", sock6);
  
  sock4 = createSocket(4);
  printf("sock4:  %d\n", sock4);

  
  if(sock4 < 0 || sock6 < 0) 
  {
    perror("socket");
    exit(1);
  }
  
  /*
  bzero((char *)&rcvr_addr, sizeof(rcvr_addr));
  rcvr_addr.sin_family = AF_INET;
  rcvr_addr.sin_addr.s_addr = inet_addr(MULTICAST_GROUP); 
  rcvr_addr.sin_port = htons(RCVR_PORT);
  addrlen = sizeof(rcvr_addr);
  */

  /* receive + send */
  while (1) 
  {
      //-------receive phasor_message
    phasor_msg_length = recvfrom(sock4, phasor_message, MAX_BUF_LENGTH, 0, (struct sockaddr *) &lv_addr, &addrlen);
    printf("Received %zu bytes\n", phasor_msg_length);

    //forward received data to multicast group 
    int sent_cnt = sendto(sock6, phasor_message, phasor_msg_length, 0, multicastAddr->ai_addr, multicastAddr->ai_addrlen);
 
    if (sent_cnt != phasor_msg_length) 
    {
      perror("sendto");
      exit(1);
    }
    printf("sent %d bytes \n", sent_cnt);
    
  }

  // Free address structure(s) allocated by getaddrinfo()
  freeaddrinfo(multicastAddr);
  
  close(sock4);
  close(sock6);

  return(0) ;
}
