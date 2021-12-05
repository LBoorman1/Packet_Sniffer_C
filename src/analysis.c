#include "analysis.h"
#include "sniff.h"
#include <netinet/in.h>
#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>

//global variables needed including the array of unique ip addresses
extern unsigned long *ip_array;
extern unsigned int ip_array_size;
extern unsigned int ip_array_last;
extern unsigned int syncount;
extern unsigned int arpcount;
extern unsigned int blacklistcount;

//update global vars lock initialise
pthread_mutex_t countLock = PTHREAD_MUTEX_INITIALIZER;
//updating array lock
pthread_mutex_t arrayLock = PTHREAD_MUTEX_INITIALIZER;

int array_contains(unsigned long *ip_array, unsigned int ip_array_size, unsigned long address){
  for(int i = 0; i <= ip_array_size; i++) {
    if(ip_array[i] == address) return 1;
  }
  return 0;
}

//function to handle incrementing global variables
void update_global_vars(int syntrue, int arptrue, int blacklisttrue){
  if(syntrue){
    syncount++;
  }
  if(arptrue){
    arpcount++;
  }
  if(blacklisttrue){
    blacklistcount++;
  }
}


void analyse(const unsigned char *packet, int verbose) {
  //struct definitions
  struct tcphdr *tcp_head;
  struct ip *ip_head;
  const unsigned char *payload_total;

  //local flags for checks
  int syntrue = 0;
  int arptrue = 0;
  int blacklisttrue = 0;

  //{{SECTION: Parsing the packets}}
  struct ether_header *eth_header = (struct ether_header *) packet;
  
  //payload method to get out ip header
  const unsigned char *payload_ip = packet + ETH_HLEN;

  unsigned short ethernet_type = ntohs(eth_header->ether_type); //convert the header type so can compare
  
  if(ethernet_type == ETH_P_IP) {

    ip_head = (struct ip *) payload_ip; //take out the ip header from the payload
    
    //payload method to get out tcp header
    const unsigned char *payload_tcp = packet + ETH_HLEN + ip_head->ip_hl*4; //ip_hl is in 4 byte words so *4 to get length in bytes
    
    //no need to use ntohs, already appropriately typed
    if(ip_head->ip_p == IPPROTO_TCP) {
      tcp_head = (struct tcphdr *) payload_tcp;
      payload_total = packet + ETH_HLEN + ip_head->ip_hl*4 + tcp_head->doff*4; //
    }
    
  //{{END SECTION: Parsing the packets}}


  //{{SECTION: Checking for SYN attacks}}
  if(tcp_head != NULL){ //check if the tcp header is 
    if(tcp_head->syn && !tcp_head->urg && !tcp_head->ack && !tcp_head->psh && !tcp_head->rst && !tcp_head->fin){ //check if syn bit is active and all other flags are inactive
      //printf("Testing");
      syntrue++; 
      
      unsigned long src_addr = (ip_head -> ip_src).s_addr;

      //unique ip address to add
      pthread_mutex_lock(&arrayLock);
      if(array_contains(ip_array, ip_array_size, src_addr) == 0){
        
        if(ip_array_last == ip_array_size){
          ip_array_size*=2;
          ip_array = (unsigned long *)realloc(ip_array, ip_array_size*sizeof(unsigned long));
        }
        ip_array[ip_array_last] = src_addr;
        ip_array_last+=1;
      }
      pthread_mutex_unlock(&arrayLock);

    }    
  }
  }
  //{{END SECTION: Checking for SYN attacks}}



  //{{SECTION: ARP poisoning}}
  if(ethernet_type == ETH_P_ARP){
    //printf("ARP packet found");
    arptrue++;
    //printf("%d", arpcount);
    
  }
  //{{END SECTION: Checking for ARP poisoning}}

  //{{SECTION: Checking for blacklisted URL}}
  if(tcp_head != NULL){
    if(ntohs(tcp_head->dest) == 80 || ntohs(tcp_head->dest) == 8080){
      const char *hosttest = strstr((const char *)payload_total, "Host:");
      if(hosttest != NULL){
        if(strstr(hosttest, "www.bbc.com") != NULL || strstr(hosttest, "www.google.co.uk") != NULL ){
            
            struct in_addr source_addr = (ip_head -> ip_src);
            struct in_addr dest_addr = (ip_head -> ip_dst);

            //print the source and destination ip address of the blacklisted url violation           
            printf("\n==============================\n");
            printf("Blacklisted URL violation detected\n");
            printf("Source IP address: %s\n", inet_ntoa(source_addr));
            printf("Destination IP address: %s\n", inet_ntoa(dest_addr));
            printf("==============================\n");

            blacklisttrue++;
        }
      }
    }
  }  
  //{{END SECTION: Checking for blacklisted URL}}


  //{{SECTION: Adding to global variables safely from thread}}
  pthread_mutex_lock(&countLock);
  update_global_vars(syntrue, arptrue, blacklisttrue);
  pthread_mutex_unlock(&countLock);

}

