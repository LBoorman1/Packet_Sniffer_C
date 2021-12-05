#include "sniff.h"
#include "dispatch.h"
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <signal.h>
#include <netinet/if_ether.h>


//global variables to initialise
unsigned long *ip_array;
unsigned int ip_array_size = 20;
unsigned int ip_array_last = 0; //to find the last non-empty array index
unsigned int syncount = 0; //global count of synpackets
unsigned int arpcount = 0; //global count of ARP responses
unsigned int blacklistcount = 0; //global count of Blacklisted URL violations

//to catch ctrl-c
void  INThandler(int sig)
{
  int numberToPrint; //helps to adjust logic for ip_array_last
  if(ip_array_last == 0){
    numberToPrint = 0;
  } else {
    numberToPrint = ip_array_last+1;
  }
  printf("\nIntrusion Detection Report:\n");
  printf("%d SYN packets detected from %d unique IP addresses\n", syncount, numberToPrint);
  printf("%d ARP responses (cache poisoning)\n", arpcount);
  printf("%d URL Blacklist Violations\n", blacklistcount);
  free(ip_array);
  exit(0);
}


// Application main sniffing loop
void sniff(char *interface, int verbose) {

  ip_array = (unsigned long *)malloc(sizeof(unsigned long)*ip_array_size);

  char errbuf[PCAP_ERRBUF_SIZE];

  pcap_t *pcap_handle = pcap_open_live(interface, 4096, 1, 1000, errbuf);
  if (pcap_handle == NULL) {
    fprintf(stderr, "Unable to open interface %s\n", errbuf);
    exit(EXIT_FAILURE);
  } else {
    printf("SUCCESS! Opened %s for capture\n", interface);
  }
  
  signal(SIGINT, INThandler); //calls the ctrl-c handler function
  
  pcap_loop(pcap_handle, -1, (pcap_handler) dispatch, (u_char *) &verbose);
   
}

// Utility/Debugging method for dumping raw packet data
void dump(const unsigned char *data, int length) {
  unsigned int i;
  static unsigned long pcount = 0;
  // Decode Packet Header
  struct ether_header *eth_header = (struct ether_header *) data;
  printf("\n\n === PACKET %ld HEADER ===", pcount);
  printf("\nSource MAC: ");
  for (i = 0; i < 6; ++i) {
    printf("%02x", eth_header->ether_shost[i]);
    if (i < 5) {
      printf(":");
    }
  }
  printf("\nDestination MAC: ");
  for (i = 0; i < 6; ++i) {
    printf("%02x", eth_header->ether_dhost[i]);
    if (i < 5) {
      printf(":");
    }
  }
  printf("\nType: %hu\n", eth_header->ether_type);
  printf(" === PACKET %ld DATA == \n", pcount);
  // Decode Packet Data (Skipping over the header)
  int data_bytes = length - ETH_HLEN;
  const unsigned char *payload = data + ETH_HLEN;
  const static int output_sz = 20; // Output this many bytes at a time
  while (data_bytes > 0) {
    int output_bytes = data_bytes < output_sz ? data_bytes : output_sz;
    // Print data in raw hexadecimal form
    for (i = 0; i < output_sz; ++i) {
      if (i < output_bytes) {
        printf("%02x ", payload[i]);
      } else {
        printf ("   "); // Maintain padding for partial lines
      }
    }
    printf ("| ");
    // Print data in ascii form
    for (i = 0; i < output_bytes; ++i) {
      char byte = payload[i];
      if (byte > 31 && byte < 127) {
        // Byte is in printable ascii range
        printf("%c", byte);
      } else {
        printf(".");
      }
    }
    printf("\n");
    payload += output_bytes;
    data_bytes -= output_bytes;
  }
  pcount++;
}
