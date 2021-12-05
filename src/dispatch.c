#include "dispatch.h"
#include "sniff.h"
#include <pcap.h>

#include "analysis.h"

void dispatch(u_char *args, struct pcap_pkthdr *header, const unsigned char *packet) {

  int verbose = (int)*args;
  if(verbose){
    dump(packet, header->len);
  }
  
  analyse(header, packet, verbose);
}
