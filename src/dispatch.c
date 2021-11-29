#include "dispatch.h"
#include "sniff.h"
#include <pcap.h>

#include "analysis.h"

void dispatch(u_char *args, struct pcap_pkthdr *header,
              const unsigned char *packet) {

  int verbose = (int)*args;
  // TODO: Your part 2 code here
  // This method should handle dispatching of work to threads. At present
  // it is a simple passthrough as this skeleton is single-threaded.
  if(verbose){
    dump(packet, header->len);
  }
  
  analyse(header, packet, verbose);
}
