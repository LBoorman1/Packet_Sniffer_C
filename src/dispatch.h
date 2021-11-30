#ifndef CS241_DISPATCH_H
#define CS241_DISPATCH_H

#include <pcap.h>

void dispatch(u_char *args, struct pcap_pkthdr *header, const unsigned char *packet);
void threadInit(void);

#endif
