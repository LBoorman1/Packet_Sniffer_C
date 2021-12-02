#include "dispatch.h"
#include "sniff.h"
#include <pcap.h>
#include "queue.h"
#include "analysis.h"
#include <pthread.h>


extern int killProgram;

//lock initialise
pthread_mutex_t queueLock = PTHREAD_MUTEX_INITIALIZER;
//thread condition initialise
pthread_cond_t queueCond = PTHREAD_COND_INITIALIZER;

//get queue from sniff.c
extern struct queue * workQueue;

void * threadCode(void*arg){
  unsigned char * packet;
  int verbose = 0;
  //while loop to be exited later with variable
  while(1){
    pthread_mutex_lock(&queueLock);
    while(isempty(workQueue)){
      if (killProgram){
        pthread_mutex_unlock(&queueLock);
        return 0;
      }
      pthread_cond_wait(&queueCond, &queueLock);
    }
    packet=(unsigned char *)workQueue->head->item;
		dequeue(workQueue);
		pthread_mutex_unlock(&queueLock);

    if(packet!=NULL){
      analyse(packet, verbose);
    }
  }
}


void dispatch(u_char *args, struct pcap_pkthdr *header,
              const unsigned char *packet) {

  int verbose = (int)*args;
  if(verbose){
    dump(packet, header->len);
  }

  //add packet to the queue to be analysed
  pthread_mutex_lock(&queueLock);
	enqueue(workQueue,packet);
	pthread_cond_broadcast(&queueCond);
	pthread_mutex_unlock(&queueLock);

}

