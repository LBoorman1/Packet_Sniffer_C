#include "dispatch.h"
#include "sniff.h"
#include <pcap.h>
#include <pthread.h>
#include "analysis.h"
#include "queue.h"

struct queue *work_queue; //packet queue
pthread_t threads[20]; //thread id array
pthread_cond_t queueCond = PTHREAD_COND_INITIALIZER; //condition variable for the threads
pthread_mutex_t queueLock = PTHREAD_MUTEX_INITIALIZER; //mutex lock to read and write to the queue

void destroyQueue(void){
  destroy_queue(work_queue);
}

//function to deal with the packets in the queue
void * threadCode(void *arg){
  int verbose = 0;
  unsigned char * packet;
  while(1){
    pthread_mutex_lock(&queueLock);
		while(isempty(work_queue)){  
		  pthread_cond_wait(&queueCond,&queueLock);
		}
		packet=work_queue->head->item;   //take the packet from the queue
		dequeue(work_queue); //get rid of the first packet so the next one to analyse is the head
		pthread_mutex_unlock(&queueLock);

    if(packet!=NULL){
    analyse(packet, verbose);

    }
  }
  return NULL;
}

//Function to be called in sniff to initiate threads and the packet queue
//function needs to be defined in dispatch as threadCode function is defined here
void threadInit(void){
  work_queue = create_queue(); //queue for packets
  for(int i = 0; i < 20; i++){
    pthread_create(&threads[i], NULL, threadCode, NULL); 
  }
}

void dispatch(u_char *args, struct pcap_pkthdr *header,
              const unsigned char *packet) {

  int verbose = (int)*args;
  
  if(verbose){
    dump(packet, header->len);
  }
  
  //add packet to queue so that threadCode() can analyse it
  pthread_mutex_lock(&queueLock);
	enqueue(work_queue,packet);
	pthread_cond_broadcast(&queueCond);
	pthread_mutex_unlock(&queueLock);
  

}


