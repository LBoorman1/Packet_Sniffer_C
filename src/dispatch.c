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



void * threadCode(void *arg){
  //printf("thread code reached");
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

    printf("Null check reached");
    if(packet!=NULL){
    printf("\nanalyse call reached\n");
    analyse(packet, verbose);
    
  }
  }
  

  return NULL;
}




//this function is called for every packet that is captured by pcap_loop in sniff.c
//call the function in sniff.c
//create the queue and start the threads in here
void threadInit(void){
  work_queue = create_queue();
  //create threads here using for loop. create maybe 20x threads
  for(int i = 0; i < 20; i++){
    pthread_create(&threads[i], NULL, threadCode, NULL); //needs to be in this file as function definition is here
  }
}

void dispatch(u_char *args, struct pcap_pkthdr *header,
              const unsigned char *packet) {

  int verbose = (int)*args;
  // TODO: Your part 2 code here
  // This method should handle dispatching of work to threads. At present
  // it is a simple passthrough as this skeleton is single-threaded.
  if(verbose){
    dump(packet, header->len);
  }
  
  //add packet to queue 
  pthread_mutex_lock(&queueLock);
	enqueue(work_queue,packet);
	pthread_cond_broadcast(&queueCond);
	pthread_mutex_unlock(&queueLock);
  //and then it will be taken by the thread and passed to thread code function


  




  //analyse(header, packet, verbose);
}


