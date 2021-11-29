#include "stdio.h"
#include "stdlib.h"

//attempting dynamically growing array
    typedef struct
    {
      /* data */
      int *array;
      size_t size;
      size_t curr;
    } Array;

    void initarray(Array *a, int initsize) {
      a->array = malloc(initsize * sizeof(int));
      a->size = initsize;
      a->curr = 0;
    }

    void addarray(Array *a, int element) {
      if(a->curr == a->size){
        a->size = a->size*2;
        a->array = realloc(a->array, a->size * sizeof(int));
      }
      a->array[a->curr] = element;
      a->curr++;
    }