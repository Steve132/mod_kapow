
#include <stdlib.h>
#include <string.h>
#include <math.h>

#include "defines.h"

#define COUNTER_TYPE	 u32             // counter type; size is 32 bits
#define COUNTER_MAX   0xFFFFFFFF      // maximum value for the counter
#define COUNTERS      32768           // # of bins   - length (M) = 2^16
#define HASHES        3               // # of hashes - width  (K) = 3
#define FILTERS       2               // The time windows.
#define DECAY_CONST   11


typedef struct {
   // The indices of the last IP to be accessed.
   u32   index[HASHES];
   // The filters for the various time windows.
   COUNTER_TYPE filters[FILTERS][COUNTERS];
   u32   sum[FILTERS];
   u32   prev;
   u32   current;
   u32   next;
} BloomFilter;


void Initialize(BloomFilter* BF) {
   BF->prev    = 0;
   BF->current = (BF->prev + 1) % FILTERS;
   BF->next    = (BF->current + 1) % FILTERS;   
   memset(BF->filters, 0, FILTERS * COUNTERS * sizeof(COUNTER_TYPE));   
   memset(BF->sum,     0, FILTERS * sizeof(u32));
}


// XTEA.16 derived from code on Wikipedia.
const u32 DELTA    = 0x9E3779B9;
void XTEA(u32 input[2], u32 output[2], u32 key[4]) {
   register u32 y=input[0], z=input[1], sum=0, n=16;
   while(n-- > 0) {
      y += ((z << 4) ^ (z >> 5)) + (z ^ sum) + key[sum & 3];
      sum += DELTA;
      z += ((y << 4) ^ (y >> 5)) + (y ^ sum) + key[sum >> 11 & 3];
   }
   output[0]=y; output[1]=z;
}


void Index(BloomFilter* BF, u32 identity) {
   u32 input[2];
   u32 output[2];
   u32 key[4];
   u32 i = 0;
   input[0] = identity;
   input[1] = 0;
   key[0] = 0;
   key[1] = 0;
   key[2] = 0;
   key[3] = 0;
   while(i < HASHES) {
      XTEA(input, output, key);
      BF->index[i++] = output[0];
      if(i >= HASHES) break;
      BF->index[i++] = output[1];
      input[0] = output[1];
   }
}


u32 GetCount(BloomFilter* BF) {
   u32 i, count = BF->filters[BF->prev][(BF->index[0] % COUNTERS)];
   for (i = 1; i < HASHES; i++) {
      count = BF->filters[BF->prev][(BF->index[i] % COUNTERS)] < count ? BF->filters[BF->prev][(BF->index[i] % COUNTERS)] : count;
   }
   return count;
}


u32 GetSum(BloomFilter* BF) {
   return BF->sum[BF->prev];
}


void Increment(BloomFilter* BF, u32 delta) {
   u32 i;
   for (i = 0; i < HASHES; i++) {
      if ((COUNTER_MAX - BF->filters[BF->current][(BF->index[i] % COUNTERS)]) > delta) {
         BF->filters[BF->current][(BF->index[i] % COUNTERS)] += delta;
      } else {
         BF->filters[BF->current][(BF->index[i] % COUNTERS)] = COUNTER_MAX;
      }
   }
   BF->sum[BF->current] += delta;
}


void Zero(BloomFilter* BF) {
   memset(BF->filters, 0, FILTERS * COUNTERS * sizeof(COUNTER_TYPE));   
   memset(BF->sum,     0, FILTERS * sizeof(u32));
}


void Decay(BloomFilter* BF, u32 epochs) {
   u32 i, r;
   double t;
   for (i = 0; i < COUNTERS; i++) {
      t = (double)BF->filters[BF->prev][i];
      r = 0;
      if (BF->filters[BF->current][i] > DECAY_CONST) {
         t += pow((double)1.01, (double)(BF->filters[BF->current][i] - DECAY_CONST));
      } else {
         r = (DECAY_CONST * epochs) - BF->filters[BF->current][i];
      }
      if (t > (double)COUNTER_MAX) BF->filters[BF->current][i] = COUNTER_MAX;
      else if (t < r)              BF->filters[BF->current][i] = 0;
      else                         BF->filters[BF->current][i] = t - r;

      BF->filters[BF->next][i]     = 0;
   }
   BF->prev    =  BF->current;
   BF->current =  BF->next;
   BF->next    = (BF->next + 1) % FILTERS;
}
