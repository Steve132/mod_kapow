// Copyright (c) Ed Kaiser 2007-2008
// Portland State University


#include "defines.h"


// Ths SHA1 initial vector.
const u32 I0 = 0x67452301;
const u32 I1 = 0xEFCDAB89;
const u32 I2 = 0x98BADCFE;
const u32 I3 = 0x10325476;
const u32 I4 = 0xC3D2E1F0;

// The SHA1 constants.
const u32 K1 = 0x5A827999L;                              // Rounds  0-19: sqrt(2)  * 2^30
const u32 K2 = 0x6ED9EBA1L;                              // Rounds 20-39: sqrt(3)  * 2^30
const u32 K3 = 0x8F1BBCDCL;                              // Rounds 40-59: sqrt(5)  * 2^30
const u32 K4 = 0xCA62C1D6L;                              // Rounds 60-79: sqrt(10) * 2^30

// The SHA1 Feistel functions.
#define f1(x, y, z) (((x) & (y)) | ((~(x)) & (z)))       // Rounds  0-19: x ? y : z
#define f2(x, y, z) ((x) ^ (y) ^ (z))                    // Rounds 20-39: XOR
#define f3(x, y, z) (((x) & (y)) + ((z) & ((x) ^ (y))))  // Rounds 40-59: majority
#define f4(x, y, z) ((x) ^ (y) ^ (z))                    // Rounds 60-79: XOR

// Rotate function.
#define ROTL(x, n) (((x) << n) | ((x) >> (32 - n)))      // Rotate x LEFT n bits.

void kaPoW_SHA1(u32 input[16], u32 output[5]) {
   u32 t[80], temp, i;
   for (i =  0; i < 16; i++) t[i] = input[i];
   for (i = 16; i < 80; i++) t[i] = ROTL(t[i-16] ^ t[i-14] ^ t[i-8] ^ t[i-3], 1);

   output[0] = I0;
   output[1] = I1;
   output[2] = I2;
   output[3] = I3;
   output[4] = I4;

   // Mangle.
   for (i = 0; i < 80; i++) {
      if (i < 40) {
         if (i < 20) temp = f1(output[1], output[2], output[3]) + K1;
         else        temp = f2(output[1], output[2], output[3]) + K2;
      } else {
         if (i < 60) temp = f3(output[1], output[2], output[3]) + K3;
         else        temp = f4(output[1], output[2], output[3]) + K4;
      }
      temp += ROTL(output[0], 5) + output[4] + t[i];
      output[4] = output[3];
      output[3] = output[2];
      output[2] = ROTL(output[1], 30);
      output[1] = output[0];
      output[0] = temp;
   }
}
