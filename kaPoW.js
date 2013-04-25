// Copyright (c) Ed Kaiser 2007-2008
// Portland State University


// The SHA1 initial values.
var I0 = 0x67452301;
var I1 = 0xEFCDAB89;
var I2 = 0x98BADCFE;
var I3 = 0x10325476;
var I4 = 0xC3D2E1F0;

// The SHA1 constants.
var K1 = 0x5A827999;                                            // Rounds  0-19: sqrt(2)  * 2^30
var K2 = 0x6ED9EBA1;                                            // Rounds 20-39: sqrt(3)  * 2^30
var K3 = 0x8F1BBCDC;                                            // Rounds 40-59: sqrt(5)  * 2^30
var K4 = 0xCA62C1D6;                                            // Rounds 60-79: sqrt(10) * 2^30

// The SHA1 function.
function SHA1(input) {
   var output = [I0, I1, I2, I3, I4];
   var i;
   // Stretch input.
   var t = new Array(80);
   for (i =  0; i < 16; i++) t[i] = input[i];
   for (i = 16; i < 80; i++) t[i] = (((t[i-16] ^ t[i-14] ^ t[i-8] ^ t[i-3]) << 1) | ((t[i-16] ^ t[i-14] ^ t[i-8] ^ t[i-3]) >>> 31));

   // First 20 rounds.
   output[4] += ((output[0] << 5) | (output[0] >>> 27)) + (output[3] ^ (output[1] & (output[2] ^ output[3]))) + K1 + t[0];   output[1] = ((output[1] << 30) | (output[1] >>> 2));
   output[3] += ((output[4] << 5) | (output[4] >>> 27)) + (output[2] ^ (output[0] & (output[1] ^ output[2]))) + K1 + t[1];   output[0] = ((output[0] << 30) | (output[0] >>> 2));
   output[2] += ((output[3] << 5) | (output[3] >>> 27)) + (output[1] ^ (output[4] & (output[0] ^ output[1]))) + K1 + t[2];   output[4] = ((output[4] << 30) | (output[4] >>> 2));
   output[1] += ((output[2] << 5) | (output[2] >>> 27)) + (output[0] ^ (output[3] & (output[4] ^ output[0]))) + K1 + t[3];   output[3] = ((output[3] << 30) | (output[3] >>> 2));
   output[0] += ((output[1] << 5) | (output[1] >>> 27)) + (output[4] ^ (output[2] & (output[3] ^ output[4]))) + K1 + t[4];   output[2] = ((output[2] << 30) | (output[2] >>> 2));
   output[4] += ((output[0] << 5) | (output[0] >>> 27)) + (output[3] ^ (output[1] & (output[2] ^ output[3]))) + K1 + t[5];   output[1] = ((output[1] << 30) | (output[1] >>> 2));
   output[3] += ((output[4] << 5) | (output[4] >>> 27)) + (output[2] ^ (output[0] & (output[1] ^ output[2]))) + K1 + t[6];   output[0] = ((output[0] << 30) | (output[0] >>> 2));
   output[2] += ((output[3] << 5) | (output[3] >>> 27)) + (output[1] ^ (output[4] & (output[0] ^ output[1]))) + K1 + t[7];   output[4] = ((output[4] << 30) | (output[4] >>> 2));
   output[1] += ((output[2] << 5) | (output[2] >>> 27)) + (output[0] ^ (output[3] & (output[4] ^ output[0]))) + K1 + t[8];   output[3] = ((output[3] << 30) | (output[3] >>> 2));
   output[0] += ((output[1] << 5) | (output[1] >>> 27)) + (output[4] ^ (output[2] & (output[3] ^ output[4]))) + K1 + t[9];   output[2] = ((output[2] << 30) | (output[2] >>> 2));
   output[4] += ((output[0] << 5) | (output[0] >>> 27)) + (output[3] ^ (output[1] & (output[2] ^ output[3]))) + K1 + t[10];  output[1] = ((output[1] << 30) | (output[1] >>> 2));
   output[3] += ((output[4] << 5) | (output[4] >>> 27)) + (output[2] ^ (output[0] & (output[1] ^ output[2]))) + K1 + t[11];  output[0] = ((output[0] << 30) | (output[0] >>> 2));
   output[2] += ((output[3] << 5) | (output[3] >>> 27)) + (output[1] ^ (output[4] & (output[0] ^ output[1]))) + K1 + t[12];  output[4] = ((output[4] << 30) | (output[4] >>> 2));
   output[1] += ((output[2] << 5) | (output[2] >>> 27)) + (output[0] ^ (output[3] & (output[4] ^ output[0]))) + K1 + t[13];  output[3] = ((output[3] << 30) | (output[3] >>> 2));
   output[0] += ((output[1] << 5) | (output[1] >>> 27)) + (output[4] ^ (output[2] & (output[3] ^ output[4]))) + K1 + t[14];  output[2] = ((output[2] << 30) | (output[2] >>> 2));
   output[4] += ((output[0] << 5) | (output[0] >>> 27)) + (output[3] ^ (output[1] & (output[2] ^ output[3]))) + K1 + t[15];  output[1] = ((output[1] << 30) | (output[1] >>> 2));
   output[3] += ((output[4] << 5) | (output[4] >>> 27)) + (output[2] ^ (output[0] & (output[1] ^ output[2]))) + K1 + t[16];  output[0] = ((output[0] << 30) | (output[0] >>> 2));
   output[2] += ((output[3] << 5) | (output[3] >>> 27)) + (output[1] ^ (output[4] & (output[0] ^ output[1]))) + K1 + t[17];  output[4] = ((output[4] << 30) | (output[4] >>> 2));
   output[1] += ((output[2] << 5) | (output[2] >>> 27)) + (output[0] ^ (output[3] & (output[4] ^ output[0]))) + K1 + t[18];  output[3] = ((output[3] << 30) | (output[3] >>> 2));
   output[0] += ((output[1] << 5) | (output[1] >>> 27)) + (output[4] ^ (output[2] & (output[3] ^ output[4]))) + K1 + t[19];  output[2] = ((output[2] << 30) | (output[2] >>> 2));
   // Second 20 rounds.
   output[4] += ((output[0] << 5) | (output[0] >>> 27)) + (output[1] ^ output[2] ^ output[3]) + K2 + t[20];  output[1] = ((output[1] << 30) | (output[1] >>> 2));
   output[3] += ((output[4] << 5) | (output[4] >>> 27)) + (output[0] ^ output[1] ^ output[2]) + K2 + t[21];  output[0] = ((output[0] << 30) | (output[0] >>> 2));
   output[2] += ((output[3] << 5) | (output[3] >>> 27)) + (output[4] ^ output[0] ^ output[1]) + K2 + t[22];  output[4] = ((output[4] << 30) | (output[4] >>> 2));
   output[1] += ((output[2] << 5) | (output[2] >>> 27)) + (output[3] ^ output[4] ^ output[0]) + K2 + t[23];  output[3] = ((output[3] << 30) | (output[3] >>> 2));
   output[0] += ((output[1] << 5) | (output[1] >>> 27)) + (output[2] ^ output[3] ^ output[4]) + K2 + t[24];  output[2] = ((output[2] << 30) | (output[2] >>> 2));
   output[4] += ((output[0] << 5) | (output[0] >>> 27)) + (output[1] ^ output[2] ^ output[3]) + K2 + t[25];  output[1] = ((output[1] << 30) | (output[1] >>> 2));
   output[3] += ((output[4] << 5) | (output[4] >>> 27)) + (output[0] ^ output[1] ^ output[2]) + K2 + t[26];  output[0] = ((output[0] << 30) | (output[0] >>> 2));
   output[2] += ((output[3] << 5) | (output[3] >>> 27)) + (output[4] ^ output[0] ^ output[1]) + K2 + t[27];  output[4] = ((output[4] << 30) | (output[4] >>> 2));
   output[1] += ((output[2] << 5) | (output[2] >>> 27)) + (output[3] ^ output[4] ^ output[0]) + K2 + t[28];  output[3] = ((output[3] << 30) | (output[3] >>> 2));
   output[0] += ((output[1] << 5) | (output[1] >>> 27)) + (output[2] ^ output[3] ^ output[4]) + K2 + t[29];  output[2] = ((output[2] << 30) | (output[2] >>> 2));
   output[4] += ((output[0] << 5) | (output[0] >>> 27)) + (output[1] ^ output[2] ^ output[3]) + K2 + t[30];  output[1] = ((output[1] << 30) | (output[1] >>> 2));
   output[3] += ((output[4] << 5) | (output[4] >>> 27)) + (output[0] ^ output[1] ^ output[2]) + K2 + t[31];  output[0] = ((output[0] << 30) | (output[0] >>> 2));
   output[2] += ((output[3] << 5) | (output[3] >>> 27)) + (output[4] ^ output[0] ^ output[1]) + K2 + t[32];  output[4] = ((output[4] << 30) | (output[4] >>> 2));
   output[1] += ((output[2] << 5) | (output[2] >>> 27)) + (output[3] ^ output[4] ^ output[0]) + K2 + t[33];  output[3] = ((output[3] << 30) | (output[3] >>> 2));
   output[0] += ((output[1] << 5) | (output[1] >>> 27)) + (output[2] ^ output[3] ^ output[4]) + K2 + t[34];  output[2] = ((output[2] << 30) | (output[2] >>> 2));
   output[4] += ((output[0] << 5) | (output[0] >>> 27)) + (output[1] ^ output[2] ^ output[3]) + K2 + t[35];  output[1] = ((output[1] << 30) | (output[1] >>> 2));
   output[3] += ((output[4] << 5) | (output[4] >>> 27)) + (output[0] ^ output[1] ^ output[2]) + K2 + t[36];  output[0] = ((output[0] << 30) | (output[0] >>> 2));
   output[2] += ((output[3] << 5) | (output[3] >>> 27)) + (output[4] ^ output[0] ^ output[1]) + K2 + t[37];  output[4] = ((output[4] << 30) | (output[4] >>> 2));
   output[1] += ((output[2] << 5) | (output[2] >>> 27)) + (output[3] ^ output[4] ^ output[0]) + K2 + t[38];  output[3] = ((output[3] << 30) | (output[3] >>> 2));
   output[0] += ((output[1] << 5) | (output[1] >>> 27)) + (output[2] ^ output[3] ^ output[4]) + K2 + t[39];  output[2] = ((output[2] << 30) | (output[2] >>> 2));
   // Third 20 rounds.
   output[4] += ((output[0] << 5) | (output[0] >>> 27)) + ((output[1] & output[2]) | (output[1] & output[3]) | (output[2] & output[3])) + K3 + t[40];  output[1] = ((output[1] << 30) | (output[1] >>> 2));
   output[3] += ((output[4] << 5) | (output[4] >>> 27)) + ((output[0] & output[1]) | (output[0] & output[2]) | (output[1] & output[2])) + K3 + t[41];  output[0] = ((output[0] << 30) | (output[0] >>> 2));
   output[2] += ((output[3] << 5) | (output[3] >>> 27)) + ((output[4] & output[0]) | (output[4] & output[1]) | (output[0] & output[1])) + K3 + t[42];  output[4] = ((output[4] << 30) | (output[4] >>> 2));
   output[1] += ((output[2] << 5) | (output[2] >>> 27)) + ((output[3] & output[4]) | (output[3] & output[0]) | (output[4] & output[0])) + K3 + t[43];  output[3] = ((output[3] << 30) | (output[3] >>> 2));
   output[0] += ((output[1] << 5) | (output[1] >>> 27)) + ((output[2] & output[3]) | (output[2] & output[4]) | (output[3] & output[4])) + K3 + t[44];  output[2] = ((output[2] << 30) | (output[2] >>> 2));
   output[4] += ((output[0] << 5) | (output[0] >>> 27)) + ((output[1] & output[2]) | (output[1] & output[3]) | (output[2] & output[3])) + K3 + t[45];  output[1] = ((output[1] << 30) | (output[1] >>> 2));
   output[3] += ((output[4] << 5) | (output[4] >>> 27)) + ((output[0] & output[1]) | (output[0] & output[2]) | (output[1] & output[2])) + K3 + t[46];  output[0] = ((output[0] << 30) | (output[0] >>> 2));
   output[2] += ((output[3] << 5) | (output[3] >>> 27)) + ((output[4] & output[0]) | (output[4] & output[1]) | (output[0] & output[1])) + K3 + t[47];  output[4] = ((output[4] << 30) | (output[4] >>> 2));
   output[1] += ((output[2] << 5) | (output[2] >>> 27)) + ((output[3] & output[4]) | (output[3] & output[0]) | (output[4] & output[0])) + K3 + t[48];  output[3] = ((output[3] << 30) | (output[3] >>> 2));
   output[0] += ((output[1] << 5) | (output[1] >>> 27)) + ((output[2] & output[3]) | (output[2] & output[4]) | (output[3] & output[4])) + K3 + t[49];  output[2] = ((output[2] << 30) | (output[2] >>> 2));
   output[4] += ((output[0] << 5) | (output[0] >>> 27)) + ((output[1] & output[2]) | (output[1] & output[3]) | (output[2] & output[3])) + K3 + t[50];  output[1] = ((output[1] << 30) | (output[1] >>> 2));
   output[3] += ((output[4] << 5) | (output[4] >>> 27)) + ((output[0] & output[1]) | (output[0] & output[2]) | (output[1] & output[2])) + K3 + t[51];  output[0] = ((output[0] << 30) | (output[0] >>> 2));
   output[2] += ((output[3] << 5) | (output[3] >>> 27)) + ((output[4] & output[0]) | (output[4] & output[1]) | (output[0] & output[1])) + K3 + t[52];  output[4] = ((output[4] << 30) | (output[4] >>> 2));
   output[1] += ((output[2] << 5) | (output[2] >>> 27)) + ((output[3] & output[4]) | (output[3] & output[0]) | (output[4] & output[0])) + K3 + t[53];  output[3] = ((output[3] << 30) | (output[3] >>> 2));
   output[0] += ((output[1] << 5) | (output[1] >>> 27)) + ((output[2] & output[3]) | (output[2] & output[4]) | (output[3] & output[4])) + K3 + t[54];  output[2] = ((output[2] << 30) | (output[2] >>> 2));
   output[4] += ((output[0] << 5) | (output[0] >>> 27)) + ((output[1] & output[2]) | (output[1] & output[3]) | (output[2] & output[3])) + K3 + t[55];  output[1] = ((output[1] << 30) | (output[1] >>> 2));
   output[3] += ((output[4] << 5) | (output[4] >>> 27)) + ((output[0] & output[1]) | (output[0] & output[2]) | (output[1] & output[2])) + K3 + t[56];  output[0] = ((output[0] << 30) | (output[0] >>> 2));
   output[2] += ((output[3] << 5) | (output[3] >>> 27)) + ((output[4] & output[0]) | (output[4] & output[1]) | (output[0] & output[1])) + K3 + t[57];  output[4] = ((output[4] << 30) | (output[4] >>> 2));
   output[1] += ((output[2] << 5) | (output[2] >>> 27)) + ((output[3] & output[4]) | (output[3] & output[0]) | (output[4] & output[0])) + K3 + t[58];  output[3] = ((output[3] << 30) | (output[3] >>> 2));
   output[0] += ((output[1] << 5) | (output[1] >>> 27)) + ((output[2] & output[3]) | (output[2] & output[4]) | (output[3] & output[4])) + K3 + t[59];  output[2] = ((output[2] << 30) | (output[2] >>> 2));
   // Final 20 rounds.
   output[4] += ((output[0] << 5) | (output[0] >>> 27)) + (output[1] ^ output[2] ^ output[3]) + K4 + t[60];  output[1] = ((output[1] << 30) | (output[1] >>> 2));
   output[3] += ((output[4] << 5) | (output[4] >>> 27)) + (output[0] ^ output[1] ^ output[2]) + K4 + t[61];  output[0] = ((output[0] << 30) | (output[0] >>> 2));
   output[2] += ((output[3] << 5) | (output[3] >>> 27)) + (output[4] ^ output[0] ^ output[1]) + K4 + t[62];  output[4] = ((output[4] << 30) | (output[4] >>> 2));
   output[1] += ((output[2] << 5) | (output[2] >>> 27)) + (output[3] ^ output[4] ^ output[0]) + K4 + t[63];  output[3] = ((output[3] << 30) | (output[3] >>> 2));
   output[0] += ((output[1] << 5) | (output[1] >>> 27)) + (output[2] ^ output[3] ^ output[4]) + K4 + t[64];  output[2] = ((output[2] << 30) | (output[2] >>> 2));
   output[4] += ((output[0] << 5) | (output[0] >>> 27)) + (output[1] ^ output[2] ^ output[3]) + K4 + t[65];  output[1] = ((output[1] << 30) | (output[1] >>> 2));
   output[3] += ((output[4] << 5) | (output[4] >>> 27)) + (output[0] ^ output[1] ^ output[2]) + K4 + t[66];  output[0] = ((output[0] << 30) | (output[0] >>> 2));
   output[2] += ((output[3] << 5) | (output[3] >>> 27)) + (output[4] ^ output[0] ^ output[1]) + K4 + t[67];  output[4] = ((output[4] << 30) | (output[4] >>> 2));
   output[1] += ((output[2] << 5) | (output[2] >>> 27)) + (output[3] ^ output[4] ^ output[0]) + K4 + t[68];  output[3] = ((output[3] << 30) | (output[3] >>> 2));
   output[0] += ((output[1] << 5) | (output[1] >>> 27)) + (output[2] ^ output[3] ^ output[4]) + K4 + t[69];  output[2] = ((output[2] << 30) | (output[2] >>> 2));
   output[4] += ((output[0] << 5) | (output[0] >>> 27)) + (output[1] ^ output[2] ^ output[3]) + K4 + t[70];  output[1] = ((output[1] << 30) | (output[1] >>> 2));
   output[3] += ((output[4] << 5) | (output[4] >>> 27)) + (output[0] ^ output[1] ^ output[2]) + K4 + t[71];  output[0] = ((output[0] << 30) | (output[0] >>> 2));
   output[2] += ((output[3] << 5) | (output[3] >>> 27)) + (output[4] ^ output[0] ^ output[1]) + K4 + t[72];  output[4] = ((output[4] << 30) | (output[4] >>> 2));
   output[1] += ((output[2] << 5) | (output[2] >>> 27)) + (output[3] ^ output[4] ^ output[0]) + K4 + t[73];  output[3] = ((output[3] << 30) | (output[3] >>> 2));
   output[0] += ((output[1] << 5) | (output[1] >>> 27)) + (output[2] ^ output[3] ^ output[4]) + K4 + t[74];  output[2] = ((output[2] << 30) | (output[2] >>> 2));
   output[4] += ((output[0] << 5) | (output[0] >>> 27)) + (output[1] ^ output[2] ^ output[3]) + K4 + t[75];  output[1] = ((output[1] << 30) | (output[1] >>> 2));
   output[3] += ((output[4] << 5) | (output[4] >>> 27)) + (output[0] ^ output[1] ^ output[2]) + K4 + t[76];  output[0] = ((output[0] << 30) | (output[0] >>> 2));
   output[2] += ((output[3] << 5) | (output[3] >>> 27)) + (output[4] ^ output[0] ^ output[1]) + K4 + t[77];  output[4] = ((output[4] << 30) | (output[4] >>> 2));
   output[1] += ((output[2] << 5) | (output[2] >>> 27)) + (output[3] ^ output[4] ^ output[0]) + K4 + t[78];  output[3] = ((output[3] << 30) | (output[3] >>> 2));
   output[0] += ((output[1] << 5) | (output[1] >>> 27)) + (output[2] ^ output[3] ^ output[4]) + K4 + t[79];  output[2] = ((output[2] << 30) | (output[2] >>> 2));

   // Fix the output to be unsigned integers for 32 bit machines, and 64 bit machines if necessary.
   if (output[0] < Number.MIN_VALUE) output[0] += 0xFFFFFFFF + 1;
   if (output[0] < Number.MIN_VALUE) output[0] += 0xFFFFFFFF00000000;
   if (output[1] < Number.MIN_VALUE) output[1] += 0xFFFFFFFF + 1;
   if (output[1] < Number.MIN_VALUE) output[1] += 0xFFFFFFFF00000000;
   if (output[2] < Number.MIN_VALUE) output[2] += 0xFFFFFFFF + 1;
   if (output[2] < Number.MIN_VALUE) output[2] += 0xFFFFFFFF00000000;
   if (output[3] < Number.MIN_VALUE) output[3] += 0xFFFFFFFF + 1;
   if (output[3] < Number.MIN_VALUE) output[3] += 0xFFFFFFFF00000000;
   if (output[4] < Number.MIN_VALUE) output[4] += 0xFFFFFFFF + 1;
   if (output[4] < Number.MIN_VALUE) output[4] += 0xFFFFFFFF00000000;
   return output;
}


var EPOCH_HEX_CHARS = 3;


// The PoW validation function.
function Valid(output, D) {
   if (D <= 1) return 1;
   return (output[4] % D) == 0 ? 1 : 0;
}

// A function for spliting a query.
function ParseQuery(URL) {
   // Initialize.
   this.location = URL.split("?")[0];
   this.key      = new Array();
   this.value    = new Array();
   // If there is a query, split off key-value pairs.
   if (URL.split("?").length > 1) {
      URL = URL.split("?")[1];
      for (var i = 0; i < URL.split("&").length; i++) {
         this.key[i]   = URL.split("&")[i].split("=")[0];
         this.value[i] = URL.split("&")[i].split("=")[1];
      }
   }
   // Define an accessor.
   this.getValue = function(key) {
      for (var i = 0; i < this.key.length; i++)
         if (this.key[i] == key)
            return this.value[i];
      return false;
   }
   // Define a mutator.
   this.setValue = function(key, value) {
      for (var i = 0; i < this.key.length; i++)
         if (this.key[i] == key) {
            this.value[i] = value;
            return;
         }
      this.value[this.key.length] = value;
      this.key[this.key.length]   = key;
   }
   // Define a deletor.
   this.removeKey = function(key) {
      for (var i = 0; i < this.key.length; i++)
         if (this.key[i] == key) {
            this.key.splice(i, 1);
            this.value.splice(i, 1);
            return;
         }
   }
   // Define an output.
   this.getURL = function() {
      var URL = this.location;
      for (var i = 0; i < this.key.length; i++) {
         if (i == 0) URL += "?";
         else        URL += "&";
         URL += this.key[i] + "=" + this.value[i];
      }
      return URL;
   }
   this.getResource = function() {
      var resource = "/";
      var s1 = this.location.split("//");
      if (s1.length > 1) {
         var p = s1[1].indexOf("/");
         if (p >= 0)
            resource = s1[1].substr(p);
      }
      return resource;
   }
   // Define an out for just the query.
   this.getSearch = function() {
      var search = "";
      for (var i = 0; i < this.key.length; i++) {
         if (i != 0) search += "&";
         search += this.key[i] + "=" + this.value[i];
      }
      return search;
   }
}


var found_defaults = false;
var default_Ec     = 0;
var default_Nc     = 0;
var default_Dc     = 0;


function ShowSplash(tag) {
   document.getElementById('kaPoW-progress').style.visibility = 'visible';
 
   var width = (1 - Math.pow((1 - (1 / tag.Dc)), tag.A)) * 100;
   document.getElementById('kaPoW-progress-bar').style.width = width + '%';
 
   var t  = document.getElementById('kaPoW-progress-url');
   var np = t.firstChild;
   while (np) {
      if (np.nodeType == 3) {
         if (np.nodeValue.match(tag.href)) return;
         t.removeChild(np);
         np = t.firstChild;
      }
   }
   t.appendChild(document.createTextNode(tag.href));
}



// A simple PoW Solution algorithm.
function Solve(tag) {
   // Don't solve a second time.
   if (tag.solved == true) return true;

   // Get the URL.
   if (tag.link == undefined) {
      tag.type = "other";
      if (tag.href != undefined) {
         tag.type = "href";
         tag.link = new ParseQuery(tag.href);
      } else if (tag.src != undefined) {
         tag.type = "src";
         tag.link = new ParseQuery(tag.src);
      }
   }
 
   // Get the variables.
   if (tag.Nc == undefined) {
      tag.Ec = default_Ec;
      tag.Nc = default_Nc;
      if (navigator.appName != "Microsoft Internet Explorer" && tag.hasAttribute('Nc')) {
         var t = tag.getAttribute('Nc');
         tag.Ec = parseInt(t.substr(0, EPOCH_HEX_CHARS), 16);
         tag.Nc = parseInt(t.substr(EPOCH_HEX_CHARS), 16);
      }
   } else if (typeof(tag.Nc) == "string") {
      tag.Ec = parseInt(tag.Nc.substr(0, EPOCH_HEX_CHARS), 16);
      tag.Nc = parseInt(tag.Nc.substr(EPOCH_HEX_CHARS), 16);
   }
   if (tag.Dc == undefined) {
      tag.Dc = default_Dc;
      if (navigator.appName != "Microsoft Internet Explorer" && tag.hasAttribute('Dc')) {
         var t = tag.getAttribute('Dc');
         tag.Dc = parseInt(t, 16);
      }
   } else if (typeof(tag.Dc) == "string") {
     tag.Dc = parseInt(tag.Dc, 16);
   }
   if (tag.A == undefined) tag.A = 0;

   if (tag.type == "href" && tag.Dc > 100) {
      ShowSplash(tag);
   }

   // Create the initial input.
   if (tag.Dc > 1) {
      var input = Array(16);
      input[0] = tag.Nc;
      input[1] = tag.Dc;
      input[2] = tag.A;
      for (var i = 3; i < 16; i++) input[i] = 0;
      var i = 11;
      var resource = tag.link.getResource();
      var j_max;
      if (resource.match("index.")) j_max = resource.lastIndexOf('/') + 1;
      else                          j_max = resource.length;
      for (j = 0; j < j_max; j++) {
         if (++i > 64) i = 12;
         input[Math.floor(i / 4)] ^= resource.charCodeAt(j) << (8 * (i % 4));
      }

//      alert(input[0].toString(16) + " " + input[1].toString(16) + " " + input[2].toString(16) + " " + input[3].toString(16) + " " + input[4].toString(16) + " " + input[5].toString(16) + " " + input[6].toString(16) + " " + input[7].toString(16) + "\n" + input[8].toString(16) + " " + input[9].toString(16) + " " + input[10].toString(16) + " " + input[11].toString(16) + " " + input[12].toString(16) + " " + input[13].toString(16) + " " + input[14].toString(16) + " " + input[15].toString(16));
 
      // Search for an answer.
      var output = SHA1(input);
      var timeout = (new Date()).getTime() + 9;
      while (!Valid(output, tag.Dc)) {
         tag.A = input[2]++;
         output = SHA1(input);
         if ((new Date()).getTime() > timeout) {
            if (navigator.appName == "Microsoft Internet Explorer") {
               setTimeout(function() { Solve(tag); }, 1);
            } else {
               setTimeout(Solve, 1, tag);
            }
            return false;
         }
      }
      // Update the tag with the new answer.
      tag.A = input[2];
      document.getElementById('kaPoW-progress').style.visibility = 'hidden';

      // Re-write the URL.
      var t = tag.Nc.toString(16);
      while (t.length < 8) t = '0' + t;
      t = tag.Ec.toString(16) + t;
      while (t.length < 8 + EPOCH_HEX_CHARS) t = '0' + t;
      tag.link.setValue('Nc', t);
      tag.link.setValue('Dc', tag.Dc.toString(16));
      tag.link.setValue('A',  input[2].toString(16));
      if (tag.type == "href") {
         tag.href = tag.link.getURL();
         if (tag.replace == true) {
            window.location.replace(tag.href);
         } else {
            window.location = tag.href;
         }
      } else if (tag.type == "src") {
         tag.src = tag.link.getURL();
      }
   } else if (tag.type == "href") {
      if (tag.replace == true) {
         window.location.replace(tag.href);
      } else {
         window.location = tag.href;
      }
   }
   tag.solved = true;
}

function kaPoW_solve_new_tags() {
   if (!document || !document.getElementsByTagName) return;
   var elements = document.getElementsByTagName("*");
   if (!found_defaults) {
      for (var i = 0; i < elements.length; i++) {
         if (elements[i].tagName.match("SCRIPT") && elements[i].src.match('kaPoW.js')) {
            found_defaults = true;
            if (navigator.appName == "Microsoft Internet Explorer") {
               if (elements[i].Nc != undefined) {
                  default_Ec = parseInt(elements[i].Nc.substr(0, EPOCH_HEX_CHARS), 16);
                  default_Nc = parseInt(elements[i].Nc.substr(EPOCH_HEX_CHARS), 16);
               }
               if (elements[i].Dc != undefined) {
                  default_Dc = parseInt(elements[i].Dc, 16);
               }
            } else {
               if (elements[i].hasAttribute('Nc')) {
                  var t = elements[i].getAttribute('Nc');
                  default_Ec = parseInt(t.substr(0, EPOCH_HEX_CHARS), 16);
                  default_Nc = parseInt(t.substr(EPOCH_HEX_CHARS), 16);
               }
               if (elements[i].hasAttribute('Dc')) {
                  var t = elements[i].getAttribute('Dc');
                  default_Dc = parseInt(t, 16);
               }
            }
            elements[i].solved = true;
         }
      }
   }
   if (found_defaults) {
      for (var i = 0; i < elements.length; i++) {
         if (!elements[i].added) {
            if (elements[i].tagName.match("A") && elements[i].href) {
               elements[i].onclick = function() { return Solve(this); }
               elements[i].added  = true;
            } else if (elements[i].src) {
               elements[i].added  = true;
//               Solve(elements[i]);
            }
         }
      }
   }
}

//var interval = window.setInterval(kaPoW_solve_new_tags, 1);

function page_onload() {
   kaPoW_solve_new_tags();
//   window.clearInterval(interval);
};

// For Mozilla.
if (document.addEventListener) {
   document.addEventListener("DOMNodeInserted", kaPoW_solve_new_tags, false);
   document.addEventListener("DOMContentLoaded", page_onload, false);
}
// Standby.
window.onload = page_onload;

// Solution progress screen that starts hidden.
document.writeln('<div id="kaPoW-progress" style="visibility:hidden; position:absolute; left:0px; top:0px; width:100%; height:100%; z-index:200; opacity:0.85; background-color:#AAAAAA">\
                     <div style="position:absolute; top:50%; width:100%; font-family:verdana; font-weight:bold; color:#0000CC" align="center">\
                        <div style="position:relative; top:-20px; font-size:20px">\
                           Solving the Proof-of-Work challenge for:\
                        </div>\
                        <div id="kaPoW-progress-url" style="position:relative; top:-5px; height:40px; font-size:30px; font-style:italic">\
                        </div>\
                        <div style="position:relative; top:10px; width:300px; height:30px; border-style:solid; border-width:3px; border-color:#0000CC" align="left">\
                           <div id="kaPoW-progress-bar" style="position:relative; left:0px; top:0px; width:0%; height:100%; background-color:#0000FF">\
                           </div>\
                        </div>\
                     </div>\
                  </div>');
