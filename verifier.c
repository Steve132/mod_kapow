//                       _     _         ____     ___         __
//   _ __ ___   ___   __| |   | | _ __ _|  _ \  __\  \   _   /  /
//  | '_ ` _ \ / _ \ / _` |   | '/ / _` | (_) |/ _ \  \ / \ /  /
//  | | | | | | (_) | (_| |   |   ( (_| | .__/( (_) )  V   V  /
//  |_| |_| |_|\___/ \__,_|___|_|\_\__,_|_|    \___/ \___.___/
//                       |_____|
//
// Copyright (c) Ed Kaiser 2007-2008
// Portland State University


#include <stdlib.h>
#include <string.h>

#include "apr_lib.h"
#include "apr_strings.h"
#define  APR_WANT_STRFUNC
#include "apr_want.h"

#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "http_core.h"
#include "http_request.h"
#include "http_vhost.h"
#include "util_filter.h"

#include "defines.h"
#include "SHA1.h"


// Define a handler that gets called for each HTTP request.
apr_status_t kaPoW_Verify(request_rec* r) {
   u32 rc = DECLINED;

   // Update nonces and bloom filter if necessary.
   kaPoW_UpdateState(r->pool, r->server);
   
   // See if this is a kaPoW protected virtual host.
   if (!strstr(r->server->server_hostname, "Low") && !strstr(r->server->server_hostname, "High")) return rc;

   // Print status...
   if (strstr(r->filename, INVALID_POW_PHP)) {
      ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, r->server, "Redirected to error page %s", r->uri);
   } else {
      ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, r->server, "");
      ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, r->server, "KAPOW verifying %s with parameters %s", r->uri, r->args);
   }

   // Add the output filter to the end of the filter chain.
   ap_add_output_filter("kaPoW_Issue", NULL, r, r->connection);

   // Compute the client-specific nonce Nc and difficulty Dc from the client IP. 
   u32  IP  = kaPoW_GetIP(r);
   u32  D   = kaPoW_ComputeDc(r, IP, r->uri);

   if (D <= 1) {
      // Dc(server) is 0 or 1, so must accept it.
      ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, r->server, "No solution is required; HIGH PRIORITY");
      r->hostname = "High";
      ap_update_vhost_from_headers(r);
      r->connection->keepalive = AP_CONN_KEEPALIVE;
      // Add the filter to count the request and decrement LowClients.
      ap_add_output_filter("kaPoW_Protocol", (void*)true, r, r->connection);   // Fix this for a real context someday.
      return DECLINED;
   }

   // Don't redirect/process special pages.
   if (strstr(r->filename, KAPOW_JAVASCRIPT)) goto done_verify;
   if (strstr(r->filename, "favicon.ico"))    goto done_verify;
   if (strstr(r->filename, INVALID_POW_PHP))  goto done_verify;
   
   if (r->args) {
      u32 Nc  = 0;
      u32 Ec  = kaPoW_CurrentEpoch();
      u32 Dc  = 0xFFFFFFFF;
      u32 A   = 0;
      char* ptr  = NULL;
      char* args = apr_pstrdup(r->pool, r->args);
      char* arg  = (char*)apr_strtok(args, "&#", &ptr);
      while (arg) {
         if (strstr(arg, "Nc="))  {
            Ec  = apr_strtoi64(apr_pstrndup(r->pool, arg + 3, EPOCH_HEX_CHARS), NULL, 16);
            Nc  = apr_strtoi64(arg + 3 + EPOCH_HEX_CHARS, NULL, 16);
         }
         if (strstr(arg, "Dc="))  { Dc  = apr_strtoi64(arg + 3, NULL, 16); }
         if (strstr(arg, "A="))   { A   = apr_strtoi64(arg + 2, NULL, 16); }
         arg = (char*)apr_strtok(NULL, "&#", &ptr);
      }
      u32 N  = kaPoW_ComputeNc(IP, SERVER_DEFAULT, Ec);
      if (Dc == 0) {
         ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, r->server, "Client insists it cannot solve the PoW");
         goto done_verify;
      } else if (Nc == N && Dc == D) {
         ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, r->server, "Nc and Dc are correct");
         u32 input[16], i, j;
         input[0] = N;
         input[1] = D;
         input[2] = A;
         for (i = 3; i < 16; i++) input[i] = 0;
         u32 j_max;
         if (strstr(r->uri, "index.")) j_max = strrchr(r->uri, '/') - r->uri + 1;
         else                          j_max = strlen(r->uri);
         i = 11;
         for (j = 0; j < j_max; j++) {
            if (++i > 64) i = 12;
            input[i / 4]   ^= r->uri[j] << (8 * (i % 4));
         }
         u32 output[5];
         kaPoW_SHA1(input, output);
         if (D == 0 || output[4] % D == 0) {
            // Return the expected content.
            ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, r->server, "Valid work attached to URL; HIGH PRIORITY");
            r->hostname = "High";
            ap_update_vhost_from_headers(r);
            r->connection->keepalive = AP_CONN_KEEPALIVE;
            // Add the filter to count the request and decrement LowClients.
            ap_add_output_filter("kaPoW_Protocol", (void*)true, r, r->connection);   // Fix this for a real context someday.
            return DECLINED;
         }
         ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, r->server, "Answer %08x is invalid", A);
         ap_log_error(APLOG_MARK, APLOG_DEBUG,  0, r->server, "Input[0-7]: %08x %08x %08x %08x %08x %08x %08x %08x", input[0], input[1], input[2], input[3], input[4], input[5], input[6], input[7]);
         ap_log_error(APLOG_MARK, APLOG_DEBUG,  0, r->server, "Input[8-15]: %08x %08x %08x %08x %08x %08x %08x %08x", input[8], input[9], input[10], input[11], input[12], input[13], input[14], input[15]);
      } else {
         if (Nc != N)
            ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, r->server, "Nc=%08x does not match Nc(server)=%08x", Nc, N);
         if (Dc != D)
            ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, r->server, "Dc=%08x does not match Dc(server)=%08x", Dc, D);
      }
   } else {
      ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, r->server, "No PoW variables found");
   }

   if (kaPoW_IsPoWRequired(r, IP, r->uri)) {
      // PoW is mandatory, redirect to the error page.
      ap_internal_redirect(FULL_INVALID_POW_PHP, r);
      return APR_SUCCESS;
   }

done_verify:
   if (!kaPoW_AcceptAsLowPriority(r)) { 
      rc = HTTP_SERVICE_UNAVAILABLE;
      ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, r->server, "No low priority slots; REJECTED");
   } else {
      if (!strstr(r->filename, INVALID_POW_PHP))
         ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, r->server, "Accepted as LOW PRIORITY");
      // Add the filter to count the request and decrement LowClients.
      ap_add_output_filter("kaPoW_Protocol", (void*)true, r, r->connection);   // Fix this for a real context someday.
   }
   r->connection->keepalive = AP_CONN_CLOSE;
   return rc;
}
