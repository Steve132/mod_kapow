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
#include "apr_atomic.h"
#include "apr_global_mutex.h"

#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "http_core.h"
#include "http_request.h"
#include "http_vhost.h"
#include "util_filter.h"
#include <unistd.h>

#include "defines.h"


unsigned int low0, high0, low1, high1;
double T;

int strip_url(char* URL) {
   u32 i = 0, j = 0;
   while (URL[i] != '\0') {
      if (URL[i] != '\'' && URL[i] != '\"') URL[j++] = URL[i];
      i++;
      while ( (URL[j-1] == '?' || URL[j-1] == '&') &&
             ((strstr(URL + i, "Nc=") == URL + i) ||
              (strstr(URL + i, "Dc=") == URL + i) ||
              (strstr(URL + i, "A=")) == URL + i)) {
         while (URL[i] != '\0' && URL[i++] != '&');
      }
   }
   if (URL[j-1] == '?' || URL[j-1] == '&') j--;
   URL[j] = '\0';
   return i - j;
}


int append_null_pow(char URL[255]) {
   // Append Nc and Dc.
   u32 i = 0, q = 0;
   while (URL[i] != '\0')
      if (URL[i++] == '?') q = 1;

   if (q) URL[i++] = '&';
   else   URL[i++] = '?';
   URL[i++] = 'D';
   URL[i++] = 'c';
   URL[i++] = '=';
   URL[i++] = '0';
   URL[i++] = '\0';
   return 5;
}


u32 append_Nc(char* tag, u32 E, u32 Nc) {
   u32 rc = 0;
   tag[rc++] = ' ';
   tag[rc++] = 'N';
   tag[rc++] = 'c';
   tag[rc++] = '=';
   rc += sprintf(tag + rc, EPOCH_HEX_FMT, E);
   rc += sprintf(tag + rc, "%08x", Nc);
   return rc;
}


u32 append_Dc(char* tag, u32 Dc) {
   u32 rc = 0;
   tag[rc++] = ' ';
   tag[rc++] = 'D';
   tag[rc++] = 'c';
   tag[rc++] = '=';
   rc += sprintf(tag + rc, "%x", Dc);
   return rc;
}


// Structures for parsing the document.
typedef enum {
   PARSE_LBRACKET,
   PARSE_PRE_NAME,
   PARSE_NAME,
   PARSE_ATTRIBUTE_PRE_NAME,
   PARSE_ATTRIBUTE_NAME,
   PARSE_ATTRIBUTE_PRE_VALUE,
   PARSE_ATTRIBUTE_VALUE,
   PARSE_ATTRIBUTE_PROCESS,
   PARSE_ADD_POW,
   PARSE_RBRACKET,
   PARSE_EXECUTE
} parse_state_t;

typedef enum {
   TAG_OTHER,
   TAG_HEAD,
   TAG_HAS_SRC,
   TAG_HAS_HREF,
} parse_tag_t;


parse_state_t state;
parse_tag_t   tag_type;
u32           bytes_read;
bool          flush_now;

char          kaPoW_script_added;
char          tag[256];
char*         tag_p;
char*         tag_name;
u32           tag_name_len;
char*         tag_atr_name;
u32           tag_atr_name_len;
char*         tag_atr_val;
u32           tag_atr_val_len;
char          tag_atr_val_quoted;
u32           IP, E, default_Nc, default_Dc, Nc, Dc;



// Outgoing filter.
apr_status_t kaPoW_Issue(ap_filter_t* f, apr_bucket_brigade* bb) {
   // Guard against an empty brigade.
   u32 rc = APR_SUCCESS;
   if (APR_BRIGADE_EMPTY(bb)) return APR_SUCCESS;

   // Only munge HTML pages.
   if (!strstr(f->r->content_type, "html")) { return ap_pass_brigade(f->next, bb); }

   // Status report.
   ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, f->r->server, "KAPOW adding challenges to %s", f->r->uri);

   // Content will be added; must unset the Content-Length, Last-Modified, and ETag fields.
   apr_table_unset(f->r->headers_out, "Content-Length");
   apr_table_unset(f->r->headers_out, "Last-Modified");
   apr_table_unset(f->r->headers_out, "ETag");
   ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, f->r->server, "Initialized headers");

   state                = PARSE_LBRACKET;
   flush_now            = false;
   bytes_read           = 0;
   IP                   = kaPoW_GetIP(f->r);
   E                    = kaPoW_CurrentEpoch();
   default_Nc           = kaPoW_ComputeNc(IP, SERVER_DEFAULT, E);
   default_Dc           = kaPoW_ComputeDc(f->r, IP, SERVER_DEFAULT);
   tag[255]             = '\0';
   tag_name             = tag + 1;
   kaPoW_script_added   = 0;
   ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, f->r->server, "Initialized variables");

   const char* data = NULL, *p = NULL, *ep = NULL;
   apr_size_t length;
   apr_bucket* temp_b = NULL, *tag_b = NULL;
   u32 temp_start = 0, temp_end = 0;

   // Get the first bucket and loop over the bucket brigade.
   apr_bucket* b = APR_BRIGADE_FIRST(bb);
   while (b != APR_BRIGADE_SENTINEL(bb)) {
      // Fetch a new bucket if at the end of the last one.
      if (p == ep) {
         // Process meta-buckets.
         if (APR_BUCKET_IS_METADATA(b)) {
            temp_b = APR_BUCKET_NEXT(b);
            if (APR_BUCKET_IS_EOS(b)) {
               ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, f->r->server, "EOS bucket found");
               break;
            }
            if (APR_BUCKET_IS_FLUSH(b)) {
               ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, f->r->server, "FLUSH bucket found");
               flush_now = true;
            }
            b = temp_b;
            continue;
         }
         // Flush if needed.
         if (flush_now || bytes_read > AP_MIN_BYTES_TO_WRITE) {
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, f->r->server, "Flushing buckets");
            apr_bucket_brigade* temp_bb = apr_brigade_split(bb, b);
            rc = ap_pass_brigade(f->next, bb);
            bb = temp_bb;
            if (rc != APR_SUCCESS) {
               return rc;
            }
            flush_now  = false;
            bytes_read = 0;
         }
         // Read the data in the current bucket.
         length = 0;
         if (bytes_read > 0) {
            rc = apr_bucket_read(b, &data, &length, APR_NONBLOCK_READ);
            if (APR_STATUS_IS_EAGAIN(rc)) {
               flush_now = true;
               continue;
            }
         }
         if (!length || rc != APR_SUCCESS) {
             rc = apr_bucket_read(b, &data, &length, APR_BLOCK_READ);
         }
         if (rc != APR_SUCCESS) {
            return rc;
         }
         bytes_read += length;
         // Fetch next bucket if this one is empty.
         if (!length) {
            b = APR_BUCKET_NEXT(b);
            continue;
         }
         p = data;
         ep = data + length;
         ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, f->r->server, "Read %u bytes from bucket", length);
      }

      // The bucket has data. Start filtering.
      switch (state) {
      case PARSE_LBRACKET:
         // Search for the '<' that starts a tag.
         while (p < ep) {
            if (*p == '<') {
               tag_b = b;
               temp_start = p++ - data;
               state = PARSE_PRE_NAME;
               break;
            }
            p++;
         }
         if (p == ep) break;

      case PARSE_PRE_NAME:
         // Skip over leading whitespace before the tag's name.
         while (p < ep) {
            if (*p != ' ' && *p != '\n' && *p != '\r') {
               state    = PARSE_NAME;
               tag[0]   = '<';               
               tag_p    = tag + 1;
               *tag_p   = '\0';               
               tag_type = TAG_OTHER;
               break;
            }
            p++;
         }
         if (p == ep) break;

      case PARSE_NAME:
         // Copy the name into a buffer to do a case insensitive comparison.
         while (p < ep) {
            if (*p == ' ' || *p == '\n' || *p == '\r' || *p == '>') {
               state = PARSE_ATTRIBUTE_PRE_NAME;
               tag_name_len = tag_p - tag_name;
               *tag_p = '\0';               
               break;
            }
            *(tag_p++) = *p;
            p++;
         }
         if (p == ep) break;
         // If this is the start of the head, or body and no head exists, add the kaPoW script.
         if ( tag_name_len == 4 &&
             (((tag_name[0] == 'H' || tag_name[0] == 'h') &&
               (tag_name[1] == 'E' || tag_name[1] == 'e') &&
               (tag_name[2] == 'A' || tag_name[2] == 'a') &&
               (tag_name[3] == 'D' || tag_name[3] == 'd')) ||
              ( !kaPoW_script_added &&
               (tag_name[0] == 'B' || tag_name[0] == 'b') &&
               (tag_name[1] == 'O' || tag_name[1] == 'o') &&
               (tag_name[2] == 'D' || tag_name[2] == 'd') &&
               (tag_name[3] == 'Y' || tag_name[3] == 'y')))) {
            tag_type = TAG_HEAD;
            state = PARSE_RBRACKET;
         } else if (tag_name_len == 8 && tag_name[0] == '!'  &&
                  (tag_name[1] == 'D' || tag_name[1] == 'd') &&
                  (tag_name[2] == 'O' || tag_name[2] == 'o') &&
                  (tag_name[3] == 'C' || tag_name[3] == 'c') &&
                  (tag_name[4] == 'T' || tag_name[4] == 't') &&
                  (tag_name[5] == 'Y' || tag_name[5] == 'y') &&
                  (tag_name[6] == 'P' || tag_name[6] == 'p') &&
                  (tag_name[7] == 'E' || tag_name[7] == 'e')) {
            state = PARSE_RBRACKET;
         }
         ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, f->r->server, "Found <%s> tag", tag_name);
         if (state != PARSE_ATTRIBUTE_PRE_NAME) break;

      case PARSE_ATTRIBUTE_PRE_NAME:
         // Remove leading whitespace before the attribute.
         while (p < ep) {
            if (*p == '>') {
               if (tag_type == TAG_OTHER) state = PARSE_RBRACKET;
               else                       state = PARSE_ADD_POW;
               break;
            } else if (*p != ' ' && *p != '\n' && *p != '\r') {
               state = PARSE_ATTRIBUTE_NAME;
               *(tag_p++) = ' ';
               *tag_p     = '\0';               
               tag_atr_name = tag_p;
               break;
            }
            p++;
         }
         if (p == ep || state != PARSE_ATTRIBUTE_NAME) break;
         

      case PARSE_ATTRIBUTE_NAME:
         while (p < ep) {
            if (*p == '=' || *p == ' ' || *p == '\n' || *p == '\r') {
               state = PARSE_ATTRIBUTE_PRE_VALUE;
               tag_atr_name_len = tag_p - tag_atr_name;
               *tag_p = '\0';
               break;
            } 
            *(tag_p++) = *p;
            p++;
         }
         if (p == ep) break;

      case PARSE_ATTRIBUTE_PRE_VALUE:
         // Remove leading whitespace and equals sign before the value.
         while (p < ep) {
            if (*p != '=' && *p != ' ' && *p != '\n' && *p != '\r') {
               state = PARSE_ATTRIBUTE_VALUE;
               *(tag_p++) = '=';
               *tag_p     = '\0';               
               tag_atr_val = tag_p;
               break;
            }
            p++;
         }
         if (p == ep) break;

      case PARSE_ATTRIBUTE_VALUE:
         // Isolate the value.
         if (*p == '\'' || *p == '\"') {
            tag_atr_val_quoted = *p;
            *(tag_p++) = *(p++);
         } else {
            tag_atr_val_quoted = 0;
         }
         while (p < ep) {
            if (!tag_atr_val_quoted && (*p == '>' || *p == ' ')) {
               state = PARSE_ATTRIBUTE_PROCESS;
               *(tag_p) = '\0';
               tag_atr_val_len = tag_p - tag_atr_val;
               break;
            }
            if (*p == tag_atr_val_quoted) tag_atr_val_quoted = 0;
            *(tag_p++) = *(p++);
         }
         ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, f->r->server, "Found attribute: %s", tag_atr_name);

      case PARSE_ATTRIBUTE_PROCESS:
         state = PARSE_ATTRIBUTE_PRE_NAME;
         // Check if attribute is SRC.
         bool is_URL = false;
         if ( tag_atr_name_len == 3 &&
             (tag_atr_name[0] == 'S' || tag_atr_name[0] == 's') &&
             (tag_atr_name[1] == 'R' || tag_atr_name[1] == 'r') &&
             (tag_atr_name[2] == 'C' || tag_atr_name[2] == 'c')) {
            tag_type = TAG_HAS_SRC;
            is_URL = true;
         } else
         // Check if attribute is HREF.
         if ( tag_atr_name_len == 4 &&
             (tag_atr_name[0] == 'H' || tag_atr_name[0] == 'h') &&
             (tag_atr_name[1] == 'R' || tag_atr_name[1] == 'r') &&
             (tag_atr_name[2] == 'E' || tag_atr_name[2] == 'e') &&
             (tag_atr_name[3] == 'F' || tag_atr_name[3] == 'f')) {
            tag_type = TAG_HAS_HREF;
            is_URL = true;
         }
         if (is_URL) {
            if (tag_atr_val[0] == '\'' || tag_atr_val[0] == '\"') {
               tag_p -= strip_url(tag_atr_val + 1);
               Nc = kaPoW_ComputeNc(IP, tag_atr_val + 1, E);
               Dc = kaPoW_ComputeDc(f->r, IP, tag_atr_val + 1);
            } else {
               tag_p -= strip_url(tag_atr_val);
               Nc = kaPoW_ComputeNc(IP, tag_atr_val, E);
               Dc = kaPoW_ComputeDc(f->r, IP, tag_atr_val);
            }
            if (tag_atr_val[0] == '\'') *(tag_p++) = '\'';
            if (tag_atr_val[0] == '\"') *(tag_p++) = '\"';
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, f->r->server, "Updated the URL");
         }
         break;

      case PARSE_ADD_POW:
         // Add the work function variables as tag attributes.
         state = PARSE_RBRACKET;
         if (Nc != default_Nc) tag_p += append_Nc(tag_p, E, Nc);
         if (Dc != default_Dc) tag_p += append_Dc(tag_p,    Dc);
         *(tag_p++) = '>';
         *(tag_p)   = '\0';

      case PARSE_RBRACKET:
         // Search for the '>' that ends the tag.
         while (p < ep) {
            if (*p == '>') {
               state = PARSE_EXECUTE;
               temp_end = ++p - data;
               break;
            }
            p++;
         }
         if (p == ep) break;

      case PARSE_EXECUTE:
         state = PARSE_LBRACKET;
         // Fix the tag if necessary.
         if (tag_type != TAG_OTHER) {
            // Move the data before the tag into the passed brigade.
            if (temp_start) {
               if (tag_b != b) {
                  apr_bucket_split(tag_b, temp_start);
                  tag_b = APR_BUCKET_NEXT(tag_b);
                  while (tag_b != b) {
                     temp_b = tag_b;
                     tag_b = APR_BUCKET_NEXT(tag_b);
                     apr_bucket_delete(temp_b);
                  }
               } else {
                  apr_bucket_split(b, temp_start);
                  b = APR_BUCKET_NEXT(b);
                  if (temp_end) temp_end -= temp_start;
                  p = ep;
               }
            }

            // Move the remainder of the old tag.
            if (temp_end) {
               apr_bucket_split(b, temp_end);
               temp_b = APR_BUCKET_NEXT(b);
               if (tag_type != TAG_HEAD) {
                  APR_BUCKET_REMOVE(b);
                  apr_bucket_delete(b);
               }
               b = temp_b;
               apr_bucket_read(b, &data, &length, APR_BLOCK_READ);
               p  = data;
               ep = data + length;
            }

            if (tag_type == TAG_HEAD) {
               // Insert the SCRIPT tag after the HEAD tag.
               memcpy(tag, SCRIPT_START, strlen(SCRIPT_START));
               tag_p  = tag + strlen(SCRIPT_START);
               tag_p += append_Nc(tag_p, E, default_Nc);
               tag_p += append_Dc(tag_p,    default_Dc);
               memcpy(tag_p, SCRIPT_END, strlen(SCRIPT_END));
               tag_p += strlen(SCRIPT_END);
               APR_BUCKET_INSERT_BEFORE(b, apr_bucket_pool_create((const char*)apr_pmemdup(f->r->pool, tag, tag_p - tag),
                                        tag_p - tag, f->r->pool, f->c->bucket_alloc));
               kaPoW_script_added = 1;
            } else {
               // Add the tag using the new URL.
               APR_BUCKET_INSERT_BEFORE(b, apr_bucket_pool_create((const char*)apr_pmemdup(f->r->pool, tag, tag_p - tag),
                                        tag_p - tag, f->r->pool, f->c->bucket_alloc));
            }
         }
      } // switch(state)
      
      if (p == ep) {
         ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, f->r->server, "Moving onto next bucket");
         b = APR_BUCKET_NEXT(b);
         if (state == PARSE_EXECUTE) temp_end = 0;
      }      
   } // while(buckets in brigade)

   // Pass the brigade to the next filter.
   ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, f->r->server, "Finished filtering the document");
   return ap_pass_brigade(f->next, bb);
}


apr_status_t kaPoW_Protocol(ap_filter_t* f, apr_bucket_brigade* bb) {
   if (f->ctx) {
      f->ctx = (void*)false;
      // Adjust client's recorded usage proportional to the resources they consumed.
      u32 IP = kaPoW_GetIP(f->r);      
      kaPoW_IncrementUsage(IP, 1);  // Could be: apr_time_now() - f->r->request_time

      // If this was a low priority client, allow another access.
      if (f->r->server->server_hostname[0] == 'L') kaPoW_FinishLowPriority();
      
      ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, f->r->server, "Total processing time: %lu us", apr_time_now() - (f->r->request_time));
   }
   return ap_pass_brigade(f->next, bb);
}
