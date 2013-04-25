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
#include "apr_shm.h"
#include "apr_global_mutex.h"

#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "http_core.h"
#include "http_request.h"
#include "http_vhost.h"
#include "util_filter.h"
#include <unistd.h>

#include "BloomFilter.h"


// Directory configuration structure.
#ifndef kaPoW_dir_config
typedef struct {
   bool POW_REQUIRED;
   bool POW_REQUIRED_set;
   u32  MIN_DC;
   bool MIN_DC_set;
} kaPoW_dir_config;
#endif


apr_global_mutex_t* NsMutex = NULL;
apr_global_mutex_t* LCMutex = NULL;
apr_global_mutex_t* BFMutex = NULL;


typedef struct kaPoW_shared_memory {
   u32         Ns[VALID_EPOCHS];
   u32         CurrentEpoch;
   apr_time_t  Ts;
   u32         LowClients;
   BloomFilter BF;
} kaPoW_shared_memory;
apr_shm_t* kaPoW_shm;


apr_status_t kaPoW_InitializeModule(apr_pool_t* p, apr_pool_t* plog, apr_pool_t* ptemp, server_rec* s) {
   // Ensure that the module initializes only once.
   void* data;
   apr_pool_userdata_get(&data, "kaPoW_module_initialized", s->process->pool);
   if (!data) {
      apr_pool_userdata_set((const void*)1, "kaPoW_module_initialized", apr_pool_cleanup_null, s->process->pool);
      return OK;
   }   

   // Attempt to create the shared memory segment.
   // Try an anonymous segment first, and only if that cannot be done try a named segment.
   ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s, "KAPOW: Creating shared memory segment");
   apr_status_t rc = apr_shm_create(&kaPoW_shm, sizeof(kaPoW_shared_memory), NULL, p);
   if (APR_STATUS_IS_ENOTIMPL(rc)) {
      ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "Trying named base segment");
      apr_shm_remove("kaPoW_shared_memory", p);
      rc = apr_shm_create(&kaPoW_shm, sizeof(kaPoW_shared_memory), "kaPoW_shared_memory", p);
   }
   if (rc != APR_SUCCESS) {
      char buf[100];
      ap_log_error(APLOG_MARK, APLOG_ERR, rc, s, "Cannot allocate shared memory: (%d) %s", rc, apr_strerror(rc, buf, sizeof(buf)));
      return HTTP_INTERNAL_SERVER_ERROR;
   }
   apr_size_t size = apr_shm_size_get(kaPoW_shm);
   if (size < sizeof(kaPoW_shared_memory)) {
      ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "Not enough shared memory allocated: only %d of %d bytes", size, sizeof(kaPoW_shared_memory));
      return HTTP_INTERNAL_SERVER_ERROR;
   }

   // Create the mutexes.
   ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s, "KAPOW: Creating mutexes");
   rc = apr_global_mutex_create(&NsMutex, "kaPoW_Ns_mutex", APR_LOCK_DEFAULT, p);
   if (rc != APR_SUCCESS) {
      ap_log_error(APLOG_MARK, APLOG_ERR, rc, s, "Failed to create Ns mutex");
      return HTTP_INTERNAL_SERVER_ERROR;
   }
   rc = apr_global_mutex_create(&LCMutex, "kaPoW_LC_mutex", APR_LOCK_DEFAULT, p);
   if (rc != APR_SUCCESS) {
      ap_log_error(APLOG_MARK, APLOG_ERR, rc, s, "Failed to create LC mutex");
      return HTTP_INTERNAL_SERVER_ERROR;
   }
   rc = apr_global_mutex_create(&BFMutex, "kaPoW_BF_mutex", APR_LOCK_DEFAULT, p);
   if (rc != APR_SUCCESS) {
      ap_log_error(APLOG_MARK, APLOG_ERR, rc, s, "Failed to create BF mutex");
      return HTTP_INTERNAL_SERVER_ERROR;
   }
   
   // Initialize the state.
   ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s, "KAPOW: Initializing state");
   kaPoW_shared_memory* kshm = (kaPoW_shared_memory*)apr_shm_baseaddr_get(kaPoW_shm);
   kshm->CurrentEpoch = 0;
   srand(apr_time_now());
//   NOTE: found out that this is a strong random function, requiring entropy
//         which is known to hang modules during configuration
//   apr_generate_random_bytes((unsigned char*)(kshm->Ns), sizeof(u32) * VALID_EPOCHS);
   kshm->Ts = apr_time_now() - 3600000001;
   kshm->Ts -= 3600000000;
   kshm->LowClients = 0;
   Initialize(&(kshm->BF));
   ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s, "KAPOW: Finished initializing module");
   return OK;
}


void kaPoW_InitializeChild(apr_pool_t* p, server_rec* s) {
   // Re-open the mutexes for the child. Note the mutex pointer is global here.
   ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s, "KAPOW: Initializing child process");
   apr_status_t rc = apr_global_mutex_child_init(&NsMutex, "kaPoW_Ns_mutex", p);
   if (rc != APR_SUCCESS) {
      ap_log_error(APLOG_MARK, APLOG_CRIT, rc, s, "Failed to reopen Ns_mutex");
   }
   rc = apr_global_mutex_child_init(&LCMutex, "kaPoW_LC_mutex", p);
   if (rc != APR_SUCCESS) {
      ap_log_error(APLOG_MARK, APLOG_CRIT, rc, s, "Failed to reopen LC_mutex");
   }
   rc = apr_global_mutex_child_init(&BFMutex, "kaPoW_BF_mutex", p);
   if (rc != APR_SUCCESS) {
      ap_log_error(APLOG_MARK, APLOG_CRIT, rc, s, "Failed to reopen BF_mutex");
   }
   ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s, "KAPOW: Finished initializing child process");
}   


u32 rand_u32() {
   if (RAND_MAX > 0xFFFF) {
      return rand();
   } else {
      return (rand() << 16) | rand();
   }
}


void kaPoW_UpdateState(apr_pool_t* p, server_rec* s) {
   kaPoW_shared_memory* kshm = (kaPoW_shared_memory*)apr_shm_baseaddr_get(kaPoW_shm);
   apr_global_mutex_lock(NsMutex);
   apr_time_t now     = apr_time_now();
   apr_time_t elapsed = now - kshm->Ts;
   if (elapsed > (apr_time_t)EPOCH_LENGTH) {
      ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s, "Last:    %20llu", kshm->Ts);
      ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s, "Now:     %20llu", now);
      ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s, "Elapsed: %20llu", elapsed);
      ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s, "Length:  %20lu", EPOCH_LENGTH);
      u32 epochs = elapsed / EPOCH_LENGTH;
      ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s, "Epochs:  %20u",  epochs);
      kshm->Ts += (apr_time_t)(epochs) * (apr_time_t)EPOCH_LENGTH;
      ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s, "New:     %20llu", kshm->Ts);
//      NOTE: although this code works, it takes hella long
//      if (kshm->CurrentEpoch + epochs >= VALID_EPOCHS) {
//         apr_generate_random_bytes((unsigned char*)&(kshm->Ns[kshm->CurrentEpoch + 1]), sizeof(u32) * (VALID_EPOCHS - kshm->CurrentEpoch - 1));
//         apr_generate_random_bytes((unsigned char*)&(kshm->Ns[0]), sizeof(u32) * (kshm->CurrentEpoch + epochs + 1 - VALID_EPOCHS));
//      } else {
//         apr_generate_random_bytes((unsigned char*)&(kshm->Ns[kshm->CurrentEpoch + 1]), sizeof(u32) * epochs);
//      }
      ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s, "Old E:   %20u",  kshm->CurrentEpoch);
      int i;
      for (i = 1; i <= epochs; i++)
         kshm->Ns[(kshm->CurrentEpoch + i) % VALID_EPOCHS] = rand_u32();
      kshm->CurrentEpoch = (kshm->CurrentEpoch + epochs) % VALID_EPOCHS;
      ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s, "New E:   %20u",  kshm->CurrentEpoch);
      apr_global_mutex_lock(BFMutex);
      Decay(&(kshm->BF), epochs);
      apr_global_mutex_unlock(BFMutex);
      ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s, "");
      ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s, "KAPOW: Updating BloomFilter for %u epochs, Ts to %llu", epochs, kshm->Ts);
   }
   apr_global_mutex_unlock(NsMutex);
}


bool kaPoW_AcceptAsLowPriority() {
   kaPoW_shared_memory* kshm = (kaPoW_shared_memory*)apr_shm_baseaddr_get(kaPoW_shm);
   bool rc = false;
   apr_global_mutex_lock(LCMutex);
   if (kshm->LowClients < DEFAULT_MAX_LOW_CLIENTS) {
      kshm->LowClients++;
      rc = true;
   }
   apr_global_mutex_unlock(LCMutex);
   return rc;   
}

void kaPoW_FinishLowPriority() {
   kaPoW_shared_memory* kshm = (kaPoW_shared_memory*)apr_shm_baseaddr_get(kaPoW_shm);
   apr_global_mutex_lock(LCMutex);
   if (kshm->LowClients > 0) kshm->LowClients--;
   apr_global_mutex_unlock(LCMutex);   
}


void kaPoW_IncrementUsage(u32 IP, u32 value) {
   kaPoW_shared_memory* kshm = (kaPoW_shared_memory*)apr_shm_baseaddr_get(kaPoW_shm);
   apr_global_mutex_lock(BFMutex);
   Index(&(kshm->BF), IP);
   Increment(&(kshm->BF), value);
   apr_global_mutex_unlock(BFMutex);
}


// Get the IP.
u32 kaPoW_GetIP(request_rec* r) {
   if (r->connection->remote_addr->sa.sin.sin_family == APR_INET) {
      return r->connection->remote_addr->sa.sin.sin_addr.s_addr;
   } else if (IN6_IS_ADDR_V4MAPPED((struct in6_addr*)r->connection->remote_addr->ipaddr_ptr)) {
      return (*(unsigned long*)&r->connection->remote_addr->sa.sin6.sin6_addr.s6_addr[12]);
   }
   return 0;
}


u32 kaPoW_CurrentEpoch() {
   // Return the current epoch.
   kaPoW_shared_memory* kshm = (kaPoW_shared_memory*)apr_shm_baseaddr_get(kaPoW_shm);
   return kshm->CurrentEpoch;
}


u32 kaPoW_ComputeNc(u32 IP, char* URL, u32 E) {
   // Compute the client specific nonce Nc.
   kaPoW_shared_memory* kshm = (kaPoW_shared_memory*)apr_shm_baseaddr_get(kaPoW_shm);
   return (IP ^ kshm->Ns[E]);
}


u32 kaPoW_ComputeDc(request_rec* r, u32 IP, char* URL) {
   // If the URL off-site, return Dc = 0.
   // TODO: Right now we assume any URL with 'http://' is off-site. Fix this assumption.
   if (strstr(URL, "http://")) return 0;
   
   // Get the client specific difficulty Dc.
   kaPoW_shared_memory* kshm = (kaPoW_shared_memory*)apr_shm_baseaddr_get(kaPoW_shm);
   apr_global_mutex_lock(BFMutex);
   Index(&(kshm->BF), IP);
   u32 D = GetCount(&(kshm->BF));
   apr_global_mutex_unlock(BFMutex);
   ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "Dc for IP %s is 0x%08x", r->connection->remote_ip, D);
   // Take the larger of Dc or server/directory/location minimum value.
   request_rec* temp_r = ap_sub_req_lookup_uri(URL, r, NULL);
   kaPoW_dir_config* dconf = ap_get_module_config(temp_r->per_dir_config, &kaPoW_module);
   if (D < dconf->MIN_DC) {
      D = dconf->MIN_DC;
      ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "However the minimum Dc for %s is 0x%08x", URL, D);
   }
   ap_destroy_sub_req(temp_r);
   return D;
}


bool kaPoW_IsPoWRequired(request_rec* r, u32 IP, char* URL) {
   // Test if a valid solution is mandatory for this URL.
   bool rc = DEFAULT_POW_REQUIRED;
   request_rec* temp_r = ap_sub_req_lookup_uri(URL, r, NULL);
   kaPoW_dir_config* dconf = ap_get_module_config(temp_r->per_dir_config, &kaPoW_module);
   rc = dconf->POW_REQUIRED;
   if (rc) ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "PoW is mandatory for %s", URL);
   else    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "PoW is not mandatory for %s", URL);
   ap_destroy_sub_req(temp_r);   
   return rc;
} 


void* kaPoW_DirectoryCreateConfig(apr_pool_t* p, char* dummy) {
   kaPoW_dir_config* r = apr_pcalloc(p, sizeof(kaPoW_dir_config));
   r->POW_REQUIRED     = DEFAULT_POW_REQUIRED;
   r->POW_REQUIRED_set = false;
   r->MIN_DC           = DEFAULT_MIN_DC;
   r->MIN_DC_set       = false;
   return r;
}


void* kaPoW_DirectoryMergeConfig(apr_pool_t* p, void* base, void* add) {
   kaPoW_dir_config* r = apr_pcalloc(p, sizeof(kaPoW_dir_config));
   kaPoW_dir_config* b = (kaPoW_dir_config*)base;
   kaPoW_dir_config* a = (kaPoW_dir_config*)add;
   r->POW_REQUIRED     = a->POW_REQUIRED_set ? a->POW_REQUIRED : b->POW_REQUIRED;
   r->POW_REQUIRED_set = true;
   r->MIN_DC           = a->MIN_DC_set       ? a->MIN_DC       : b->MIN_DC;
   r->MIN_DC_set       = true;
   return r;
}


const char* kaPoW_POW_REQUIRED(cmd_parms* cmd, void* config, int flag) {
   ((kaPoW_dir_config*)config)->POW_REQUIRED     = (bool)flag;
   ((kaPoW_dir_config*)config)->POW_REQUIRED_set = true;
   return NULL;
}


const char* kaPoW_MIN_DC(cmd_parms* cmd, void* config, const char* value) {
   u32 t = strtol(value, NULL, 0);
   if (t >= 0) { 
      ((kaPoW_dir_config*)config)->MIN_DC     = t;
      ((kaPoW_dir_config*)config)->MIN_DC_set = true;
   } else {
      return "Must enter a non-negative value for MinDc.";
   }
   return NULL;
}
