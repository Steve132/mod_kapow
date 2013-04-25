// Copyright (c) Ed Kaiser 2007-2008
// Portland State University


// Data types.
#ifndef bool
#define bool unsigned char
#endif
#ifndef false
#define false 0
#endif
#ifndef true
#define true 1
#endif
#ifndef u8
#define u8 unsigned char
#endif
#ifndef u16
#define u16 unsigned short
#endif
#ifndef u32
#define u32 unsigned int
#endif
#ifndef u64
#define u64 unsigned long long
#endif




#define INVALID_POW_PHP      "invalid_pow.php"
#define FULL_INVALID_POW_PHP "/invalid_pow.php"
#define KAPOW_JAVASCRIPT     "kaPoW.js"
#define SCRIPT_START         "\n      <SCRIPT TYPE='text/javascript' SRC='/kaPoW.js'"
#define SCRIPT_END           "></SCRIPT>"


// Global variables.
#define DEFAULT_MAX_LOW_CLIENTS 4
#define DEFAULT_MIN_DC          0
#define DEFAULT_POW_REQUIRED    false
#define EPOCH_LENGTH            10000000  // 10M us = 10s
#define VALID_EPOCHS            360       // 1 hours worth
#define EPOCH_HEX_CHARS         3         // ceil( log(VALID_EPOCHS, 16) )
                                          // WARNING: Update this in kaPoW.js if changed.
#define EPOCH_HEX_FMT           "%03x"    // format corresponding to EPOCH_HEX_CHARS
#define SERVER_DEFAULT          "/"


// Functions and hooks.
// Configuration.c:
void*          kaPoW_DirectoryCreateConfig(apr_pool_t* p, char* dummy);
void*          kaPoW_DirectoryMergeConfig(apr_pool_t* p, void* base, void* add);
const char*    kaPoW_POW_REQUIRED(cmd_parms* cmd, void* config, int flag);
const char*    kaPoW_MIN_DC(cmd_parms* cmd, void* config, const char* value);
//void           kaPoW_InitializeModule(apr_pool_t* p);
apr_status_t   kaPoW_InitializeModule(apr_pool_t* p, apr_pool_t* plog, apr_pool_t* ptemp, server_rec* s);
void           kaPoW_InitializeChild(apr_pool_t* p, server_rec* s);
void           kaPoW_UpdateState(apr_pool_t* p, server_rec* s);
bool           kaPoW_AcceptAsLowPriority();
void           kaPoW_FinishLowPriority();
void           kaPoW_IncrementUsage(u32 IP, u32 value);
u32            kaPoW_GetIP(request_rec* r);
u32            kaPoW_CurrentEpoch();
u32            kaPoW_ComputeNc(u32 IP, char* URL, u32 E);
u32            kaPoW_ComputeDc(request_rec* r, u32 IP, char* URL);
bool           kaPoW_IsPoWRequired(request_rec* r, u32 IP, char* URL);


// Issuer.c:
apr_status_t   kaPoW_Issue(ap_filter_t* f, apr_bucket_brigade* bb);
apr_status_t   kaPoW_Protocol(ap_filter_t* f, apr_bucket_brigade* bb);


// Verifier.c:
apr_status_t   kaPoW_Verify(request_rec* r);


// mod_kaPoW.c:
module AP_MODULE_DECLARE_DATA kaPoW_module;
