//                       _     _         ____     ___         __
//   _ __ ___   ___   __| |   | | _ __ _|  _ \  __\  \   _   /  /
//  | '_ ` _ \ / _ \ / _` |   | '/ / _` | (_) |/ _ \  \ / \ /  /
//  | | | | | | (_) | (_| |   |   ( (_| | .__/( (_) )  V   V  /
//  |_| |_| |_|\___/ \__,_|___|_|\_\__,_|_|    \___/ \___.___/
//                       |_____|
//
// Copyright (c) Ed Kaiser 2007-2008
// Portland State University


#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "util_filter.h"

#include "defines.h"


// Directives.
const command_rec kaPoW_Directives[] = {
   AP_INIT_FLAG ("PoWRequired", kaPoW_POW_REQUIRED, NULL, RSRC_CONF|ACCESS_CONF, "If a PoW solution is mandatory."),
   AP_INIT_TAKE1("MinDc",       kaPoW_MIN_DC,       NULL, RSRC_CONF|ACCESS_CONF, "The minimum difficulty for work functions."),
   { NULL }
};


// Register the hooks.
static void kaPoW_RegisterHooks(apr_pool_t* p) {
   ap_hook_post_config(kaPoW_InitializeModule, NULL, NULL, APR_HOOK_MIDDLE);
   ap_hook_child_init(kaPoW_InitializeChild, NULL, NULL, APR_HOOK_MIDDLE);    

   ap_hook_handler(kaPoW_Verify, NULL, NULL, APR_HOOK_FIRST);
   ap_register_output_filter("kaPoW_Issue",    kaPoW_Issue, NULL, AP_FTYPE_CONTENT_SET);
   ap_register_output_filter("kaPoW_Protocol", kaPoW_Protocol, NULL, AP_FTYPE_PROTOCOL);
}


// The module's data structure.
module AP_MODULE_DECLARE_DATA kaPoW_module = {
   STANDARD20_MODULE_STUFF,
   kaPoW_DirectoryCreateConfig,
   kaPoW_DirectoryMergeConfig,
   NULL,
   NULL, 
   kaPoW_Directives,
   kaPoW_RegisterHooks,
};
