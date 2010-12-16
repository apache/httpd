/* Must include ap_config.h first so that we can redefine
    the standard prototypes macros after it messes with
    them. */
#include "ap_config.h"

/* Define all of the standard prototype macros as themselves
    so that httpd.h will not mess with them. This allows 
    them to pass untouched so that the AWK script can pick 
    them out of the preprocessed result file. */
#undef  AP_DECLARE
#define AP_DECLARE              AP_DECLARE
#undef  AP_CORE_DECLARE
#define AP_CORE_DECLARE         AP_CORE_DECLARE
#undef  AP_DECLARE_NONSTD
#define AP_DECLARE_NONSTD       AP_DECLARE_NONSTD
#undef  AP_CORE_DECLARE_NONSTD
#define AP_CORE_DECLARE_NONSTD  AP_CORE_DECLARE_NONSTD
#undef  AP_DECLARE_HOOK
#define AP_DECLARE_HOOK         AP_DECLARE_HOOK
#undef  AP_DECLARE_DATA
#define AP_DECLARE_DATA         AP_DECLARE_DATA
#undef  APACHE_OS_H

#include "httpd.h"

/* Preprocess all of the standard HTTPD headers. */
#include "ap_compat.h"
#include "ap_listen.h"
#include "ap_mmn.h"
#include "ap_mpm.h"
#include "ap_provider.h"
#include "ap_release.h"
#include "http_config.h"
#include "http_connection.h"
#include "http_core.h"
#include "http_log.h"
#include "http_main.h"
#include "http_protocol.h"
#include "http_request.h"
#include "http_vhost.h"
#include "mpm_common.h"
#include "ap_regex.h"
#include "scoreboard.h"
#include "util_cfgtree.h"
#include "util_charset.h"
#include "util_ebcdic.h"
#include "util_filter.h"
/*#include "util_ldap.h"*/
#include "util_md5.h"
#include "util_script.h"
#include "util_time.h"
#include "util_xml.h"

#include "mod_core.h"
#include "mod_auth.h"
