#ifndef AP_COMPAT_H
#define AP_COMPAT_H

/* Drag in apu (and therefore apr) renamed symbols */
#include "apu_compat.h"

/* redefine 1.3.x symbols to the new symbol names */

#define MODULE_VAR_EXPORT    AP_MODULE_DECLARE_DATA
#define ap_send_http_header(r) ;

#endif /* AP_COMPAT_H */
