/*        Copyright (c) 2004, Nick Kew.  All rights reserved.

        If this is accepted by ASF for inclusion in APR-UTIL,
        I will assign copyright to ASF and license under ASF terms.

        Otherwise I will retain copyright and license under
        terms of my choice.
*/
#ifndef DBD_H
#define DBD_H

#include <httpd.h>
#include <apr_optional.h>
#include <apr_hash.h>

typedef struct {
    apr_dbd_t *handle;
    apr_dbd_driver_t *driver;
    apr_hash_t *prepared;
} ap_dbd_t;

/* Export functions to access the database */

/* acquire a connection that MUST be explicitly closed.  Returns NULL on error */
AP_DECLARE(ap_dbd_t*) ap_dbd_open(apr_pool_t*, server_rec*);

/* release a connection acquired with ap_dbd_open */
AP_DECLARE(void) ap_dbd_close(server_rec*, ap_dbd_t*);

/* acquire a connection that will have the lifetime of a request
   and MUST NOT be explicitly closed.  Return NULL on error.
   This is the preferred function for most applications.
*/
AP_DECLARE(ap_dbd_t*) ap_dbd_acquire(request_rec*);

/* Also export them as optional functions for modules that prefer it */
APR_DECLARE_OPTIONAL_FN(ap_dbd_t*, ap_dbd_open, (apr_pool_t*, server_rec*));
APR_DECLARE_OPTIONAL_FN(void, ap_dbd_close, (server_rec*, ap_dbd_t*));
APR_DECLARE_OPTIONAL_FN(ap_dbd_t*, ap_dbd_acquire, (request_rec*));

#endif
