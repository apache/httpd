#if CONFIG_FOR_HTTPD_TEST

<Location /memory_track>
  SetHandler memory-track
</Location>

#endif

#define APACHE_HTTPD_TEST_HANDLER memory_track_handler

#include "apache_httpd_test.h"
#include "ap_mpm.h"

static int memory_track_handler(request_rec *r)
{
    int result;
    
    if (strcmp(r->handler, "memory-track")) {
        return DECLINED;
    }
    if (r->method_number != M_GET) {
        return DECLINED;
    }

    /* t/apache/leaks.t not reliable with event. */
    if (!ap_mpm_query(AP_MPMQ_IS_ASYNC, &result) && result) {
        return HTTP_SERVICE_UNAVAILABLE;
    }
    
#if APR_POOL_DEBUG
    {
        conn_rec *c = r->connection;
        apr_size_t n = apr_pool_num_bytes(c->pool, 1);
        
        ap_rprintf(r, "connection,%ld,%lu\n", c->id, n);
    }

    return OK;
#else
    return HTTP_NOT_IMPLEMENTED;
#endif
}

APACHE_HTTPD_TEST_MODULE(memory_track);

