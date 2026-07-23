#define HTTPD_TEST_REQUIRE_APACHE 2

#if CONFIG_FOR_HTTPD_TEST

<Location /test_pass_brigade>
   SetHandler test_pass_brigade
</Location>

#endif

#define APACHE_HTTPD_TEST_HANDLER test_pass_brigade_handler

#include "apache_httpd_test.h"

#include "apr_buckets.h"

#define WANT_HTTPD_TEST_SPLIT_QS_NUMBERS
#include "httpd_test_util.c"

/*
 * mainly for testing / researching core_output_filter buffering
 */

static int test_pass_brigade_handler(request_rec *r)
{
    conn_rec *c = r->connection;
    size_t total=0, remaining=1;
    char *buff;
    size_t buff_size = 8192;
    apr_bucket_brigade *bb;

    if (strcmp(r->handler, "test_pass_brigade")) {
        return DECLINED;
    }
    if (r->method_number != M_GET) {
        return DECLINED;
    }

    httpd_test_split_qs_numbers(r, &buff_size, &remaining, NULL);

    ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                  "going to echo %" APR_SIZE_T_FMT " bytes with "
                  "buffer size=%" APR_SIZE_T_FMT "",
                  remaining, buff_size);

    buff = malloc(buff_size);
    memset(buff, 'a', buff_size);
    bb = apr_brigade_create(r->pool, c->bucket_alloc);

    while (total < remaining) {
        int left = (remaining - total);
        int len = left <= buff_size ? left : buff_size;
        apr_bucket *bucket = apr_bucket_transient_create(buff, len, 
                                                         c->bucket_alloc);
        apr_status_t status;

        apr_brigade_cleanup(bb);
        APR_BRIGADE_INSERT_TAIL(bb, bucket);
        if (len + total == remaining) {
            bucket = apr_bucket_eos_create(c->bucket_alloc);
            APR_BRIGADE_INSERT_TAIL(bb, bucket);

            bucket = apr_bucket_flush_create(c->bucket_alloc);
            APR_BRIGADE_INSERT_TAIL(bb, bucket);

            ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                          "[mod_test_pass_brigade] sending EOS");
        }

        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                      "[mod_test_pass_brigade] passing to output filter %s",
                      r->output_filters->frec->name);
        
        status = ap_pass_brigade(r->output_filters, bb);

        if (status != APR_SUCCESS) {
            apr_brigade_destroy(bb);
            ap_log_rerror(APLOG_MARK, APLOG_ERR, status, r,
                          "[mod_test_pass_brigade] ap_pass_brigade failed");
            free(buff);
            return HTTP_INTERNAL_SERVER_ERROR;
        }

        total += len;

        ap_log_rerror(APLOG_MARK, APLOG_TRACE2, 0, r,
                      "[mod_test_pass_brigade] wrote %d of %d bytes",
                      len, len);
    }
    
    apr_brigade_destroy(bb);
    ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                  "[mod_test_pass_brigade] done writing %" APR_SIZE_T_FMT 
                  " of %" APR_SIZE_T_FMT " bytes",
                 total, remaining);

    free(buff);    
    return OK;
}

APACHE_HTTPD_TEST_MODULE(test_pass_brigade);

