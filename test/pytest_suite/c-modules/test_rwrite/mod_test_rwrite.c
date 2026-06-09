#if CONFIG_FOR_HTTPD_TEST

<Location /test_rwrite>
   SetHandler test_rwrite
</Location>

#endif

#define APACHE_HTTPD_TEST_HANDLER test_rwrite_handler

#include "apache_httpd_test.h"

#define WANT_HTTPD_TEST_SPLIT_QS_NUMBERS
#include "httpd_test_util.c"

static int test_rwrite_handler(request_rec *r)
{
    size_t total=0, remaining=1;
    char *buff;
    size_t buff_size = 8192;

    if (strcmp(r->handler, "test_rwrite")) {
        return DECLINED;
    }
    if (r->method_number != M_GET) {
        return DECLINED;
    }

    if (r->args) {
        remaining = atol(r->args);
    }

#ifdef APACHE1
    ap_send_http_header(r);
#endif

    httpd_test_split_qs_numbers(r, &buff_size, &remaining, NULL);

    ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                  "[mod_test_rwrite] going to echo %" APR_SIZE_T_FMT " bytes",
                  remaining);

    buff = malloc(buff_size);
    memset(buff, 'a', buff_size);

    while (total < remaining) {
        int left = (remaining - total);
        int len = left <= buff_size ? left : buff_size;
        long nrd = ap_rwrite(buff, len, r);
        total += nrd;

        ap_log_rerror(APLOG_MARK, APLOG_TRACE2, 0, r,
                      "[mod_test_rwrite] wrote %ld of %d bytes", nrd, len);
    }

    ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                  "[mod_test_rwrite] done writing %" APR_SIZE_T_FMT 
                  " of %" APR_SIZE_T_FMT " bytes",
                  total, remaining);

    free(buff);    
    return OK;
}

APACHE_HTTPD_TEST_MODULE(test_rwrite);

