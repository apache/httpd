#if CONFIG_FOR_HTTPD_TEST

<Location /eat_post>
   SetHandler eat_post
</Location>

#endif

#define APACHE_HTTPD_TEST_HANDLER eat_post_handler

#include "apache_httpd_test.h"

/* like mod_echo_post.c but does not echo back the data,
 * just sends back the number of bytes read
 */
static int eat_post_handler(request_rec *r)
{
    int rc;
    long nrd, total = 0;
#ifdef APACHE1
    char buff[IOBUFSIZE];
#else
    char buff[AP_IOBUFSIZE];
#endif

    if (strcmp(r->handler, "eat_post")) {
        return DECLINED;
    }
    if ((r->method_number != M_POST) && (r->method_number != M_PUT)) {
        return DECLINED;
    }

    if ((rc = ap_setup_client_block(r, REQUEST_CHUNKED_ERROR)) != OK) {
#ifdef APACHE1
        ap_log_error(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, r->server,
                     "[mod_eat_post] ap_setup_client_block failed: %d", rc);
#else
        ap_log_error(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r->server,
                     "[mod_eat_post] ap_setup_client_block failed: %d", rc);
#endif /* APACHE1 */
        return rc;
    }

    if (!ap_should_client_block(r)) {
        return OK;
    }

#ifdef APACHE1
    ap_send_http_header(r);
#endif
    
    while ((nrd = ap_get_client_block(r, buff, sizeof(buff))) > 0) {
        total += nrd;
    }

    ap_rprintf(r, "%ld\n", total);
    
    return OK;
}

APACHE_HTTPD_TEST_MODULE(eat_post);
