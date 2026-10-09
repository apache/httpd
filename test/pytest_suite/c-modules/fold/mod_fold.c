#if CONFIG_FOR_HTTPD_TEST

<Location /fold>
   SetHandler fold
</Location>

#endif

#define APACHE_HTTPD_TEST_HANDLER fold_handler

#include "apache_httpd_test.h"

static int fold_handler(request_rec *r)
{

    if (!r->handler || strcasecmp(r->handler, "fold")) {   
        return DECLINED;
    }

    if (r->args) { 
        ap_set_content_type(r, r->args);
    }
    else { 
        ap_set_content_type(r, "text/html");
    }

    /* This doesn't work with CGI or asis, hence the tiny module */
    apr_table_set(r->err_headers_out, "Foo", "Bar\r\n Baz"); 
    
    return OK;
}

APACHE_HTTPD_TEST_MODULE(fold);
