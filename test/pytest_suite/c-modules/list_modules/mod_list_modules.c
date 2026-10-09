#if CONFIG_FOR_HTTPD_TEST

<Location /list_modules>
   SetHandler list_modules
</Location>

#endif

#define APACHE_HTTPD_TEST_HANDLER list_modules_handler

#define CORE_PRIVATE /* for ap_top_module */
#include "apache_httpd_test.h"

static int list_modules_handler(request_rec *r)
{
    module *modp;

    if (strcmp(r->handler, "list_modules")) {
        return DECLINED;
    }
    if (r->method_number != M_GET) {
        return DECLINED;
    }

#ifdef APACHE1
#define ap_top_module top_module
    ap_send_http_header(r);
#endif

    for (modp = ap_top_module; modp; modp = modp->next) {
        ap_rvputs(r, modp->name, "\n", NULL);
    }

    return OK;
}

APACHE_HTTPD_TEST_MODULE(list_modules);

