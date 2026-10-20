#if CONFIG_FOR_HTTPD_TEST

<Location /custom_response/plain>
   ForceType image/png
   SetHandler custom_response_plain
</Location>

<Location /custom_response/ct>
   ForceType image/png
   SetHandler custom_response_ct
</Location>

<Location /custom_response/replaced>
   SetHandler custom_response_replaced
</Location>

<Location /custom_response/declined>
   SetHandler custom_response_declined
</Location>

#endif

#define APACHE_HTTPD_TEST_HANDLER custom_response_handler
#define APACHE_HTTPD_TEST_EXTRA_HOOKS custom_response_hooks

#include "apache_httpd_test.h"

/* Every handler fails with 400 and a plain text body registered with
 * ap_custom_response() or ap_custom_response_ct().
 */
static int custom_response_handler(request_rec *r)
{
    if (strcmp(r->handler, "custom_response_plain") == 0) {
        ap_custom_response(r, HTTP_BAD_REQUEST, "<html>Bad request</html>");
        return HTTP_BAD_REQUEST;
    }
    if (strcmp(r->handler, "custom_response_ct") == 0) {
        ap_custom_response_ct(r, HTTP_BAD_REQUEST, "{\"error\":\"bad request\"}",
                              "application/json");
        return HTTP_BAD_REQUEST;
    }
    if (strcmp(r->handler, "custom_response_replaced") == 0) {
        ap_custom_response_ct(r, HTTP_BAD_REQUEST, "first",
                              "application/json");
        ap_custom_response(r, HTTP_BAD_REQUEST, "second");
        return HTTP_BAD_REQUEST;
    }
    if (strcmp(r->handler, "custom_response_declined") == 0) {
        ap_custom_response(r, HTTP_BAD_REQUEST, "<html>Bad request</html>");
        return HTTP_BAD_REQUEST;
    }
    return DECLINED;
}

/* runs before the handler above, sets a type for its own purposes and
 * declines, so the type must not end up on the body of the next handler
 */
static int custom_response_decliner(request_rec *r)
{
    if (strcmp(r->handler, "custom_response_declined") == 0) {
        ap_set_content_type(r, "application/x-custom-response");
    }
    return DECLINED;
}

static void custom_response_hooks(apr_pool_t *p)
{
    ap_hook_handler(custom_response_decliner, NULL, NULL, APR_HOOK_FIRST);
}

APACHE_HTTPD_TEST_MODULE(custom_response);
