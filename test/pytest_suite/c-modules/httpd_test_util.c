/* poor man's optional functions
 * if we didn't need to support 1.x we could use optional functions.
 * just hack in this util functions with #define/#include/static for now.
 *
 * tho we could create our own version optional functions using
 * the 1.3/2.0 dlsym-ish function to lookup function pointers given a
 * mod_httpd_test_util.so and httpd_test_util.dynamic_load_handle
 * but thats more trouble than it is worth at the moment.
 */

#ifdef WANT_HTTPD_TEST_SPLIT_QS_NUMBERS

/* split query string in the form of GET /foo?1024,5000 */

static int httpd_test_split_qs_numbers(request_rec *r, ...)
{
    va_list va;
    char *endptr, *args = r->args;

    if (!args) {
        return 0;
    }

    va_start(va, r);

    while (1) {
        apr_size_t *s = va_arg(va, apr_size_t *);
        if (!s) {
            break;
        }
        *s = strtol(args, &endptr, 0);
        if (endptr && (*endptr == ',')) {
            ++endptr;
            args = endptr;
        }
    }

    va_end(va);

    return 1;
}

#endif /* WANT_HTTPD_TEST_SPLIT_QS_NUMBERS */

