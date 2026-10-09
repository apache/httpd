#define HTTPD_TEST_REQUIRE_APACHE 2.3

#if CONFIG_FOR_HTTPD_TEST

<IfModule mod_session.c>
    <Location /sessiontest>
         Session Off
         TestSession On
         SetHandler test-session-handler
    </Location>
    <Location /sessiontest/on>
        Session On
        SessionHeader X-Test-Session-Override
    </Location>
    <Location /sessiontest/on/encode>
        TestSessionEncoder On
    </Location>
    <IfModule mod_include.c>
        Alias /sessiontest/on/env/on @DocumentRoot@/modules/session
        <Directory @DocumentRoot@/modules/session>
            Session On
            SessionEnv Off
            TestSession On
            Options +IncludesNOEXEC
        </Directory>
        <Location /sessiontest/on/env>
            SetHandler None
        </Location>
        <Location /sessiontest/on/env/on>
            SessionEnv On
        </Location>
    </IfModule>
    <Location /sessiontest/on/expire>
        SessionMaxAge 100
    </Location>
    <IfModule mod_version.c>
        <IfVersion >= 2.4.41>
            <Location /sessiontest/on/expire/cache>
                SessionExpiryUpdateInterval 50
            </Location>
        </IfVersion>
    </IfModule>
    <Location /sessiontest/on/include>
        SessionInclude /sessiontest/on/include/yes
        SessionExclude /sessiontest/on/include/yes/no
    </Location>
</IfModule>

#endif

#include "apr_strings.h"
#include "mod_session.h"

#define APACHE_HTTPD_TEST_EXTRA_HOOKS extra_hooks
#define APACHE_HTTPD_TEST_CHILD_INIT test_session_init
#define APACHE_HTTPD_TEST_HANDLER test_session_handler
#define APACHE_HTTPD_TEST_COMMANDS test_session_cmds
#define APACHE_HTTPD_TEST_PER_DIR_CREATE test_session_dcfg_create
#define APACHE_HTTPD_TEST_PER_DIR_MERGE test_session_dcfg_merge

#include "apache_httpd_test.h"

#define TEST_SESSION_HANDLER "test-session-handler"
#define TEST_SESSION_ENCODER "test-session-encoder"
#define TEST_SESSION_NOTE "mod_test_session"
#define TEST_SESSION_HEADER "X-Test-Session-Override"
#define TEST_SESSION_ENCODING_PREFIX "TestEncoded:"

typedef struct {
    int session;
    int session_set;
    int encoder;
    int encoder_set;
} test_session_dcfg_t;

typedef enum {
    TEST_SESSION_ACTION_NONE,
    TEST_SESSION_ACTION_GET,
    TEST_SESSION_ACTION_SET
} TestSessionAction;

module AP_MODULE_DECLARE_DATA test_session_module;

static APR_OPTIONAL_FN_TYPE(ap_session_get) *ap_session_get_fn = NULL;
static APR_OPTIONAL_FN_TYPE(ap_session_set) *ap_session_set_fn = NULL;
static APR_OPTIONAL_FN_TYPE(ap_session_load) *ap_session_load_fn = NULL;
static APR_OPTIONAL_FN_TYPE(ap_session_save) *ap_session_save_fn = NULL;

static void test_session_init(apr_pool_t *p, server_rec *s)
{
    ap_session_get_fn = APR_RETRIEVE_OPTIONAL_FN(ap_session_get);
    ap_session_set_fn = APR_RETRIEVE_OPTIONAL_FN(ap_session_set);
    ap_session_save_fn = APR_RETRIEVE_OPTIONAL_FN(ap_session_save);
    ap_session_load_fn = APR_RETRIEVE_OPTIONAL_FN(ap_session_load);
}

static apr_status_t test_session_load(request_rec * r, session_rec ** z)
{
    session_rec *zz;
    test_session_dcfg_t *dconf = ap_get_module_config(r->per_dir_config,
                                                      &test_session_module);
    if (!dconf || !dconf->session)
        return DECLINED;

    zz = (session_rec *)apr_table_get(r->notes, TEST_SESSION_NOTE);

    if (!zz) {
        /* Create the session using the query string as the data. */
        char *data = apr_pstrdup(r->pool, r->args);

        if (data) {
            int result = ap_unescape_urlencoded(data);
            if (result)
                return result;
        }

        zz = (session_rec *)apr_pcalloc(r->pool, sizeof(session_rec));
        zz->pool = r->pool;
        zz->entries = apr_table_make(r->pool, 10);
        zz->encoded = data;
        apr_table_setn(r->notes, TEST_SESSION_NOTE, (char *)zz);
    }

    *z = zz;
    return OK;
}

static apr_status_t test_session_save(request_rec * r, session_rec * z)
{
    test_session_dcfg_t *dconf = ap_get_module_config(r->per_dir_config,
                                                      &test_session_module);
    if (!dconf || !dconf->session)
        return DECLINED;

    /* Save the session into headers. */
    apr_table_setn(r->headers_out, "X-Test-Session-Dirty",
        z->dirty ? "1" : "0");

    apr_table_set(r->headers_out, "X-Test-Session", z->encoded);

    return OK;
}

static apr_status_t test_session_encode(request_rec * r, session_rec * z)
{
    test_session_dcfg_t *dconf = ap_get_module_config(r->per_dir_config,
                                                      &test_session_module);
    if (!dconf || !dconf->encoder)
        return DECLINED;

    /* Simple encoding by adding a prefix. */
    z->encoded = apr_pstrcat(r->pool, TEST_SESSION_ENCODING_PREFIX,
                             z->encoded, NULL);
    return OK;
}

static apr_status_t test_session_decode(request_rec * r, session_rec * z)
{
    const size_t prefix_len = strlen(TEST_SESSION_ENCODING_PREFIX);
    test_session_dcfg_t *dconf = ap_get_module_config(r->per_dir_config,
                                                      &test_session_module);
    if (!dconf || !dconf->encoder || !z->encoded)
        return DECLINED;

    /* Simple decoding by removing a prefix. */
    if (!strncmp(z->encoded, TEST_SESSION_ENCODING_PREFIX, prefix_len)) {
        z->encoded += prefix_len;
        return OK;
    }

    return HTTP_BAD_REQUEST;
}

static int test_session_get(request_rec *r, char *name)
{
    session_rec *z = NULL;
    const char *value = NULL;
    apr_status_t result = ap_session_load_fn(r, &z);

    if (result == OK)
        result = ap_session_get_fn(r, z, name, &value);

    if (result == OK) {
        if (value)
            result = ap_rputs(value, r) > 0 ? OK : HTTP_INTERNAL_SERVER_ERROR;
        else
            result = HTTP_NOT_FOUND;
    }

    return result;
}

static int test_session_set(request_rec *r, char *name, char *value)
{
    session_rec *z = NULL;
    apr_status_t result = ap_session_load_fn(r, &z);

    if (result == OK)
        result = ap_session_set_fn(r, z, name, value);

    return result;
}

static int test_session_handler(request_rec *r)
{
    const char *overrides = NULL;

    if (strcmp(r->handler, TEST_SESSION_HANDLER))
        return DECLINED;

    /* Copy the header for SessionHeader from the request to the response. */
    if ((overrides = apr_table_get(r->headers_in, TEST_SESSION_HEADER)))
        apr_table_setn(r->headers_out, TEST_SESSION_HEADER, overrides);

    /* Additional commands to test the session API via POST. */
    if (r->method_number == M_POST) {
        char *fieldName = NULL;
        char *fieldValue = NULL;
        apr_array_header_t *pairs = NULL;
        apr_status_t result;
        TestSessionAction action;

        if (!ap_session_get_fn || !ap_session_set_fn ||
            !ap_session_load_fn || !ap_session_save_fn)
            return HTTP_INTERNAL_SERVER_ERROR;

        action = TEST_SESSION_ACTION_NONE;
        result = ap_parse_form_data(r, NULL, &pairs, 3, 1024);

        if (result != OK)
            return result;

        while (pairs && !apr_is_empty_array(pairs)) {
            ap_form_pair_t *pair = (ap_form_pair_t *)apr_array_pop(pairs);
            if (!strcmp(pair->name, "action")) {
                apr_size_t len;
                char *value = NULL;
                result = apr_brigade_pflatten(pair->value, &value, &len,
                                              r->pool);
                if (result == OK && !strncmp(value, "get", len))
                    action = TEST_SESSION_ACTION_GET;
                else if (result == OK && !strncmp(value, "set", len))
                    action = TEST_SESSION_ACTION_SET;
                else
                    return HTTP_BAD_REQUEST;
            }
            else if (!strcmp(pair->name, "name")) {
                apr_off_t off;
                apr_size_t len;
                apr_brigade_length(pair->value, 1, &off);
                len = (apr_size_t)off;
                fieldName = apr_pcalloc(r->pool, sizeof(char) * len + 1);
                result = apr_brigade_flatten(pair->value, fieldName, &len);
            }
            else if (!strcmp(pair->name, "value")) {
                apr_off_t off;
                apr_size_t len;
                apr_brigade_length(pair->value, 1, &off);
                len = (apr_size_t)off;
                fieldValue = apr_pcalloc(r->pool, sizeof(char) * len + 1);
                result = apr_brigade_flatten(pair->value, fieldValue, &len);
            }
            else {
                return HTTP_BAD_REQUEST;
            }

            if (result != OK)
                return result;
        }

        switch (action) {
        case TEST_SESSION_ACTION_GET:
            return test_session_get(r, fieldName);

        case TEST_SESSION_ACTION_SET:
            return test_session_set(r, fieldName, fieldValue);

        default:
            return HTTP_BAD_REQUEST;
        }
    }

    return OK;
}

static void *test_session_dcfg_create(apr_pool_t *p, char *dummy)
{
    return apr_pcalloc(p, sizeof(test_session_dcfg_t));
}

static void *test_session_dcfg_merge(apr_pool_t * p, void *basev, void *addv)
{
    test_session_dcfg_t *add = addv;
    test_session_dcfg_t *base = basev;
    test_session_dcfg_t *new = apr_pcalloc(p, sizeof(test_session_dcfg_t));

    new->session = (add->session_set == 0) ? base->session : add->session;
    new->session_set = add->session_set || base->session_set;
    new->encoder = (add->encoder_set == 0) ? base->encoder : add->encoder;
    new->encoder_set = add->encoder_set || base->encoder_set;

    return new;
}

static const char *set_session_enable(cmd_parms * parms, void *dconf, int flag)
{
    test_session_dcfg_t *conf = dconf;

    conf->session = flag;
    conf->session_set = 1;

    return NULL;
}

static const char *set_encoder_enable(cmd_parms * parms, void *dconf, int flag)
{
    test_session_dcfg_t *conf = dconf;

    conf->encoder = flag;
    conf->encoder_set = 1;

    return NULL;
}

static const command_rec test_session_cmds[] = {
    AP_INIT_FLAG("TestSession", set_session_enable, NULL, OR_ALL,
                 "Enable test sessions"),
    AP_INIT_FLAG("TestSessionEncoder", set_encoder_enable, NULL, OR_ALL,
                 "Enable test session encoding"),
    { NULL }
};

static void extra_hooks(apr_pool_t *pool)
{
    ap_hook_session_load(test_session_load,
                         NULL, NULL, APR_HOOK_MIDDLE);

    ap_hook_session_save(test_session_save,
                         NULL, NULL, APR_HOOK_MIDDLE);

    ap_hook_session_encode(test_session_encode,
                           NULL, NULL, APR_HOOK_MIDDLE);

    ap_hook_session_decode(test_session_decode,
                           NULL, NULL, APR_HOOK_MIDDLE);
}

APACHE_HTTPD_TEST_MODULE(test_session);
