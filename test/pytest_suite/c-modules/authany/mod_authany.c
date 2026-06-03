#if CONFIG_FOR_HTTPD_TEST

Alias /authany @DocumentRoot@
<Location /authany>
   require user any-user
   AuthType Basic
   AuthName authany
   <IfDefine !APACHE1>
      <IfVersion >= 2.3>
         AuthBasicProvider any
      </IfVersion>
   </IfDefine>
</Location>

#endif

#include "ap_mmn.h"

/* do not accept empty "" strings */
#define strtrue(s) (s && *s)

#if AP_MODULE_MAGIC_AT_LEAST(20060110, 0)

#include "ap_provider.h"
#include "mod_auth.h"

static authn_status authn_check_password(request_rec *r, const char *user,
                                         const char *password)
{
    return strtrue(r->user) && strcmp(r->user, "guest") == 0
        ? AUTH_GRANTED : AUTH_DENIED;
}

static const authn_provider authn_any_provider =
{
    &authn_check_password
};

static authz_status any_check_authorization(request_rec *r,
                                            const char *requirement,
                                            const void *dummy)
{
#if AP_MODULE_MAGIC_AT_LEAST(20100714,0)
    if (!r->user)
        return AUTHZ_DENIED_NO_USER;
#endif

    return strtrue(r->user) && strcmp(requirement, "any-user") == 0 
        ? AUTHZ_GRANTED : AUTHZ_DENIED;
}

static const authz_provider authz_any_provider =
{
    &any_check_authorization
};

static void extra_hooks(apr_pool_t *p)
{
    ap_register_provider(p, AUTHN_PROVIDER_GROUP,
                         "any", "0", &authn_any_provider);
    ap_register_provider(p, AUTHZ_PROVIDER_GROUP,
                         "user", "0", &authz_any_provider);
}

#define APACHE_HTTPD_TEST_EXTRA_HOOKS extra_hooks

#include "apache_httpd_test.h"

#else /* < 2.3 */

#ifdef APACHE2

#include "apr_pools.h"

static void extra_hooks(apr_pool_t *);

#define APACHE_HTTPD_TEST_EXTRA_HOOKS extra_hooks

#else

#define APACHE_HTTPD_TEST_HOOK_ORDER    APR_HOOK_FIRST
#define APACHE_HTTPD_TEST_CHECK_USER_ID authany_handler
#define APACHE_HTTPD_TEST_AUTH_CHECKER  require_any_user

#endif

#include "apache_httpd_test.h"
 
static int require_any_user(request_rec *r)
{
    const apr_array_header_t *requires = ap_requires(r);
    require_line *rq;
    int x;

    if (!requires) {
        return DECLINED;
    }

    rq = (require_line *) requires->elts;

    for (x = 0; x < requires->nelts; x++) {
        const char *line, *requirement;

        line = rq[x].requirement;
        requirement = ap_getword(r->pool, &line, ' ');

        if ((strcmp(requirement, "user") == 0) &&
            (strcmp(line, "any-user") == 0))
        {
            return OK;
        }
    }

    return DECLINED;
}

static int authany_handler(request_rec *r)
{
     const char *sent_pw; 
     int rc = ap_get_basic_auth_pw(r, &sent_pw); 
     char *user;

     if (rc != OK) {
         return rc;
     }

     if (require_any_user(r) != OK) {
         return DECLINED;
     }

#ifdef APACHE1
     user = r->connection->user;
#endif
#ifdef APACHE2
     user = r->user;
#endif

     if (!(strtrue(user) && strtrue(sent_pw))) {
         ap_note_basic_auth_failure(r);  
#ifdef APACHE1
         ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
                       "Both a username and password must be provided");
#endif
#ifdef APACHE2
         ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                       "Both a username and password must be provided");
#endif
         return HTTP_UNAUTHORIZED;
     }

     return OK;
}

#ifdef APACHE2
static void extra_hooks(apr_pool_t *p)
{
    /* mod_authany and mod_ssl both specify APR_HOOK_FIRST as the
     * ordering of their check-user-id hooks.
     * mod_ssl's must run before mod_authany because it may need to
     * generate the Basic auth information based on the certificate.
     */
    static const char * const modssl_runs_before[] = {"mod_ssl.c", NULL};

    ap_hook_check_user_id(authany_handler, modssl_runs_before, NULL,
                          APR_HOOK_FIRST);
    ap_hook_auth_checker(require_any_user, NULL, NULL, APR_HOOK_FIRST);
}
#endif

#endif

APACHE_HTTPD_TEST_MODULE(authany);
