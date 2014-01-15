/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Security options etc.
 *
 * Module derived from code originally written by Rob McCool
 *
 */

#include "apr_strings.h"
#include "apr_network_io.h"
#include "apr_md5.h"
#include "apr_hash.h"

#define APR_WANT_STRFUNC
#define APR_WANT_BYTEFUNC
#include "apr_want.h"

#include "ap_config.h"
#include "ap_provider.h"
#include "httpd.h"
#include "http_core.h"
#include "http_config.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"

#include "mod_auth.h"

#if APR_HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

/*
 * To save memory if the same subnets are used in hundres of vhosts, we store
 * each subnet only once and use this temporary hash to find it again.
 */
static apr_hash_t *parsed_subnets;

static apr_ipsubnet_t *localhost_v4;
#if APR_HAVE_IPV6
static apr_ipsubnet_t *localhost_v6;
#endif

static int in_domain(const char *domain, const char *what)
{
    int dl = strlen(domain);
    int wl = strlen(what);

    if ((wl - dl) >= 0) {
        if (strcasecmp(domain, &what[wl - dl]) != 0) {
            return 0;
        }

        /* Make sure we matched an *entire* subdomain --- if the user
         * said 'allow from good.com', we don't want people from nogood.com
         * to be able to get in.
         */

        if (wl == dl) {
            return 1;                /* matched whole thing */
        }
        else {
            return (domain[0] == '.' || what[wl - dl - 1] == '.');
        }
    }
    else {
        return 0;
    }
}

static const char *ip_parse_config(cmd_parms *cmd,
                                   const char *require_line,
                                   const void **parsed_require_line)
{
    const char *t, *w;
    int count = 0;
    apr_ipsubnet_t **ip;
    apr_pool_t *ptemp = cmd->temp_pool;
    apr_pool_t *p = cmd->pool;

    /* The 'ip' provider will allow the configuration to specify a list of
        ip addresses to check rather than a single address.  This is different
        from the previous host based syntax. */

    t = require_line;
    while ((w = ap_getword_conf(ptemp, &t)) && w[0])
        count++;

    if (count == 0)
        return "'require ip' requires an argument";

    ip = apr_pcalloc(p, sizeof(apr_ipsubnet_t *) * (count + 1));
    *parsed_require_line = ip;

    t = require_line;
    while ((w = ap_getword_conf(ptemp, &t)) && w[0]) {
        char *addr = apr_pstrdup(ptemp, w);
        char *mask;
        apr_status_t rv;

        if (parsed_subnets &&
            (*ip = apr_hash_get(parsed_subnets, w, APR_HASH_KEY_STRING)) != NULL)
        {
            /* we already have parsed this subnet */
            ip++;
            continue;
        }

        if ((mask = ap_strchr(addr, '/')))
            *mask++ = '\0';

        rv = apr_ipsubnet_create(ip, addr, mask, p);

        if(APR_STATUS_IS_EINVAL(rv)) {
            /* looked nothing like an IP address */
            return apr_psprintf(p, "ip address '%s' appears to be invalid", w);
        }
        else if (rv != APR_SUCCESS) {
            return apr_psprintf(p, "ip address '%s' appears to be invalid: %pm",
                                w, &rv);
        }

        if (parsed_subnets)
            apr_hash_set(parsed_subnets, w, APR_HASH_KEY_STRING, *ip);
        ip++;
    }

    return NULL;
}

static authz_status ip_check_authorization(request_rec *r,
                                           const char *require_line,
                                           const void *parsed_require_line)
{
    /* apr_ipsubnet_test should accept const but doesn't */
    apr_ipsubnet_t **ip = (apr_ipsubnet_t **)parsed_require_line;

    while (*ip) {
        if (apr_ipsubnet_test(*ip, r->useragent_addr))
            return AUTHZ_GRANTED;
        ip++;
    }

    /* authz_core will log the require line and the result at DEBUG */
    return AUTHZ_DENIED;
}

static authz_status host_check_authorization(request_rec *r,
                                             const char *require_line,
                                             const void *parsed_require_line)
{
    const char *t, *w;
    const char *remotehost = NULL;
    int remotehost_is_ip;

    remotehost = ap_get_remote_host(r->connection,
                                    r->per_dir_config,
                                    REMOTE_DOUBLE_REV,
                                    &remotehost_is_ip);

    if ((remotehost == NULL) || remotehost_is_ip) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01753)
                      "access check of '%s' to %s failed, reason: unable to get the "
                      "remote host name", require_line, r->uri);
    }
    else {
        const char *err = NULL;
        const ap_expr_info_t *expr = parsed_require_line;
        const char *require;

        require = ap_expr_str_exec(r, expr, &err);
        if (err) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(02593)
                          "authz_host authorize: require host: Can't "
                          "evaluate require expression: %s", err);
            return AUTHZ_DENIED;
        }

        /* The 'host' provider will allow the configuration to specify a list of
            host names to check rather than a single name.  This is different
            from the previous host based syntax. */
        t = require;
        while ((w = ap_getword_conf(r->pool, &t)) && w[0]) {
            if (in_domain(w, remotehost)) {
                return AUTHZ_GRANTED;
            }
        }
    }

    /* authz_core will log the require line and the result at DEBUG */
    return AUTHZ_DENIED;
}

static authz_status local_check_authorization(request_rec *r,
                                              const char *require_line,
                                              const void *parsed_require_line)
{
     if (   apr_sockaddr_equal(r->connection->local_addr,
                               r->useragent_addr)
         || apr_ipsubnet_test(localhost_v4, r->useragent_addr)
#if APR_HAVE_IPV6
         || apr_ipsubnet_test(localhost_v6, r->useragent_addr)
#endif
        )
     {
        return AUTHZ_GRANTED;
     }

     return AUTHZ_DENIED;
}

static const char *host_parse_config(cmd_parms *cmd, const char *require_line,
                                     const void **parsed_require_line)
{
    const char *expr_err = NULL;
    ap_expr_info_t *expr;

    expr = ap_expr_parse_cmd(cmd, require_line, AP_EXPR_FLAG_STRING_RESULT,
            &expr_err, NULL);

    if (expr_err)
        return apr_pstrcat(cmd->temp_pool,
                           "Cannot parse expression in require line: ",
                           expr_err, NULL);

    *parsed_require_line = expr;

    return NULL;
}

static const authz_provider authz_ip_provider =
{
    &ip_check_authorization,
    &ip_parse_config,
};

static const authz_provider authz_host_provider =
{
    &host_check_authorization,
    &host_parse_config,
};

static const authz_provider authz_local_provider =
{
    &local_check_authorization,
    NULL,
};


static int authz_host_pre_config(apr_pool_t *p, apr_pool_t *plog,
                                 apr_pool_t *ptemp)
{
    /* we only use this hash in the parse config phase, ptemp is enough */
    parsed_subnets = apr_hash_make(ptemp);

    apr_ipsubnet_create(&localhost_v4, "127.0.0.0", "8", p);
    apr_hash_set(parsed_subnets, "127.0.0.0/8", APR_HASH_KEY_STRING, localhost_v4);

#if APR_HAVE_IPV6
    apr_ipsubnet_create(&localhost_v6, "::1", NULL, p);
    apr_hash_set(parsed_subnets, "::1", APR_HASH_KEY_STRING, localhost_v6);
#endif

    return OK;
}

static int authz_host_post_config(apr_pool_t *p, apr_pool_t *plog,
                                  apr_pool_t *ptemp, server_rec *s)
{
    /* make sure we don't use this during .htaccess parsing */
    parsed_subnets = NULL;

    return OK;
}

static void register_hooks(apr_pool_t *p)
{
    ap_hook_pre_config(authz_host_pre_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_post_config(authz_host_post_config, NULL, NULL, APR_HOOK_MIDDLE);

    ap_register_auth_provider(p, AUTHZ_PROVIDER_GROUP, "ip",
                              AUTHZ_PROVIDER_VERSION,
                              &authz_ip_provider, AP_AUTH_INTERNAL_PER_CONF);
    ap_register_auth_provider(p, AUTHZ_PROVIDER_GROUP, "host",
                              AUTHZ_PROVIDER_VERSION,
                              &authz_host_provider, AP_AUTH_INTERNAL_PER_CONF);
    ap_register_auth_provider(p, AUTHZ_PROVIDER_GROUP, "local",
                              AUTHZ_PROVIDER_VERSION,
                              &authz_local_provider, AP_AUTH_INTERNAL_PER_CONF);
}

AP_DECLARE_MODULE(authz_host) =
{
    STANDARD20_MODULE_STUFF,
    NULL,                           /* dir config creater */
    NULL,                           /* dir merger --- default is to override */
    NULL,                           /* server config */
    NULL,                           /* merge server config */
    NULL,
    register_hooks                  /* register hooks */
};
