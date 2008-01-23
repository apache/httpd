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

#define APR_WANT_STRFUNC
#define APR_WANT_BYTEFUNC
#include "apr_want.h"

#include "ap_config.h"
#include "httpd.h"
#include "http_core.h"
#include "http_config.h"
#include "http_log.h"
#include "http_request.h"

#if APR_HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

enum allowdeny_type {
    T_ENV,
    T_ALL,
    T_IP,
    T_HOST,
    T_FAIL
};

typedef struct {
    apr_int64_t limited;
    union {
        char *from;
        apr_ipsubnet_t *ip;
    } x;
    enum allowdeny_type type;
} allowdeny;

/* things in the 'order' array */
#define DENY_THEN_ALLOW 0
#define ALLOW_THEN_DENY 1
#define MUTUAL_FAILURE 2

typedef struct {
    int order[METHODS];
    apr_array_header_t *allows;
    apr_array_header_t *denys;
} authz_host_dir_conf;

module AP_MODULE_DECLARE_DATA authz_host_module;

static void *create_authz_host_dir_config(apr_pool_t *p, char *dummy)
{
    int i;
    authz_host_dir_conf *conf =
        (authz_host_dir_conf *)apr_pcalloc(p, sizeof(authz_host_dir_conf));

    for (i = 0; i < METHODS; ++i) {
        conf->order[i] = DENY_THEN_ALLOW;
    }
    conf->allows = apr_array_make(p, 1, sizeof(allowdeny));
    conf->denys = apr_array_make(p, 1, sizeof(allowdeny));

    return (void *)conf;
}

static const char *order(cmd_parms *cmd, void *dv, const char *arg)
{
    authz_host_dir_conf *d = (authz_host_dir_conf *) dv;
    int i, o;

    if (!strcasecmp(arg, "allow,deny"))
        o = ALLOW_THEN_DENY;
    else if (!strcasecmp(arg, "deny,allow"))
        o = DENY_THEN_ALLOW;
    else if (!strcasecmp(arg, "mutual-failure"))
        o = MUTUAL_FAILURE;
    else
        return "unknown order";

    for (i = 0; i < METHODS; ++i)
        if (cmd->limited & (AP_METHOD_BIT << i))
            d->order[i] = o;

    return NULL;
}

static const char *allow_cmd(cmd_parms *cmd, void *dv, const char *from,
                             const char *where_c)
{
    authz_host_dir_conf *d = (authz_host_dir_conf *) dv;
    allowdeny *a;
    char *where = apr_pstrdup(cmd->pool, where_c);
    char *s;
    char msgbuf[120];
    apr_status_t rv;

    if (strcasecmp(from, "from"))
        return "allow and deny must be followed by 'from'";

    a = (allowdeny *) apr_array_push(cmd->info ? d->allows : d->denys);
    a->x.from = where;
    a->limited = cmd->limited;

    if (!strncasecmp(where, "env=", 4)) {
        a->type = T_ENV;
        a->x.from += 4;

    }
    else if (!strcasecmp(where, "all")) {
        a->type = T_ALL;
    }
    else if ((s = ap_strchr(where, '/'))) {
        *s++ = '\0';
        rv = apr_ipsubnet_create(&a->x.ip, where, s, cmd->pool);
        if(APR_STATUS_IS_EINVAL(rv)) {
            /* looked nothing like an IP address */
            return "An IP address was expected";
        }
        else if (rv != APR_SUCCESS) {
            apr_strerror(rv, msgbuf, sizeof msgbuf);
            return apr_pstrdup(cmd->pool, msgbuf);
        }
        a->type = T_IP;
    }
    else if (!APR_STATUS_IS_EINVAL(rv = apr_ipsubnet_create(&a->x.ip, where,
                                                            NULL, cmd->pool))) {
        if (rv != APR_SUCCESS) {
            apr_strerror(rv, msgbuf, sizeof msgbuf);
            return apr_pstrdup(cmd->pool, msgbuf);
        }
        a->type = T_IP;
    }
    else { /* no slash, didn't look like an IP address => must be a host */
        a->type = T_HOST;
    }

    return NULL;
}

static char its_an_allow;

static const command_rec authz_host_cmds[] =
{
    AP_INIT_TAKE1("order", order, NULL, OR_LIMIT,
                  "'allow,deny', 'deny,allow', or 'mutual-failure'"),
    AP_INIT_ITERATE2("allow", allow_cmd, &its_an_allow, OR_LIMIT,
                     "'from' followed by hostnames or IP-address wildcards"),
    AP_INIT_ITERATE2("deny", allow_cmd, NULL, OR_LIMIT,
                     "'from' followed by hostnames or IP-address wildcards"),
    {NULL}
};

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

static int find_allowdeny(request_rec *r, apr_array_header_t *a, int method)
{

    allowdeny *ap = (allowdeny *) a->elts;
    apr_int64_t mmask = (AP_METHOD_BIT << method);
    int i;
    int gothost = 0;
    const char *remotehost = NULL;

    for (i = 0; i < a->nelts; ++i) {
        if (!(mmask & ap[i].limited)) {
            continue;
        }

        switch (ap[i].type) {
        case T_ENV:
            if (apr_table_get(r->subprocess_env, ap[i].x.from)) {
                return 1;
            }
            break;

        case T_ALL:
            return 1;

        case T_IP:
            if (apr_ipsubnet_test(ap[i].x.ip, r->connection->remote_addr)) {
                return 1;
            }
            break;

        case T_HOST:
            if (!gothost) {
                int remotehost_is_ip;

                remotehost = ap_get_remote_host(r->connection,
                                                r->per_dir_config,
                                                REMOTE_DOUBLE_REV,
                                                &remotehost_is_ip);

                if ((remotehost == NULL) || remotehost_is_ip) {
                    gothost = 1;
                }
                else {
                    gothost = 2;
                }
            }

            if ((gothost == 2) && in_domain(ap[i].x.from, remotehost)) {
                return 1;
            }
            break;

        case T_FAIL:
            /* do nothing? */
            break;
        }
    }

    return 0;
}

static int check_dir_access(request_rec *r)
{
    int method = r->method_number;
    int ret = OK;
    authz_host_dir_conf *a = (authz_host_dir_conf *)
        ap_get_module_config(r->per_dir_config, &authz_host_module);

    if (a->order[method] == ALLOW_THEN_DENY) {
        ret = HTTP_FORBIDDEN;
        if (find_allowdeny(r, a->allows, method)) {
            ret = OK;
        }
        if (find_allowdeny(r, a->denys, method)) {
            ret = HTTP_FORBIDDEN;
        }
    }
    else if (a->order[method] == DENY_THEN_ALLOW) {
        if (find_allowdeny(r, a->denys, method)) {
            ret = HTTP_FORBIDDEN;
        }
        if (find_allowdeny(r, a->allows, method)) {
            ret = OK;
        }
    }
    else {
        if (find_allowdeny(r, a->allows, method)
            && !find_allowdeny(r, a->denys, method)) {
            ret = OK;
        }
        else {
            ret = HTTP_FORBIDDEN;
        }
    }

    if (ret == HTTP_FORBIDDEN
        && (ap_satisfies(r) != SATISFY_ANY || !ap_some_auth_required(r))) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
            "client denied by server configuration: %s%s",
            r->filename ? "" : "uri ",
            r->filename ? r->filename : r->uri);
    }

    return ret;
}

static void register_hooks(apr_pool_t *p)
{
    /* This can be access checker since we don't require r->user to be set. */
    ap_hook_access_checker(check_dir_access,NULL,NULL,APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA authz_host_module =
{
    STANDARD20_MODULE_STUFF,
    create_authz_host_dir_config,   /* dir config creater */
    NULL,                           /* dir merger --- default is to override */
    NULL,                           /* server config */
    NULL,                           /* merge server config */
    authz_host_cmds,
    register_hooks                  /* register hooks */
};
