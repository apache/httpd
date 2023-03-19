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

#include "mod_proxy.h"
#include "mod_core.h"
#include "apr_optional.h"
#include "apr_strings.h"
#include "scoreboard.h"
#include "mod_status.h"
#include "proxy_util.h"

#if (MODULE_MAGIC_NUMBER_MAJOR > 20020903)
#include "mod_ssl.h"
#else
APR_DECLARE_OPTIONAL_FN(int, ssl_proxy_enable, (conn_rec *));
APR_DECLARE_OPTIONAL_FN(int, ssl_engine_disable, (conn_rec *));
APR_DECLARE_OPTIONAL_FN(int, ssl_engine_set, (conn_rec *,
                                              ap_conf_vector_t *,
                                              int proxy, int enable));
#endif

#ifndef MAX
#define MAX(x,y) ((x) >= (y) ? (x) : (y))
#endif

/*
 * We do health-checks only if that (sub)module is loaded in. This
 * allows for us to continue as is w/o requiring mod_watchdog for
 * those implementations which aren't using health checks
 */
static APR_OPTIONAL_FN_TYPE(set_worker_hc_param) *set_worker_hc_param_f = NULL;

/* Externals */
proxy_hcmethods_t PROXY_DECLARE_DATA proxy_hcmethods[] = {
    {NONE, "NONE", 1},
    {TCP, "TCP", 1},
    {OPTIONS, "OPTIONS", 1},
    {HEAD, "HEAD", 1},
    {GET, "GET", 1},
    {CPING, "CPING", 0},
    {PROVIDER, "PROVIDER", 0},
    {OPTIONS11, "OPTIONS11", 1},
    {HEAD11, "HEAD11", 1},
    {GET11, "GET11", 1},
    {EOT, NULL, 1}
};

proxy_wstat_t PROXY_DECLARE_DATA proxy_wstat_tbl[] = {
    {PROXY_WORKER_INITIALIZED,   PROXY_WORKER_INITIALIZED_FLAG,   "Init "},
    {PROXY_WORKER_IGNORE_ERRORS, PROXY_WORKER_IGNORE_ERRORS_FLAG, "Ign "},
    {PROXY_WORKER_DRAIN,         PROXY_WORKER_DRAIN_FLAG,         "Drn "},
    {PROXY_WORKER_GENERIC,       PROXY_WORKER_GENERIC_FLAG,       "Gen "},
    {PROXY_WORKER_IN_SHUTDOWN,   PROXY_WORKER_IN_SHUTDOWN_FLAG,   "Shut "},
    {PROXY_WORKER_DISABLED,      PROXY_WORKER_DISABLED_FLAG,      "Dis "},
    {PROXY_WORKER_STOPPED,       PROXY_WORKER_STOPPED_FLAG,       "Stop "},
    {PROXY_WORKER_IN_ERROR,      PROXY_WORKER_IN_ERROR_FLAG,      "Err "},
    {PROXY_WORKER_HOT_STANDBY,   PROXY_WORKER_HOT_STANDBY_FLAG,   "Stby "},
    {PROXY_WORKER_HOT_SPARE,     PROXY_WORKER_HOT_SPARE_FLAG,     "Spar "},
    {PROXY_WORKER_FREE,          PROXY_WORKER_FREE_FLAG,          "Free "},
    {PROXY_WORKER_HC_FAIL,       PROXY_WORKER_HC_FAIL_FLAG,       "HcFl "},
    {0x0, '\0', NULL}
};

static const char * const proxy_id = "proxy";
apr_global_mutex_t *proxy_mutex = NULL;

/*
 * A Web proxy module. Stages:
 *
 *  translate_name: set filename to proxy:<URL>
 *  map_to_storage: run proxy_walk (rather than directory_walk/file_walk)
 *                  can't trust directory_walk/file_walk since these are
 *                  not in our filesystem.  Prevents mod_http from serving
 *                  the TRACE request we will set aside to handle later.
 *  fix_ups:        convert the URL stored in the filename to the
 *                  canonical form.
 *  handler:        handle proxy requests
 */

/* -------------------------------------------------------------- */
/* Translate the URL into a 'filename' */

static const char *set_worker_param(apr_pool_t *p,
                                    server_rec *s,
                                    proxy_worker *worker,
                                    const char *key,
                                    const char *val)
{

    int ival;
    apr_interval_time_t timeout;

    if (!strcasecmp(key, "loadfactor")) {
        /* Normalized load factor. Used with BalancerMember,
         * it is a number between 1 and 100.
         */
        double fval = atof(val);
        ival = fval * 100.0;
        if (ival < 100 || ival > 10000)
            return "LoadFactor must be a number between 1..100";
        worker->s->lbfactor = ival;
    }
    else if (!strcasecmp(key, "retry")) {
        /* If set it will give the retry timeout for the worker
         * The default value is 60 seconds, meaning that if
         * in error state, it will be retried after that timeout.
         */
        ival = atoi(val);
        if (ival < 0)
            return "Retry must be a positive value";
        worker->s->retry = apr_time_from_sec(ival);
        worker->s->retry_set = 1;
    }
    else if (!strcasecmp(key, "ttl")) {
        /* Time in seconds that will destroy all the connections
         * that exceed the smax
         */
        ival = atoi(val);
        if (ival < 1)
            return "TTL must be at least one second";
        worker->s->ttl = apr_time_from_sec(ival);
    }
    else if (!strcasecmp(key, "min")) {
        /* Initial number of connections to remote
         */
        ival = atoi(val);
        if (ival < 0)
            return "Min must be a positive number";
        worker->s->min = ival;
    }
    else if (!strcasecmp(key, "max")) {
        /* Maximum number of connections to remote
         */
        ival = atoi(val);
        if (ival < 0)
            return "Max must be a positive number";
        worker->s->hmax = ival;
    }
    /* XXX: More intelligent naming needed */
    else if (!strcasecmp(key, "smax")) {
        /* Maximum number of connections to remote that
         * will not be destroyed
         */
        ival = atoi(val);
        if (ival < 0)
            return "Smax must be a positive number";
        worker->s->smax = ival;
    }
    else if (!strcasecmp(key, "acquire")) {
        /* Acquire timeout in given unit (default is milliseconds).
         * If set this will be the maximum time to
         * wait for a free connection.
         */
        if (ap_timeout_parameter_parse(val, &timeout, "ms") != APR_SUCCESS)
            return "Acquire timeout has wrong format";
        if (timeout < 1000)
            return "Acquire must be at least one millisecond";
        worker->s->acquire = timeout;
        worker->s->acquire_set = 1;
    }
    else if (!strcasecmp(key, "timeout")) {
        /* Connection timeout in seconds.
         * Defaults to server timeout.
         */
        ival = atoi(val);
        if (ival < 1)
            return "Timeout must be at least one second";
        worker->s->timeout = apr_time_from_sec(ival);
        worker->s->timeout_set = 1;
    }
    else if (!strcasecmp(key, "iobuffersize")) {
        long s = atol(val);
        if (s < 512 && s) {
            return "IOBufferSize must be >= 512 bytes, or 0 for system default.";
        }
        worker->s->io_buffer_size = (s ? s : AP_IOBUFSIZE);
        worker->s->io_buffer_size_set = 1;
    }
    else if (!strcasecmp(key, "receivebuffersize")) {
        ival = atoi(val);
        if (ival < 512 && ival != 0) {
            return "ReceiveBufferSize must be >= 512 bytes, or 0 for system default.";
        }
        worker->s->recv_buffer_size = ival;
        worker->s->recv_buffer_size_set = 1;
    }
    else if (!strcasecmp(key, "keepalive")) {
        if (!strcasecmp(val, "on"))
            worker->s->keepalive = 1;
        else if (!strcasecmp(val, "off"))
            worker->s->keepalive = 0;
        else
            return "KeepAlive must be On|Off";
        worker->s->keepalive_set = 1;
    }
    else if (!strcasecmp(key, "disablereuse")) {
        if (!strcasecmp(val, "on"))
            worker->s->disablereuse = 1;
        else if (!strcasecmp(val, "off"))
            worker->s->disablereuse = 0;
        else
            return "DisableReuse must be On|Off";
        worker->s->disablereuse_set = 1;
    }
    else if (!strcasecmp(key, "enablereuse")) {
        if (!strcasecmp(val, "on"))
            worker->s->disablereuse = 0;
        else if (!strcasecmp(val, "off"))
            worker->s->disablereuse = 1;
        else
            return "EnableReuse must be On|Off";
        worker->s->disablereuse_set = 1;
    }
    else if (!strcasecmp(key, "route")) {
        /* Worker route.
         */
        if (strlen(val) >= sizeof(worker->s->route))
            return apr_psprintf(p, "Route length must be < %d characters",
                    (int)sizeof(worker->s->route));
        PROXY_STRNCPY(worker->s->route, val);
    }
    else if (!strcasecmp(key, "redirect")) {
        /* Worker redirection route.
         */
        if (strlen(val) >= sizeof(worker->s->redirect))
            return apr_psprintf(p, "Redirect length must be < %d characters",
                    (int)sizeof(worker->s->redirect));
        PROXY_STRNCPY(worker->s->redirect, val);
    }
    else if (!strcasecmp(key, "status")) {
        const char *v;
        int mode = 1;
        apr_status_t rv;
        /* Worker status.
         */
        for (v = val; *v; v++) {
            if (*v == '+') {
                mode = 1;
                v++;
            }
            else if (*v == '-') {
                mode = 0;
                v++;
            }
            rv = ap_proxy_set_wstatus(*v, mode, worker);
            if (rv != APR_SUCCESS)
                return "Unknown status parameter option";
        }
    }
    else if (!strcasecmp(key, "flushpackets")) {
        if (!strcasecmp(val, "on"))
            worker->s->flush_packets = flush_on;
        else if (!strcasecmp(val, "off"))
            worker->s->flush_packets = flush_off;
        else if (!strcasecmp(val, "auto"))
            worker->s->flush_packets = flush_auto;
        else
            return "flushpackets must be on|off|auto";
    }
    else if (!strcasecmp(key, "flushwait")) {
        ival = atoi(val);
        if (ival > 1000 || ival < 0) {
            return "flushwait must be <= 1000, or 0 for system default of 10 millseconds.";
        }
        if (ival == 0)
            worker->s->flush_wait = PROXY_FLUSH_WAIT;
        else
            worker->s->flush_wait = ival * 1000;    /* change to microseconds */
    }
    else if (!strcasecmp(key, "ping")) {
        /* Ping/Pong timeout in given unit (default is second).
         */
        if (ap_timeout_parameter_parse(val, &timeout, "s") != APR_SUCCESS)
            return "Ping/Pong timeout has wrong format";
        if (timeout < 1000)
            return "Ping/Pong timeout must be at least one millisecond";
        worker->s->ping_timeout = timeout;
        worker->s->ping_timeout_set = 1;
    }
    else if (!strcasecmp(key, "lbset")) {
        ival = atoi(val);
        if (ival < 0 || ival > 99)
            return "lbset must be between 0 and 99";
        worker->s->lbset = ival;
    }
    else if (!strcasecmp(key, "connectiontimeout")) {
        /* Request timeout in given unit (default is second).
         * Defaults to connection timeout
         */
        if (ap_timeout_parameter_parse(val, &timeout, "s") != APR_SUCCESS)
            return "Connectiontimeout has wrong format";
        if (timeout < 1000)
            return "Connectiontimeout must be at least one millisecond.";
        worker->s->conn_timeout = timeout;
        worker->s->conn_timeout_set = 1;
    }
    else if (!strcasecmp(key, "flusher")) {
        if (PROXY_STRNCPY(worker->s->flusher, val) != APR_SUCCESS) {
            return apr_psprintf(p, "flusher name length must be < %d characters",
                                (int)sizeof(worker->s->flusher));
        }
    }
    else if (!strcasecmp(key, "upgrade")) {
        if (PROXY_STRNCPY(worker->s->upgrade,
                          strcasecmp(val, "ANY") ? val : "*") != APR_SUCCESS) {
            return apr_psprintf(p, "upgrade protocol length must be < %d characters",
                                (int)sizeof(worker->s->upgrade));
        }
    }
    else if (!strcasecmp(key, "responsefieldsize")) {
        long s = atol(val);
        if (s < 0) {
            return "ResponseFieldSize must be greater than 0 bytes, or 0 for system default.";
        }
        worker->s->response_field_size = (s ? s : HUGE_STRING_LEN);
        worker->s->response_field_size_set = 1;
    }
    else if (!strcasecmp(key, "secret")) {
        if (PROXY_STRNCPY(worker->s->secret, val) != APR_SUCCESS) {
            return apr_psprintf(p, "Secret length must be < %d characters",
                                (int)sizeof(worker->s->secret));
        }
    }
    else {
        if (set_worker_hc_param_f) {
            return set_worker_hc_param_f(p, s, worker, key, val, NULL);
        } else {
            return "unknown Worker parameter";
        }
    }
    return NULL;
}

static const char *set_balancer_param(proxy_server_conf *conf,
                                      apr_pool_t *p,
                                      proxy_balancer *balancer,
                                      const char *key,
                                      const char *val)
{

    int ival;
    if (!strcasecmp(key, "stickysession")) {
        char *path;
        /* Balancer sticky session name.
         * Set to something like JSESSIONID or
         * PHPSESSIONID, etc..,
         */
        if (strlen(val) >= sizeof(balancer->s->sticky_path))
            apr_psprintf(p, "stickysession length must be < %d characters",
                    (int)sizeof(balancer->s->sticky_path));
        PROXY_STRNCPY(balancer->s->sticky_path, val);
        PROXY_STRNCPY(balancer->s->sticky, val);

        if ((path = strchr((char *)balancer->s->sticky, '|'))) {
            *path++ = '\0';
            PROXY_STRNCPY(balancer->s->sticky_path, path);
        }
    }
    else if (!strcasecmp(key, "stickysessionsep")) {
        /* separator/delimiter for sessionid and route,
         * normally '.'
         */
        if (strlen(val) != 1) {
            if (!strcasecmp(val, "off"))
                balancer->s->sticky_separator = 0;
            else      
                return "stickysessionsep must be a single character or Off";
        }
        else
            balancer->s->sticky_separator = *val;
        balancer->s->sticky_separator_set = 1;
    }
    else if (!strcasecmp(key, "nofailover")) {
        /* If set to 'on' the session will break
         * if the worker is in error state or
         * disabled.
         */
        if (!strcasecmp(val, "on"))
            balancer->s->sticky_force = 1;
        else if (!strcasecmp(val, "off"))
            balancer->s->sticky_force = 0;
        else
            return "failover must be On|Off";
        balancer->s->sticky_force_set = 1;
    }
    else if (!strcasecmp(key, "timeout")) {
        /* Balancer timeout in seconds.
         * If set this will be the maximum time to
         * wait for a free worker.
         * Default is not to wait.
         */
        ival = atoi(val);
        if (ival < 1)
            return "timeout must be at least one second";
        balancer->s->timeout = apr_time_from_sec(ival);
    }
    else if (!strcasecmp(key, "maxattempts")) {
        /* Maximum number of failover attempts before
         * giving up.
         */
        ival = atoi(val);
        if (ival < 0)
            return "maximum number of attempts must be a positive number";
        balancer->s->max_attempts = ival;
        balancer->s->max_attempts_set = 1;
    }
    else if (!strcasecmp(key, "lbmethod")) {
        proxy_balancer_method *provider;
        if (strlen(val) > (sizeof(balancer->s->lbpname)-1))
            return "unknown lbmethod";
        provider = ap_lookup_provider(PROXY_LBMETHOD, val, "0");
        if (provider) {
            balancer->lbmethod = provider;
            if (PROXY_STRNCPY(balancer->s->lbpname, val) == APR_SUCCESS) {
                balancer->lbmethod_set = 1;
                return NULL;
            }
            else {
                return "lbmethod name too large";
            }
        }
        return "unknown lbmethod";
    }
    else if (!strcasecmp(key, "scolonpathdelim")) {
        /* If set to 'on' then ';' will also be
         * used as a session path separator/delim (ala
         * mod_jk)
         */
        if (!strcasecmp(val, "on"))
            balancer->s->scolonsep = 1;
        else if (!strcasecmp(val, "off"))
            balancer->s->scolonsep = 0;
        else
            return "scolonpathdelim must be On|Off";
        balancer->s->scolonsep_set = 1;
    }
    else if (!strcasecmp(key, "failonstatus")) {
        char *val_split;
        char *status;
        char *tok_state;

        val_split = apr_pstrdup(p, val);

        balancer->errstatuses = apr_array_make(p, 1, sizeof(int));

        status = apr_strtok(val_split, ", ", &tok_state);
        while (status != NULL) {
            ival = atoi(status);
            if (ap_is_HTTP_VALID_RESPONSE(ival)) {
                *(int *)apr_array_push(balancer->errstatuses) = ival;
            }
            else {
                return "failonstatus must be one or more HTTP response codes";
            }
            status = apr_strtok(NULL, ", ", &tok_state);
        }

    }
    else if (!strcasecmp(key, "failontimeout")) {
        if (!strcasecmp(val, "on"))
            balancer->failontimeout = 1;
        else if (!strcasecmp(val, "off"))
            balancer->failontimeout = 0;
        else
            return "failontimeout must be On|Off";
        balancer->failontimeout_set = 1;
    }
    else if (!strcasecmp(key, "nonce")) {
        if (!strcasecmp(val, "None")) {
            *balancer->s->nonce = '\0';
        }
        else {
            if (PROXY_STRNCPY(balancer->s->nonce, val) != APR_SUCCESS) {
                return "Provided nonce is too large";
            }
        }
        balancer->s->nonce_set = 1;
    }
    else if (!strcasecmp(key, "growth")) {
        ival = atoi(val);
        if (ival < 1 || ival > 100)   /* arbitrary limit here */
            return "growth must be between 1 and 100";
        balancer->growth = ival;
        balancer->growth_set = 1;
    }
    else if (!strcasecmp(key, "forcerecovery")) {
        if (!strcasecmp(val, "on"))
            balancer->s->forcerecovery = 1;
        else if (!strcasecmp(val, "off"))
            balancer->s->forcerecovery = 0;
        else
            return "forcerecovery must be On|Off";
        balancer->s->forcerecovery_set = 1;
    }
    else {
        return "unknown Balancer parameter";
    }
    return NULL;
}

static int alias_match(const char *uri, const char *alias_fakename)
{
    const char *end_fakename = alias_fakename + strlen(alias_fakename);
    const char *aliasp = alias_fakename, *urip = uri;
    const char *end_uri = uri + strlen(uri);

    while (aliasp < end_fakename && urip < end_uri) {
        if (*aliasp == '/') {
            /* any number of '/' in the alias matches any number in
             * the supplied URI, but there must be at least one...
             */
            if (*urip != '/')
                return 0;

            while (*aliasp == '/')
                ++aliasp;
            while (*urip == '/')
                ++urip;
        }
        else {
            /* Other characters are compared literally */
            if (*urip++ != *aliasp++)
                return 0;
        }
    }

    /* fixup badly encoded stuff (e.g. % as last character) */
    if (aliasp > end_fakename) {
        aliasp = end_fakename;
    }
    if (urip > end_uri) {
        urip = end_uri;
    }

   /* We reach the end of the uri before the end of "alias_fakename"
    * for example uri is "/" and alias_fakename "/examples"
    */
   if (urip == end_uri && aliasp != end_fakename) {
       return 0;
   }

    /* Check last alias path component matched all the way */
    if (aliasp[-1] != '/' && *urip != '\0' && *urip != '/')
        return 0;

    /* Return number of characters from URI which matched (may be
     * greater than length of alias, since we may have matched
     * doubled slashes)
     */

    return urip - uri;
}

/*
 * Inspired by mod_jk's jk_servlet_normalize().
 */
static int alias_match_servlet(apr_pool_t *p,
                               const char **urip,
                               const char *alias)
{
    char *map;
    const char *uri = *urip;
    apr_array_header_t *stack;
    int map_pos, uri_pos, alias_pos, first_pos;
    int alias_depth = 0, depth;

    /* Both uri and alias should start with '/' */
    if (uri[0] != '/' || alias[0] != '/') {
        return 0;
    }

    stack = apr_array_make(p, 5, sizeof(int));
    map = apr_palloc(p, strlen(uri) + 1);
    map[0] = '/';
    map[1] = '\0';

    map_pos = uri_pos = alias_pos = first_pos = 1;
    while (uri[uri_pos] != '\0') {
        /* Remove path parameters ;foo=bar/ from any path segment */
        if (uri[uri_pos] == ';') {
            do {
                uri_pos++;
            } while (uri[uri_pos] != '/' && uri[uri_pos] != '\0');
            continue;
        }

        if (map[map_pos - 1] == '/') {
            /* Collapse ///// sequences to / */
            if (uri[uri_pos] == '/') {
                do {
                    uri_pos++;
                } while (uri[uri_pos] == '/');
                continue;
            }

            if (uri[uri_pos] == '.') {
                /* Remove /./ segments */
                if (uri[uri_pos + 1] == '/'
                        || uri[uri_pos + 1] == ';'
                        || uri[uri_pos + 1] == '\0') {
                    uri_pos++;
                    if (uri[uri_pos] == '/') {
                        uri_pos++;
                    }
                    continue;
                }

                /* Remove /xx/../ segments */
                if (uri[uri_pos + 1] == '.'
                    && (uri[uri_pos + 2] == '/'
                        || uri[uri_pos + 2] == ';'
                        || uri[uri_pos + 2] == '\0')) {
                    /* Wind map segment back the previous one */
                    if (map_pos == 1) {
                        /* Above root */
                        return 0;
                    }
                    do {
                        map_pos--;
                    } while (map[map_pos - 1] != '/');
                    map[map_pos] = '\0';

                    /* Wind alias segment back, unless in deeper segment */
                    if (alias_depth == stack->nelts) {
                        if (alias[alias_pos] == '\0') {
                            alias_pos--;
                        }
                        while (alias_pos > 0 && alias[alias_pos] == '/') {
                            alias_pos--;
                        }
                        while (alias_pos > 0 && alias[alias_pos - 1] != '/') {
                            alias_pos--;
                        }
                        AP_DEBUG_ASSERT(alias_pos > 0);
                        alias_depth--;
                    }
                    apr_array_pop(stack);

                    /* Move uri forward to the next segment */
                    uri_pos += 2;
                    if (uri[uri_pos] == '/') {
                        uri_pos++;
                    }
                    first_pos = 0;
                    continue;
                }
            }
            if (first_pos) {
                while (uri[first_pos] == '/') {
                    first_pos++;
                }
            }

            /* New segment */
            APR_ARRAY_PUSH(stack, int) = first_pos ? first_pos : uri_pos;
            if (alias[alias_pos] != '\0') {
                if (alias[alias_pos - 1] != '/') {
                    /* Remain in pair with uri segments */
                    do {
                        alias_pos++;
                    } while (alias[alias_pos - 1] != '/' && alias[alias_pos]);
                }
                while (alias[alias_pos] == '/') {
                    alias_pos++;
                }
                if (alias[alias_pos] != '\0') {
                    alias_depth++;
                }
            }
        }

        if (alias[alias_pos] != '\0') {
            int *match = &APR_ARRAY_IDX(stack, alias_depth - 1, int);
            if (*match) {
                if (alias[alias_pos] != uri[uri_pos]) {
                    /* Current segment does not match */
                    *match = 0;
                }
                else if (alias[alias_pos + 1] == '\0'
                         && alias[alias_pos] != '/') {
                    if (uri[uri_pos + 1] == ';') {
                        /* We'll preserve the parameters of the last
                         * segment if it does not end with '/', so mark
                         * the match as negative for below handling.
                         */
                        *match = -(uri_pos + 1);
                    }
                    else if (uri[uri_pos + 1] != '/'
                             && uri[uri_pos + 1] != '\0') {
                        /* Last segment does not match all the way */
                        *match = 0;
                    }
                }
            }
            /* Don't go past the segment if the uri isn't there yet */
            if (alias[alias_pos] != '/' || uri[uri_pos] == '/') {
                alias_pos++;
            }
        }

        if (uri[uri_pos] == '/') {
            first_pos = uri_pos + 1;
        }
        map[map_pos++] = uri[uri_pos++];
        map[map_pos] = '\0';
    }

    /* Can't reach the end of uri before the end of the alias,
     * for example if uri is "/" and alias is "/examples"
     */
    if (alias[alias_pos] != '\0') {
        return 0;
    }

    /* Check whether each alias segment matched */
    for (depth = 0; depth < alias_depth; ++depth) {
        if (!APR_ARRAY_IDX(stack, depth, int)) {
            return 0;
        }
    }

    /* If alias_depth == stack->nelts we have a full match, i.e.
     * uri == alias so we can return uri_pos as is (the end of uri)
     */
    if (alias_depth < stack->nelts) {
        /* Return the segment following the alias */
        uri_pos = APR_ARRAY_IDX(stack, alias_depth, int);
        if (alias_depth) {
            /* But if the last segment of the alias does not end with '/'
             * and the corresponding segment of the uri has parameters,
             * we want to forward those parameters (see above for the
             * negative pos trick/mark).
             */
            int pos = APR_ARRAY_IDX(stack, alias_depth - 1, int);
            if (pos < 0) {
                uri_pos = -pos;
            }
        }
    }
    /* If the alias lacks a trailing slash, take it from the uri (if any) */
    if (alias[alias_pos - 1] != '/' && uri[uri_pos - 1] == '/') {
        uri_pos--;
    }

    *urip = map;
    return uri_pos;
}

/* Detect if an absoluteURI should be proxied or not.  Note that we
 * have to do this during this phase because later phases are
 * "short-circuiting"... i.e. translate_names will end when the first
 * module returns OK.  So for example, if the request is something like:
 *
 * GET http://othervhost/cgi-bin/printenv HTTP/1.0
 *
 * mod_alias will notice the /cgi-bin part and ScriptAlias it and
 * short-circuit the proxy... just because of the ordering in the
 * configuration file.
 */
static int proxy_detect(request_rec *r)
{
    void *sconf = r->server->module_config;
    proxy_server_conf *conf =
        (proxy_server_conf *) ap_get_module_config(sconf, &proxy_module);

    /* Ick... msvc (perhaps others) promotes ternary short results to int */

    if (conf->req && r->parsed_uri.scheme) {
        /* but it might be something vhosted */
        if (!r->parsed_uri.hostname
            || ap_cstr_casecmp(r->parsed_uri.scheme, ap_http_scheme(r)) != 0
            || !ap_matches_request_vhost(r, r->parsed_uri.hostname,
                                         (apr_port_t)(r->parsed_uri.port_str
                                                      ? r->parsed_uri.port
                                                      : ap_default_port(r)))) {
            r->proxyreq = PROXYREQ_PROXY;
            r->uri = r->unparsed_uri;
            r->filename = apr_pstrcat(r->pool, "proxy:", r->uri, NULL);
            r->handler = "proxy-server";
        }
    }
    /* We need special treatment for CONNECT proxying: it has no scheme part */
    else if (conf->req && r->method_number == M_CONNECT
             && r->parsed_uri.hostname
             && r->parsed_uri.port_str) {
        r->proxyreq = PROXYREQ_PROXY;
        r->uri = r->unparsed_uri;
        r->filename = apr_pstrcat(r->pool, "proxy:", r->uri, NULL);
        r->handler = "proxy-server";
    }
    return DECLINED;
}

static const char *proxy_interpolate(request_rec *r, const char *str)
{
    /* Interpolate an env str in a configuration string
     * Syntax ${var} --> value_of(var)
     * Method: replace one var, and recurse on remainder of string
     * Nothing clever here, and crap like nested vars may do silly things
     * but we'll at least avoid sending the unwary into a loop
     */
    const char *start;
    const char *end;
    const char *var;
    const char *val;
    const char *firstpart;

    start = ap_strstr_c(str, "${");
    if (start == NULL) {
        return str;
    }
    end = ap_strchr_c(start+2, '}');
    if (end == NULL) {
        return str;
    }
    /* OK, this is syntax we want to interpolate.  Is there such a var ? */
    var = apr_pstrmemdup(r->pool, start+2, end-(start+2));
    val = apr_table_get(r->subprocess_env, var);
    firstpart = apr_pstrmemdup(r->pool, str, (start-str));

    if (val == NULL) {
        return apr_pstrcat(r->pool, firstpart,
                           proxy_interpolate(r, end+1), NULL);
    }
    else {
        return apr_pstrcat(r->pool, firstpart, val,
                           proxy_interpolate(r, end+1), NULL);
    }
}
static apr_array_header_t *proxy_vars(request_rec *r,
                                      apr_array_header_t *hdr)
{
    int i;
    apr_array_header_t *ret = apr_array_make(r->pool, hdr->nelts,
                                             sizeof (struct proxy_alias));
    struct proxy_alias *old = (struct proxy_alias *) hdr->elts;

    for (i = 0; i < hdr->nelts; ++i) {
        struct proxy_alias *newcopy = apr_array_push(ret);
        newcopy->fake = (old[i].flags & PROXYPASS_INTERPOLATE)
                        ? proxy_interpolate(r, old[i].fake) : old[i].fake;
        newcopy->real = (old[i].flags & PROXYPASS_INTERPOLATE)
                        ? proxy_interpolate(r, old[i].real) : old[i].real;
    }
    return ret;
}

PROXY_DECLARE(int) ap_proxy_trans_match(request_rec *r, struct proxy_alias *ent,
                                        proxy_dir_conf *dconf)
{
    int len;
    const char *fake;
    const char *real;
    ap_regmatch_t regm[AP_MAX_REG_MATCH];
    ap_regmatch_t reg1[AP_MAX_REG_MATCH];
    char *found = NULL;
    int mismatch = 0;
    unsigned int nocanon = ent->flags & PROXYPASS_NOCANON;
    const char *use_uri = nocanon ? r->unparsed_uri : r->uri;
    const char *servlet_uri = NULL;

    if (dconf && (dconf->interpolate_env == 1) && (ent->flags & PROXYPASS_INTERPOLATE)) {
        fake = proxy_interpolate(r, ent->fake);
        real = proxy_interpolate(r, ent->real);
    }
    else {
        fake = ent->fake;
        real = ent->real;
    }

    ap_log_rerror(APLOG_MARK, APLOG_TRACE2, 0, r, APLOGNO(03461)
                  "attempting to match URI path '%s' against %s '%s' for "
                  "proxying", r->uri, (ent->regex ? "pattern" : "prefix"),
                  fake);

    if (ent->regex) {
        if (!ap_regexec(ent->regex, r->uri, AP_MAX_REG_MATCH, regm, 0)) {
            if ((real[0] == '!') && (real[1] == '\0')) {
                ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r, APLOGNO(03462)
                              "proxying is explicitly disabled for URI path "
                              "'%s'; declining", r->uri);
                return DECLINED;
            }
            /* test that we haven't reduced the URI */
            if (nocanon && ap_regexec(ent->regex, r->unparsed_uri,
                    AP_MAX_REG_MATCH, reg1, 0)) {
                mismatch = 1;
                use_uri = r->uri;
            }
            found = ap_pregsub(r->pool, real, use_uri, AP_MAX_REG_MATCH,
                    (use_uri == r->uri) ? regm : reg1);
            if (!found) {
                ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0, r, APLOGNO(01135)
                              "Substitution in regular expression failed. "
                              "Replacement too long?");
                return HTTP_INTERNAL_SERVER_ERROR;
            }

            /* Note: The strcmp() below catches cases where there
             * was no regex substitution. This is so cases like:
             *
             *    ProxyPassMatch \.gif balancer://foo
             *
             * will work "as expected". The upshot is that the 2
             * directives below act the exact same way (ie: $1 is implied):
             *
             *    ProxyPassMatch ^(/.*\.gif)$ balancer://foo
             *    ProxyPassMatch ^(/.*\.gif)$ balancer://foo$1
             *
             * which may be confusing.
             */
            if (strcmp(found, real) != 0) {
                found = apr_pstrcat(r->pool, "proxy:", found, NULL);
            }
            else {
                found = apr_pstrcat(r->pool, "proxy:", real, use_uri, NULL);
            }
        }
    }
    else {
        if ((ent->flags & PROXYPASS_MAP_SERVLET) == PROXYPASS_MAP_SERVLET) {
            servlet_uri = r->uri;
            len = alias_match_servlet(r->pool, &servlet_uri, fake);
            nocanon = 0; /* ignored since servlet's normalization applies */
        }
        else {
            len = alias_match(r->uri, fake);
        }

        if (len != 0) {
            if ((real[0] == '!') && (real[1] == '\0')) {
                ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r, APLOGNO(03463)
                              "proxying is explicitly disabled for URI path "
                              "'%s'; declining", r->uri);
                return DECLINED;
            }
            if (nocanon && len != alias_match(r->unparsed_uri, fake)) {
                mismatch = 1;
                use_uri = r->uri;
            }
            found = apr_pstrcat(r->pool, "proxy:", real, use_uri + len, NULL);
        }
    }
    if (mismatch) {
        /* We made a reducing transformation, so we can't safely use
         * unparsed_uri.  Safe fallback is to ignore nocanon.
         */
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, APLOGNO(01136)
                "Unescaped URL path matched ProxyPass; ignoring unsafe nocanon");
    }

    if (found) {
        unsigned int encoded = ent->flags & PROXYPASS_MAP_ENCODED;

        /* A proxy module is assigned this URL, check whether it's interested
         * in the request itself (e.g. proxy_wstunnel cares about Upgrade
         * requests only, and could hand over to proxy_http otherwise).
         */
        int rc = proxy_run_check_trans(r, found + 6);
        if (rc != OK && rc != DECLINED) {
            return HTTP_CONTINUE;
        }

        r->filename = found;
        r->handler = "proxy-server";
        r->proxyreq = PROXYREQ_REVERSE;
        if (nocanon && !mismatch) {
            /* mod_proxy_http needs to be told.  Different module. */
            apr_table_setn(r->notes, "proxy-nocanon", "1");
        }
        if (ent->flags & PROXYPASS_NOQUERY) {
            apr_table_setn(r->notes, "proxy-noquery", "1");
        }
        if (encoded) {
            apr_table_setn(r->notes, "proxy-noencode", "1");
        }

        if (servlet_uri) {
            ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r, APLOGNO(10248)
                          "Servlet path '%s' (%s) matches proxy handler '%s'",
                          r->uri, servlet_uri, found);
            /* Apply servlet normalization to r->uri so that <Location> or any
             * directory context match does not have to handle path parameters.
             * We change r->uri in-place so that r->parsed_uri.path is updated
             * too. Since normalized servlet_uri is necessarily shorter than
             * the original r->uri, strcpy() is fine.
             */
            AP_DEBUG_ASSERT(strlen(r->uri) >= strlen(servlet_uri));
            strcpy(r->uri, servlet_uri);
        }
        else {
            ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r, APLOGNO(03464)
                          "URI path '%s' matches proxy handler '%s'", r->uri,
                          found);
        }
        return (encoded) ? DONE : OK;
    }

    return HTTP_CONTINUE;
}

static int proxy_trans(request_rec *r, int pre_trans)
{
    int i, enc;
    struct proxy_alias *ent;
    proxy_dir_conf *dconf;
    proxy_server_conf *conf;

    if (r->proxyreq) {
        /* someone has already set up the proxy, it was possibly ourselves
         * in proxy_detect (DONE will prevent further decoding of r->uri,
         * only if proxyreq is set before pre_trans already).
         */
        return pre_trans ? DONE : OK;
    }

    /* In early pre_trans hook, r->uri was not manipulated yet so we are
     * compliant with RFC1945 at this point. Otherwise, it probably isn't
     * an issue because this is a hybrid proxy/origin server.
     */

    dconf = ap_get_module_config(r->per_dir_config, &proxy_module);
    conf = (proxy_server_conf *) ap_get_module_config(r->server->module_config,
                                                      &proxy_module);

    /* Always and only do PROXY_MAP_ENCODED mapping in pre_trans, when
     * r->uri is still encoded, or we might consider for instance that
     * a decoded sub-delim is now a delimiter (e.g. "%3B" => ';' for
     * path parameters), which it's not.
     */
    if ((pre_trans && !conf->map_encoded_one)
            || (!pre_trans && conf->map_encoded_all)) {
        /* Fast path, nothing at this stage */
        return DECLINED;
    }

    if ((r->unparsed_uri[0] == '*' && r->unparsed_uri[1] == '\0')
        || !r->uri || r->uri[0] != '/') {
        return DECLINED;
    }
   
    if (apr_table_get(r->subprocess_env, "no-proxy")) { 
        return DECLINED;
    }

    /* short way - this location is reverse proxied? */
    if (dconf->alias) {
        enc = (dconf->alias->flags & PROXYPASS_MAP_ENCODED) != 0;
        if (!(pre_trans ^ enc)) {
            int rv = ap_proxy_trans_match(r, dconf->alias, dconf);
            if (rv != HTTP_CONTINUE) {
                return rv;
            }
        }
    }

    /* long way - walk the list of aliases, find a match */
    for (i = 0; i < conf->aliases->nelts; i++) {
        ent = &((struct proxy_alias *)conf->aliases->elts)[i];
        enc = (ent->flags & PROXYPASS_MAP_ENCODED) != 0;
        if (!(pre_trans ^ enc)) {
            int rv = ap_proxy_trans_match(r, ent, dconf);
            if (rv != HTTP_CONTINUE) {
                return rv;
            }
        }
    }

    return DECLINED;
}

static int proxy_pre_translate_name(request_rec *r)
{
    return proxy_trans(r, 1);
}

static int proxy_translate_name(request_rec *r)
{
    return proxy_trans(r, 0);
}

static int proxy_walk(request_rec *r)
{
    proxy_server_conf *sconf = ap_get_module_config(r->server->module_config,
                                                    &proxy_module);
    ap_conf_vector_t *per_dir_defaults = r->per_dir_config;
    ap_conf_vector_t **sec_proxy = (ap_conf_vector_t **) sconf->sec_proxy->elts;
    ap_conf_vector_t *entry_config;
    proxy_dir_conf *entry_proxy;
    int num_sec = sconf->sec_proxy->nelts;
    /* XXX: shouldn't we use URI here?  Canonicalize it first?
     * Pass over "proxy:" prefix
     */
    const char *proxyname = r->filename + 6;
    int j;
    apr_pool_t *rxpool = NULL;

    for (j = 0; j < num_sec; ++j)
    {
        int nmatch = 0;
        int i;
        ap_regmatch_t *pmatch = NULL;

        entry_config = sec_proxy[j];
        entry_proxy = ap_get_module_config(entry_config, &proxy_module);

        if (entry_proxy->r) {

            if (entry_proxy->refs && entry_proxy->refs->nelts) {
                if (!rxpool) {
                    apr_pool_create(&rxpool, r->pool);
                    apr_pool_tag(rxpool, "proxy_rxpool");
                }
                nmatch = entry_proxy->refs->nelts;
                pmatch = apr_palloc(rxpool, nmatch*sizeof(ap_regmatch_t));
            }

            if (ap_regexec(entry_proxy->r, proxyname, nmatch, pmatch, 0)) {
                continue;
            }

            for (i = 0; i < nmatch; i++) {
                if (pmatch[i].rm_so >= 0 && pmatch[i].rm_eo >= 0 &&
                        ((const char **)entry_proxy->refs->elts)[i]) {
                    apr_table_setn(r->subprocess_env,
                            ((const char **)entry_proxy->refs->elts)[i],
                            apr_pstrndup(r->pool,
                                    proxyname + pmatch[i].rm_so,
                                    pmatch[i].rm_eo - pmatch[i].rm_so));
                }
            }
        }

        else if (
            /* XXX: What about case insensitive matching ???
             * Compare regex, fnmatch or string as appropriate
             * If the entry doesn't relate, then continue
             */
            entry_proxy->p_is_fnmatch ? apr_fnmatch(entry_proxy->p,
                    proxyname, 0) :
                    strncmp(proxyname, entry_proxy->p,
                            strlen(entry_proxy->p))) {
            continue;
        }
        per_dir_defaults = ap_merge_per_dir_configs(r->pool, per_dir_defaults,
                                                             entry_config);
    }

    r->per_dir_config = per_dir_defaults;

    if (rxpool) {
        apr_pool_destroy(rxpool);
    }

    return OK;
}

static int proxy_map_location(request_rec *r)
{
    int access_status;

    if (!r->proxyreq || !r->filename || strncmp(r->filename, "proxy:", 6) != 0)
        return DECLINED;

    /* Don't let the core or mod_http map_to_storage hooks handle this,
     * We don't need directory/file_walk, and we want to TRACE on our own.
     */
    if ((access_status = proxy_walk(r))) {
        ap_die(access_status, r);
        return access_status;
    }

    return OK;
}

/* -------------------------------------------------------------- */
/* Fixup the filename */

/*
 * Canonicalise the URL
 */
static int proxy_fixup(request_rec *r)
{
    char *url, *p;
    int access_status;
    proxy_dir_conf *dconf = ap_get_module_config(r->per_dir_config,
                                                 &proxy_module);

    if (!r->proxyreq || !r->filename || strncmp(r->filename, "proxy:", 6) != 0)
        return DECLINED;

    /* XXX: Shouldn't we try this before we run the proxy_walk? */
    url = &r->filename[6];

    if ((dconf->interpolate_env == 1) && (r->proxyreq == PROXYREQ_REVERSE)) {
        /* create per-request copy of reverse proxy conf,
         * and interpolate vars in it
         */
        proxy_req_conf *rconf = apr_palloc(r->pool, sizeof(proxy_req_conf));
        ap_set_module_config(r->request_config, &proxy_module, rconf);
        rconf->raliases = proxy_vars(r, dconf->raliases);
        rconf->cookie_paths = proxy_vars(r, dconf->cookie_paths);
        rconf->cookie_domains = proxy_vars(r, dconf->cookie_domains);
    }

    /* canonicalise each specific scheme */
    if ((access_status = proxy_run_canon_handler(r, url))) {
        return access_status;
    }

    p = strchr(url, ':');
    if (p == NULL || p == url)
        return HTTP_BAD_REQUEST;

    return OK;      /* otherwise; we've done the best we can */
}
/* Send a redirection if the request contains a hostname which is not */
/* fully qualified, i.e. doesn't have a domain name appended. Some proxy */
/* servers like Netscape's allow this and access hosts from the local */
/* domain in this case. I think it is better to redirect to a FQDN, since */
/* these will later be found in the bookmarks files. */
/* The "ProxyDomain" directive determines what domain will be appended */
static int proxy_needsdomain(request_rec *r, const char *url, const char *domain)
{
    char *nuri;
    const char *ref;

    /* We only want to worry about GETs */
    if (!r->proxyreq || r->method_number != M_GET || !r->parsed_uri.hostname)
        return DECLINED;

    /* If host does contain a dot already, or it is "localhost", decline */
    if (strchr(r->parsed_uri.hostname, '.') != NULL /* has domain, or IPv4 literal */
     || strchr(r->parsed_uri.hostname, ':') != NULL /* IPv6 literal */
     || ap_cstr_casecmp(r->parsed_uri.hostname, "localhost") == 0)
        return DECLINED;    /* host name has a dot already */

    ref = apr_table_get(r->headers_in, "Referer");

    /* Reassemble the request, but insert the domain after the host name */
    /* Note that the domain name always starts with a dot */
    r->parsed_uri.hostname = apr_pstrcat(r->pool, r->parsed_uri.hostname,
                                         domain, NULL);
    nuri = apr_uri_unparse(r->pool,
                           &r->parsed_uri,
                           APR_URI_UNP_REVEALPASSWORD);

    apr_table_setn(r->headers_out, "Location", nuri);
    ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, APLOGNO(01138)
                  "Domain missing: %s sent to %s%s%s", r->uri,
                  apr_uri_unparse(r->pool, &r->parsed_uri,
                                  APR_URI_UNP_OMITUSERINFO),
                  ref ? " from " : "", ref ? ref : "");

    return HTTP_MOVED_PERMANENTLY;
}

/* -------------------------------------------------------------- */
/* Invoke handler */

static int proxy_handler(request_rec *r)
{
    char *uri, *scheme, *p;
    const char *p2;
    void *sconf = r->server->module_config;
    proxy_server_conf *conf = (proxy_server_conf *)
        ap_get_module_config(sconf, &proxy_module);
    apr_array_header_t *proxies = conf->proxies;
    struct proxy_remote *ents = (struct proxy_remote *) proxies->elts;
    int i, rc, access_status;
    int direct_connect = 0;
    const char *str;
    apr_int64_t maxfwd;
    proxy_balancer *balancer = NULL;
    proxy_worker *worker = NULL;
    int attempts = 0, max_attempts = 0;
    struct dirconn_entry *list = (struct dirconn_entry *)conf->dirconn->elts;
    int saved_status;

    /* is this for us? */
    if (!r->filename) {
        return DECLINED;
    }

    if (!r->proxyreq) {
        /* We may have forced the proxy handler via config or .htaccess */
        if (r->handler &&
            strncmp(r->handler, "proxy:", 6) == 0 &&
            strncmp(r->filename, "proxy:", 6) != 0) {
            r->proxyreq = PROXYREQ_REVERSE;
            r->filename = apr_pstrcat(r->pool, r->handler, r->filename, NULL);
        }
        else {
            return DECLINED;
        }
    } else if (strncmp(r->filename, "proxy:", 6) != 0) {
        return DECLINED;
    }

    /* handle max-forwards / OPTIONS / TRACE */
    if ((str = apr_table_get(r->headers_in, "Max-Forwards"))) {
        char *end;
        maxfwd = apr_strtoi64(str, &end, 10);
        if (maxfwd < 0 || maxfwd == APR_INT64_MAX || *end) {
            ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, APLOGNO(10188) 
                          "Max-Forwards value '%s' could not be parsed", str);
            return ap_proxyerror(r, HTTP_BAD_REQUEST, 
                          "Max-Forwards request header could not be parsed");
        }
        else if (maxfwd == 0) {
            switch (r->method_number) {
            case M_TRACE: {
                int access_status;
                r->proxyreq = PROXYREQ_NONE;
                access_status = ap_send_http_trace(r);
                ap_die(access_status, r);
                return OK;
            }
            case M_OPTIONS: {
                int access_status;
                r->proxyreq = PROXYREQ_NONE;
                access_status = ap_send_http_options(r);
                ap_die(access_status, r);
                return OK;
            }
            default: {
                return ap_proxyerror(r, HTTP_BAD_REQUEST,
                                     "Max-Forwards has reached zero - proxy loop?");
            }
            }
        }
        maxfwd = (maxfwd > 0) ? maxfwd - 1 : 0;
    }
    else {
        /* set configured max-forwards */
        maxfwd = conf->maxfwd;
    }
    if (maxfwd >= 0) {
        apr_table_setn(r->headers_in, "Max-Forwards",
                       apr_psprintf(r->pool, "%" APR_INT64_T_FMT, maxfwd));
    }

    if (r->method_number == M_TRACE) {
        core_server_config *coreconf = (core_server_config *)
                                       ap_get_core_module_config(sconf);

        if (coreconf->trace_enable == AP_TRACE_DISABLE)
        {
            /* Allow "error-notes" string to be printed by ap_send_error_response()
             * Note; this goes nowhere, canned error response need an overhaul.
             */
            apr_table_setn(r->notes, "error-notes",
                           "TRACE forbidden by server configuration");
            apr_table_setn(r->notes, "verbose-error-to", "*");
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01139)
                          "TRACE forbidden by server configuration");
            return HTTP_METHOD_NOT_ALLOWED;
        }

        /* Can't test ap_should_client_block, we aren't ready to send
         * the client a 100 Continue response till the connection has
         * been established
         */
        if (coreconf->trace_enable != AP_TRACE_EXTENDED
            && (r->read_length || r->read_chunked || r->remaining))
        {
            /* Allow "error-notes" string to be printed by ap_send_error_response()
             * Note; this goes nowhere, canned error response need an overhaul.
             */
            apr_table_setn(r->notes, "error-notes",
                           "TRACE with request body is not allowed");
            apr_table_setn(r->notes, "verbose-error-to", "*");
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01140)
                          "TRACE with request body is not allowed");
            return HTTP_REQUEST_ENTITY_TOO_LARGE;
        }
    }

    uri = r->filename + 6;
    p = strchr(uri, ':');
    if (p == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01141)
                      "proxy_handler no URL in %s", r->filename);
        return HTTP_BAD_REQUEST;
    }

    /* If the host doesn't have a domain name, add one and redirect. */
    if (conf->domain != NULL) {
        rc = proxy_needsdomain(r, uri, conf->domain);
        if (ap_is_HTTP_REDIRECT(rc))
            return HTTP_MOVED_PERMANENTLY;
    }

    scheme = apr_pstrmemdup(r->pool, uri, p - uri);
    /* Check URI's destination host against NoProxy hosts */
    /* Bypass ProxyRemote server lookup if configured as NoProxy */
    for (direct_connect = i = 0; i < conf->dirconn->nelts &&
                                        !direct_connect; i++) {
        direct_connect = list[i].matcher(&list[i], r);
    }
#if DEBUGGING
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                (direct_connect) ? APLOGNO(03231) "NoProxy for %s" : APLOGNO(03232) "UseProxy for %s",
                r->uri);
#endif

    do {
        char *url = uri;
        /* Try to obtain the most suitable worker */
        access_status = ap_proxy_pre_request(&worker, &balancer, r, conf, &url);
        if (access_status != OK) {
            /*
             * Only return if access_status is not HTTP_SERVICE_UNAVAILABLE
             * This gives other modules the chance to hook into the
             * request_status hook and decide what to do in this situation.
             */
            if (access_status != HTTP_SERVICE_UNAVAILABLE)
                return access_status;
            /*
             * Ensure that balancer is NULL if worker is NULL to prevent
             * potential problems in the post_request hook.
             */
            if (!worker)
                balancer = NULL;
            goto cleanup;
        }

        /* Initialise worker if needed, note the shared area must be initialized by the balancer logic */
        if (balancer) {
            ap_proxy_initialize_worker(worker, r->server, conf->pool);
        }

        if (balancer && balancer->s->max_attempts_set && !max_attempts)
            max_attempts = balancer->s->max_attempts;
        /* firstly, try a proxy, unless a NoProxy directive is active */
        if (!direct_connect) {
            for (i = 0; i < proxies->nelts; i++) {
                p2 = ap_strchr_c(ents[i].scheme, ':');  /* is it a partial URL? */
                if (strcmp(ents[i].scheme, "*") == 0 ||
                    (ents[i].use_regex &&
                     ap_regexec(ents[i].regexp, url, 0, NULL, 0) == 0) ||
                    (p2 == NULL && ap_cstr_casecmp(scheme, ents[i].scheme) == 0) ||
                    (p2 != NULL &&
                    ap_cstr_casecmpn(url, ents[i].scheme,
                                strlen(ents[i].scheme)) == 0)) {

                    /* handle the scheme */
                    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01142)
                                  "Trying to run scheme_handler against proxy");
                    access_status = proxy_run_scheme_handler(r, worker,
                                                             conf, url,
                                                             ents[i].hostname,
                                                             ents[i].port);

                    /* Did the scheme handler process the request? */
                    if (access_status != DECLINED) {
                        const char *cl_a;
                        apr_off_t cl;

                        /*
                         * An fatal error or success, so no point in
                         * retrying with a direct connection.
                         */
                        if (access_status != HTTP_BAD_GATEWAY) {
                            goto cleanup;
                        }

                        cl_a = apr_table_get(r->headers_in, "Content-Length");
                        if (cl_a && (!ap_parse_strict_length(&cl, cl_a)
                                     || cl > 0)) {
                            /*
                             * The request body is of length > 0. We cannot
                             * retry with a direct connection since we already
                             * sent (parts of) the request body to the proxy
                             * and do not have any longer.
                             */
                            goto cleanup;
                        }
                        /*
                         * Transfer-Encoding was set as input header, so we had
                         * a request body. We cannot retry with a direct
                         * connection for the same reason as above.
                         */
                        if (apr_table_get(r->headers_in, "Transfer-Encoding")) {
                            goto cleanup;
                        }
                    }
                }
            }
        }

        /* otherwise, try it direct */
        /* N.B. what if we're behind a firewall, where we must use a proxy or
        * give up??
        */

        /* handle the scheme */
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01143)
                      "Running scheme %s handler (attempt %d)",
                      scheme, attempts);
        AP_PROXY_RUN(r, worker, conf, url, attempts);
        access_status = proxy_run_scheme_handler(r, worker, conf,
                                                 url, NULL, 0);
        if (access_status == OK
                || apr_table_get(r->notes, "proxy-error-override"))
            break;
        else if (access_status == HTTP_INTERNAL_SERVER_ERROR) {
            /* Unrecoverable server error.
             * We can not failover to another worker.
             * Mark the worker as unusable if member of load balancer
             */
            if (balancer
                && !(worker->s->status & PROXY_WORKER_IGNORE_ERRORS)) {
                worker->s->status |= PROXY_WORKER_IN_ERROR;
                worker->s->error_time = apr_time_now();
            }
            break;
        }
        else if (access_status == HTTP_SERVICE_UNAVAILABLE) {
            /* Recoverable server error.
             * We can failover to another worker
             * Mark the worker as unusable if member of load balancer
             */
            if (balancer
                && !(worker->s->status & PROXY_WORKER_IGNORE_ERRORS)) {
                worker->s->status |= PROXY_WORKER_IN_ERROR;
                worker->s->error_time = apr_time_now();
            }
        }
        else {
            /* Unrecoverable error.
             * Return the origin status code to the client.
             */
            break;
        }
        /* Try again if the worker is unusable and the service is
         * unavailable.
         */
    } while (!PROXY_WORKER_IS_USABLE(worker) &&
             max_attempts > attempts++);

    if (DECLINED == access_status) {
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, APLOGNO(01144)
                      "No protocol handler was valid for the URL %s " 
                      "(scheme '%s'). "
                      "If you are using a DSO version of mod_proxy, make sure "
                      "the proxy submodules are included in the configuration "
                      "using LoadModule.", r->uri, scheme);
        access_status = HTTP_INTERNAL_SERVER_ERROR;
        goto cleanup;
    }
cleanup:
    /*
     * Save current r->status and set it to the value of access_status which
     * might be different (e.g. r->status could be HTTP_OK if e.g. we override
     * the error page on the proxy or if the error was not generated by the
     * backend itself but by the proxy e.g. a bad gateway) in order to give
     * ap_proxy_post_request a chance to act correctly on the status code.
     * But only do the above if access_status is not OK and not DONE, because
     * in this case r->status might contain the true status and overwriting
     * it with OK or DONE would be wrong.
     */
    if ((access_status != OK) && (access_status != DONE)) {
        saved_status = r->status;
        r->status = access_status;
        ap_proxy_post_request(worker, balancer, r, conf);
        /*
         * Only restore r->status if it has not been changed by
         * ap_proxy_post_request as we assume that this change was intentional.
         */
        if (r->status == access_status) {
            r->status = saved_status;
        }
    }
    else {
        ap_proxy_post_request(worker, balancer, r, conf);
    }

    proxy_run_request_status(&access_status, r);
    AP_PROXY_RUN_FINISHED(r, attempts, access_status);

    return access_status;
}

/* -------------------------------------------------------------- */
/* Setup configurable data */

static void * create_proxy_config(apr_pool_t *p, server_rec *s)
{
    proxy_server_conf *ps = apr_pcalloc(p, sizeof(proxy_server_conf));

    ps->sec_proxy = apr_array_make(p, 10, sizeof(ap_conf_vector_t *));
    ps->proxies = apr_array_make(p, 10, sizeof(struct proxy_remote));
    ps->aliases = apr_array_make(p, 10, sizeof(struct proxy_alias));
    ps->noproxies = apr_array_make(p, 10, sizeof(struct noproxy_entry));
    ps->dirconn = apr_array_make(p, 10, sizeof(struct dirconn_entry));
    ps->workers = apr_array_make(p, 10, sizeof(proxy_worker));
    ps->balancers = apr_array_make(p, 10, sizeof(proxy_balancer));
    ps->forward = NULL;
    ps->reverse = NULL;
    ps->domain = NULL;
    ps->map_encoded_one = 0;
    ps->map_encoded_all = 1;
    ps->id = apr_psprintf(p, "p%x", 1); /* simply for storage size */
    ps->viaopt = via_off; /* initially backward compatible with 1.3.1 */
    ps->viaopt_set = 0; /* 0 means default */
    ps->req = 0;
    ps->max_balancers = 0;
    ps->bal_persist = 0;
    ps->inherit = 1;
    ps->inherit_set = 0;
    ps->ppinherit = 1;
    ps->ppinherit_set = 0;
    ps->bgrowth = 5;
    ps->bgrowth_set = 0;
    ps->req_set = 0;
    ps->recv_buffer_size = 0; /* this default was left unset for some reason */
    ps->recv_buffer_size_set = 0;
    ps->io_buffer_size = AP_IOBUFSIZE;
    ps->io_buffer_size_set = 0;
    ps->maxfwd = DEFAULT_MAX_FORWARDS;
    ps->maxfwd_set = 0;
    ps->timeout = 0;
    ps->timeout_set = 0;
    ps->badopt = bad_error;
    ps->badopt_set = 0;
    ps->source_address = NULL;
    ps->source_address_set = 0;
    apr_pool_create_ex(&ps->pool, p, NULL, NULL);
    apr_pool_tag(ps->pool, "proxy_server_conf");

    return ps;
}

static apr_array_header_t *merge_balancers(apr_pool_t *p,
                                           apr_array_header_t *base,
                                           apr_array_header_t *overrides)
{
    proxy_balancer *b1;
    proxy_balancer *b2;
    proxy_balancer tmp;
    int x, y, found;
    apr_array_header_t *tocopy = apr_array_make(p, 1, sizeof(proxy_balancer));

    /* Check if the balancer is defined in both override and base configs:
     * a) If it is, Create copy of base balancer and change the configuration
     *    which can be changed by ProxyPass.
     * b) Otherwise, copy the balancer to tocopy array and merge it later.
     */
    b1 = (proxy_balancer *) base->elts;
    for (y = 0; y < base->nelts; y++) {
        b2 = (proxy_balancer *) overrides->elts;
        for (x = 0, found = 0; x < overrides->nelts; x++) {
            if (b1->hash.def == b2->hash.def && b1->hash.fnv == b2->hash.fnv) {
                tmp = *b2;
                *b2 = *b1;
                b2->s = tmp.s;

                /* For shared memory entries, b2->s belongs to override
                 * balancer, so if some entry is not set there, we have to
                 * update it according to the base balancer. */
                if (*b2->s->sticky == 0 && *b1->s->sticky) {
                    PROXY_STRNCPY(b2->s->sticky_path, b1->s->sticky_path);
                    PROXY_STRNCPY(b2->s->sticky, b1->s->sticky);
                }
                if (!b2->s->sticky_separator_set
                    && b1->s->sticky_separator_set) {
                    b2->s->sticky_separator_set = b1->s->sticky_separator_set;
                    b2->s->sticky_separator = b1->s->sticky_separator;
                }
                if (!b2->s->timeout && b1->s->timeout) {
                    b2->s->timeout = b1->s->timeout;
                }
                if (!b2->s->max_attempts_set && b1->s->max_attempts_set) {
                    b2->s->max_attempts_set = b1->s->max_attempts_set;
                    b2->s->max_attempts = b1->s->max_attempts;
                }
                if (!b2->s->nonce_set && b1->s->nonce_set) {
                    b2->s->nonce_set = b1->s->nonce_set;
                    PROXY_STRNCPY(b2->s->nonce, b1->s->nonce);
                }
                if (!b2->s->sticky_force_set && b1->s->sticky_force_set) {
                    b2->s->sticky_force_set = b1->s->sticky_force_set;
                    b2->s->sticky_force = b1->s->sticky_force;
                }
                if (!b2->s->scolonsep_set && b1->s->scolonsep_set) {
                    b2->s->scolonsep_set = b1->s->scolonsep_set;
                    b2->s->scolonsep = b1->s->scolonsep;
                }
                if (!b2->s->forcerecovery_set && b1->s->forcerecovery_set) {
                    b2->s->forcerecovery_set = b1->s->forcerecovery_set;
                    b2->s->forcerecovery = b1->s->forcerecovery;
                }

                /* For non-shared memory entries, b2 is copy of b1, so we have
                 * to use tmp copy of b1 to detect changes done in override. */
                if (tmp.lbmethod_set) {
                    b2->lbmethod_set = tmp.lbmethod_set;
                    b2->lbmethod = tmp.lbmethod;
                }
                if (tmp.growth_set) {
                    b2->growth_set = tmp.growth_set;
                    b2->growth = tmp.growth;
                }
                if (tmp.failontimeout_set) {
                    b2->failontimeout_set = tmp.failontimeout_set;
                    b2->failontimeout = tmp.failontimeout;
                }
                if (!apr_is_empty_array(tmp.errstatuses)) {
                    apr_array_cat(tmp.errstatuses, b2->errstatuses);
                    b2->errstatuses = tmp.errstatuses;
                }

                found = 1;
                break;
            }
            b2++;
        }
        if (!found) {
            *(proxy_balancer *)apr_array_push(tocopy) = *b1;
        }
        b1++;
    }

    return apr_array_append(p, tocopy, overrides);
}

static void * merge_proxy_config(apr_pool_t *p, void *basev, void *overridesv)
{
    proxy_server_conf *ps = apr_pcalloc(p, sizeof(proxy_server_conf));
    proxy_server_conf *base = (proxy_server_conf *) basev;
    proxy_server_conf *overrides = (proxy_server_conf *) overridesv;

    ps->inherit = (overrides->inherit_set == 0) ? base->inherit : overrides->inherit;
    ps->inherit_set = overrides->inherit_set || base->inherit_set;

    ps->ppinherit = (overrides->ppinherit_set == 0) ? base->ppinherit : overrides->ppinherit;
    ps->ppinherit_set = overrides->ppinherit_set || base->ppinherit_set;

    if (ps->ppinherit) {
        ps->proxies = apr_array_append(p, base->proxies, overrides->proxies);
    }
    else {
        ps->proxies = overrides->proxies;
    }
    ps->sec_proxy = apr_array_append(p, base->sec_proxy, overrides->sec_proxy);
    ps->aliases = apr_array_append(p, base->aliases, overrides->aliases);
    ps->noproxies = apr_array_append(p, base->noproxies, overrides->noproxies);
    ps->dirconn = apr_array_append(p, base->dirconn, overrides->dirconn);
    if (ps->inherit || ps->ppinherit) {
        ps->workers = apr_array_append(p, base->workers, overrides->workers);
        ps->balancers = merge_balancers(p, base->balancers, overrides->balancers);
    }
    else {
        ps->workers = overrides->workers;
        ps->balancers = overrides->balancers;
    }
    ps->forward = overrides->forward ? overrides->forward : base->forward;
    ps->reverse = overrides->reverse ? overrides->reverse : base->reverse;

    ps->map_encoded_one = overrides->map_encoded_one || base->map_encoded_one;
    ps->map_encoded_all = overrides->map_encoded_all && base->map_encoded_all;

    ps->domain = (overrides->domain == NULL) ? base->domain : overrides->domain;
    ps->id = (overrides->id == NULL) ? base->id : overrides->id;
    ps->viaopt = (overrides->viaopt_set == 0) ? base->viaopt : overrides->viaopt;
    ps->viaopt_set = overrides->viaopt_set || base->viaopt_set;
    ps->req = (overrides->req_set == 0) ? base->req : overrides->req;
    ps->req_set = overrides->req_set || base->req_set;
    ps->bgrowth = (overrides->bgrowth_set == 0) ? base->bgrowth : overrides->bgrowth;
    ps->bgrowth_set = overrides->bgrowth_set || base->bgrowth_set;
    ps->max_balancers = overrides->max_balancers || base->max_balancers;
    ps->bal_persist = overrides->bal_persist;
    ps->recv_buffer_size = (overrides->recv_buffer_size_set == 0) ? base->recv_buffer_size : overrides->recv_buffer_size;
    ps->recv_buffer_size_set = overrides->recv_buffer_size_set || base->recv_buffer_size_set;
    ps->io_buffer_size = (overrides->io_buffer_size_set == 0) ? base->io_buffer_size : overrides->io_buffer_size;
    ps->io_buffer_size_set = overrides->io_buffer_size_set || base->io_buffer_size_set;
    ps->maxfwd = (overrides->maxfwd_set == 0) ? base->maxfwd : overrides->maxfwd;
    ps->maxfwd_set = overrides->maxfwd_set || base->maxfwd_set;
    ps->timeout = (overrides->timeout_set == 0) ? base->timeout : overrides->timeout;
    ps->timeout_set = overrides->timeout_set || base->timeout_set;
    ps->badopt = (overrides->badopt_set == 0) ? base->badopt : overrides->badopt;
    ps->badopt_set = overrides->badopt_set || base->badopt_set;
    ps->proxy_status = (overrides->proxy_status_set == 0) ? base->proxy_status : overrides->proxy_status;
    ps->proxy_status_set = overrides->proxy_status_set || base->proxy_status_set;
    ps->source_address = (overrides->source_address_set == 0) ? base->source_address : overrides->source_address;
    ps->source_address_set = overrides->source_address_set || base->source_address_set;
    ps->pool = base->pool;
    return ps;
}
static const char *set_source_address(cmd_parms *parms, void *dummy,
                                      const char *arg)
{
    proxy_server_conf *psf =
        ap_get_module_config(parms->server->module_config, &proxy_module);
    struct apr_sockaddr_t *addr;

    if (APR_SUCCESS == apr_sockaddr_info_get(&addr, arg, APR_UNSPEC, 0, 0,
                                             psf->pool)) {
        psf->source_address = addr;
        psf->source_address_set = 1;
    }
    else {
        return "ProxySourceAddress invalid value";
    }

    return NULL;
}

static void *create_proxy_dir_config(apr_pool_t *p, char *dummy)
{
    proxy_dir_conf *new =
        (proxy_dir_conf *) apr_pcalloc(p, sizeof(proxy_dir_conf));

    /* Filled in by proxysection, when applicable */

    /* Put these in the dir config so they work inside <Location> */
    new->raliases = apr_array_make(p, 10, sizeof(struct proxy_alias));
    new->cookie_paths = apr_array_make(p, 10, sizeof(struct proxy_alias));
    new->cookie_domains = apr_array_make(p, 10, sizeof(struct proxy_alias));
    new->error_override_codes = apr_array_make(p, 10, sizeof(int));
    new->preserve_host_set = 0;
    new->preserve_host = 0;
    new->interpolate_env = -1; /* unset */
    new->error_override = 0;
    new->error_override_set = 0;
    new->add_forwarded_headers = 1;
    new->add_forwarded_headers_set = 0;
    new->forward_100_continue = 1;
    new->forward_100_continue_set = 0;

    return (void *) new;
}

static int int_order(const void *i1, const void *i2)
{
    return *(const int *)i1 - *(const int *)i2;
}

static void *merge_proxy_dir_config(apr_pool_t *p, void *basev, void *addv)
{
    proxy_dir_conf *new = (proxy_dir_conf *) apr_pcalloc(p, sizeof(proxy_dir_conf));
    proxy_dir_conf *add = (proxy_dir_conf *) addv;
    proxy_dir_conf *base = (proxy_dir_conf *) basev;

    new->p = add->p;
    new->p_is_fnmatch = add->p_is_fnmatch;
    new->r = add->r;
    new->refs = add->refs;

    /* Put these in the dir config so they work inside <Location> */
    new->raliases = apr_array_append(p, base->raliases, add->raliases);
    new->cookie_paths
        = apr_array_append(p, base->cookie_paths, add->cookie_paths);
    new->cookie_domains
        = apr_array_append(p, base->cookie_domains, add->cookie_domains);
    new->error_override_codes
        = apr_array_append(p, base->error_override_codes, add->error_override_codes);
    /* Keep the array sorted for binary search (since "base" and "add" are
     * already sorted, it's only needed only if both are merged).
     */
    if (base->error_override_codes->nelts
            && add->error_override_codes->nelts) {
        qsort(new->error_override_codes->elts,
              new->error_override_codes->nelts,
              sizeof(int), int_order);
    }
    new->interpolate_env = (add->interpolate_env == -1) ? base->interpolate_env
                                                        : add->interpolate_env;
    new->preserve_host = (add->preserve_host_set == 0) ? base->preserve_host
                                                        : add->preserve_host;
    new->preserve_host_set = add->preserve_host_set || base->preserve_host_set;
    new->error_override = (add->error_override_set == 0) ? base->error_override
                                                        : add->error_override;
    new->error_override_set = add->error_override_set || base->error_override_set;
    new->alias = (add->alias_set == 0) ? base->alias : add->alias;
    new->alias_set = add->alias_set || base->alias_set;
    new->add_forwarded_headers =
        (add->add_forwarded_headers_set == 0) ? base->add_forwarded_headers
        : add->add_forwarded_headers;
    new->add_forwarded_headers_set = add->add_forwarded_headers_set
        || base->add_forwarded_headers_set;
    new->forward_100_continue =
        (add->forward_100_continue_set == 0) ? base->forward_100_continue
                                             : add->forward_100_continue;
    new->forward_100_continue_set = add->forward_100_continue_set
                                    || base->forward_100_continue_set;

    return new;
}

static const char *
    add_proxy(cmd_parms *cmd, void *dummy, const char *f1, const char *r1, int regex)
{
    server_rec *s = cmd->server;
    proxy_server_conf *conf =
    (proxy_server_conf *) ap_get_module_config(s->module_config, &proxy_module);
    struct proxy_remote *new;
    char *p, *q;
    char *r, *f, *scheme;
    ap_regex_t *reg = NULL;
    int port;

    r = apr_pstrdup(cmd->pool, r1);
    scheme = apr_pstrdup(cmd->pool, r1);
    f = apr_pstrdup(cmd->pool, f1);
    p = strchr(r, ':');
    if (p == NULL || p[1] != '/' || p[2] != '/' || p[3] == '\0') {
        if (regex)
            return "ProxyRemoteMatch: Bad syntax for a remote proxy server";
        else
            return "ProxyRemote: Bad syntax for a remote proxy server";
    }
    else {
        scheme[p-r] = 0;
    }
    q = strchr(p + 3, ':');
    if (q != NULL) {
        if (sscanf(q + 1, "%u", &port) != 1 || port > 65535) {
            if (regex)
                return "ProxyRemoteMatch: Bad syntax for a remote proxy server (bad port number)";
            else
                return "ProxyRemote: Bad syntax for a remote proxy server (bad port number)";
        }
        *q = '\0';
    }
    else
        port = -1;
    *p = '\0';
    if (regex) {
        reg = ap_pregcomp(cmd->pool, f, AP_REG_EXTENDED);
        if (!reg)
            return "Regular expression for ProxyRemoteMatch could not be compiled.";
    }
    else
        if (strchr(f, ':') == NULL)
            ap_str_tolower(f);      /* lowercase scheme */
    ap_str_tolower(p + 3);      /* lowercase hostname */

    if (port == -1) {
        port = apr_uri_port_of_scheme(scheme);
    }

    new = apr_array_push(conf->proxies);
    new->scheme = f;
    new->protocol = r;
    new->hostname = p + 3;
    new->port = port;
    new->regexp = reg;
    new->use_regex = regex;
    return NULL;
}

static const char *
    add_proxy_noregex(cmd_parms *cmd, void *dummy, const char *f1, const char *r1)
{
    return add_proxy(cmd, dummy, f1, r1, 0);
}

static const char *
    add_proxy_regex(cmd_parms *cmd, void *dummy, const char *f1, const char *r1)
{
    return add_proxy(cmd, dummy, f1, r1, 1);
}

PROXY_DECLARE(const char *) ap_proxy_de_socketfy(apr_pool_t *p, const char *url)
{
    const char *ptr;
    /*
     * We could be passed a URL during the config stage that contains
     * the UDS path... ignore it
     */
    if (!ap_cstr_casecmpn(url, "unix:", 5) &&
        ((ptr = ap_strchr_c(url + 5, '|')) != NULL)) {
        /* move past the 'unix:...|' UDS path info */
        const char *ret, *c;

        ret = ptr + 1;
        /* special case: "unix:....|scheme:" is OK, expand
         * to "unix:....|scheme://localhost"
         * */
        c = ap_strchr_c(ret, ':');
        if (c == NULL) {
            return NULL;
        }
        if (c[1] == '\0') {
            return apr_pstrcat(p, ret, "//localhost", NULL);
        }
        else {
            return ret;
        }
    }
    return url;
}

static const char *
    add_pass(cmd_parms *cmd, void *dummy, const char *arg, int is_regex)
{
    proxy_dir_conf *dconf = (proxy_dir_conf *)dummy;
    server_rec *s = cmd->server;
    proxy_server_conf *conf =
    (proxy_server_conf *) ap_get_module_config(s->module_config, &proxy_module);
    struct proxy_alias *new;
    char *f = cmd->path;
    char *r = NULL;
    const char *real;
    char *word;
    apr_table_t *params = apr_table_make(cmd->pool, 5);
    const apr_array_header_t *arr;
    const apr_table_entry_t *elts;
    int i;
    unsigned int worker_type = (is_regex) ? AP_PROXY_WORKER_IS_MATCH
                                          : AP_PROXY_WORKER_IS_PREFIX;
    unsigned int flags = 0;
    const char *err;

    err = ap_check_cmd_context(cmd, NOT_IN_DIRECTORY|NOT_IN_FILES);
    if (err) {
        return err;
    }

    while (*arg) {
        word = ap_getword_conf(cmd->pool, &arg);
        if (!f) {
            if (!strcmp(word, "~")) {
                if (is_regex) {
                    return "ProxyPassMatch invalid syntax ('~' usage).";
                }
                worker_type = AP_PROXY_WORKER_IS_MATCH;
                continue;
            }
            f = word;
        }
        else if (!r) {
            r = word;
        }
        else if (!strcasecmp(word,"nocanon")) {
            flags |= PROXYPASS_NOCANON;
        }
        else if (!strcasecmp(word,"interpolate")) {
            flags |= PROXYPASS_INTERPOLATE;
        }
        else if (!strcasecmp(word,"noquery")) {
            flags |= PROXYPASS_NOQUERY;
        }
        else {
            char *val = strchr(word, '=');
            if (!val) {
                if (cmd->path) {
                    if (*r == '/') {
                        return "ProxyPass|ProxyPassMatch can not have a path when defined in "
                               "a location.";
                    }
                    else {
                        return "Invalid ProxyPass|ProxyPassMatch parameter. Parameter must "
                               "be in the form 'key=value'.";
                    }
                }
                else {
                    return "Invalid ProxyPass|ProxyPassMatch parameter. Parameter must be "
                           "in the form 'key=value'.";
                }
            }
            else {
                *val++ = '\0';
            }
            if (!strcasecmp(word, "mapping")) {
                if (!strcasecmp(val, "encoded")) {
                    flags |= PROXYPASS_MAP_ENCODED;
                }
                else if (!strcasecmp(val, "servlet")) {
                    flags |= PROXYPASS_MAP_SERVLET;
                }
                else {
                    return "unknown mapping";
                }
            }
            else {
                apr_table_setn(params, word, val);
            }
        }
    }
    if (flags & PROXYPASS_MAP_ENCODED) {
        conf->map_encoded_one = 1;
    }
    else {
        conf->map_encoded_all = 0;
    }

    if (r == NULL) {
        return "ProxyPass|ProxyPassMatch needs a path when not defined in a location";
    }
    if (!(real = ap_proxy_de_socketfy(cmd->temp_pool, r))) {
        return "ProxyPass|ProxyPassMatch uses an invalid \"unix:\" URL";
    }


    /* if per directory, save away the single alias */
    if (cmd->path) {
        dconf->alias = apr_pcalloc(cmd->pool, sizeof(struct proxy_alias));
        dconf->alias_set = 1;
        new = dconf->alias;
        if (apr_fnmatch_test(f)) {
            worker_type = AP_PROXY_WORKER_IS_MATCH;
        }
    }
    /* if per server, add to the alias array */
    else {
        new = apr_array_push(conf->aliases);
    }

    new->fake = apr_pstrdup(cmd->pool, f);
    new->real = apr_pstrdup(cmd->pool, real);
    new->flags = flags;
    if (worker_type & AP_PROXY_WORKER_IS_MATCH) {
        new->regex = ap_pregcomp(cmd->pool, f, AP_REG_EXTENDED);
        if (new->regex == NULL)
            return "Regular expression could not be compiled.";
    }
    else {
        new->regex = NULL;
    }

    if (r[0] == '!' && r[1] == '\0')
        return NULL;

    arr = apr_table_elts(params);
    elts = (const apr_table_entry_t *)arr->elts;
    /* Distinguish the balancer from worker */
    if (ap_proxy_valid_balancer_name(r, 9)) {
        proxy_balancer *balancer = ap_proxy_get_balancer(cmd->pool, conf, r, 0);
        char *fake_copy;

        /*
         * In the regex case supplying a fake URL doesn't make sense as it
         * cannot be parsed anyway with apr_uri_parse later on in
         * ap_proxy_define_balancer / ap_proxy_update_balancer
         */
        if (worker_type & AP_PROXY_WORKER_IS_MATCH) {
            fake_copy = NULL;
        }
        else {
            fake_copy = f;
        }
        if (!balancer) {
            const char *err = ap_proxy_define_balancer(cmd->pool, &balancer, conf, r, fake_copy, 0);
            if (err)
                return apr_pstrcat(cmd->temp_pool, "ProxyPass ", err, NULL);
        }
        else {
            ap_proxy_update_balancer(cmd->pool, balancer, fake_copy);
        }
        for (i = 0; i < arr->nelts; i++) {
            const char *err = set_balancer_param(conf, cmd->pool, balancer, elts[i].key,
                                                 elts[i].val);
            if (err)
                return apr_pstrcat(cmd->temp_pool, "ProxyPass ", err, NULL);
        }
        new->balancer = balancer;
    }
    else {
        int reuse = 0;
        proxy_worker *worker = ap_proxy_get_worker_ex(cmd->temp_pool, NULL,
                                                      conf, new->real,
                                                      worker_type);
        if (!worker) {
            const char *err;
            err = ap_proxy_define_worker_ex(cmd->pool, &worker, NULL,
                                            conf, r, worker_type);
            if (err)
                return apr_pstrcat(cmd->temp_pool, "ProxyPass ", err, NULL);

            PROXY_COPY_CONF_PARAMS(worker, conf);
        }
        else {
            reuse = 1;
            ap_log_error(APLOG_MARK, APLOG_INFO, 0, cmd->server, APLOGNO(01145)
                         "Sharing worker '%s' instead of creating new worker '%s'",
                         ap_proxy_worker_name(cmd->pool, worker), new->real);
        }

        for (i = 0; i < arr->nelts; i++) {
            if (reuse) {
                ap_log_error(APLOG_MARK, APLOG_WARNING, 0, cmd->server, APLOGNO(01146)
                             "Ignoring parameter '%s=%s' for worker '%s' because of worker sharing",
                             elts[i].key, elts[i].val, ap_proxy_worker_name(cmd->pool, worker));
            } else {
                const char *err = set_worker_param(cmd->pool, s, worker, elts[i].key,
                                                   elts[i].val);
                if (err)
                    return apr_pstrcat(cmd->temp_pool, "ProxyPass ", err, NULL);
            }
        }
    }
    return NULL;
}

static const char *
    add_pass_noregex(cmd_parms *cmd, void *dummy, const char *arg)
{
    return add_pass(cmd, dummy, arg, 0);
}

static const char *
    add_pass_regex(cmd_parms *cmd, void *dummy, const char *arg)
{
    return add_pass(cmd, dummy, arg, 1);
}


static const char * add_pass_reverse(cmd_parms *cmd, void *dconf, const char *f,
                                     const char *r, const char *i)
{
    proxy_dir_conf *conf = dconf;
    struct proxy_alias *new;
    const char *fake;
    const char *real;
    const char *interp;
    const char *err;

    err = ap_check_cmd_context(cmd, NOT_IN_DIRECTORY|NOT_IN_FILES);
    if (err) {
        return err;
    }

    if (cmd->path == NULL) {
        if (r == NULL || !strcasecmp(r, "interpolate")) {
            return "ProxyPassReverse needs a path when not defined in a location";
        }
        fake = f;
        real = r;
        interp = i;
    }
    else {
        if (r && strcasecmp(r, "interpolate")) {
            return "ProxyPassReverse can not have a path when defined in a location";
        }
        fake = cmd->path;
        real = f;
        interp = r;
    }

    new = apr_array_push(conf->raliases);
    new->fake = fake;
    new->real = real;
    new->flags = interp ? PROXYPASS_INTERPOLATE : 0;

    return NULL;
}
static const char* cookie_path(cmd_parms *cmd, void *dconf, const char *f,
                               const char *r, const char *interp)
{
    proxy_dir_conf *conf = dconf;
    struct proxy_alias *new;

    new = apr_array_push(conf->cookie_paths);
    new->fake = f;
    new->real = r;
    new->flags = interp ? PROXYPASS_INTERPOLATE : 0;

    return NULL;
}
static const char* cookie_domain(cmd_parms *cmd, void *dconf, const char *f,
                                 const char *r, const char *interp)
{
    proxy_dir_conf *conf = dconf;
    struct proxy_alias *new;

    new = apr_array_push(conf->cookie_domains);
    new->fake = f;
    new->real = r;
    new->flags = interp ? PROXYPASS_INTERPOLATE : 0;
    return NULL;
}

static const char *
    set_proxy_exclude(cmd_parms *parms, void *dummy, const char *arg)
{
    server_rec *s = parms->server;
    proxy_server_conf *conf =
    ap_get_module_config(s->module_config, &proxy_module);
    struct noproxy_entry *new;
    struct noproxy_entry *list = (struct noproxy_entry *) conf->noproxies->elts;
    struct apr_sockaddr_t *addr;
    int found = 0;
    int i;

    /* Don't duplicate entries */
    for (i = 0; i < conf->noproxies->nelts; i++) {
        if (strcasecmp(arg, list[i].name) == 0) { /* ignore case for host names */
            found = 1;
            break;
        }
    }

    if (!found) {
        new = apr_array_push(conf->noproxies);
        new->name = arg;
        if (APR_SUCCESS == apr_sockaddr_info_get(&addr, new->name, APR_UNSPEC, 0, 0, parms->pool)) {
            new->addr = addr;
        }
        else {
            new->addr = NULL;
        }
    }
    return NULL;
}


/* Similar to set_proxy_exclude(), but defining directly connected hosts,
 * which should never be accessed via the configured ProxyRemote servers
 */
static const char *
    set_proxy_dirconn(cmd_parms *parms, void *dummy, const char *arg)
{
    server_rec *s = parms->server;
    proxy_server_conf *conf =
    ap_get_module_config(s->module_config, &proxy_module);
    struct dirconn_entry *New;
    struct dirconn_entry *list = (struct dirconn_entry *) conf->dirconn->elts;
    int found = 0;
    int i;

    /* Don't duplicate entries */
    for (i = 0; i < conf->dirconn->nelts; i++) {
        if (strcasecmp(arg, list[i].name) == 0) {
            found = 1;
            break;
        }
    }

    if (!found) {
        New = apr_array_push(conf->dirconn);
        New->name = apr_pstrdup(parms->pool, arg);
        New->hostaddr = NULL;

        if (ap_proxy_is_ipaddr(New, parms->pool)) {
#if DEBUGGING
            ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL, APLOGNO(03018)
                         "Parsed addr %s", inet_ntoa(New->addr));
            ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL, APLOGNO(03019)
                         "Parsed mask %s", inet_ntoa(New->mask));
#endif
        }
        else if (ap_proxy_is_domainname(New, parms->pool)) {
            ap_str_tolower(New->name);
#if DEBUGGING
            ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL, APLOGNO(03020)
                         "Parsed domain %s", New->name);
#endif
        }
        else if (ap_proxy_is_hostname(New, parms->pool)) {
            ap_str_tolower(New->name);
#if DEBUGGING
            ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL, APLOGNO(03021)
                         "Parsed host %s", New->name);
#endif
        }
        else {
            ap_proxy_is_word(New, parms->pool);
#if DEBUGGING
            fprintf(stderr, "Parsed word %s\n", New->name);
#endif
        }
    }
    return NULL;
}

static const char *
    set_proxy_domain(cmd_parms *parms, void *dummy, const char *arg)
{
    proxy_server_conf *psf =
    ap_get_module_config(parms->server->module_config, &proxy_module);

    if (arg[0] != '.')
        return "ProxyDomain: domain name must start with a dot.";

    psf->domain = arg;
    return NULL;
}

static const char *
    set_proxy_req(cmd_parms *parms, void *dummy, int flag)
{
    proxy_server_conf *psf =
    ap_get_module_config(parms->server->module_config, &proxy_module);

    psf->req = flag;
    psf->req_set = 1;
    return NULL;
}

static const char *
    set_proxy_error_override(cmd_parms *parms, void *dconf, const char *arg)
{
    proxy_dir_conf *conf = dconf;

    if (strcasecmp(arg, "Off") == 0) {
        conf->error_override = 0;
        conf->error_override_set = 1;
    }
    else if (strcasecmp(arg, "On") == 0) {
        conf->error_override = 1;
        conf->error_override_set = 1;
    }
    else if (conf->error_override_set == 1) {
        int *newcode;
        int argcode, i;
        if (!apr_isdigit(arg[0]))
            return "ProxyErrorOverride: status codes to intercept must be numeric";
        if (!conf->error_override) 
            return "ProxyErrorOverride: status codes must follow a value of 'on'";

        argcode = strtol(arg, NULL, 10);
        if (!ap_is_HTTP_ERROR(argcode))
            return "ProxyErrorOverride: status codes to intercept must be valid HTTP Status Codes >=400 && <600";

        newcode = apr_array_push(conf->error_override_codes);
        *newcode = argcode;

        /* Keep the array sorted for binary search. */
        for (i = conf->error_override_codes->nelts - 1; i > 0; --i) {
            int *oldcode = &((int *)conf->error_override_codes->elts)[i - 1];
            if (*oldcode <= argcode) {
                break;
            }
            *newcode = *oldcode;
            *oldcode = argcode;
            newcode = oldcode;
        }
    }
    else
        return "ProxyErrorOverride first parameter must be one of: off | on";

    return NULL;
}

static const char *
   add_proxy_http_headers(cmd_parms *parms, void *dconf, int flag)
{
   proxy_dir_conf *conf = dconf;
   conf->add_forwarded_headers = flag;
   conf->add_forwarded_headers_set = 1;
   return NULL;
}
static const char *
    set_preserve_host(cmd_parms *parms, void *dconf, int flag)
{
    proxy_dir_conf *conf = dconf;

    conf->preserve_host = flag;
    conf->preserve_host_set = 1;
    return NULL;
}
static const char *
   forward_100_continue(cmd_parms *parms, void *dconf, int flag)
{
   proxy_dir_conf *conf = dconf;
   conf->forward_100_continue = flag;
   conf->forward_100_continue_set = 1;
   return NULL;
}

static const char *
    set_recv_buffer_size(cmd_parms *parms, void *dummy, const char *arg)
{
    proxy_server_conf *psf =
    ap_get_module_config(parms->server->module_config, &proxy_module);
    int s = atoi(arg);
    if (s < 512 && s != 0) {
        return "ProxyReceiveBufferSize must be >= 512 bytes, or 0 for system default.";
    }

    psf->recv_buffer_size = s;
    psf->recv_buffer_size_set = 1;
    return NULL;
}

static const char *
    set_io_buffer_size(cmd_parms *parms, void *dummy, const char *arg)
{
    proxy_server_conf *psf =
    ap_get_module_config(parms->server->module_config, &proxy_module);
    long s = atol(arg);
    if (s < 512 && s) {
        return "ProxyIOBufferSize must be >= 512 bytes, or 0 for system default.";
    }
    psf->io_buffer_size = (s ? s : AP_IOBUFSIZE);
    psf->io_buffer_size_set = 1;
    return NULL;
}

static const char *
    set_max_forwards(cmd_parms *parms, void *dummy, const char *arg)
{
    proxy_server_conf *psf =
    ap_get_module_config(parms->server->module_config, &proxy_module);
    long s = atol(arg);

    psf->maxfwd = s;
    psf->maxfwd_set = 1;
    return NULL;
}
static const char*
    set_proxy_timeout(cmd_parms *parms, void *dummy, const char *arg)
{
    proxy_server_conf *psf =
    ap_get_module_config(parms->server->module_config, &proxy_module);
    int timeout;

    timeout = atoi(arg);
    if (timeout<1) {
        return "Proxy Timeout must be at least 1 second.";
    }
    psf->timeout_set = 1;
    psf->timeout = apr_time_from_sec(timeout);

    return NULL;
}

static const char*
    set_via_opt(cmd_parms *parms, void *dummy, const char *arg)
{
    proxy_server_conf *psf =
    ap_get_module_config(parms->server->module_config, &proxy_module);

    if (strcasecmp(arg, "Off") == 0)
        psf->viaopt = via_off;
    else if (strcasecmp(arg, "On") == 0)
        psf->viaopt = via_on;
    else if (strcasecmp(arg, "Block") == 0)
        psf->viaopt = via_block;
    else if (strcasecmp(arg, "Full") == 0)
        psf->viaopt = via_full;
    else {
        return "ProxyVia must be one of: "
            "off | on | full | block";
    }

    psf->viaopt_set = 1;
    return NULL;
}

static const char*
    set_bad_opt(cmd_parms *parms, void *dummy, const char *arg)
{
    proxy_server_conf *psf =
    ap_get_module_config(parms->server->module_config, &proxy_module);

    if (strcasecmp(arg, "IsError") == 0)
        psf->badopt = bad_error;
    else if (strcasecmp(arg, "Ignore") == 0)
        psf->badopt = bad_ignore;
    else if (strcasecmp(arg, "StartBody") == 0)
        psf->badopt = bad_body;
    else {
        return "ProxyBadHeader must be one of: "
            "IsError | Ignore | StartBody";
    }

    psf->badopt_set = 1;
    return NULL;
}

static const char*
    set_status_opt(cmd_parms *parms, void *dummy, const char *arg)
{
    proxy_server_conf *psf =
    ap_get_module_config(parms->server->module_config, &proxy_module);

    if (strcasecmp(arg, "Off") == 0)
        psf->proxy_status = status_off;
    else if (strcasecmp(arg, "On") == 0)
        psf->proxy_status = status_on;
    else if (strcasecmp(arg, "Full") == 0)
        psf->proxy_status = status_full;
    else {
        return "ProxyStatus must be one of: "
            "off | on | full";
    }

    psf->proxy_status_set = 1;
    return NULL;
}

static const char *set_bgrowth(cmd_parms *parms, void *dummy, const char *arg)
{
    proxy_server_conf *psf =
    ap_get_module_config(parms->server->module_config, &proxy_module);

    int growth = atoi(arg);
    if (growth < 0 || growth > 1000) {
        return "BalancerGrowth must be between 0 and 1000";
    }
    psf->bgrowth = growth;
    psf->bgrowth_set = 1;

    return NULL;
}

static const char *set_persist(cmd_parms *parms, void *dummy, int flag)
{
    proxy_server_conf *psf =
    ap_get_module_config(parms->server->module_config, &proxy_module);

    psf->bal_persist = flag;
    return NULL;
}

static const char *set_inherit(cmd_parms *parms, void *dummy, int flag)
{
    proxy_server_conf *psf =
    ap_get_module_config(parms->server->module_config, &proxy_module);

    psf->inherit = flag;
    psf->inherit_set = 1;
    return NULL;
}

static const char *set_ppinherit(cmd_parms *parms, void *dummy, int flag)
{
    proxy_server_conf *psf =
    ap_get_module_config(parms->server->module_config, &proxy_module);

    psf->ppinherit = flag;
    psf->ppinherit_set = 1;
    return NULL;
}

static const char *add_member(cmd_parms *cmd, void *dummy, const char *arg)
{
    server_rec *s = cmd->server;
    proxy_server_conf *conf =
    ap_get_module_config(s->module_config, &proxy_module);
    proxy_balancer *balancer;
    proxy_worker *worker;
    char *path = cmd->path;
    char *name = NULL;
    const char *real;
    char *word;
    apr_table_t *params = apr_table_make(cmd->pool, 5);
    const apr_array_header_t *arr;
    const apr_table_entry_t *elts;
    int reuse = 0;
    int i;
    /* XXX: Should this be NOT_IN_DIRECTORY|NOT_IN_FILES? */
    const char *err = ap_check_cmd_context(cmd, NOT_IN_HTACCESS);
    if (err)
        return err;

    if (cmd->path)
        path = apr_pstrdup(cmd->pool, cmd->path);

    while (*arg) {
        char *val;
        word = ap_getword_conf(cmd->pool, &arg);
        val = strchr(word, '=');

        if (!val) {
            if (!path)
                path = word;
            else if (!name)
                name = word;
            else {
                if (cmd->path)
                    return "BalancerMember can not have a balancer name when defined in a location";
                else
                    return "Invalid BalancerMember parameter. Parameter must "
                           "be in the form 'key=value'";
            }
        } else {
            *val++ = '\0';
            apr_table_setn(params, word, val);
        }
    }
    if (!path)
        return "BalancerMember must define balancer name when outside <Proxy > section";
    if (!name)
        return "BalancerMember must define remote proxy server";
    if (!(real = ap_proxy_de_socketfy(cmd->temp_pool, name))) {
        return "BalancerMember uses an invalid \"unix:\" URL";
    }

    ap_str_tolower(path);   /* lowercase scheme://hostname */

    /* Try to find the balancer */
    balancer = ap_proxy_get_balancer(cmd->temp_pool, conf, path, 0);
    if (!balancer) {
        err = ap_proxy_define_balancer(cmd->pool, &balancer, conf, path, "/", 0);
        if (err)
            return apr_pstrcat(cmd->temp_pool, "BalancerMember ", err, NULL);
    }

    /* Try to find existing worker */
    worker = ap_proxy_get_worker(cmd->temp_pool, balancer, conf, real);
    if (!worker) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, cmd->server, APLOGNO(01147)
                     "Defining worker '%s' for balancer '%s'",
                     name, balancer->s->name);
        if ((err = ap_proxy_define_worker(cmd->pool, &worker, balancer, conf, name, 0)) != NULL)
            return apr_pstrcat(cmd->temp_pool, "BalancerMember ", err, NULL);
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, cmd->server, APLOGNO(01148)
                     "Defined worker '%s' for balancer '%s'",
                     ap_proxy_worker_name(cmd->pool, worker), balancer->s->name);
        PROXY_COPY_CONF_PARAMS(worker, conf);
    } else {
        reuse = 1;
        ap_log_error(APLOG_MARK, APLOG_INFO, 0, cmd->server, APLOGNO(01149)
                     "Sharing worker '%s' instead of creating new worker '%s'",
                     ap_proxy_worker_name(cmd->pool, worker), name);
    }
    if (!worker->section_config) {
        worker->section_config = balancer->section_config;
    }

    arr = apr_table_elts(params);
    elts = (const apr_table_entry_t *)arr->elts;
    for (i = 0; i < arr->nelts; i++) {
        if (reuse) {
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, cmd->server, APLOGNO(01150)
                         "Ignoring parameter '%s=%s' for worker '%s' because of worker sharing",
                         elts[i].key, elts[i].val, ap_proxy_worker_name(cmd->pool, worker));
        } else {
            err = set_worker_param(cmd->pool, cmd->server, worker, elts[i].key,
                                   elts[i].val);
            if (err)
                return apr_pstrcat(cmd->temp_pool, "BalancerMember ", err, NULL);
        }
    }

    return NULL;
}

static const char *
    set_proxy_param(cmd_parms *cmd, void *dummy, const char *arg)
{
    server_rec *s = cmd->server;
    proxy_server_conf *conf =
    (proxy_server_conf *) ap_get_module_config(s->module_config, &proxy_module);
    char *name = NULL;
    char *word, *val;
    proxy_balancer *balancer = NULL;
    proxy_worker *worker = NULL;
    unsigned int worker_type = 0;
    int in_proxy_section = 0;
    /* XXX: Should this be NOT_IN_DIRECTORY|NOT_IN_FILES? */
    const char *err = ap_check_cmd_context(cmd, NOT_IN_HTACCESS);
    if (err)
        return err;

    if (cmd->directive->parent &&
        strncasecmp(cmd->directive->parent->directive,
                    "<Proxy", 6) == 0) {
        const char *pargs = cmd->directive->parent->args;
        /* Directive inside <Proxy section
         * Parent directive arg is the worker/balancer name.
         */
        name = ap_getword_conf(cmd->temp_pool, &pargs);
        if ((word = ap_strchr(name, '>')))
            *word = '\0';
        if (strncasecmp(cmd->directive->parent->directive + 6,
                        "Match", 5) == 0) {
            worker_type = AP_PROXY_WORKER_IS_MATCH;
        }
        else {
            worker_type = AP_PROXY_WORKER_IS_PREFIX;
        }
        in_proxy_section = 1;
    }
    else {
        /* Standard set directive with worker/balancer
         * name as first param.
         */
        name = ap_getword_conf(cmd->temp_pool, &arg);
    }

    if (ap_proxy_valid_balancer_name(name, 9)) {
        balancer = ap_proxy_get_balancer(cmd->pool, conf, name, 0);
        if (!balancer) {
            if (in_proxy_section) {
                err = ap_proxy_define_balancer(cmd->pool, &balancer, conf, name, "/", 0);
                if (err)
                    return apr_pstrcat(cmd->temp_pool, "ProxySet ",
                                       err, NULL);
            }
            else
                return apr_pstrcat(cmd->temp_pool, "ProxySet can not find '",
                                   name, "' Balancer.", NULL);
        }
    }
    else {
        const char *real;

        if (!(real = ap_proxy_de_socketfy(cmd->temp_pool, name))) {
            return "ProxySet uses an invalid \"unix:\" URL";
        }

        worker = ap_proxy_get_worker_ex(cmd->temp_pool, NULL, conf,
                                        real, worker_type);
        if (!worker) {
            if (in_proxy_section) {
                err = ap_proxy_define_worker_ex(cmd->pool, &worker, NULL,
                                                conf, name, worker_type);
                if (err)
                    return apr_pstrcat(cmd->temp_pool, "ProxySet ",
                                       err, NULL);
            }
            else
                return apr_pstrcat(cmd->temp_pool, "ProxySet can not find '",
                                   name, "' Worker.", NULL);
        }
    }

    while (*arg) {
        word = ap_getword_conf(cmd->pool, &arg);
        val = strchr(word, '=');
        if (!val) {
            return "Invalid ProxySet parameter. Parameter must be "
                   "in the form 'key=value'";
        }
        else
            *val++ = '\0';
        if (worker)
            err = set_worker_param(cmd->pool, cmd->server, worker, word, val);
        else
            err = set_balancer_param(conf, cmd->pool, balancer, word, val);

        if (err)
            return apr_pstrcat(cmd->temp_pool, "ProxySet: ", err, " ", word, "=", val, "; ", name, NULL);
    }

    return NULL;
}

static void ap_add_per_proxy_conf(server_rec *s, ap_conf_vector_t *dir_config)
{
    proxy_server_conf *sconf = ap_get_module_config(s->module_config,
                                                    &proxy_module);
    void **new_space = (void **)apr_array_push(sconf->sec_proxy);

    *new_space = dir_config;
}

static const char *proxysection(cmd_parms *cmd, void *mconfig, const char *arg)
{
    const char *errmsg;
    const char *endp = ap_strrchr_c(arg, '>');
    int old_overrides = cmd->override;
    char *old_path = cmd->path;
    proxy_dir_conf *conf;
    ap_conf_vector_t *new_dir_conf = ap_create_per_dir_config(cmd->pool);
    ap_regex_t *r = NULL;
    const command_rec *thiscmd = cmd->cmd;
    char *word, *val;
    proxy_balancer *balancer = NULL;
    proxy_worker *worker = NULL;
    unsigned int worker_type = AP_PROXY_WORKER_IS_PREFIX;
    const char *err = ap_check_cmd_context(cmd, NOT_IN_DIR_CONTEXT);
    proxy_server_conf *sconf =
    (proxy_server_conf *) ap_get_module_config(cmd->server->module_config, &proxy_module);

    if (err != NULL) {
        return err;
    }

    if (endp == NULL) {
        return apr_pstrcat(cmd->pool, cmd->cmd->name,
                           "> directive missing closing '>'", NULL);
    }

    arg = apr_pstrndup(cmd->pool, arg, endp-arg);

    if (!arg) {
        if (thiscmd->cmd_data)
            return "<ProxyMatch > block must specify a path";
        else
            return "<Proxy > block must specify a path";
    }

    cmd->path = ap_getword_conf(cmd->pool, &arg);
    cmd->override = OR_ALL|ACCESS_CONF|PROXY_CONF;

    if (!strncasecmp(cmd->path, "proxy:", 6))
        cmd->path += 6;

    /* XXX Ignore case?  What if we proxy a case-insensitive server?!?
     * While we are at it, shouldn't we also canonicalize the entire
     * scheme?  See proxy_fixup()
     */
    if (thiscmd->cmd_data) { /* <ProxyMatch> */
        r = ap_pregcomp(cmd->pool, cmd->path, AP_REG_EXTENDED);
        if (!r) {
            return "Regex could not be compiled";
        }
        worker_type = AP_PROXY_WORKER_IS_MATCH;
    }

    /* initialize our config and fetch it */
    conf = ap_set_config_vectors(cmd->server, new_dir_conf, cmd->path,
                                 &proxy_module, cmd->pool);

    errmsg = ap_walk_config(cmd->directive->first_child, cmd, new_dir_conf);
    if (errmsg != NULL)
        return errmsg;

    conf->r = r;
    conf->p = cmd->path;
    conf->p_is_fnmatch = apr_fnmatch_test(conf->p);

    if (r) {
        conf->refs = apr_array_make(cmd->pool, 8, sizeof(char *));
        ap_regname(r, conf->refs, AP_REG_MATCH, 1);
    }

    ap_add_per_proxy_conf(cmd->server, new_dir_conf);

    if (*arg != '\0') {
        if (thiscmd->cmd_data)
            return "Multiple <ProxyMatch> arguments not (yet) supported.";
        if (conf->p_is_fnmatch)
            return apr_pstrcat(cmd->pool, thiscmd->name,
                               "> arguments are not supported for wildchar url.",
                               NULL);
        if (!ap_strchr_c(conf->p, ':'))
            return apr_pstrcat(cmd->pool, thiscmd->name,
                               "> arguments are not supported for non url.",
                               NULL);
        if (ap_proxy_valid_balancer_name((char *)conf->p, 9)) {
            balancer = ap_proxy_get_balancer(cmd->pool, sconf, conf->p, 0);
            if (!balancer) {
                err = ap_proxy_define_balancer(cmd->pool, &balancer,
                                               sconf, conf->p, "/", 0);
                if (err)
                    return apr_pstrcat(cmd->temp_pool, thiscmd->name,
                                       " ", err, NULL);
            }
            if (!balancer->section_config) {
                balancer->section_config = new_dir_conf;
            }
        }
        else {
            const char *real;

            if (!(real = ap_proxy_de_socketfy(cmd->temp_pool, conf->p))) {
                return "<Proxy/ProxyMatch > uses an invalid \"unix:\" URL";
            }

            worker = ap_proxy_get_worker_ex(cmd->temp_pool, NULL, sconf,
                                            real, worker_type);
            if (!worker) {
                err = ap_proxy_define_worker_ex(cmd->pool, &worker, NULL, sconf,
                                                conf->p, worker_type);
                if (err)
                    return apr_pstrcat(cmd->temp_pool, thiscmd->name,
                                       " ", err, NULL);
            }
            if (!worker->section_config) {
                worker->section_config = new_dir_conf;
            }
        }
        if (worker == NULL && balancer == NULL) {
            return apr_pstrcat(cmd->pool, thiscmd->name,
                               "> arguments are supported only for workers.",
                               NULL);
        }
        while (*arg) {
            word = ap_getword_conf(cmd->pool, &arg);
            val = strchr(word, '=');
            if (!val) {
                return "Invalid Proxy parameter. Parameter must be "
                       "in the form 'key=value'";
            }
            else
                *val++ = '\0';
            if (worker)
                err = set_worker_param(cmd->pool, cmd->server, worker, word, val);
            else
                err = set_balancer_param(sconf, cmd->pool, balancer,
                                         word, val);
            if (err)
                return apr_pstrcat(cmd->temp_pool, thiscmd->name, " ", err, " ",
                                   word, "=", val, "; ", conf->p, NULL);
        }
    }

    cmd->path = old_path;
    cmd->override = old_overrides;

    return NULL;
}

static const command_rec proxy_cmds[] =
{
    AP_INIT_RAW_ARGS("<Proxy", proxysection, NULL, RSRC_CONF,
    "Container for directives affecting resources located in the proxied "
    "location"),
    AP_INIT_RAW_ARGS("<ProxyMatch", proxysection, (void*)1, RSRC_CONF,
    "Container for directives affecting resources located in the proxied "
    "location, in regular expression syntax"),
    AP_INIT_FLAG("ProxyRequests", set_proxy_req, NULL, RSRC_CONF,
     "on if the true proxy requests should be accepted"),
    AP_INIT_TAKE2("ProxyRemote", add_proxy_noregex, NULL, RSRC_CONF,
     "a scheme, partial URL or '*' and a proxy server"),
    AP_INIT_TAKE2("ProxyRemoteMatch", add_proxy_regex, NULL, RSRC_CONF,
     "a regex pattern and a proxy server"),
    AP_INIT_FLAG("ProxyPassInterpolateEnv", ap_set_flag_slot_char,
        (void*)APR_OFFSETOF(proxy_dir_conf, interpolate_env),
        RSRC_CONF|ACCESS_CONF, "Interpolate Env Vars in reverse Proxy") ,
    AP_INIT_RAW_ARGS("ProxyPass", add_pass_noregex, NULL, RSRC_CONF|ACCESS_CONF,
     "a virtual path and a URL"),
    AP_INIT_RAW_ARGS("ProxyPassMatch", add_pass_regex, NULL, RSRC_CONF|ACCESS_CONF,
     "a virtual path and a URL"),
    AP_INIT_TAKE123("ProxyPassReverse", add_pass_reverse, NULL, RSRC_CONF|ACCESS_CONF,
     "a virtual path and a URL for reverse proxy behaviour"),
    AP_INIT_TAKE23("ProxyPassReverseCookiePath", cookie_path, NULL,
       RSRC_CONF|ACCESS_CONF, "Path rewrite rule for proxying cookies"),
    AP_INIT_TAKE23("ProxyPassReverseCookieDomain", cookie_domain, NULL,
       RSRC_CONF|ACCESS_CONF, "Domain rewrite rule for proxying cookies"),
    AP_INIT_ITERATE("ProxyBlock", set_proxy_exclude, NULL, RSRC_CONF,
     "A list of names, hosts or domains to which the proxy will not connect"),
    AP_INIT_TAKE1("ProxyReceiveBufferSize", set_recv_buffer_size, NULL, RSRC_CONF,
     "Receive buffer size for outgoing HTTP and FTP connections in bytes"),
    AP_INIT_TAKE1("ProxyIOBufferSize", set_io_buffer_size, NULL, RSRC_CONF,
     "IO buffer size for outgoing HTTP and FTP connections in bytes"),
    AP_INIT_TAKE1("ProxyMaxForwards", set_max_forwards, NULL, RSRC_CONF,
     "The maximum number of proxies a request may be forwarded through."),
    AP_INIT_ITERATE("NoProxy", set_proxy_dirconn, NULL, RSRC_CONF,
     "A list of domains, hosts, or subnets to which the proxy will connect directly"),
    AP_INIT_TAKE1("ProxyDomain", set_proxy_domain, NULL, RSRC_CONF,
     "The default intranet domain name (in absence of a domain in the URL)"),
    AP_INIT_TAKE1("ProxyVia", set_via_opt, NULL, RSRC_CONF,
     "Configure Via: proxy header header to one of: on | off | block | full"),
    AP_INIT_ITERATE("ProxyErrorOverride", set_proxy_error_override, NULL, RSRC_CONF|ACCESS_CONF,
     "use our error handling pages instead of the servers' we are proxying"),
    AP_INIT_FLAG("ProxyPreserveHost", set_preserve_host, NULL, RSRC_CONF|ACCESS_CONF,
     "on if we should preserve host header while proxying"),
    AP_INIT_TAKE1("ProxyTimeout", set_proxy_timeout, NULL, RSRC_CONF,
     "Set the timeout (in seconds) for a proxied connection. "
     "This overrides the server timeout"),
    AP_INIT_TAKE1("ProxyBadHeader", set_bad_opt, NULL, RSRC_CONF,
     "How to handle bad header line in response: IsError | Ignore | StartBody"),
    AP_INIT_RAW_ARGS("BalancerMember", add_member, NULL, RSRC_CONF|ACCESS_CONF,
     "A balancer name and scheme with list of params"),
    AP_INIT_TAKE1("BalancerGrowth", set_bgrowth, NULL, RSRC_CONF,
     "Number of additional Balancers that can be added post-config"),
    AP_INIT_FLAG("BalancerPersist", set_persist, NULL, RSRC_CONF,
     "on if the balancer should persist changes on reboot/restart made via the Balancer Manager"),
    AP_INIT_FLAG("BalancerInherit", set_inherit, NULL, RSRC_CONF,
     "on if this server should inherit Balancers and Workers defined in the main server "
     "(Setting to off recommended if using the Balancer Manager)"),
    AP_INIT_FLAG("ProxyPassInherit", set_ppinherit, NULL, RSRC_CONF,
     "on if this server should inherit all ProxyPass directives defined in the main server "
     "(Setting to off recommended if using the Balancer Manager)"),
    AP_INIT_TAKE1("ProxyStatus", set_status_opt, NULL, RSRC_CONF,
     "Configure Status: proxy status to one of: on | off | full"),
    AP_INIT_RAW_ARGS("ProxySet", set_proxy_param, NULL, RSRC_CONF|ACCESS_CONF,
     "A balancer or worker name with list of params"),
    AP_INIT_TAKE1("ProxySourceAddress", set_source_address, NULL, RSRC_CONF,
     "Configure local source IP used for request forward"),
    AP_INIT_FLAG("ProxyAddHeaders", add_proxy_http_headers, NULL, RSRC_CONF|ACCESS_CONF,
     "on if X-Forwarded-* headers should be added or completed"),
    AP_INIT_FLAG("Proxy100Continue", forward_100_continue, NULL, RSRC_CONF|ACCESS_CONF,
     "on if 100-Continue should be forwarded to the origin server, off if the "
     "proxy should handle it by itself"),
    {NULL}
};

static APR_OPTIONAL_FN_TYPE(ssl_proxy_enable) *proxy_ssl_enable = NULL;
static APR_OPTIONAL_FN_TYPE(ssl_engine_disable) *proxy_ssl_disable = NULL;
static APR_OPTIONAL_FN_TYPE(ssl_engine_set) *proxy_ssl_engine = NULL;

PROXY_DECLARE(int) ap_proxy_ssl_enable(conn_rec *c)
{
    /*
     * if c == NULL just check if the optional function was imported
     * else run the optional function so ssl filters are inserted
     */
    if (c == NULL) {
        return ap_ssl_has_outgoing_handlers();
    }
    return ap_ssl_bind_outgoing(c, NULL, 1) == OK;
}

PROXY_DECLARE(int) ap_proxy_ssl_disable(conn_rec *c)
{
    return ap_ssl_bind_outgoing(c, NULL, 0) == OK;
}

PROXY_DECLARE(int) ap_proxy_ssl_engine(conn_rec *c,
                                       ap_conf_vector_t *per_dir_config,
                                       int enable)
{
    /*
     * if c == NULL just check if the optional function was imported
     * else run the optional function so ssl filters are inserted
     */
    if (c == NULL) {
        return ap_ssl_has_outgoing_handlers();
    }
    return ap_ssl_bind_outgoing(c, per_dir_config, enable) == OK;
}

PROXY_DECLARE(int) ap_proxy_conn_is_https(conn_rec *c)
{
    return ap_ssl_conn_is_ssl(c);
}

PROXY_DECLARE(const char *) ap_proxy_ssl_val(apr_pool_t *p, server_rec *s,
                                             conn_rec *c, request_rec *r,
                                             const char *var)
{
    return ap_ssl_var_lookup(p, s, c, r, var);
}

static int proxy_post_config(apr_pool_t *pconf, apr_pool_t *plog,
                             apr_pool_t *ptemp, server_rec *main_s)
{
    server_rec *s = main_s;
    apr_status_t rv = ap_global_mutex_create(&proxy_mutex, NULL,
                                             proxy_id, NULL, s, pconf, 0);
    if (rv != APR_SUCCESS) {
        ap_log_perror(APLOG_MARK, APLOG_CRIT, rv, plog, APLOGNO(02478)
        "failed to create %s mutex", proxy_id);
        return rv;
    }

    proxy_ssl_enable = APR_RETRIEVE_OPTIONAL_FN(ssl_proxy_enable);
    proxy_ssl_disable = APR_RETRIEVE_OPTIONAL_FN(ssl_engine_disable);
    proxy_ssl_engine = APR_RETRIEVE_OPTIONAL_FN(ssl_engine_set);
    ap_proxy_strmatch_path = apr_strmatch_precompile(pconf, "path=", 0);
    ap_proxy_strmatch_domain = apr_strmatch_precompile(pconf, "domain=", 0);

    for (; s; s = s->next) {
        int rc, i;
        proxy_server_conf *sconf =
            ap_get_module_config(s->module_config, &proxy_module);
        ap_conf_vector_t **sections =
            (ap_conf_vector_t **)sconf->sec_proxy->elts;

        for (i = 0; i < sconf->sec_proxy->nelts; ++i) {
            rc = proxy_run_section_post_config(pconf, ptemp, plog,
                                               s, sections[i]);
            if (rc != OK && rc != DECLINED) {
                return rc;
            }
        }
    }

    return OK;
}

/*
 *  proxy Extension to mod_status
 */
static int proxy_status_hook(request_rec *r, int flags)
{
    int i, n;
    void *sconf = r->server->module_config;
    proxy_server_conf *conf = (proxy_server_conf *)
        ap_get_module_config(sconf, &proxy_module);
    proxy_balancer *balancer = NULL;
    proxy_worker **worker = NULL;

    if (conf->balancers->nelts == 0 ||
        conf->proxy_status == status_off)
        return OK;

    balancer = (proxy_balancer *)conf->balancers->elts;
    for (i = 0; i < conf->balancers->nelts; i++) {
        if (!(flags & AP_STATUS_SHORT)) {
            ap_rputs("<hr />\n<h1>Proxy LoadBalancer Status for ", r);
            ap_rvputs(r, balancer->s->name, "</h1>\n\n", NULL);
            ap_rputs("\n\n<table border=\"0\"><tr>"
                     "<th>SSes</th><th>Timeout</th><th>Method</th>"
                     "</tr>\n<tr>", r);
            if (*balancer->s->sticky) {
                if (strcmp(balancer->s->sticky, balancer->s->sticky_path)) {
                    ap_rvputs(r, "<td>", balancer->s->sticky, " | ",
                              balancer->s->sticky_path, NULL);
                }
                else {
                    ap_rvputs(r, "<td>", balancer->s->sticky, NULL);
                }
            }
            else {
                ap_rputs("<td> - ", r);
            }
            ap_rprintf(r, "</td><td>%" APR_TIME_T_FMT "</td>",
                       apr_time_sec(balancer->s->timeout));
            ap_rprintf(r, "<td>%s</td>\n",
                       balancer->lbmethod->name);
            ap_rputs("</table>\n", r);
            ap_rputs("\n\n<table border=\"0\"><tr>"
                     "<th>Sch</th><th>Host</th><th>Stat</th>"
                     "<th>Route</th><th>Redir</th>"
                     "<th>F</th><th>Set</th><th>Acc</th><th>Busy</th><th>Wr</th><th>Rd</th>"
                     "</tr>\n", r);
        }
        else {
            ap_rprintf(r, "ProxyBalancer[%d]Name: %s\n", i, balancer->s->name);
        }

        worker = (proxy_worker **)balancer->workers->elts;
        for (n = 0; n < balancer->workers->nelts; n++) {
            char fbuf[50];
            if (!(flags & AP_STATUS_SHORT)) {
                ap_rvputs(r, "<tr>\n<td>", (*worker)->s->scheme, "</td>", NULL);
                ap_rvputs(r, "<td>", (*worker)->s->hostname_ex, "</td><td>", NULL);
                ap_rvputs(r, ap_proxy_parse_wstatus(r->pool, *worker), NULL);
                ap_rvputs(r, "</td><td>", (*worker)->s->route, NULL);
                ap_rvputs(r, "</td><td>", (*worker)->s->redirect, NULL);
                ap_rprintf(r, "</td><td>%.2f</td>", (float)((*worker)->s->lbfactor)/100.0);
                ap_rprintf(r, "<td>%d</td>", (*worker)->s->lbset);
                ap_rprintf(r, "<td>%" APR_SIZE_T_FMT "</td>",
                           (*worker)->s->elected);
                ap_rprintf(r, "<td>%" APR_SIZE_T_FMT "</td><td>",
                           (*worker)->s->busy);
                ap_rputs(apr_strfsize((*worker)->s->transferred, fbuf), r);
                ap_rputs("</td><td>", r);
                ap_rputs(apr_strfsize((*worker)->s->read, fbuf), r);
                ap_rputs("</td>\n", r);

                /* TODO: Add the rest of dynamic worker data */
                ap_rputs("</tr>\n", r);
            }
            else {
                ap_rprintf(r, "ProxyBalancer[%d]Worker[%d]Name: %s\n",
                           i, n, (*worker)->s->name_ex);
                ap_rprintf(r, "ProxyBalancer[%d]Worker[%d]Status: %s\n",
                           i, n, ap_proxy_parse_wstatus(r->pool, *worker));
                ap_rprintf(r, "ProxyBalancer[%d]Worker[%d]Elected: %"
                              APR_SIZE_T_FMT "\n",
                           i, n, (*worker)->s->elected);
                ap_rprintf(r, "ProxyBalancer[%d]Worker[%d]Busy: %"
                              APR_SIZE_T_FMT "\n",
                           i, n, (*worker)->s->busy);
                ap_rprintf(r, "ProxyBalancer[%d]Worker[%d]Sent: %"
                              APR_OFF_T_FMT "K\n",
                           i, n, (*worker)->s->transferred >> 10);
                ap_rprintf(r, "ProxyBalancer[%d]Worker[%d]Rcvd: %"
                              APR_OFF_T_FMT "K\n",
                           i, n, (*worker)->s->read >> 10);

                /* TODO: Add the rest of dynamic worker data */
            }

            ++worker;
        }
        if (!(flags & AP_STATUS_SHORT)) {
            ap_rputs("</table>\n", r);
        }
        ++balancer;
    }
    if (!(flags & AP_STATUS_SHORT)) {
        ap_rputs("<hr /><table>\n"
                 "<tr><th>SSes</th><td>Sticky session name</td></tr>\n"
                 "<tr><th>Timeout</th><td>Balancer Timeout</td></tr>\n"
                 "<tr><th>Sch</th><td>Connection scheme</td></tr>\n"
                 "<tr><th>Host</th><td>Backend Hostname</td></tr>\n"
                 "<tr><th>Stat</th><td>Worker status</td></tr>\n"
                 "<tr><th>Route</th><td>Session Route</td></tr>\n"
                 "<tr><th>Redir</th><td>Session Route Redirection</td></tr>\n"
                 "<tr><th>F</th><td>Load Balancer Factor</td></tr>\n"
                 "<tr><th>Acc</th><td>Number of uses</td></tr>\n"
                 "<tr><th>Wr</th><td>Number of bytes transferred</td></tr>\n"
                 "<tr><th>Rd</th><td>Number of bytes read</td></tr>\n"
                 "</table>", r);
    }

    return OK;
}

static void child_init(apr_pool_t *p, server_rec *s)
{
    proxy_worker *reverse = NULL;

    apr_status_t rv = apr_global_mutex_child_init(&proxy_mutex,
                                      apr_global_mutex_lockfile(proxy_mutex),
                                      p);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s, APLOGNO(02479)
                     "could not init proxy_mutex in child");
        exit(1); /* Ugly, but what else? */
    }

    /* TODO */
    while (s) {
        void *sconf = s->module_config;
        proxy_server_conf *conf;
        proxy_worker *worker;
        int i;

        conf = (proxy_server_conf *)ap_get_module_config(sconf, &proxy_module);
        /*
         * NOTE: non-balancer members don't use shm at all...
         *       after all, why should they?
         */
        worker = (proxy_worker *)conf->workers->elts;
        for (i = 0; i < conf->workers->nelts; i++, worker++) {
            ap_proxy_initialize_worker(worker, s, p);
        }
        /* Create and initialize forward worker if defined */
        if (conf->req_set && conf->req) {
            proxy_worker *forward;
            ap_proxy_define_worker(conf->pool, &forward, NULL, NULL,
                                   "http://www.apache.org", 0);
            conf->forward = forward;
            PROXY_STRNCPY(conf->forward->s->name,     "proxy:forward");
            PROXY_STRNCPY(conf->forward->s->name_ex,  "proxy:forward");
            PROXY_STRNCPY(conf->forward->s->hostname, "*"); /* for compatibility */
            PROXY_STRNCPY(conf->forward->s->hostname_ex, "*");
            PROXY_STRNCPY(conf->forward->s->scheme,   "*");
            conf->forward->hash.def = conf->forward->s->hash.def =
                ap_proxy_hashfunc(conf->forward->s->name_ex, PROXY_HASHFUNC_DEFAULT);
             conf->forward->hash.fnv = conf->forward->s->hash.fnv =
                ap_proxy_hashfunc(conf->forward->s->name_ex, PROXY_HASHFUNC_FNV);
            /* Do not disable worker in case of errors */
            conf->forward->s->status |= PROXY_WORKER_IGNORE_ERRORS;
            /* Mark as the "generic" worker */
            conf->forward->s->status |= PROXY_WORKER_GENERIC;
            ap_proxy_initialize_worker(conf->forward, s, p);
            /* Disable address cache for generic forward worker */
            conf->forward->s->is_address_reusable = 0;
        }
        if (!reverse) {
            ap_proxy_define_worker(conf->pool, &reverse, NULL, NULL,
                                   "http://www.apache.org", 0);
            PROXY_STRNCPY(reverse->s->name,     "proxy:reverse");
            PROXY_STRNCPY(reverse->s->name_ex,  "proxy:reverse");
            PROXY_STRNCPY(reverse->s->hostname, "*"); /* for compatibility */
            PROXY_STRNCPY(reverse->s->hostname_ex, "*");
            PROXY_STRNCPY(reverse->s->scheme,   "*");
            reverse->hash.def = reverse->s->hash.def =
                ap_proxy_hashfunc(reverse->s->name_ex, PROXY_HASHFUNC_DEFAULT);
            reverse->hash.fnv = reverse->s->hash.fnv =
                ap_proxy_hashfunc(reverse->s->name_ex, PROXY_HASHFUNC_FNV);
            /* Do not disable worker in case of errors */
            reverse->s->status |= PROXY_WORKER_IGNORE_ERRORS;
            /* Mark as the "generic" worker */
            reverse->s->status |= PROXY_WORKER_GENERIC;
            conf->reverse = reverse;
            ap_proxy_initialize_worker(conf->reverse, s, p);
            /* Disable address cache for generic reverse worker */
            reverse->s->is_address_reusable = 0;
        }
        conf->reverse = reverse;
        s = s->next;
    }
}

/*
 * This routine is called before the server processes the configuration
 * files.
 */
static int proxy_pre_config(apr_pool_t *pconf, apr_pool_t *plog,
                            apr_pool_t *ptemp)
{
    apr_status_t rv = ap_mutex_register(pconf, proxy_id, NULL,
            APR_LOCK_DEFAULT, 0);
    if (rv != APR_SUCCESS) {
        ap_log_perror(APLOG_MARK, APLOG_CRIT, rv, plog, APLOGNO(02480)
                "failed to register %s mutex", proxy_id);
        return 500; /* An HTTP status would be a misnomer! */
    }

    APR_OPTIONAL_HOOK(ap, status_hook, proxy_status_hook, NULL, NULL,
                      APR_HOOK_MIDDLE);
    /* Reset workers count on graceful restart */
    proxy_lb_workers = 0;
    set_worker_hc_param_f = APR_RETRIEVE_OPTIONAL_FN(set_worker_hc_param);
    return OK;
}
static void register_hooks(apr_pool_t *p)
{
    /* fixup before mod_rewrite, so that the proxied url will not
     * escaped accidentally by our fixup.
     */
    static const char * const aszSucc[] = { "mod_rewrite.c", NULL};
    /* Only the mpm_winnt has child init hook handler.
     * make sure that we are called after the mpm
     * initializes.
     */
    static const char *const aszPred[] = { "mpm_winnt.c", "mod_proxy_balancer.c",
                                           "mod_proxy_hcheck.c", NULL};
    /* handler */
    ap_hook_handler(proxy_handler, NULL, NULL, APR_HOOK_FIRST);
    /* filename-to-URI translation */
    ap_hook_pre_translate_name(proxy_pre_translate_name, NULL, NULL,
                               APR_HOOK_MIDDLE);
    ap_hook_translate_name(proxy_translate_name, aszSucc, NULL,
                           APR_HOOK_FIRST);
    /* walk <Proxy > entries and suppress default TRACE behavior */
    ap_hook_map_to_storage(proxy_map_location, NULL,NULL, APR_HOOK_FIRST);
    /* fixups */
    ap_hook_fixups(proxy_fixup, NULL, aszSucc, APR_HOOK_FIRST);
    /* post read_request handling */
    ap_hook_post_read_request(proxy_detect, NULL, NULL, APR_HOOK_FIRST);
    /* pre config handling */
    ap_hook_pre_config(proxy_pre_config, NULL, NULL, APR_HOOK_MIDDLE);
    /* post config handling */
    ap_hook_post_config(proxy_post_config, NULL, NULL, APR_HOOK_MIDDLE);
    /* child init handling */
    ap_hook_child_init(child_init, aszPred, NULL, APR_HOOK_MIDDLE);

    /* register optional functions within proxy_util.c */
    proxy_util_register_hooks(p);
}

AP_DECLARE_MODULE(proxy) =
{
    STANDARD20_MODULE_STUFF,
    create_proxy_dir_config,    /* create per-directory config structure */
    merge_proxy_dir_config,     /* merge per-directory config structures */
    create_proxy_config,        /* create per-server config structure */
    merge_proxy_config,         /* merge per-server config structures */
    proxy_cmds,                 /* command table */
    register_hooks
};

APR_HOOK_STRUCT(
    APR_HOOK_LINK(scheme_handler)
    APR_HOOK_LINK(canon_handler)
    APR_HOOK_LINK(pre_request)
    APR_HOOK_LINK(post_request)
    APR_HOOK_LINK(request_status)
    APR_HOOK_LINK(check_trans)
)

APR_IMPLEMENT_EXTERNAL_HOOK_RUN_FIRST(proxy, PROXY, int, scheme_handler,
                                     (request_rec *r, proxy_worker *worker,
                                      proxy_server_conf *conf,
                                      char *url, const char *proxyhost,
                                      apr_port_t proxyport),(r,worker,conf,
                                      url,proxyhost,proxyport),DECLINED)
APR_IMPLEMENT_EXTERNAL_HOOK_RUN_FIRST(proxy, PROXY, int, check_trans,
                                      (request_rec *r, const char *url),
                                      (r, url), DECLINED)
APR_IMPLEMENT_EXTERNAL_HOOK_RUN_FIRST(proxy, PROXY, int, canon_handler,
                                      (request_rec *r, char *url),(r,
                                      url),DECLINED)
APR_IMPLEMENT_EXTERNAL_HOOK_RUN_FIRST(proxy, PROXY, int, pre_request, (
                                      proxy_worker **worker,
                                      proxy_balancer **balancer,
                                      request_rec *r,
                                      proxy_server_conf *conf,
                                      char **url),(worker,balancer,
                                      r,conf,url),DECLINED)
APR_IMPLEMENT_EXTERNAL_HOOK_RUN_FIRST(proxy, PROXY, int, post_request,
                                      (proxy_worker *worker,
                                       proxy_balancer *balancer,
                                       request_rec *r,
                                       proxy_server_conf *conf),(worker,
                                       balancer,r,conf),DECLINED)
APR_IMPLEMENT_OPTIONAL_HOOK_RUN_ALL(proxy, PROXY, int, section_post_config,
                                    (apr_pool_t *p, apr_pool_t *plog,
                                     apr_pool_t *ptemp, server_rec *s,
                                     ap_conf_vector_t *section_config),
                                    (p, ptemp, plog, s, section_config),
                                    OK, DECLINED)
APR_IMPLEMENT_OPTIONAL_HOOK_RUN_ALL(proxy, PROXY, int, fixups,
                                    (request_rec *r), (r),
                                    OK, DECLINED)
APR_IMPLEMENT_OPTIONAL_HOOK_RUN_ALL(proxy, PROXY, int, request_status,
                                    (int *status, request_rec *r),
                                    (status, r),
                                    OK, DECLINED)
