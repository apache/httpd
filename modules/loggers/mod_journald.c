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
 * 
 */

#include <stdint.h>
#include <ap_config.h>
#include "ap_mpm.h"
#include "ap_provider.h"
#include <http_core.h>
#include <httpd.h>
#include <http_log.h>
#include <apr_version.h>
#include <apr_pools.h>
#include <apr_strings.h>
#include "unixd.h"
#include "scoreboard.h"
#include "mpm_common.h"
#include "mod_log_config.h"

#if APR_HAVE_UNISTD_H
#include <unistd.h>
#endif

/* XXX: keep this after any other #include.
 * Some systemd versions use the "inline" keyword which is not
 * c89/c90 compliant, so override it...
 */
#if defined(__STDC__) && (!defined(__STDC_VERSION__) \
                          || __STDC_VERSION__ < 199901L)
#undef inline
#define inline APR_INLINE
#endif
#define SD_JOURNAL_SUPPRESS_LOCATION 1
#include <systemd/sd-journal.h>

#define MAX_ENTRIES 15

static int journald_info_get_priority(int level)
{
    switch(level) {
        /* We don't use EMERG here, because journald broadcasts EMERG messages
         * to all terminals. APLOG_EMERG is usually not used in this context.
         * in httpd code. */
        case APLOG_EMERG:   return LOG_ALERT;
        case APLOG_ALERT:   return LOG_ALERT;
        case APLOG_CRIT:    return LOG_CRIT;
        case APLOG_ERR:     return LOG_ERR;
        case APLOG_WARNING: return LOG_WARNING;
        case APLOG_NOTICE:  return LOG_NOTICE;
        case APLOG_INFO:    return LOG_INFO;
        case APLOG_DEBUG:   return LOG_DEBUG;
        case -1:            return LOG_INFO;
        default:            return LOG_DEBUG;
    }
    return LOG_INFO;
}

static apr_pool_t *journald_info_get_pool(const ap_errorlog_info *info)
{
    if (info->r && info->r->pool)
        return info->r->pool;
    if (info->c && info->c->pool)
        return info->c->pool;
    if (info->pool)
        return info->pool;
    if (info->s && info->s->process && info->s->process->pool)
        return info->s->process->pool;
    return 0;
}

static apr_status_t iovec_add_entry(apr_pool_t *pool, struct iovec *iov,
                                    const char *format, int len, ...)
{
    va_list ap;
    va_start(ap, len);
    iov->iov_base = apr_pvsprintf(pool, format, ap);
    va_end(ap);
    if (!iov->iov_base) {
        return APR_ENOMEM;
    }
    if (len < 0) {
        iov->iov_len = strlen(iov->iov_base);
    }
    else {
        iov->iov_len = len;
    }
    return APR_SUCCESS;
}

static void journald_log(apr_pool_t *pool, const char *log,
                         const char *errstr, int len, int priority,
                         const server_rec *s, const request_rec *r)
{
    apr_pool_t *subpool;
    apr_status_t rv = APR_SUCCESS;
    struct iovec iov[MAX_ENTRIES];
    int iov_size = 0;

    if (apr_pool_create(&subpool, pool) != APR_SUCCESS) {
        /* We were not able to create subpool, log at least what we have. */
        sd_journal_send("MESSAGE=%s", errstr, "LOG=%s", log,
                    "PRIORITY=%i", priority,
                    NULL);
        return;
    }

    /* Adds new entry to iovec if previous additions were successful. */
#define IOVEC_ADD_LEN(FORMAT, VAR, LEN) \
    if (rv == APR_SUCCESS && iov_size < MAX_ENTRIES) { \
        rv = iovec_add_entry(subpool, &iov[iov_size], FORMAT, LEN, VAR); \
        if (rv == APR_SUCCESS) \
            iov_size++; \
    }
#define IOVEC_ADD(FORMAT, VAR) IOVEC_ADD_LEN(FORMAT, VAR, -1)

    IOVEC_ADD_LEN("MESSAGE=%s", errstr, len + 8);
    IOVEC_ADD("LOG=%s", log);
    IOVEC_ADD("PRIORITY=%i", priority);

    if (s) {
        IOVEC_ADD("SERVER_HOSTNAME=%s", s->server_hostname);
    }

    if (r) {
        IOVEC_ADD("REQUEST_HOSTNAME=%s", r->hostname);
        IOVEC_ADD("REQUEST_USER=%s", r->user ? r->user : "");
        IOVEC_ADD("REQUEST_URI=%s", r->uri ? r->uri : "");
        IOVEC_ADD("REQUEST_USERAGENT_IP=%s", r->useragent_ip);
    }

    sd_journal_sendv(iov, iov_size);
    apr_pool_destroy(subpool);
}

static void *journald_error_log_init(apr_pool_t *p, server_rec *s)
{
    void *success = (void *)p; /* anything non-NULL is success */
    return success;
}

static apr_status_t journald_error_log(const ap_errorlog_info *info,
                                       void *handle, const char *errstr,
                                       apr_size_t len)
{
    const server_rec *s = info->s;
    const request_rec *r = info->r;
    apr_pool_t *pool;
    const char *log_name = (s && s->error_fname && *s->error_fname) ?
                            s->error_fname : "error_log";

    pool = journald_info_get_pool(info);
    if (!pool) {
        /* We don't have any pool, so at least log the message without
         * any additional data. */
        sd_journal_send("MESSAGE=%s", errstr, "LOG=%s", "log_name",
                    "PRIORITY=%i", journald_info_get_priority(info->level),
                    NULL);
        return APR_SUCCESS;
    }

    journald_log(pool, log_name, errstr, len,
                 journald_info_get_priority(info->level), s, r);

    return APR_SUCCESS;
}

static const char *journald_error_log_parse(cmd_parms *cmd, const char *arg)
{
    return NULL;
}

static void journald_register_hooks(apr_pool_t *p)
{
    static const ap_errorlog_provider journald_provider = {
        &journald_error_log_init,
        &journald_error_log,
        &journald_error_log_parse,
        0
    };

    ap_register_provider(p, AP_ERRORLOG_PROVIDER_GROUP, "journald",
                         AP_ERRORLOG_PROVIDER_VERSION,
                         &journald_provider);
}

AP_DECLARE_MODULE(journald) =
{
    STANDARD20_MODULE_STUFF,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    journald_register_hooks,
};
