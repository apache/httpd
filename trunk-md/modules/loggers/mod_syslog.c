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
#include <http_main.h>
#include <apr_version.h>
#include <apr_pools.h>
#include <apr_strings.h>
#include "unixd.h"
#include "scoreboard.h"
#include "mpm_common.h"

#include "syslog.h"

#if APR_HAVE_UNISTD_H
#include <unistd.h>
#endif

typedef struct {
    const char *t_name;
    int t_val;
} TRANS;

static const TRANS facilities[] = {
    {"auth",    LOG_AUTH},
#ifdef LOG_AUTHPRIV
    {"authpriv",LOG_AUTHPRIV},
#endif
#ifdef LOG_CRON
    {"cron",    LOG_CRON},
#endif
#ifdef LOG_DAEMON
    {"daemon",  LOG_DAEMON},
#endif
#ifdef LOG_FTP
    {"ftp", LOG_FTP},
#endif
#ifdef LOG_KERN
    {"kern",    LOG_KERN},
#endif
#ifdef LOG_LPR
    {"lpr", LOG_LPR},
#endif
#ifdef LOG_MAIL
    {"mail",    LOG_MAIL},
#endif
#ifdef LOG_NEWS
    {"news",    LOG_NEWS},
#endif
#ifdef LOG_SYSLOG
    {"syslog",  LOG_SYSLOG},
#endif
#ifdef LOG_USER
    {"user",    LOG_USER},
#endif
#ifdef LOG_UUCP
    {"uucp",    LOG_UUCP},
#endif
#ifdef LOG_LOCAL0
    {"local0",  LOG_LOCAL0},
#endif
#ifdef LOG_LOCAL1
    {"local1",  LOG_LOCAL1},
#endif
#ifdef LOG_LOCAL2
    {"local2",  LOG_LOCAL2},
#endif
#ifdef LOG_LOCAL3
    {"local3",  LOG_LOCAL3},
#endif
#ifdef LOG_LOCAL4
    {"local4",  LOG_LOCAL4},
#endif
#ifdef LOG_LOCAL5
    {"local5",  LOG_LOCAL5},
#endif
#ifdef LOG_LOCAL6
    {"local6",  LOG_LOCAL6},
#endif
#ifdef LOG_LOCAL7
    {"local7",  LOG_LOCAL7},
#endif
    {NULL,      -1},
};


static void *syslog_error_log_init(apr_pool_t *p, server_rec *s)
{
    char *fname = s->error_fname;
    void *success = (void *)p; /* anything non-NULL is success */

    if (*fname == '\0') {
        openlog(ap_server_argv0, LOG_NDELAY|LOG_CONS|LOG_PID, LOG_LOCAL7);
    }
    else {
        /* s->error_fname could be [level]:[tag] (see #60525) */
        const char *tag;
        apr_size_t flen;
        const TRANS *fac;

        tag = strchr(fname, ':');
        if (tag) {
            flen = tag - fname;
            tag++;
            if (*tag == '\0') {
                tag = ap_server_argv0;
            }
        } else {
            flen = strlen(fname);
            tag = ap_server_argv0;
        }
        if (flen == 0) {
            /* Was something like syslog::foobar */
            openlog(tag, LOG_NDELAY|LOG_CONS|LOG_PID, LOG_LOCAL7);
        } else {
            for (fac = facilities; fac->t_name; fac++) {
                if (!strncasecmp(fname, fac->t_name, flen)) {
                    openlog(tag, LOG_NDELAY|LOG_CONS|LOG_PID,
                            fac->t_val);
                    return success;
                }
            }
            /* Huh? Invalid level name? */
            return NULL;
        }
    }
    return success;
}

static apr_status_t syslog_error_log(const ap_errorlog_info *info,
                                     void *handle, const char *errstr,
                                     apr_size_t len)
{
    int level = info->level;

    if (level != APLOG_NOTICE) {
        syslog(level < LOG_PRIMASK ? level : APLOG_DEBUG, "%.*s", (int)len, errstr);
    }
    return APR_SUCCESS;
}

static const char *syslog_error_log_parse(cmd_parms *cmd, const char *arg)
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);

    if (err != NULL) {
        return apr_pstrcat(cmd->pool,
                           "When using syslog error log provider, ", err,
                           NULL);
    }

    return NULL;
}

static void syslog_register_hooks(apr_pool_t *p)
{
    static const ap_errorlog_provider syslog_provider = {
        &syslog_error_log_init,
        &syslog_error_log,
        &syslog_error_log_parse,
        0
    };

    ap_register_provider(p, AP_ERRORLOG_PROVIDER_GROUP, "syslog",
                         AP_ERRORLOG_PROVIDER_VERSION, &syslog_provider);
}

AP_DECLARE_MODULE(syslog) =
{
    STANDARD20_MODULE_STUFF,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    syslog_register_hooks,
};
