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

#include <ap_config.h>
#include <apr_version.h>
#include <apr_pools.h>
#include <apr_strings.h>

#include "http_core.h"
#include "httpd.h"
#include "http_log.h"
#include "http_main.h"
#include "ap_provider.h"

struct tee_handle {
    apr_file_t *fd;
    ap_errorlog_provider *provider;
    void *handle;
    struct tee_handle *next;
};

static void *tee_error_log_init(apr_pool_t *p, server_rec *s)
{
    struct tee_handle *prev = NULL, *this = NULL;
    char *tok;
    const char *lognames = s->error_fname;
    /* If this is the error log provider for the main vhost then the
     * first file-based log should be treated as main (for stderr
     * handling). */
    int is_main = s == ap_server_conf;
    
    if (lognames == NULL) {
        /* doesn't make sense */
        ap_log_error(APLOG_MARK, APLOG_CRIT, 0, s,
                     "tee: cannot be used without an argument");
        return NULL;
    }

    while (*lognames) {
        char *arg, *name;

        tok = ap_getword_conf(p, &lognames);
        arg = strchr(tok, ':');
        
        this = apr_pcalloc(p, sizeof *this);

        if (arg) {
            name = apr_pstrmemdup(p, tok, arg - tok);
            arg++;

            this->provider = ap_lookup_provider(AP_ERRORLOG_PROVIDER_GROUP, name,
                                                AP_ERRORLOG_PROVIDER_VERSION);
            if (!this->provider) {
                ap_log_error(APLOG_MARK, APLOG_STARTUP|APLOG_CRIT, 0, s,
                             "cannot find error log provider %s", name);
                return NULL;
            }

            /* Substitute the configured "filename" (argument) for
             * provider initialization. */
            s->error_fname = arg;
            this->handle = this->provider->init(p, s);
            
            if (!this->handle) {
                /* Must already be logged. */
                return NULL;
            }
        }
        else {
            this->fd = ap_open_error_log(tok, is_main, p);
            if (!this->fd) {
                ap_log_error(APLOG_MARK, APLOG_STARTUP|APLOG_CRIT, 0, s,
                             "cannot open error log file %s", tok);
                return NULL;
            }
            /* Only the first iteration is treated as "main". */
            is_main = 0;
        }
            
        this->next = prev;
        prev = this;
        tok = NULL;
    }

    if (this == NULL) {
        ap_log_error(APLOG_MARK, APLOG_STARTUP|APLOG_CRIT, 0, s,
                     "no log files specified to tee for: %s", s->error_fname);
        return NULL;
    }
    
    return this;
}

static apr_status_t tee_error_log(const ap_errorlog_info *info,
                                  void *handle, const char *errstr,
                                  apr_size_t len)
{
    struct tee_handle *mlh;
    apr_status_t rv = APR_SUCCESS;

    for (mlh = handle; rv == APR_SUCCESS && mlh != NULL; mlh = mlh->next) {
        if (mlh->fd) {
            apr_size_t wlen = len;
            apr_file_write(mlh->fd, errstr, &wlen);
            apr_file_flush(mlh->fd);
        }
        else {
            apr_size_t errlen = len;

            if ((mlh->provider->flags & AP_ERRORLOG_PROVIDER_ADD_EOL_STR) == 0)
                errlen -= strlen(APR_EOL_STR);
            
            mlh->provider->writer(info, mlh->handle, errstr, errlen);
        }
    }
        
    return APR_SUCCESS;
}

static const char *tee_error_log_parse(cmd_parms *cmd, const char *arg)
{
    return NULL;
}

static void log_tee_register_hooks(apr_pool_t *p)
{
    static const ap_errorlog_provider log_tee_provider = {
        &tee_error_log_init,
        &tee_error_log,
        &tee_error_log_parse,
        AP_ERRORLOG_PROVIDER_ADD_EOL_STR | AP_ERRORLOG_PROVIDER_ADD_TIMESTAMP,
    };

    ap_register_provider(p, AP_ERRORLOG_PROVIDER_GROUP, "tee",
                         AP_ERRORLOG_PROVIDER_VERSION, &log_tee_provider);
}

AP_DECLARE_MODULE(log_tee) =
{
    STANDARD20_MODULE_STUFF,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    log_tee_register_hooks,
};
