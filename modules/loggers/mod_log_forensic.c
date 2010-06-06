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
 * See also support/check_forensic.
 * Relate the forensic log to the transfer log by including
 * %{forensic-id}n in the custom log format, for example:
 * CustomLog logs/custom "%h %l %u %t \"%r\" %>s %b %{forensic-id}n"
 *
 * Credit is due to Tina Bird <tbird precision-guesswork.com>, whose
 * idea this module was.
 *
 *   Ben Laurie 29/12/2003
 */

#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "apr_strings.h"
#include "apr_atomic.h"
#include "http_protocol.h"
#include "test_char.h"
#if APR_HAVE_UNISTD_H
#include <unistd.h>
#endif

module AP_MODULE_DECLARE_DATA log_forensic_module;

typedef struct fcfg {
    const char *logname;
    apr_file_t *fd;
} fcfg;

static apr_uint32_t next_id;

static void *make_forensic_log_scfg(apr_pool_t *p, server_rec *s)
{
    fcfg *cfg = apr_pcalloc(p, sizeof *cfg);

    cfg->logname = NULL;
    cfg->fd = NULL;

    return cfg;
}

static void *merge_forensic_log_scfg(apr_pool_t *p, void *parent, void *new)
{
    fcfg *cfg = apr_pcalloc(p, sizeof *cfg);
    fcfg *pc = parent;
    fcfg *nc = new;

    cfg->logname = apr_pstrdup(p, nc->logname ? nc->logname : pc->logname);
    cfg->fd = NULL;

    return cfg;
}

static int open_log(server_rec *s, apr_pool_t *p)
{
    fcfg *cfg = ap_get_module_config(s->module_config, &log_forensic_module);

    if (!cfg->logname || cfg->fd)
        return 1;

    if (*cfg->logname == '|') {
        piped_log *pl;
        const char *pname = ap_server_root_relative(p, cfg->logname + 1);

        pl = ap_open_piped_log(p, pname);
        if (pl == NULL) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                         "couldn't spawn forensic log pipe %s", cfg->logname);
            return 0;
        }
        cfg->fd = ap_piped_log_write_fd(pl);
    }
    else {
        const char *fname = ap_server_root_relative(p, cfg->logname);
        apr_status_t rv;

        if ((rv = apr_file_open(&cfg->fd, fname,
                                APR_WRITE | APR_APPEND | APR_CREATE,
                                APR_OS_DEFAULT, p)) != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                         "could not open forensic log file %s.", fname);
            return 0;
        }
    }

    return 1;
}

static int log_init(apr_pool_t *pc, apr_pool_t *p, apr_pool_t *pt,
                     server_rec *s)
{
    for ( ; s ; s = s->next) {
        if (!open_log(s, p)) {
            return HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    return OK;
}


/* e is the first _invalid_ location in q
   N.B. returns the terminating NUL.
 */
static char *log_escape(char *q, const char *e, const char *p)
{
    for ( ; *p ; ++p) {
        ap_assert(q < e);
        if (test_char_table[*(unsigned char *)p]&T_ESCAPE_FORENSIC) {
            ap_assert(q+2 < e);
            *q++ = '%';
            sprintf(q, "%02x", *(unsigned char *)p);
            q += 2;
        }
        else
            *q++ = *p;
    }
    ap_assert(q < e);
    *q = '\0';

    return q;
}

typedef struct hlog {
    char *log;
    char *pos;
    char *end;
    apr_pool_t *p;
    apr_size_t count;
} hlog;

static int count_string(const char *p)
{
    int n;

    for (n = 0 ; *p ; ++p, ++n)
        if (test_char_table[*(unsigned char *)p]&T_ESCAPE_FORENSIC)
            n += 2;
    return n;
}

static int count_headers(void *h_, const char *key, const char *value)
{
    hlog *h = h_;

    h->count += count_string(key)+count_string(value)+2;

    return 1;
}

static int log_headers(void *h_, const char *key, const char *value)
{
    hlog *h = h_;

    /* note that we don't have to check h->pos here, coz its been done
       for us by log_escape */
    *h->pos++ = '|';
    h->pos = log_escape(h->pos, h->end, key);
    *h->pos++ = ':';
    h->pos = log_escape(h->pos, h->end, value);

    return 1;
}

static int log_before(request_rec *r)
{
    fcfg *cfg = ap_get_module_config(r->server->module_config,
                                     &log_forensic_module);
    const char *id;
    hlog h;
    apr_size_t n;
    apr_status_t rv;

    if (!cfg->fd || r->prev) {
        return DECLINED;
    }

    if (!(id = apr_table_get(r->subprocess_env, "UNIQUE_ID"))) {
        /* we make the assumption that we can't go through all the PIDs in
           under 1 second */
        id = apr_psprintf(r->pool, "%" APR_PID_T_FMT ":%lx:%x", getpid(), 
                          time(NULL), apr_atomic_inc32(&next_id));
    }
    ap_set_module_config(r->request_config, &log_forensic_module, (char *)id);

    h.p = r->pool;
    h.count = 0;

    apr_table_do(count_headers, &h, r->headers_in, NULL);

    h.count += 1+strlen(id)+1+count_string(r->the_request)+1+1;
    h.log = apr_palloc(r->pool, h.count);
    h.pos = h.log;
    h.end = h.log+h.count;

    *h.pos++ = '+';
    strcpy(h.pos, id);
    h.pos += strlen(h.pos);
    *h.pos++ = '|';
    h.pos = log_escape(h.pos, h.end, r->the_request);

    apr_table_do(log_headers, &h, r->headers_in, NULL);

    ap_assert(h.pos < h.end);
    *h.pos++ = '\n';

    n = h.count-1;
    rv = apr_file_write(cfg->fd, h.log, &n);
    ap_assert(rv == APR_SUCCESS && n == h.count-1);

    apr_table_setn(r->notes, "forensic-id", id);

    return OK;
}

static int log_after(request_rec *r)
{
    fcfg *cfg = ap_get_module_config(r->server->module_config,
                                     &log_forensic_module);
    const char *id = ap_get_module_config(r->request_config,
                                          &log_forensic_module);
    char *s;
    apr_size_t l, n;
    apr_status_t rv;

    if (!cfg->fd) {
        return DECLINED;
    }

    s = apr_pstrcat(r->pool, "-", id, "\n", NULL);
    l = n = strlen(s);
    rv = apr_file_write(cfg->fd, s, &n);
    ap_assert(rv == APR_SUCCESS && n == l);

    return OK;
}

static const char *set_forensic_log(cmd_parms *cmd, void *dummy, const char *fn)
{
    fcfg *cfg = ap_get_module_config(cmd->server->module_config,
                                     &log_forensic_module);

    cfg->logname = fn;
    return NULL;
}

static const command_rec forensic_log_cmds[] =
{
    AP_INIT_TAKE1("ForensicLog",  set_forensic_log,  NULL,  RSRC_CONF,
                  "the filename of the forensic log"),
    { NULL }
};

static void register_hooks(apr_pool_t *p)
{
    static const char * const pre[] = { "mod_unique_id.c", NULL };

    ap_hook_open_logs(log_init,NULL,NULL,APR_HOOK_MIDDLE);
    ap_hook_post_read_request(log_before,pre,NULL,APR_HOOK_REALLY_FIRST);
    ap_hook_log_transaction(log_after,NULL,NULL,APR_HOOK_REALLY_LAST);
}

AP_DECLARE_MODULE(log_forensic) =
{
    STANDARD20_MODULE_STUFF,
    NULL,                       /* create per-dir config */
    NULL,                       /* merge per-dir config */
    make_forensic_log_scfg,     /* server config */
    merge_forensic_log_scfg,    /* merge server config */
    forensic_log_cmds,          /* command apr_table_t */
    register_hooks              /* register hooks */
};
