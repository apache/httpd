/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2003, 2004 The Apache Software Foundation.  All rights
 * reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The end-user documentation included with the redistribution,
 *    if any, must include the following acknowledgment:
 *       "This product includes software developed by the
 *        Apache Software Foundation (http://www.apache.org/)."
 *    Alternately, this acknowledgment may appear in the software itself,
 *    if and wherever such third-party acknowledgments normally appear.
 *
 * 4. The names "Apache" and "Apache Software Foundation" must
 *    not be used to endorse or promote products derived from this
 *    software without prior written permission. For written
 *    permission, please contact apache@apache.org.
 *
 * 5. Products derived from this software may not be called "Apache",
 *    nor may "Apache" appear in their name, without prior written
 *    permission of the Apache Software Foundation.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE APACHE SOFTWARE FOUNDATION OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Software Foundation.  For more
 * information on the Apache Software Foundation, please see
 * <http://www.apache.org/>.
 *
 * Portions of this software are based upon public domain software
 * originally written at the National Center for Supercomputing Applications,
 * University of Illinois, Urbana-Champaign.
 */

/*
 * See also support/check_forensic.
 * Relate the forensic log to the transfer log by including
 * %{forensic-id}n in the custom log format, for example:
 * CustomLog logs/custom "%h %l %u %t \"%r\" %>s %b %{forensic-id}n"
 *
 * Credit is due to Tina Bird <tbird@precision-guesswork.com>, whose
 * idea this module was.
 *
 *   Ben Laurie 29/12/2003
 */

#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "apr_strings.h"
#include "apr_atomic.h"
#include <unistd.h>
#include "http_protocol.h"
#include "../../server/test_char.h"

module AP_MODULE_DECLARE_DATA log_forensic_module;

typedef struct fcfg {
    const char *logname;
    apr_file_t *fd;
} fcfg;

static int next_id;

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

static void open_log(server_rec *s, apr_pool_t *p)
{
    fcfg *cfg = ap_get_module_config(s->module_config, &log_forensic_module);

    if (!cfg->logname || cfg->fd)
        return;

    if (*cfg->logname == '|') {
        piped_log *pl;

        pl = ap_open_piped_log(p, cfg->logname+1);
        if (pl == NULL) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                         "couldn't spawn forensic log pipe %s", cfg->logname);
            exit(1);
        }
        cfg->fd = ap_piped_log_write_fd(pl);
    }
    else {
        char *fname = ap_server_root_relative(p, cfg->logname);
        apr_status_t rv;

        if ((rv = apr_file_open(&cfg->fd, fname,
                                APR_WRITE | APR_APPEND | APR_CREATE,
                                APR_OS_DEFAULT, p) != APR_SUCCESS)
            < 0) {
            ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                         "could not open forensic log file %s.", fname);
            exit(1);
        }
    }
}

static int log_init(apr_pool_t *pc, apr_pool_t *p, apr_pool_t *pt,
                     server_rec *s)
{
    for ( ; s ; s = s->next)
        open_log(s, p);
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
    int count;
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
    int n;
    apr_status_t rv;

    if (!cfg->fd) {
        return DECLINED;
    }

    if (!(id = apr_table_get(r->subprocess_env, "UNIQUE_ID"))) {
        /* we make the assumption that we can't go through all the PIDs in
           under 1 second */
        id = apr_psprintf(r->pool, "%x:%lx:%x", getpid(), time(NULL),
                          apr_atomic_inc32(&next_id));
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
    int l,n;
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
     "the filename of the forensic log (default is logs/forensic_log" ),
    { NULL }
};

static void register_hooks(apr_pool_t *p)
{
    static const char * const pre[] = { "mod_unique_id.c", NULL };

    ap_hook_open_logs(log_init,NULL,NULL,APR_HOOK_MIDDLE);
    ap_hook_post_read_request(log_before,pre,NULL,APR_HOOK_REALLY_FIRST);
    ap_hook_log_transaction(log_after,NULL,NULL,APR_HOOK_REALLY_LAST);
}

module AP_MODULE_DECLARE_DATA log_forensic_module =
{
    STANDARD20_MODULE_STUFF,
    NULL,                       /* create per-dir config */
    NULL,                       /* merge per-dir config */
    make_forensic_log_scfg,     /* server config */
    merge_forensic_log_scfg,    /* merge server config */
    forensic_log_cmds,          /* command apr_table_t */
    register_hooks              /* register hooks */
};
