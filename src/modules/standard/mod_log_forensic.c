/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2003-2004 The Apache Software Foundation.  All rights
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
#include <assert.h>
#include "../../main/test_char.h"

module MODULE_VAR_EXPORT log_forensic_module;

typedef struct fcfg {
    char *logname;
    int fd;
} fcfg;

static int next_id;

static void *make_forensic_log_scfg(pool *p, server_rec *s)
{
    fcfg *cfg = ap_pcalloc(p, sizeof *cfg);

    cfg->logname = NULL;
    cfg->fd = -1;

    return cfg;
}

static void *merge_forensic_log_scfg(pool *p, void *parent, void *new)
{
    fcfg *cfg = ap_pcalloc(p, sizeof *cfg);
    fcfg *pc = parent;
    fcfg *nc = new;

    cfg->logname = ap_pstrdup(p, nc->logname ? nc->logname : pc->logname);
    cfg->fd = -1;

    return cfg;
}

static void open_log(server_rec *s, pool *p)
{
    fcfg *cfg = ap_get_module_config(s->module_config, &log_forensic_module);

    if (!cfg->logname || cfg->fd >= 0)
        return;

    if (*cfg->logname == '|') {
        piped_log *pl;

        pl = ap_open_piped_log(p, cfg->logname+1);
        if (pl == NULL) {
            ap_log_error(APLOG_MARK, APLOG_ERR, s,
                         "couldn't spawn forensic log pipe %s", cfg->logname);
            exit(1);
        }
        cfg->fd = ap_piped_log_write_fd(pl);
    }
    else {
        char *fname = ap_server_root_relative(p, cfg->logname);

        if ((cfg->fd = ap_popenf_ex(p, fname, O_WRONLY | O_APPEND | O_CREAT,
                                    S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH, 1))
            < 0) {
            ap_log_error(APLOG_MARK, APLOG_ERR, s,
                         "could not open forensic log file %s.", fname);
            exit(1);
        }
    }
}

static void log_init(server_rec *s, pool *p)
{
    for ( ; s ; s = s->next)
        open_log(s, p);
}

  
/* e is the first _invalid_ location in q
   N.B. returns the terminating NUL.
 */
static char *log_escape(char *q, const char *e, const char *p)
{
    for ( ; *p ; ++p) {
        assert(q < e);
        if (test_char_table[*(unsigned char *)p]&T_ESCAPE_FORENSIC) {
            assert(q+2 < e);
            *q++ = '%';
            sprintf(q, "%02x", *(unsigned char *)p);
            q += 2;
        }
        else
            *q++ = *p;
    }
    assert(q < e);
    *q = '\0';

    return q;
}

typedef struct hlog {
    char *log;
    char *pos;
    char *end;
    pool *p;
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

/* this structure only exists to allow typesafety */
typedef struct {
    const char *id;
} rcfg;

static int log_before(request_rec *r)
{
    fcfg *cfg = ap_get_module_config(r->server->module_config,
                                     &log_forensic_module);
    static rcfg rcfg;
    const char *id;
    hlog h;

    if (cfg->fd < 0)
        return DECLINED;

    if (!(id = ap_table_get(r->subprocess_env, "UNIQUE_ID"))) {
        /* we make the assumption that we can't go through all the PIDs in
           under 1 second */
        id = ap_psprintf(r->pool, "%x:%lx:%x", getpid(), time(NULL), next_id++);
    }
    rcfg.id = id;
    ap_set_module_config(r->request_config, &log_forensic_module, &rcfg);

    h.p = r->pool;
    h.count = 0;

    ap_table_do(count_headers, &h, r->headers_in, NULL);

    h.count += 1+strlen(id)+1+count_string(r->the_request)+1+1;
    h.log = ap_palloc(r->pool, h.count);
    h.pos = h.log;
    h.end = h.log+h.count;

    *h.pos++ = '+';
    strcpy(h.pos, id);
    h.pos += strlen(h.pos);
    *h.pos++ = '|';
    h.pos = log_escape(h.pos, h.end, r->the_request);

    ap_table_do(log_headers, &h, r->headers_in, NULL);

    assert(h.pos < h.end);
    *h.pos++ = '\n';

    write(cfg->fd, h.log, h.count-1);

    ap_table_setn(r->notes, "forensic-id", id);

    return OK;
}

static int log_after(request_rec *r)
{
    fcfg *cfg = ap_get_module_config(r->server->module_config,
                                     &log_forensic_module);
    char *s;
    rcfg *rcfg;
    
    if(cfg->fd < 0)
        return DECLINED;

    rcfg = ap_get_module_config(r->request_config, &log_forensic_module);
    s = ap_pstrcat(r->pool, "-", rcfg->id, "\n", NULL);
    write(cfg->fd, s, strlen(s));

    return OK;
}

static const char *set_forensic_log(cmd_parms *cmd,  void *dummy,  char *fn)
{
    fcfg *cfg = ap_get_module_config(cmd->server->module_config,
                                     &log_forensic_module);

    cfg->logname = fn;
    return NULL;
}

static const command_rec forensic_log_cmds[] =
{
    { "ForensicLog",  set_forensic_log,  NULL,  RSRC_CONF,  TAKE1,
      "the filename of the forensic log (default is logs/forensic_log" },
    { NULL }
};

module MODULE_VAR_EXPORT log_forensic_module =
{
    STANDARD_MODULE_STUFF,
    log_init,                   /* initializer */
    NULL,                       /* create per-dir config */
    NULL,                       /* merge per-dir config */
    make_forensic_log_scfg,     /* server config */
    merge_forensic_log_scfg,    /* merge server config */
    forensic_log_cmds,          /* command table */
    NULL,                       /* handlers */
    NULL,                       /* filename translation */
    NULL,                       /* check_user_id */
    NULL,                       /* check auth */
    NULL,                       /* check access */
    NULL,                       /* type_checker */
    NULL,                       /* fixups */
    log_after,                  /* logger */
    NULL,                       /* header parser */
    NULL,                       /* child_init */
    NULL,                       /* child_exit */
    log_before                  /* post read-request */
};
