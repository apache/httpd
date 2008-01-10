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
 * Credit is due to Tina Bird <tbird@precision-guesswork.com>, whose
 * idea this module was.
 *
 *   Ben Laurie 29/12/2003
 */

#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "multithread.h"

#ifdef NETWARE
#include "test_char.h"
#else
/* XXX This should be fixed in the INCLUDE path of the makefile
   so that a specific location is not hard coded here. */
#include "../../main/test_char.h"
#endif

module MODULE_VAR_EXPORT log_forensic_module;

#ifdef WIN32

static DWORD tls_index;

BOOL WINAPI DllMain (HINSTANCE dllhandle, DWORD reason, LPVOID reserved)
{
    switch (reason) {
    case DLL_PROCESS_ATTACH:
	tls_index = TlsAlloc();
    case DLL_THREAD_ATTACH: /* intentional no break */
	TlsSetValue(tls_index, 0);
	break;
    }
    return TRUE;
}

const char * get_forensic_id(pool *p)
{
    /* The 'error' default for Get undefined is 0 - a nice number
     * for this purpose.  The cast might look evil, but the evil
     * empire had switched this API out from underneath developers,
     * and the DWORD flavor will truncate nicely for our purposes.
     */
    DWORD next_id = (DWORD)TlsGetValue(tls_index);
    TlsSetValue(tls_index, (void*)(next_id + 1));

    return ap_psprintf(p, "%x:%x:%lx:%x", GetCurrentProcessId(), 
                                          GetCurrentThreadId(), 
                                          time(NULL), next_id);
}

#else /* !WIN32 */

/* Even when not MULTITHREAD, this will return a single structure, since
 * APACHE_TLS should be defined as empty on single-threaded platforms.
 */
const char * get_forensic_id(pool *p)
{
    static APACHE_TLS next_id = 0;

    /* we make the assumption that we can't go through all the PIDs in
       under 1 second */
#ifdef MULTITHREAD
    return ap_psprintf(p, "%x:%x:%lx:%x", getpid(), gettid(), time(NULL), next_id++);
#else
    return ap_psprintf(p, "%x:%lx:%x", getpid(), time(NULL), next_id++);
#endif
}

#endif /* !WIN32 */

typedef struct fcfg {
    char *logname;
    int fd;
} fcfg;

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
                                    0644, 1)) < 0) {
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

static int log_before(request_rec *r)
{
    fcfg *cfg = ap_get_module_config(r->server->module_config,
                                     &log_forensic_module);
    const char *id;
    hlog h;

    if (cfg->fd < 0 || r->prev)
        return DECLINED;

    if (!(id = ap_table_get(r->subprocess_env, "UNIQUE_ID"))) {
        id = get_forensic_id(r->pool);
    }

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

    ap_assert(h.pos < h.end);
    *h.pos++ = '\n';

    write(cfg->fd, h.log, h.count-1);

    ap_table_setn(r->notes, "forensic-id", id);

    return OK;
}

static int log_after(request_rec *r)
{
    fcfg *cfg = ap_get_module_config(r->server->module_config,
                                     &log_forensic_module);
    const char *id;
    char *s;

    if(cfg->fd < 0)
        return DECLINED;

    id = ap_table_get(r->notes, "forensic-id");

    if (!id)
        return DECLINED;

    s = ap_pstrcat(r->pool, "-", id, "\n", NULL);
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
      "the filename of the forensic log" },
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
