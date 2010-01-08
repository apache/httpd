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

#include "httpd.h"
#include "http_config.h"
#include "http_log.h"

module agent_log_module;

static int xfer_flags = (O_WRONLY | O_APPEND | O_CREAT);
#ifdef OS2
/* OS/2 dosen't support users and groups */
static mode_t xfer_mode = (S_IREAD | S_IWRITE);
#else
static mode_t xfer_mode = (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
#endif

typedef struct {
    char *fname;
    int agent_fd;
} agent_log_state;

static void *make_agent_log_state(pool *p, server_rec *s)
{
    agent_log_state *cls =
    (agent_log_state *) ap_palloc(p, sizeof(agent_log_state));

    cls->fname = "";
    cls->agent_fd = -1;

    return (void *) cls;
}

static const char *set_agent_log(cmd_parms *parms, void *dummy, char *arg)
{
    agent_log_state *cls = ap_get_module_config(parms->server->module_config,
                                             &agent_log_module);

    cls->fname = arg;
    return NULL;
}

static const command_rec agent_log_cmds[] =
{
    {"AgentLog", set_agent_log, NULL, RSRC_CONF, TAKE1,
     "the filename of the agent log"},
    {NULL}
};

static void open_agent_log(server_rec *s, pool *p)
{
    agent_log_state *cls = ap_get_module_config(s->module_config,
                                             &agent_log_module);

    char *fname = ap_server_root_relative(p, cls->fname);

    if (cls->agent_fd > 0)
        return;                 /* virtual log shared w/main server */

    if (*cls->fname == '|') {
        piped_log *pl;

        pl = ap_open_piped_log(p, cls->fname + 1);
        if (pl == NULL) {
	    ap_log_error(APLOG_MARK, APLOG_ERR, s,
			 "couldn't spawn agent log pipe");
            exit(1);
        }
        cls->agent_fd = ap_piped_log_write_fd(pl);
    }
    else if (*cls->fname != '\0') {
        if ((cls->agent_fd = ap_popenf_ex(p, fname, xfer_flags, xfer_mode, 1))
             < 0) {
            ap_log_error(APLOG_MARK, APLOG_ERR, s,
                         "could not open agent log file %s.", fname);
            exit(1);
        }
    }
}

static void init_agent_log(server_rec *s, pool *p)
{
    for (; s; s = s->next)
        open_agent_log(s, p);
}

static int agent_log_transaction(request_rec *orig)
{
    agent_log_state *cls = ap_get_module_config(orig->server->module_config,
                                             &agent_log_module);

    char str[HUGE_STRING_LEN];
    const char *agent;
    request_rec *r;

    if (cls->agent_fd < 0)
        return OK;

    for (r = orig; r->next; r = r->next)
        continue;
    if (*cls->fname == '\0')    /* Don't log agent */
        return DECLINED;

    agent = ap_table_get(orig->headers_in, "User-Agent");
    if (agent != NULL) {
        ap_snprintf(str, sizeof(str), "%s\n", agent);
        write(cls->agent_fd, str, strlen(str));
    }

    return OK;
}

module agent_log_module =
{
    STANDARD_MODULE_STUFF,
    init_agent_log,             /* initializer */
    NULL,                       /* create per-dir config */
    NULL,                       /* merge per-dir config */
    make_agent_log_state,       /* server config */
    NULL,                       /* merge server config */
    agent_log_cmds,             /* command table */
    NULL,                       /* handlers */
    NULL,                       /* filename translation */
    NULL,                       /* check_user_id */
    NULL,                       /* check auth */
    NULL,                       /* check access */
    NULL,                       /* type_checker */
    NULL,                       /* fixups */
    agent_log_transaction,      /* logger */
    NULL,                       /* header parser */
    NULL,                       /* child_init */
    NULL,                       /* child_exit */
    NULL                        /* post read-request */
};
