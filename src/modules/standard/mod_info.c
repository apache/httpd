/* ====================================================================
 * Copyright (c) 1995-1997 The Apache Group.  All rights reserved.
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
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the Apache Group
 *    for use in the Apache HTTP server project (http://www.apache.org/)."
 *
 * 4. The names "Apache Server" and "Apache Group" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    apache@apache.org.
 *
 * 5. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the Apache Group
 *    for use in the Apache HTTP server project (http://www.apache.org/)."
 *
 * THIS SOFTWARE IS PROVIDED BY THE APACHE GROUP ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE APACHE GROUP OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Group and was originally based
 * on public domain software written at the National Center for
 * Supercomputing Applications, University of Illinois, Urbana-Champaign.
 * For more information on the Apache Group and the Apache HTTP server
 * project, please see <http://www.apache.org/>.
 *
 */

/* 
 * Info Module.  Display configuration information for the server and
 * all included modules.
 *
 * <Location /server-info>
 * SetHandler server-info
 * </Location>
 *
 * GET /server-info - Returns full configuration page for server and all modules
 * GET /server-info?server - Returns server configuration only
 * GET /server-info?module_name - Returns configuration for a single module
 * GET /server-info?list - Returns quick list of included modules
 *
 * Rasmus Lerdorf <rasmus@vex.net>, May 1996
 *
 * 05.01.96 Initial Version
 *
 * Lou Langholtz <ldl@usi.utah.edu>, July 1997
 *
 * 07.11.97 Addition of the AddModuleInfo directive
 * 
 */

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_main.h"
#include "http_protocol.h"
#include "util_script.h"
#include "http_conf_globals.h"

typedef struct {
    char *name;                 /* matching module name */
    char *info;                 /* additional info */
} info_entry;

typedef struct {
    array_header *more_info;
} info_svr_conf;

typedef struct info_cfg_lines {
    char *cmd;
    char *line;
    struct info_cfg_lines *next;
} info_cfg_lines;

module MODULE_VAR_EXPORT info_module;
extern module *top_module;

static void *create_info_config(pool *p, server_rec *s)
{
    info_svr_conf *conf = (info_svr_conf *) pcalloc(p, sizeof(info_svr_conf));

    conf->more_info = make_array(p, 20, sizeof(info_entry));
    return conf;
}

static void *merge_info_config(pool *p, void *basev, void *overridesv)
{
    info_svr_conf *new = (info_svr_conf *) pcalloc(p, sizeof(info_svr_conf));
    info_svr_conf *base = (info_svr_conf *) basev;
    info_svr_conf *overrides = (info_svr_conf *) overridesv;

    new->more_info = append_arrays(p, overrides->more_info, base->more_info);
    return new;
}

static char *mod_info_html_cmd_string(char *string)
{
    char *s, *t;
    static char ret[256];       /* What is the max size of a command? */
    char *end_ret;

    ret[0] = '\0';
    s = string;
    t = ret;
    end_ret = t + sizeof(ret);
    while ((*s) && ((t - ret) < sizeof(ret))) {
        if (*s == '<') {
            strncpy(t, "&lt;", end_ret - t);
            t += 4;
        }
        else if (*s == '>') {
            strncpy(t, "&gt;", end_ret - t);
            t += 4;
        }
        else if (*s == '&') {
            strncpy(t, "&amp;", end_ret - t);
            t += 5;
        }
        else {
            *t++ = *s;
        }
        s++;
    }
    *t = '\0';
    return (ret);
}

static info_cfg_lines *mod_info_load_config(pool *p, char *filename,
                                            request_rec *r)
{
    char s[MAX_STRING_LEN];
    FILE *fp;
    info_cfg_lines *new, *ret = NULL, *prev = NULL;
    char *t, *tt, o, *msg;

    fp = pfopen(p, filename, "r");
    if (!fp) {
        msg = pstrcat(r->pool, "mod_info: couldn't open config file ",
                      filename, NULL);
        aplog_error(APLOG_MARK, APLOG_WARNING, r->server, msg);
        return NULL;
    }
    while (!cfg_getline(s, MAX_STRING_LEN, fp)) {
        if (*s == '#') {
            continue;           /* skip comments */
        }
        new = palloc(p, sizeof(struct info_cfg_lines));
        new->next = NULL;
        if (!ret) {
            ret = new;
        }
        if (prev) {
            prev->next = new;
        }
        t = strchr(s, ' ');
        tt = strchr(s, '\t');
        if (t && tt) {
            t = (t < tt) ? t : tt;
        }
        else if (tt) {
            t = tt;
        }
        if (t) {
            o = *t;
            *t = '\0';
            new->cmd = pstrdup(p, s);
            new->line = pstrdup(p, t + 1);
            *t = o;
        }
        else {
            new->cmd = pstrdup(p, s);
            new->line = NULL;
        }
        prev = new;
    }
    pfclose(p, fp);
    return (ret);
}

static void mod_info_module_cmds(request_rec *r, info_cfg_lines *cfg,
                                 command_rec *cmds, char *label)
{
    command_rec *cmd = cmds;
    info_cfg_lines *li = cfg, *li_st = NULL, *li_se = NULL;
    info_cfg_lines *block_start = NULL;
    int lab = 0, nest = 0;

    while (li) {
        if (!strncasecmp(li->cmd, "<directory", 10) ||
            !strncasecmp(li->cmd, "<location", 9) ||
            !strncasecmp(li->cmd, "<limit", 6) ||
            !strncasecmp(li->cmd, "<files", 6)) {
            if (nest) {
                li_se = li;
            }
            else {
                li_st = li;
            }
            li = li->next;
            nest++;
            continue;
        }
        else if (nest && (!strncasecmp(li->cmd, "</limit", 7) ||
                          !strncasecmp(li->cmd, "</location", 10) ||
                          !strncasecmp(li->cmd, "</directory", 11) ||
                          !strncasecmp(li->cmd, "</files", 7))) {
            if (block_start) {
                if ((nest == 1 && block_start == li_st) ||
                    (nest == 2 && block_start == li_se)) {
                    rputs("<dd><tt>", r);
                    if (nest == 2) {
                        rputs("&nbsp;&nbsp;", r);
                    }
                    rputs(mod_info_html_cmd_string(li->cmd), r);
                    rputs(" ", r);
                    if (li->line) {
                        rputs(mod_info_html_cmd_string(li->line), r);
                    }
                    rputs("</tt>\n", r);
                    nest--;
                    if (!nest) {
                        block_start = NULL;
                        li_st = NULL;
                    }
                    else {
                        block_start = li_st;
                    }
                    li_se = NULL;
                }
                else {
                    nest--;
                    if (!nest) {
                        li_st = NULL;
                    }
                    li_se = NULL;
                }
            }
            else {
                nest--;
                if (!nest) {
                    li_st = NULL;
                }
                li_se = NULL;
            }
            li = li->next;
            continue;
        }
        cmd = cmds;
        while (cmd) {
            if (cmd->name) {
                if (!strcasecmp(cmd->name, li->cmd)) {
                    if (!lab) {
                        rputs("<dt><strong>", r);
                        rputs(label, r);
                        rputs("</strong>\n", r);
                        lab = 1;
                    }
                    if (((nest && block_start == NULL) ||
                         (nest == 2 && block_start == li_st)) &&
                        (strncasecmp(li->cmd, "<directory", 10) &&
                         strncasecmp(li->cmd, "<location", 9) &&
                         strncasecmp(li->cmd, "<limit", 6) &&
                         strncasecmp(li->cmd, "</limit", 7) &&
                         strncasecmp(li->cmd, "</location", 10) &&
                         strncasecmp(li->cmd, "</directory", 11) &&
                         strncasecmp(li->cmd, "</files", 7))) {
                        rputs("<dd><tt>", r);
                        rputs(mod_info_html_cmd_string(li_st->cmd), r);
                        rputs(" ", r);
                        if (li_st->line) {
                            rputs(mod_info_html_cmd_string(li_st->line), r);
                        }
                        rputs("</tt>\n", r);
                        block_start = li_st;
                        if (li_se) {
                            rputs("<dd><tt>&nbsp;&nbsp;", r);
                            rputs(mod_info_html_cmd_string(li_se->cmd), r);
                            rputs(" ", r);
                            if (li_se->line) {
                                rputs(mod_info_html_cmd_string(li_se->line), r);
                            }
                            rputs("</tt>\n", r);
                            block_start = li_se;
                        }
                    }
                    rputs("<dd><tt>", r);
                    if (nest) {
                        rputs("&nbsp;&nbsp;", r);
                    }
                    if (nest == 2) {
                        rputs("&nbsp;&nbsp;", r);
                    }
                    rputs(mod_info_html_cmd_string(li->cmd), r);
                    if (li->line) {
                        rputs(" <i>", r);
                        rputs(mod_info_html_cmd_string(li->line), r);
                        rputs("</i></tt>", r);
                    }
                }
            }
            else
                break;
            cmd++;
        }
        li = li->next;
    }
}

static char *find_more_info(server_rec *s, const char *module_name)
{
    int i;
    info_svr_conf *conf = (info_svr_conf *) get_module_config(s->module_config,
                                                              &info_module);
    info_entry *entry = (info_entry *) conf->more_info->elts;

    if (!module_name) {
        return 0;
    }
    for (i = 0; i < conf->more_info->nelts; i++) {
        if (!strcmp(module_name, entry->name)) {
            return entry->info;
        }
        entry++;
    }
    return 0;
}

static int display_info(request_rec *r)
{
    module *modp = NULL;
    char buf[512], *cfname;
    char *more_info;
    command_rec *cmd = NULL;
    handler_rec *hand = NULL;
    server_rec *serv = r->server;
    int comma = 0;
    info_cfg_lines *mod_info_cfg_httpd = NULL;
    info_cfg_lines *mod_info_cfg_srm = NULL;
    info_cfg_lines *mod_info_cfg_access = NULL;

    r->content_type = "text/html";
    send_http_header(r);
    if (r->header_only) {
        return 0;
    }
    hard_timeout("send server info", r);

    rputs("<html><head><title>Server Information</title></head>\n", r);
    rputs("<body><h1 align=center>Apache Server Information</h1>\n", r);
    if (!r->args || strcasecmp(r->args, "list")) {
        cfname = server_root_relative(r->pool, server_confname);
        mod_info_cfg_httpd = mod_info_load_config(r->pool, cfname, r);
        cfname = server_root_relative(r->pool, serv->srm_confname);
        mod_info_cfg_srm = mod_info_load_config(r->pool, cfname, r);
        cfname = server_root_relative(r->pool, serv->access_confname);
        mod_info_cfg_access = mod_info_load_config(r->pool, cfname, r);
        if (!r->args) {
            rputs("<tt><a href=\"#server\">Server Settings</a>, ", r);
            for (modp = top_module; modp; modp = modp->next) {
                ap_snprintf(buf, sizeof(buf),
                          "<a href=\"#%s\">%s</a>", modp->name, modp->name);
                rputs(buf, r);
                if (modp->next) {
                    rputs(", ", r);
                }
            }
            rputs("</tt><hr>", r);

        }
        if (!r->args || !strcasecmp(r->args, "server")) {
            ap_snprintf(buf, sizeof(buf),
                      "<a name=\"server\"><strong>Server Version:</strong> "
                        "<font size=+1><tt>%s</tt></a></font><br>\n",
                        SERVER_VERSION);
            rputs(buf, r);
            ap_snprintf(buf, sizeof(buf),
                        "<strong>Server Built:</strong> "
                        "<font size=+1><tt>%s</tt></a></font><br>\n",
                        SERVER_BUILT);
            rputs(buf, r);
            ap_snprintf(buf, sizeof(buf),
                        "<strong>API Version:</strong> "
                        "<tt>%d</tt><br>\n",
                        MODULE_MAGIC_NUMBER);
            rputs(buf, r);
            ap_snprintf(buf, sizeof(buf),
                        "<strong>Run Mode:</strong> <tt>%s</tt><br>\n",
                        (standalone ? "standalone" : "inetd"));
            rputs(buf, r);
            ap_snprintf(buf, sizeof(buf),
                        "<strong>User/Group:</strong> "
                        "<tt>%s(%d)/%d</tt><br>\n",
                        user_name, (int) user_id, (int) group_id);
            rputs(buf, r);
            ap_snprintf(buf, sizeof(buf),
                        "<strong>Hostname/port:</strong> "
                        "<tt>%s:%u</tt><br>\n",
                        serv->server_hostname, serv->port);
            rputs(buf, r);
            ap_snprintf(buf, sizeof(buf),
                        "<strong>Daemons:</strong> "
                        "<tt>start: %d &nbsp;&nbsp; "
                        "min idle: %d &nbsp;&nbsp; "
                        "max idle: %d &nbsp;&nbsp; "
                        "max: %d</tt><br>\n",
                        daemons_to_start, daemons_min_free,
                        daemons_max_free, daemons_limit);
            rputs(buf, r);
            ap_snprintf(buf, sizeof(buf),
                        "<strong>Max Requests:</strong> "
                        "<tt>per child: %d &nbsp;&nbsp; "
                        "keep alive: %s &nbsp;&nbsp; "
                        "max per connection: %d</tt><br>\n",
                        max_requests_per_child,
                        (serv->keep_alive ? "on" : "off"),
                        serv->keep_alive_max);
            rputs(buf, r);
            ap_snprintf(buf, sizeof(buf),
                        "<strong>Threads:</strong> "
                        "<tt>per child: %d &nbsp;&nbsp; </tt><br>\n",
                        threads_per_child);
            rputs(buf, r);
            ap_snprintf(buf, sizeof(buf),
                        "<strong>Excess requests:</strong> "
                        "<tt>per child: %d &nbsp;&nbsp; </tt><br>\n",
                        excess_requests_per_child);
            rputs(buf, r);
            ap_snprintf(buf, sizeof(buf),
                        "<strong>Timeouts:</strong> "
                        "<tt>connection: %d &nbsp;&nbsp; "
                        "keep-alive: %d</tt><br>",
                        serv->timeout, serv->keep_alive_timeout);
            rputs(buf, r);
            ap_snprintf(buf, sizeof(buf),
                        "<strong>Server Root:</strong> "
                        "<tt>%s</tt><br>\n", server_root);
            rputs(buf, r);
            ap_snprintf(buf, sizeof(buf),
                        "<strong>Config File:</strong> "
                        "<tt>%s</tt><br>\n", server_confname);
            rputs(buf, r);
            ap_snprintf(buf, sizeof(buf),
                        "<strong>PID File:</strong> "
                        "<tt>%s</tt><br>\n", pid_fname);
            rputs(buf, r);
            ap_snprintf(buf, sizeof(buf),
                        "<strong>Scoreboard File:</strong> "
                        "<tt>%s</tt><br>\n", scoreboard_fname);
            rputs(buf, r);
        }
        rputs("<hr><dl>", r);
        for (modp = top_module; modp; modp = modp->next) {
            if (!r->args || !strcasecmp(modp->name, r->args)) {
                ap_snprintf(buf, sizeof(buf),
                         "<dt><a name=\"%s\"><strong>Module Name:</strong> "
                            "<font size=+1><tt>%s</tt></a></font>\n",
                            modp->name, modp->name);
                rputs(buf, r);
                rputs("<dt><strong>Content handlers:</strong>", r);
                hand = modp->handlers;
                if (hand) {
                    while (hand) {
                        if (hand->content_type) {
                            ap_snprintf(buf, sizeof(buf),
                                      " <tt>%s</tt>\n", hand->content_type);
                            rputs(buf, r);
                        }
                        else {
                            break;
                        }
                        hand++;
                        if (hand && hand->content_type) {
                            rputs(",", r);
                        }
                    }
                }
                else {
                    rputs("<tt> <EM>none</EM></tt>", r);
                }
                rputs("<dt><strong>Configuration Phase Participation:</strong> \n",
                      r);
                if (modp->child_init) {
                    rputs("<tt>Child Init</tt>", r);
                    comma = 1;
                }
                if (modp->create_dir_config) {
                    if (comma) {
                        rputs(", ", r);
                    }
                    rputs("<tt>Create Directory Config</tt>", r);
                    comma = 1;
                }
                if (modp->merge_dir_config) {
                    if (comma) {
                        rputs(", ", r);
                    }
                    rputs("<tt>Merge Directory Configs</tt>", r);
                    comma = 1;
                }
                if (modp->create_server_config) {
                    if (comma) {
                        rputs(", ", r);
                    }
                    rputs("<tt>Create Server Config</tt>", r);
                    comma = 1;
                }
                if (modp->merge_server_config) {
                    if (comma) {
                        rputs(", ", r);
                    }
                    rputs("<tt>Merge Server Configs</tt>", r);
                    comma = 1;
                }
                if (modp->child_exit) {
                    if (comma) {
                        rputs(", ", r);
                    }
                    rputs("<tt>Child Exit</tt>", r);
                    comma = 1;
                }
                if (!comma)
                    rputs("<tt> <EM>none</EM></tt>", r);
                comma = 0;
                rputs("<dt><strong>Request Phase Participation:</strong> \n",
                      r);
                if (modp->post_read_request) {
                    rputs("<tt>Post-Read Request</tt>", r);
                    comma = 1;
                }
                if (modp->header_parser) {
                    if (comma) {
                        rputs(", ", r);
                    }
                    rputs("<tt>Header Parse</tt>", r);
                    comma = 1;
                }
                if (modp->translate_handler) {
                    if (comma) {
                        rputs(", ", r);
                    }
                    rputs("<tt>Translate Path</tt>", r);
                    comma = 1;
                }
                if (modp->access_checker) {
                    if (comma) {
                        rputs(", ", r);
                    }
                    rputs("<tt>Check Access</tt>", r);
                    comma = 1;
                }
                if (modp->check_user_id) {
                    if (comma) {
                        rputs(", ", r);
                    }
                    rputs("<tt>Verify User ID</tt>", r);
                    comma = 1;
                }
                if (modp->auth_checker) {
                    if (comma) {
                        rputs(", ", r);
                    }
                    rputs("<tt>Verify User Access</tt>", r);
                    comma = 1;
                }
                if (modp->type_checker) {
                    if (comma) {
                        rputs(", ", r);
                    }
                    rputs("<tt>Check Type</tt>", r);
                    comma = 1;
                }
                if (modp->fixer_upper) {
                    if (comma) {
                        rputs(", ", r);
                    }
                    rputs("<tt>Fixups</tt>", r);
                    comma = 1;
                }
                if (modp->logger) {
                    if (comma) {
                        rputs(", ", r);
                    }
                    rputs("<tt>Logging</tt>", r);
                    comma = 1;
                }
                if (!comma)
                    rputs("<tt> <EM>none</EM></tt>", r);
                comma = 0;
                rputs("<dt><strong>Module Directives:</strong> ", r);
                cmd = modp->cmds;
                if (cmd) {
                    while (cmd) {
                        if (cmd->name) {
                            ap_snprintf(buf, sizeof(buf),
                                        "<dd><tt>%s - <i>",
                                        mod_info_html_cmd_string(cmd->name));
                            rputs(buf, r);
                            if (cmd->errmsg) {
                                rputs(cmd->errmsg, r);
                            }
                            rputs("</i></tt>\n", r);
                        }
                        else {
                            break;
                        }
                        cmd++;
                    }
                    rputs("<dt><strong>Current Configuration:</strong>\n", r);
                    mod_info_module_cmds(r, mod_info_cfg_httpd, modp->cmds,
                                         "httpd.conf");
                    mod_info_module_cmds(r, mod_info_cfg_srm, modp->cmds,
                                         "srm.conf");
                    mod_info_module_cmds(r, mod_info_cfg_access, modp->cmds,
                                         "access.conf");
                }
                else {
                    rputs("<tt> none</tt>\n", r);
                }
                more_info = find_more_info(serv, modp->name);
                if (more_info) {
                    rputs("<dt><strong>Additional Information:</strong>\n<dd>",
                          r);
                    rputs(more_info, r);
                }
                rputs("<dt><hr>\n", r);
                if (r->args) {
                    break;
                }
            }
        }
        if (!modp && r->args && strcasecmp(r->args, "server")) {
            rputs("<b>No such module</b>\n", r);
        }
    }
    else {
        for (modp = top_module; modp; modp = modp->next) {
            rputs(modp->name, r);
            if (modp->next) {
                rputs("<br>", r);
            }
        }
    }
    rputs("</dl></body></html>\n", r);
    /* Done, turn off timeout, close file and return */
    kill_timeout(r);
    return 0;
}

static const char *add_module_info(cmd_parms *cmd, void *dummy, char *name,
                                   char *info)
{
    server_rec *s = cmd->server;
    info_svr_conf *conf = (info_svr_conf *) get_module_config(s->module_config,
                                                              &info_module);
    info_entry *new = push_array(conf->more_info);

    new->name = name;
    new->info = info;
    return NULL;
}

static command_rec info_cmds[] =
{
    {"AddModuleInfo", add_module_info, NULL, RSRC_CONF, TAKE2,
     "a module name and additional information on that module"},
    {NULL}
};

static handler_rec info_handlers[] =
{
    {"server-info", display_info},
    {NULL}
};

module MODULE_VAR_EXPORT info_module =
{
    STANDARD_MODULE_STUFF,
    NULL,                       /* initializer */
    NULL,                       /* dir config creater */
    NULL,                       /* dir merger --- default is to override */
    create_info_config,         /* server config */
    merge_info_config,          /* merge server config */
    info_cmds,                  /* command table */
    info_handlers,              /* handlers */
    NULL,                       /* filename translation */
    NULL,                       /* check_user_id */
    NULL,                       /* check auth */
    NULL,                       /* check access */
    NULL,                       /* type_checker */
    NULL,                       /* fixups */
    NULL,                       /* logger */
    NULL,                       /* header parser */
    NULL,                       /* child_init */
    NULL,                       /* child_exit */
    NULL                        /* post read-request */
};
