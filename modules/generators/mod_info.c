/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000-2003 The Apache Software Foundation.  All rights
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
 * Ryan Morgan <rmorgan@covalent.net>
 * 
 * 8.11.00 Port to Apache 2.0.  Read configuation from the configuration
 * tree rather than reparse the entire configuation file.
 * 
 */

#define CORE_PRIVATE

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_main.h"
#include "http_protocol.h"
#include "http_request.h"
#include "util_script.h"
#include "apr_strings.h"
#include "apr_lib.h"
#define APR_WANT_STRFUNC
#include "apr_want.h"
#include "ap_mpm.h"

typedef struct {
    const char *name;                 /* matching module name */
    const char *info;                 /* additional info */
} info_entry;

typedef struct {
    apr_array_header_t *more_info;
} info_svr_conf;

module AP_MODULE_DECLARE_DATA info_module;

static void *create_info_config(apr_pool_t *p, server_rec *s)
{
    info_svr_conf *conf = (info_svr_conf *) apr_pcalloc(p, sizeof(info_svr_conf));

    conf->more_info = apr_array_make(p, 20, sizeof(info_entry));
    return conf;
}

static void *merge_info_config(apr_pool_t *p, void *basev, void *overridesv)
{
    info_svr_conf *new = (info_svr_conf *) apr_pcalloc(p, sizeof(info_svr_conf));
    info_svr_conf *base = (info_svr_conf *) basev;
    info_svr_conf *overrides = (info_svr_conf *) overridesv;

    new->more_info = apr_array_append(p, overrides->more_info, base->more_info);
    return new;
}

static void mod_info_html_cmd_string(request_rec *r, const char *string,
                                     int close)
{
    const char *s;

    s = string;
    /* keep space for \0 byte */
    while (*s) {
        if (*s == '<') {
	    if (close) {
                ap_rputs("&lt;/", r);
	    } else {
                ap_rputs("&lt;", r);
	    }
        }
        else if (*s == '>') {
            ap_rputs("&gt;", r);
        }
        else if (*s == '&') {
            ap_rputs("&amp;", r);
        }
	else if (*s == ' ') {
	    if (close) {
	        ap_rputs("&gt;", r);
	        break;
	    } else {
                ap_rputc(*s, r);
            }
	} else {
            ap_rputc(*s, r);
        }
        s++;
    }
}

static void mod_info_module_cmds(request_rec * r, const command_rec * cmds,
				 ap_directive_t * conftree)
{
    const command_rec *cmd;
    ap_directive_t *tmptree = conftree;
    char htmlstring[MAX_STRING_LEN];
    int block_start = 0;
    int nest = 0;

    while (tmptree != NULL) {
	cmd = cmds;
	while (cmd->name) {
	    if ((cmd->name[0] != '<') && 
                (strcasecmp(cmd->name, tmptree->directive) == 0)) {
		if (nest > block_start) {
		    block_start++;
		    apr_snprintf(htmlstring, sizeof(htmlstring), "%s %s",
				tmptree->parent->directive,
				tmptree->parent->args);
                    ap_rputs("<dd><tt>", r);
                    mod_info_html_cmd_string(r, htmlstring, 0);
                    ap_rputs("</tt></dd>\n", r);
		}
		if (nest == 2) {
		    ap_rprintf(r, "<dd><tt>&nbsp;&nbsp;&nbsp;&nbsp;%s "
			       "<i>%s</i></tt></dd>\n",
			       tmptree->directive, tmptree->args);
		} else if (nest == 1) {
		    ap_rprintf(r,
			       "<dd><tt>&nbsp;&nbsp;%s <i>%s</i></tt></dd>\n",
			       tmptree->directive, tmptree->args);
		} else {
                    ap_rputs("<dd><tt>", r);
                    mod_info_html_cmd_string(r, tmptree->directive, 0);
                    ap_rprintf(r, " <i>%s</i></tt></dd>\n", tmptree->args);
		}
	    }
	    ++cmd;
	}
	if (tmptree->first_child != NULL) {
	    tmptree = tmptree->first_child;
	    nest++;
	} else if (tmptree->next != NULL) {
	    tmptree = tmptree->next;
	} else {
	    if (block_start) {
		apr_snprintf(htmlstring, sizeof(htmlstring), "%s %s",
			    tmptree->parent->directive,
			    tmptree->parent->args);
		ap_rputs("<dd><tt>", r);
                mod_info_html_cmd_string(r, htmlstring, 1);
                ap_rputs("</tt></dd>\n", r);
		block_start--;
	    }
            if (tmptree->parent) {
                tmptree = tmptree->parent->next;
            }
            else {
                tmptree = NULL;
            }
	    nest--;
	}

    }
}

typedef struct { /*XXX: should get something from apr_hooks.h instead */
    void (*pFunc)(void); /* just to get the right size */
    const char *szName;
    const char * const *aszPredecessors;
    const char * const *aszSuccessors;
    int nOrder;
} hook_struct_t;

/*
 * hook_get_t is a pointer to a function that takes void as an argument and
 * returns a pointer to an apr_array_header_t.  The nasty WIN32 ifdef
 * is required to account for the fact that the ap_hook* calls all use
 * STDCALL calling convention. 
 */
typedef apr_array_header_t * ( 
#ifdef WIN32
__stdcall 
#endif
* hook_get_t)(void);

typedef struct {
    const char *name;
    hook_get_t get;
} hook_lookup_t;

static hook_lookup_t request_hooks[] = {
    {"Post-Read Request", ap_hook_get_post_read_request},
    {"Header Parse", ap_hook_get_header_parser},
    {"Translate Path", ap_hook_get_translate_name},
    {"Check Access", ap_hook_get_access_checker},
    {"Verify User ID", ap_hook_get_check_user_id},
    {"Verify User Access", ap_hook_get_auth_checker},
    {"Check Type", ap_hook_get_type_checker},
    {"Fixups", ap_hook_get_fixups},
    {"Logging", ap_hook_get_log_transaction},
    {NULL},
};

static int module_find_hook(module *modp,
                            hook_get_t hook_get)
{
    int i;
    apr_array_header_t *hooks = hook_get();
    hook_struct_t *elts;

    if (!hooks) {
        return 0;
    }

    elts = (hook_struct_t *)hooks->elts;

    for (i=0; i< hooks->nelts; i++) {
        if (strcmp(elts[i].szName, modp->name) == 0) {
            return 1;
        }
    }

    return 0;
}

static void module_participate(request_rec *r,
                               module *modp,
                               hook_lookup_t *lookup,
                               int *comma)
{
    if (module_find_hook(modp, lookup->get)) {
        if (*comma) {
            ap_rputs(", ", r);
        }
        ap_rvputs(r, "<tt>", lookup->name, "</tt>", NULL);
        *comma = 1;
    }
}

static void module_request_hook_participate(request_rec *r, module *modp)
{
    int i, comma=0;

    ap_rputs("<dt><strong>Request Phase Participation:</strong>\n", r);

    for (i=0; request_hooks[i].name; i++) {
        module_participate(r, modp, &request_hooks[i], &comma);
    }

    if (!comma) {
        ap_rputs("<tt> <em>none</em></tt>", r);
    }
    ap_rputs("</dt>\n", r);
}

static const char *find_more_info(server_rec *s, const char *module_name)
{
    int i;
    info_svr_conf *conf = (info_svr_conf *) ap_get_module_config(s->module_config,
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
    const char *more_info;
    const command_rec *cmd = NULL;
#ifdef NEVERMORE
    const handler_rec *hand = NULL;
#endif
    server_rec *serv = r->server;
    int comma = 0;

    if (strcmp(r->handler, "server-info"))
        return DECLINED;

    r->allowed |= (AP_METHOD_BIT << M_GET);
    if (r->method_number != M_GET)
	return DECLINED;

    ap_set_content_type(r, "text/html");

    ap_rputs(DOCTYPE_HTML_3_2
	     "<html><head><title>Server Information</title></head>\n", r);
    ap_rputs("<body><h1 align=\"center\">Apache Server Information</h1>\n", r);
    if (!r->args || strcasecmp(r->args, "list")) {
        if (!r->args) {
            ap_rputs("<dl><dt><tt><a href=\"#server\">Server Settings</a>, ", r);
            for (modp = ap_top_module; modp; modp = modp->next) {
                ap_rprintf(r, "<a href=\"#%s\">%s</a>", modp->name, modp->name);
                if (modp->next) {
                    ap_rputs(", ", r);
                }
            }
            ap_rputs("</tt></dt></dl><hr />", r);

        }
        if (!r->args || !strcasecmp(r->args, "server")) {
            int max_daemons, forked, threaded;

            ap_rprintf(r, "<dl><dt><a name=\"server\"><strong>Server Version:</strong> "
                        "<font size=\"+1\"><tt>%s</tt></font></a></dt>\n",
                        ap_get_server_version());
            ap_rprintf(r, "<dt><strong>Server Built:</strong> "
                        "<font size=\"+1\"><tt>%s</tt></font></dt>\n",
                        ap_get_server_built());
            ap_rprintf(r, "<dt><strong>API Version:</strong> "
                        "<tt>%d:%d</tt></dt>\n",
                        MODULE_MAGIC_NUMBER_MAJOR, MODULE_MAGIC_NUMBER_MINOR);
            ap_rprintf(r, "<dt><strong>Hostname/port:</strong> "
                        "<tt>%s:%u</tt></dt>\n",
                        ap_get_server_name(r), ap_get_server_port(r));
            ap_rprintf(r, "<dt><strong>Timeouts:</strong> "
                        "<tt>connection: %d &nbsp;&nbsp; "
                        "keep-alive: %d</tt></dt>",
                        (int)(apr_time_sec(serv->timeout)), 
                        (int)(apr_time_sec(serv->timeout)));
            ap_mpm_query(AP_MPMQ_MAX_DAEMON_USED, &max_daemons);
            ap_mpm_query(AP_MPMQ_IS_THREADED, &threaded);
            ap_mpm_query(AP_MPMQ_IS_FORKED, &forked);
            ap_rprintf(r, "<dt><strong>MPM Name:</strong> <tt>%s</tt></dt>\n", ap_show_mpm());
            ap_rprintf(r, "<dt><strong>MPM Information:</strong> "
		       "<tt>Max Daemons: %d Threaded: %s Forked: %s</tt></dt>\n",
                       max_daemons, threaded ? "yes" : "no",
                       forked ? "yes" : "no");
            ap_rprintf(r, "<dt><strong>Server Root:</strong> "
                        "<tt>%s</tt></dt>\n", ap_server_root);
            ap_rprintf(r, "<dt><strong>Config File:</strong> "
		       "<tt>%s</tt></dt>\n", ap_conftree->filename);
            ap_rputs("</dl><hr />", r);
        }
        for (modp = ap_top_module; modp; modp = modp->next) {
            if (!r->args || !strcasecmp(modp->name, r->args)) {
                ap_rprintf(r, "<dl><dt><a name=\"%s\"><strong>Module Name:</strong> "
                            "<font size=\"+1\"><tt>%s</tt></font></a></dt>\n",
                            modp->name, modp->name);
                ap_rputs("<dt><strong>Content handlers:</strong> ", r);
#ifdef NEVERMORE
                hand = modp->handlers;
                if (hand) {
                    while (hand) {
                        if (hand->content_type) {
                            ap_rprintf(r, " <tt>%s</tt>\n", hand->content_type);
                        }
                        else {
                            break;
                        }
                        hand++;
                        if (hand && hand->content_type) {
                            ap_rputs(",", r);
                        }
                    }
                }
                else {
                    ap_rputs("<tt> <em>none</em></tt>", r);
                }
#else
                if (module_find_hook(modp, ap_hook_get_handler)) {
                    ap_rputs("<tt> <em>yes</em></tt>", r);
                }
                else {
                    ap_rputs("<tt> <em>none</em></tt>", r);
                }
#endif
                ap_rputs("</dt>", r);
                ap_rputs("<dt><strong>Configuration Phase Participation:</strong>\n",
                      r);
                if (modp->create_dir_config) {
                    if (comma) {
                        ap_rputs(", ", r);
                    }
                    ap_rputs("<tt>Create Directory Config</tt>", r);
                    comma = 1;
                }
                if (modp->merge_dir_config) {
                    if (comma) {
                        ap_rputs(", ", r);
                    }
                    ap_rputs("<tt>Merge Directory Configs</tt>", r);
                    comma = 1;
                }
                if (modp->create_server_config) {
                    if (comma) {
                        ap_rputs(", ", r);
                    }
                    ap_rputs("<tt>Create Server Config</tt>", r);
                    comma = 1;
                }
                if (modp->merge_server_config) {
                    if (comma) {
                        ap_rputs(", ", r);
                    }
                    ap_rputs("<tt>Merge Server Configs</tt>", r);
                    comma = 1;
                }
                if (!comma)
                    ap_rputs("<tt> <em>none</em></tt>", r);
                comma = 0;
                ap_rputs("</dt>", r);

                module_request_hook_participate(r, modp);

                cmd = modp->cmds;
                if (cmd) {
                    ap_rputs("<dt><strong>Module Directives:</strong></dt>", r);
                    while (cmd) {
                        if (cmd->name) {
                            ap_rputs("<dd><tt>", r);
                            mod_info_html_cmd_string(r, cmd->name, 0);
                            ap_rputs(" - <i>", r);
                            if (cmd->errmsg) {
                                ap_rputs(cmd->errmsg, r);
                            }
                            ap_rputs("</i></tt></dd>\n", r);
                        }
                        else {
                            break;
                        }
                        cmd++;
                    }
                    ap_rputs("<dt><strong>Current Configuration:</strong></dt>\n", r);
                    mod_info_module_cmds(r, modp->cmds, ap_conftree);
                }
                else {
                    ap_rputs("<dt><strong>Module Directives:</strong> <tt>none</tt></dt>", r);
                }
                more_info = find_more_info(serv, modp->name);
                if (more_info) {
                    ap_rputs("<dt><strong>Additional Information:</strong>\n</dt><dd>",
                          r);
                    ap_rputs(more_info, r);
                    ap_rputs("</dd>", r);
                }
                ap_rputs("</dl><hr />\n", r);
                if (r->args) {
                    break;
                }
            }
        }
        if (!modp && r->args && strcasecmp(r->args, "server")) {
            ap_rputs("<p><b>No such module</b></p>\n", r);
        }
    }
    else {
        ap_rputs("<dl><dt>Server Module List</dt>", r);
        for (modp = ap_top_module; modp; modp = modp->next) {
            ap_rputs("<dd>", r);
            ap_rputs(modp->name, r);
            ap_rputs("</dd>", r);
        }
        ap_rputs("</dl><hr />", r);
    }
    ap_rputs(ap_psignature("",r), r);
    ap_rputs("</body></html>\n", r);
    /* Done, turn off timeout, close file and return */
    return 0;
}

static const char *add_module_info(cmd_parms *cmd, void *dummy, 
                                   const char *name, const char *info)
{
    server_rec *s = cmd->server;
    info_svr_conf *conf = (info_svr_conf *) ap_get_module_config(s->module_config,
                                                              &info_module);
    info_entry *new = apr_array_push(conf->more_info);

    new->name = name;
    new->info = info;
    return NULL;
}

static const command_rec info_cmds[] =
{
    AP_INIT_TAKE2("AddModuleInfo", add_module_info, NULL, RSRC_CONF,
                  "a module name and additional information on that module"),
    {NULL}
};

static void register_hooks(apr_pool_t *p)
{
    ap_hook_handler(display_info, NULL, NULL, APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA info_module =
{
    STANDARD20_MODULE_STUFF,
    NULL,                       /* dir config creater */
    NULL,                       /* dir merger --- default is to override */
    create_info_config,         /* server config */
    merge_info_config,          /* merge server config */
    info_cmds,                  /* command apr_table_t */
    register_hooks
};
