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
 * Apache example_hooks module.  Provide demonstrations of how modules do things.
 * It is not meant to be used in a production server.  Since it participates
 * in all of the processing phases, it could conceivable interfere with
 * the proper operation of other modules -- particularly the ones related
 * to security.
 *
 * In the interest of brevity, all functions and structures internal to
 * this module, but which may have counterparts in *real* modules, are
 * prefixed with 'x_' instead of 'example_'.
 *
 * To use mod_example_hooks, configure the Apache build with
 * --enable-example-hooks and compile.  Set up a <Location> block in your
 * configuration file like so:
 *
 * <Location /example>
 *    SetHandler example-hooks-handler
 * </Location>
 *
 * When you look at that location on your server, you will see a backtrace of
 * the callbacks that have been invoked up to that point.  See the ErrorLog for
 * more information on code paths that  touch mod_example_hooks.
 *
 * IMPORTANT NOTES
 * ===============
 *
 * Do NOT use this module on a production server. It attaches itself to every
 * phase of the server runtime operations including startup, shutdown and
 * request processing, and produces copious amounts of logging data.  This will
 * negatively affect server performance.
 *
 * Do NOT use mod_example_hooks as the basis for your own code.  This module
 * implements every callback hook offered by the Apache core, and your
 * module will almost certainly not have to implement this much.  If you
 * want a simple module skeleton to start development, use apxs -g.
 *
 * XXX TO DO XXX
 * =============
 *
 * * Enable HTML backtrace entries for more callbacks that are not directly
 *   associated with a request
 * * Make sure every callback that posts an HTML backtrace entry does so in the *   right category, so nothing gets overwritten
 * * Implement some logic to show what happens in the parent, and what in the
 *   child(ren)
 */

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_main.h"
#include "http_protocol.h"
#include "http_request.h"
#include "util_script.h"
#include "http_connection.h"
#ifdef HAVE_UNIX_SUEXEC
#include "unixd.h"
#endif
#include "scoreboard.h"
#include "mpm_common.h"

#include "apr_strings.h"

#include <stdio.h>

/*--------------------------------------------------------------------------*/
/*                                                                          */
/* Data declarations.                                                       */
/*                                                                          */
/* Here are the static cells and structure declarations private to our      */
/* module.                                                                  */
/*                                                                          */
/*--------------------------------------------------------------------------*/

/*
 * Sample configuration record.  Used for both per-directory and per-server
 * configuration data.
 *
 * It's perfectly reasonable to have two different structures for the two
 * different environments.  The same command handlers will be called for
 * both, though, so the handlers need to be able to tell them apart.  One
 * possibility is for both structures to start with an int which is 0 for
 * one and 1 for the other.
 *
 * Note that while the per-directory and per-server configuration records are
 * available to most of the module handlers, they should be treated as
 * READ-ONLY by all except the command and merge handlers.  Sometimes handlers
 * are handed a record that applies to the current location by implication or
 * inheritance, and modifying it will change the rules for other locations.
 */
typedef struct x_cfg {
    int cmode;                  /* Environment to which record applies
                                 * (directory, server, or combination).
                                 */
#define CONFIG_MODE_SERVER 1
#define CONFIG_MODE_DIRECTORY 2
#define CONFIG_MODE_COMBO 3     /* Shouldn't ever happen. */
    int local;                  /* Boolean: "Example" directive declared
                                 * here?
                                 */
    int congenital;             /* Boolean: did we inherit an "Example"? */
    char *trace;                /* Pointer to trace string. */
    char *loc;                  /* Location to which this record applies. */
} x_cfg;

/*
 * String pointer to hold the startup trace. No harm working with a global until
 * the server is (may be) multi-threaded.
 */
static const char *trace = NULL;

/*
 * Declare ourselves so the configuration routines can find and know us.
 * We'll fill it in at the end of the module.
 */
module AP_MODULE_DECLARE_DATA example_hooks_module;

/*--------------------------------------------------------------------------*/
/*                                                                          */
/* The following pseudo-prototype declarations illustrate the parameters    */
/* passed to command handlers for the different types of directive          */
/* syntax.  If an argument was specified in the directive definition        */
/* (look for "command_rec" below), it's available to the command handler    */
/* via the (void *) info field in the cmd_parms argument passed to the      */
/* handler (cmd->info for the examples below).                              */
/*                                                                          */
/*--------------------------------------------------------------------------*/

/*
 * Command handler for a NO_ARGS directive.  Declared in the command_rec
 * list with
 *   AP_INIT_NO_ARGS("directive", function, mconfig, where, help)
 *
 * static const char *handle_NO_ARGS(cmd_parms *cmd, void *mconfig);
 */

/*
 * Command handler for a RAW_ARGS directive.  The "args" argument is the text
 * of the commandline following the directive itself.  Declared in the
 * command_rec list with
 *   AP_INIT_RAW_ARGS("directive", function, mconfig, where, help)
 *
 * static const char *handle_RAW_ARGS(cmd_parms *cmd, void *mconfig,
 *                                    const char *args);
 */

/*
 * Command handler for a FLAG directive.  The single parameter is passed in
 * "bool", which is either zero or not for Off or On respectively.
 * Declared in the command_rec list with
 *   AP_INIT_FLAG("directive", function, mconfig, where, help)
 *
 * static const char *handle_FLAG(cmd_parms *cmd, void *mconfig, int bool);
 */

/*
 * Command handler for a TAKE1 directive.  The single parameter is passed in
 * "word1".  Declared in the command_rec list with
 *   AP_INIT_TAKE1("directive", function, mconfig, where, help)
 *
 * static const char *handle_TAKE1(cmd_parms *cmd, void *mconfig,
 *                                 char *word1);
 */

/*
 * Command handler for a TAKE2 directive.  TAKE2 commands must always have
 * exactly two arguments.  Declared in the command_rec list with
 *   AP_INIT_TAKE2("directive", function, mconfig, where, help)
 *
 * static const char *handle_TAKE2(cmd_parms *cmd, void *mconfig,
 *                                 char *word1, char *word2);
 */

/*
 * Command handler for a TAKE3 directive.  Like TAKE2, these must have exactly
 * three arguments, or the parser complains and doesn't bother calling us.
 * Declared in the command_rec list with
 *   AP_INIT_TAKE3("directive", function, mconfig, where, help)
 *
 * static const char *handle_TAKE3(cmd_parms *cmd, void *mconfig,
 *                                 char *word1, char *word2, char *word3);
 */

/*
 * Command handler for a TAKE12 directive.  These can take either one or two
 * arguments.
 * - word2 is a NULL pointer if no second argument was specified.
 * Declared in the command_rec list with
 *   AP_INIT_TAKE12("directive", function, mconfig, where, help)
 *
 * static const char *handle_TAKE12(cmd_parms *cmd, void *mconfig,
 *                                  char *word1, char *word2);
 */

/*
 * Command handler for a TAKE123 directive.  A TAKE123 directive can be given,
 * as might be expected, one, two, or three arguments.
 * - word2 is a NULL pointer if no second argument was specified.
 * - word3 is a NULL pointer if no third argument was specified.
 * Declared in the command_rec list with
 *   AP_INIT_TAKE123("directive", function, mconfig, where, help)
 *
 * static const char *handle_TAKE123(cmd_parms *cmd, void *mconfig,
 *                                   char *word1, char *word2, char *word3);
 */

/*
 * Command handler for a TAKE13 directive.  Either one or three arguments are
 * permitted - no two-parameters-only syntax is allowed.
 * - word2 and word3 are NULL pointers if only one argument was specified.
 * Declared in the command_rec list with
 *   AP_INIT_TAKE13("directive", function, mconfig, where, help)
 *
 * static const char *handle_TAKE13(cmd_parms *cmd, void *mconfig,
 *                                  char *word1, char *word2, char *word3);
 */

/*
 * Command handler for a TAKE23 directive.  At least two and as many as three
 * arguments must be specified.
 * - word3 is a NULL pointer if no third argument was specified.
 * Declared in the command_rec list with
 *   AP_INIT_TAKE23("directive", function, mconfig, where, help)
 *
 * static const char *handle_TAKE23(cmd_parms *cmd, void *mconfig,
 *                                  char *word1, char *word2, char *word3);
 */

/*
 * Command handler for a ITERATE directive.
 * - Handler is called once for each of n arguments given to the directive.
 * - word1 points to each argument in turn.
 * Declared in the command_rec list with
 *   AP_INIT_ITERATE("directive", function, mconfig, where, help)
 *
 * static const char *handle_ITERATE(cmd_parms *cmd, void *mconfig,
 *                                   char *word1);
 */

/*
 * Command handler for a ITERATE2 directive.
 * - Handler is called once for each of the second and subsequent arguments
 *   given to the directive.
 * - word1 is the same for each call for a particular directive instance (the
 *   first argument).
 * - word2 points to each of the second and subsequent arguments in turn.
 * Declared in the command_rec list with
 *   AP_INIT_ITERATE2("directive", function, mconfig, where, help)
 *
 * static const char *handle_ITERATE2(cmd_parms *cmd, void *mconfig,
 *                                    char *word1, char *word2);
 */

/*--------------------------------------------------------------------------*/
/*                                                                          */
/* These routines are strictly internal to this module, and support its     */
/* operation.  They are not referenced by any external portion of the       */
/* server.                                                                  */
/*                                                                          */
/*--------------------------------------------------------------------------*/

/*
 * Locate our directory configuration record for the current request.
 */
static x_cfg *our_dconfig(const request_rec *r)
{
    return (x_cfg *) ap_get_module_config(r->per_dir_config, &example_hooks_module);
}

/*
 * The following utility routines are not used in the module. Don't
 * compile them so -Wall doesn't complain about functions that are
 * defined but not used.
 */
#if 0
/*
 * Locate our server configuration record for the specified server.
 */
static x_cfg *our_sconfig(const server_rec *s)
{
    return (x_cfg *) ap_get_module_config(s->module_config, &example_hooks_module);
}

/*
 * Likewise for our configuration record for the specified request.
 */
static x_cfg *our_rconfig(const request_rec *r)
{
    return (x_cfg *) ap_get_module_config(r->request_config, &example_hooks_module);
}
#endif /* if 0 */

/*
 * Likewise for our configuration record for a connection.
 */
static x_cfg *our_cconfig(const conn_rec *c)
{
    return (x_cfg *) ap_get_module_config(c->conn_config, &example_hooks_module);
}

/*
 * You *could* change the following if you wanted to see the calling
 * sequence reported in the server's error_log, but beware - almost all of
 * these co-routines are called for every single request, and the impact
 * on the size (and readability) of the error_log is considerable.
 */
#ifndef EXAMPLE_LOG_EACH
#define EXAMPLE_LOG_EACH 0
#endif

#if EXAMPLE_LOG_EACH
static void example_log_each(apr_pool_t *p, server_rec *s, const char *note)
{
    if (s != NULL) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, "mod_example_hooks: %s", note);
    }
    else {
        apr_file_t *out = NULL;
        apr_file_open_stderr(&out, p);
        apr_file_printf(out, "mod_example_hooks traced in non-loggable "
                        "context: %s\n", note);
    }
}
#endif

/*
 * This utility routine traces the hooks called when the server starts up.
 * It leaves a trace in a global variable, so it should not be called from
 * a hook handler that runs in a multi-threaded situation.
 */

static void trace_startup(apr_pool_t *p, server_rec *s, x_cfg *mconfig,
                          const char *note)
{
    const char *sofar;
    char *where, *addon;

#if EXAMPLE_LOG_EACH
    example_log_each(p, s, note);
#endif

    /*
     * If we weren't passed a configuration record, we can't figure out to
     * what location this call applies.  This only happens for co-routines
     * that don't operate in a particular directory or server context.  If we
     * got a valid record, extract the location (directory or server) to which
     * it applies.
     */
    where = (mconfig != NULL) ? mconfig->loc : "nowhere";
    where = (where != NULL) ? where : "";

    addon = apr_pstrcat(p,
                        "   <li>\n"
                        "    <dl>\n"
                        "     <dt><samp>", note, "</samp></dt>\n"
                        "     <dd><samp>[", where, "]</samp></dd>\n"
                        "    </dl>\n"
                        "   </li>\n",
                        NULL);

    /*
     * Make sure that we start with a valid string, even if we have never been
     * called.
     */
    sofar = (trace == NULL) ? "" : trace;

    trace = apr_pstrcat(p, sofar, addon, NULL);
}


/*
 * This utility route traces the hooks called as a request is handled.
 * It takes the current request as argument
 */
#define TRACE_NOTE "example-hooks-trace"

static void trace_request(const request_rec *r, const char *note)
{
    const char *trace_copy, *sofar;
    char *addon, *where;
    x_cfg *cfg;

#if EXAMPLE_LOG_EACH
    example_log_each(r->pool, r->server, note);
#endif

    if ((sofar = apr_table_get(r->notes, TRACE_NOTE)) == NULL) {
        sofar = "";
    }

    cfg = our_dconfig(r);

    where = (cfg != NULL) ? cfg->loc : "nowhere";
    where = (where != NULL) ? where : "";

    addon = apr_pstrcat(r->pool,
                        "   <li>\n"
                        "    <dl>\n"
                        "     <dt><samp>", note, "</samp></dt>\n"
                        "     <dd><samp>[", where, "]</samp></dd>\n"
                        "    </dl>\n"
                        "   </li>\n",
                        NULL);

    trace_copy = apr_pstrcat(r->pool, sofar, addon, NULL);
    apr_table_set(r->notes, TRACE_NOTE, trace_copy);
}

/*
 * This utility routine traces the hooks called while processing a
 * Connection. Its trace is kept in the pool notes of the pool associated
 * with the Connection.
 */

/*
 * Key to get and set the userdata.  We should be able to get away
 * with a constant key, since in prefork mode the process will have
 * the connection and its pool to itself entirely, and in
 * multi-threaded mode each connection will have its own pool.
 */
#define CONN_NOTE "example-hooks-connection"

static void trace_connection(conn_rec *c, const char *note)
{
    const char *trace_copy, *sofar;
    char *addon, *where;
    void *data;
    x_cfg *cfg;

#if EXAMPLE_LOG_EACH
    example_log_each(c->pool, c->base_server, note);
#endif

    cfg = our_cconfig(c);

    where = (cfg != NULL) ? cfg->loc : "nowhere";
    where = (where != NULL) ? where : "";

    addon = apr_pstrcat(c->pool,
                        "   <li>\n"
                        "    <dl>\n"
                        "     <dt><samp>", note, "</samp></dt>\n"
                        "     <dd><samp>[", where, "]</samp></dd>\n"
                        "    </dl>\n"
                        "   </li>\n",
                        NULL);

    /* Find existing notes and copy */
    apr_pool_userdata_get(&data, CONN_NOTE, c->pool);
    sofar = (data == NULL) ? "" : (const char *) data;

    /* Tack addon onto copy */
    trace_copy = apr_pstrcat(c->pool, sofar, addon, NULL);

    /*
     * Stash copy back into pool notes.  This call has a cleanup
     * parameter, but we're not using it because the string has been
     * allocated from that same pool.  There is also an unused return
     * value: we have nowhere to communicate any error that might
     * occur, and will have to check for the existence of this data on
     * the other end.
     */
    apr_pool_userdata_set((const void *) trace_copy, CONN_NOTE,
                          NULL, c->pool);
}

static void trace_nocontext(apr_pool_t *p, const char *file, int line,
                            const char *note)
{
    /*
     * Since we have no request or connection to trace, or any idea
     * from where this routine was called, there's really not much we
     * can do.  If we are not logging everything by way of the
     * EXAMPLE_LOG_EACH constant, do nothing in this routine.
     */

#ifdef EXAMPLE_LOG_EACH
    ap_log_perror(file, line, APLOG_MODULE_INDEX, APLOG_NOTICE, 0, p, "%s", note);
#endif
}


/*--------------------------------------------------------------------------*/
/* We prototyped the various syntax for command handlers (routines that     */
/* are called when the configuration parser detects a directive declared    */
/* by our module) earlier.  Now we actually declare a "real" routine that   */
/* will be invoked by the parser when our "real" directive is               */
/* encountered.                                                             */
/*                                                                          */
/* If a command handler encounters a problem processing the directive, it   */
/* signals this fact by returning a non-NULL pointer to a string            */
/* describing the problem.                                                  */
/*                                                                          */
/* The magic return value DECLINE_CMD is used to deal with directives       */
/* that might be declared by multiple modules.  If the command handler      */
/* returns NULL, the directive was processed; if it returns DECLINE_CMD,    */
/* the next module (if any) that declares the directive is given a chance   */
/* at it.  If it returns any other value, it's treated as the text of an    */
/* error message.                                                           */
/*--------------------------------------------------------------------------*/
/*
 * Command handler for the NO_ARGS "Example" directive.  All we do is mark the
 * call in the trace log, and flag the applicability of the directive to the
 * current location in that location's configuration record.
 */
static const char *cmd_example(cmd_parms *cmd, void *mconfig)
{
    x_cfg *cfg = (x_cfg *) mconfig;

    /*
     * "Example Wuz Here"
     */
    cfg->local = 1;
    trace_startup(cmd->pool, cmd->server, cfg, "cmd_example()");
    return NULL;
}

/*
 * This function gets called to create a per-directory configuration
 * record.  This will be called for the "default" server environment, and for
 * each directory for which the parser finds any of our directives applicable.
 * If a directory doesn't have any of our directives involved (i.e., they
 * aren't in the .htaccess file, or a <Location>, <Directory>, or related
 * block), this routine will *not* be called - the configuration for the
 * closest ancestor is used.
 *
 * The return value is a pointer to the created module-specific
 * structure.
 */
static void *x_create_dir_config(apr_pool_t *p, char *dirspec)
{
    x_cfg *cfg;
    char *dname = dirspec;
    char *note;

    /*
     * Allocate the space for our record from the pool supplied.
     */
    cfg = (x_cfg *) apr_pcalloc(p, sizeof(x_cfg));
    /*
     * Now fill in the defaults.  If there are any `parent' configuration
     * records, they'll get merged as part of a separate callback.
     */
    cfg->local = 0;
    cfg->congenital = 0;
    cfg->cmode = CONFIG_MODE_DIRECTORY;
    /*
     * Finally, add our trace to the callback list.
     */
    dname = (dname != NULL) ? dname : "";
    cfg->loc = apr_pstrcat(p, "DIR(", dname, ")", NULL);
    note = apr_psprintf(p, "x_create_dir_config(p == %pp, dirspec == %s)",
                        (void*) p, dirspec);
    trace_startup(p, NULL, cfg, note);
    return (void *) cfg;
}

/*
 * This function gets called to merge two per-directory configuration
 * records.  This is typically done to cope with things like .htaccess files
 * or <Location> directives for directories that are beneath one for which a
 * configuration record was already created.  The routine has the
 * responsibility of creating a new record and merging the contents of the
 * other two into it appropriately.  If the module doesn't declare a merge
 * routine, the record for the closest ancestor location (that has one) is
 * used exclusively.
 *
 * The routine MUST NOT modify any of its arguments!
 *
 * The return value is a pointer to the created module-specific structure
 * containing the merged values.
 */
static void *x_merge_dir_config(apr_pool_t *p, void *parent_conf,
                                      void *newloc_conf)
{

    x_cfg *merged_config = (x_cfg *) apr_pcalloc(p, sizeof(x_cfg));
    x_cfg *pconf = (x_cfg *) parent_conf;
    x_cfg *nconf = (x_cfg *) newloc_conf;
    char *note;

    /*
     * Some things get copied directly from the more-specific record, rather
     * than getting merged.
     */
    merged_config->local = nconf->local;
    merged_config->loc = apr_pstrdup(p, nconf->loc);
    /*
     * Others, like the setting of the `congenital' flag, get ORed in.  The
     * setting of that particular flag, for instance, is TRUE if it was ever
     * true anywhere in the upstream configuration.
     */
    merged_config->congenital = (pconf->congenital | pconf->local);
    /*
     * If we're merging records for two different types of environment (server
     * and directory), mark the new record appropriately.  Otherwise, inherit
     * the current value.
     */
    merged_config->cmode =
        (pconf->cmode == nconf->cmode) ? pconf->cmode : CONFIG_MODE_COMBO;
    /*
     * Now just record our being called in the trace list.  Include the
     * locations we were asked to merge.
     */
    note = apr_psprintf(p, "x_merge_dir_config(p == %pp, parent_conf == "
                        "%pp, newloc_conf == %pp)", (void*) p,
                        (void*) parent_conf, (void*) newloc_conf);
    trace_startup(p, NULL, merged_config, note);
    return (void *) merged_config;
}

/*
 * This function gets called to create a per-server configuration
 * record.  It will always be called for the "default" server.
 *
 * The return value is a pointer to the created module-specific
 * structure.
 */
static void *x_create_server_config(apr_pool_t *p, server_rec *s)
{

    x_cfg *cfg;
    char *sname = s->server_hostname;

    /*
     * As with the x_create_dir_config() reoutine, we allocate and fill
     * in an empty record.
     */
    cfg = (x_cfg *) apr_pcalloc(p, sizeof(x_cfg));
    cfg->local = 0;
    cfg->congenital = 0;
    cfg->cmode = CONFIG_MODE_SERVER;
    /*
     * Note that we were called in the trace list.
     */
    sname = (sname != NULL) ? sname : "";
    cfg->loc = apr_pstrcat(p, "SVR(", sname, ")", NULL);
    trace_startup(p, s, cfg, "x_create_server_config()");
    return (void *) cfg;
}

/*
 * This function gets called to merge two per-server configuration
 * records.  This is typically done to cope with things like virtual hosts and
 * the default server configuration  The routine has the responsibility of
 * creating a new record and merging the contents of the other two into it
 * appropriately.  If the module doesn't declare a merge routine, the more
 * specific existing record is used exclusively.
 *
 * The routine MUST NOT modify any of its arguments!
 *
 * The return value is a pointer to the created module-specific structure
 * containing the merged values.
 */
static void *x_merge_server_config(apr_pool_t *p, void *server1_conf,
                                         void *server2_conf)
{

    x_cfg *merged_config = (x_cfg *) apr_pcalloc(p, sizeof(x_cfg));
    x_cfg *s1conf = (x_cfg *) server1_conf;
    x_cfg *s2conf = (x_cfg *) server2_conf;
    char *note;

    /*
     * Our inheritance rules are our own, and part of our module's semantics.
     * Basically, just note whence we came.
     */
    merged_config->cmode =
        (s1conf->cmode == s2conf->cmode) ? s1conf->cmode : CONFIG_MODE_COMBO;
    merged_config->local = s2conf->local;
    merged_config->congenital = (s1conf->congenital | s1conf->local);
    merged_config->loc = apr_pstrdup(p, s2conf->loc);
    /*
     * Trace our call, including what we were asked to merge.
     */
    note = apr_pstrcat(p, "x_merge_server_config(\"", s1conf->loc, "\",\"",
                   s2conf->loc, "\")", NULL);
    trace_startup(p, NULL, merged_config, note);
    return (void *) merged_config;
}


/*--------------------------------------------------------------------------*
 *                                                                          *
 * Now let's declare routines for each of the callback hooks in order.      *
 * (That's the order in which they're listed in the callback list, *not     *
 * the order in which the server calls them!  See the command_rec           *
 * declaration near the bottom of this file.)  Note that these may be       *
 * called for situations that don't relate primarily to our function - in   *
 * other words, the fixup handler shouldn't assume that the request has     *
 * to do with "example_hooks" stuff.                                        *
 *                                                                          *
 * With the exception of the content handler, all of our routines will be   *
 * called for each request, unless an earlier handler from another module   *
 * aborted the sequence.                                                    *
 *                                                                          *
 * There are three types of hooks (see include/ap_config.h):                *
 *                                                                          *
 * VOID      : No return code, run all handlers declared by any module      *
 * RUN_FIRST : Run all handlers until one returns something other           *
 *             than DECLINED. Hook runner result is result of last callback *
 * RUN_ALL   : Run all handlers until one returns something other than OK   *
 *             or DECLINED. The hook runner returns that other value. If    *
 *             all hooks run, the hook runner returns OK.                   *
 *                                                                          *
 * Handlers that are declared as "int" can return the following:            *
 *                                                                          *
 *  OK          Handler accepted the request and did its thing with it.     *
 *  DECLINED    Handler took no action.                                     *
 *  HTTP_mumble Handler looked at request and found it wanting.             *
 *                                                                          *
 * See include/httpd.h for a list of HTTP_mumble status codes.  Handlers    *
 * that are not declared as int return a valid pointer, or NULL if they     *
 * DECLINE to handle their phase for that specific request.  Exceptions, if *
 * any, are noted with each routine.                                        *
 *--------------------------------------------------------------------------*/

/*
 * This routine is called before the server processes the configuration
 * files.  There is no return value.
 */
static int x_pre_config(apr_pool_t *pconf, apr_pool_t *plog,
                        apr_pool_t *ptemp)
{
    /*
     * Log the call and exit.
     */
    trace_startup(ptemp, NULL, NULL, "x_pre_config()");
    return OK;
}

/*
 * This routine is called after the server processes the configuration
 * files.  At this point the module may review and adjust its configuration
 * settings in relation to one another and report any problems.  On restart,
 * this routine will be called twice, once in the startup process (which
 * exits shortly after this phase) and once in the running server process.
 *
 * The return value is OK, DECLINED, or HTTP_mumble.  If we return OK, the
 * server will still call any remaining modules with an handler for this
 * phase.
 */
static int x_check_config(apr_pool_t *pconf, apr_pool_t *plog,
                          apr_pool_t *ptemp, server_rec *s)
{
    /*
     * Log the call and exit.
     */
    trace_startup(ptemp, s, NULL, "x_check_config()");
    return OK;
}

/*
 * This routine is called when the -t command-line option is supplied.
 * It executes only once, in the startup process, after the check_config
 * phase and just before the process exits.  At this point the module
 * may output any information useful in configuration testing.
 *
 * This is a VOID hook: all defined handlers get called.
 */
static void x_test_config(apr_pool_t *pconf, server_rec *s)
{
    apr_file_t *out = NULL;

    apr_file_open_stderr(&out, pconf);

    apr_file_printf(out, "Example module configuration test routine\n");

    trace_startup(pconf, s, NULL, "x_test_config()");
}

/*
 * This routine is called to perform any module-specific log file
 * openings. It is invoked just before the post_config phase
 *
 * The return value is OK, DECLINED, or HTTP_mumble.  If we return OK, the
 * server will still call any remaining modules with an handler for this
 * phase.
 */
static int x_open_logs(apr_pool_t *pconf, apr_pool_t *plog,
                        apr_pool_t *ptemp, server_rec *s)
{
    /*
     * Log the call and exit.
     */
    trace_startup(ptemp, s, NULL, "x_open_logs()");
    return OK;
}

/*
 * This routine is called after the server finishes the configuration
 * process.  At this point the module may review and adjust its configuration
 * settings in relation to one another and report any problems.  On restart,
 * this routine will be called only once, in the running server process.
 *
 * The return value is OK, DECLINED, or HTTP_mumble.  If we return OK, the
 * server will still call any remaining modules with an handler for this
 * phase.
 */
static int x_post_config(apr_pool_t *pconf, apr_pool_t *plog,
                          apr_pool_t *ptemp, server_rec *s)
{
    /*
     * Log the call and exit.
     */
    trace_startup(ptemp, s, NULL, "x_post_config()");
    return OK;
}

/*
 * All our process-death routine does is add its trace to the log.
 */
static apr_status_t x_child_exit(void *data)
{
    char *note;
    server_rec *s = data;
    char *sname = s->server_hostname;

    /*
     * The arbitrary text we add to our trace entry indicates for which server
     * we're being called.
     */
    sname = (sname != NULL) ? sname : "";
    note = apr_pstrcat(s->process->pool, "x_child_exit(", sname, ")", NULL);
    trace_startup(s->process->pool, s, NULL, note);
    return APR_SUCCESS;
}

/*
 * All our process initialiser does is add its trace to the log.
 *
 * This is a VOID hook: all defined handlers get called.
 */
static void x_child_init(apr_pool_t *p, server_rec *s)
{
    char *note;
    char *sname = s->server_hostname;

    /*
     * The arbitrary text we add to our trace entry indicates for which server
     * we're being called.
     */
    sname = (sname != NULL) ? sname : "";
    note = apr_pstrcat(p, "x_child_init(", sname, ")", NULL);
    trace_startup(p, s, NULL, note);

    apr_pool_cleanup_register(p, s, x_child_exit, x_child_exit);
}

/*
 * The hook runner for ap_hook_http_scheme is aliased to ap_http_scheme(),
 * a routine that the core and other modules call when they need to know
 * the URL scheme for the request.  For instance, mod_ssl returns "https"
 * if the server_rec associated with the request has SSL enabled.
 *
 * This hook was named 'ap_hook_http_method' in httpd 2.0.
 *
 * This is a RUN_FIRST hook: the first handler to return a non NULL
 * value aborts the handler chain.  The http_core module inserts a
 * fallback handler (with APR_HOOK_REALLY_LAST preference) that returns
 * "http".
 */
static const char *x_http_scheme(const request_rec *r)
{
    /*
     * Log the call and exit.
     */
    trace_request(r, "x_http_scheme()");

    /* We have no claims to make about the request scheme */
    return NULL;
}

/*
 * The runner for this hook is aliased to ap_default_port(), which the
 * core and other modules call when they need to know the default port
 * for a particular server.  This is used for instance to omit the
 * port number from a Redirect response Location header URL if the port
 * number is equal to the default port for the service (like 80 for http).
 *
 * This is a RUN_FIRST hook: the first handler to return a non-zero
 * value is the last one executed.  The http_core module inserts a
 * fallback handler (with APR_HOOK_REALLY_LAST order specifier) that
 * returns 80.
 */
static apr_port_t x_default_port(const request_rec *r)
{
    /*
     * Log the call and exit.
     */
    trace_request(r, "x_default_port()");
    return 0;
}

/*
 * This routine is called just before the handler gets invoked. It allows
 * a module to insert a previously defined filter into the filter chain.
 *
 * No filter has been defined by this module, so we just log the call
 * and exit.
 *
 * This is a VOID hook: all defined handlers get called.
 */
static void x_insert_filter(request_rec *r)
{
    /*
     * Log the call and exit.
     */
    trace_request(r, "x_insert_filter()");
}

/*
 * This routine is called to insert a previously defined error filter into
 * the filter chain as the request is being processed.
 *
 * For the purpose of this example, we don't have a filter to insert,
 * so just add to the trace and exit.
 *
 * This is a VOID hook: all defined handlers get called.
 */
static void x_insert_error_filter(request_rec *r)
{
    trace_request(r, "x_insert_error_filter()");
}

/*--------------------------------------------------------------------------*/
/*                                                                          */
/* Now we declare our content handlers, which are invoked when the server   */
/* encounters a document which our module is supposed to have a chance to   */
/* see.  (See mod_mime's SetHandler and AddHandler directives, and the      */
/* mod_info and mod_status examples, for more details.)                     */
/*                                                                          */
/* Since content handlers are dumping data directly into the connection     */
/* (using the r*() routines, such as rputs() and rprintf()) without         */
/* intervention by other parts of the server, they need to make             */
/* sure any accumulated HTTP headers are sent first.  This is done by       */
/* calling send_http_header().  Otherwise, no header will be sent at all,   */
/* and the output sent to the client will actually be HTTP-uncompliant.     */
/*--------------------------------------------------------------------------*/
/*
 * Sample content handler.  All this does is display the call list that has
 * been built up so far.
 *
 * This routine gets called for every request, unless another handler earlier
 * in the callback chain has already handled the request. It is up to us to
 * test the request_rec->handler field and see whether we are meant to handle
 * this request.
 *
 * The content handler gets to write directly to the client using calls like
 * ap_rputs() and ap_rprintf()
 *
 * This is a RUN_FIRST hook.
 */
static int x_handler(request_rec *r)
{
    x_cfg *dcfg;
    char *note;
    void *conn_data;
    apr_status_t status;

    dcfg = our_dconfig(r);
    /*
     * Add our trace to the log, and whether we get to write
     * content for this request.
     */
    note = apr_pstrcat(r->pool, "x_handler(), handler is \"",
                      r->handler, "\"", NULL);
    trace_request(r, note);

    /* If it's not for us, get out as soon as possible. */
    if (strcmp(r->handler, "example-hooks-handler")) {
        return DECLINED;
    }

    /*
     * Set the Content-type header. Note that we do not actually have to send
     * the headers: this is done by the http core.
     */
    ap_set_content_type(r, "text/html");
    /*
     * If we're only supposed to send header information (HEAD request), we're
     * already there.
     */
    if (r->header_only) {
        return OK;
    }

    /*
     * Now send our actual output.  Since we tagged this as being
     * "text/html", we need to embed any HTML.
     */
    ap_rputs(DOCTYPE_HTML_3_2, r);
    ap_rputs("<HTML>\n", r);
    ap_rputs(" <HEAD>\n", r);
    ap_rputs("  <TITLE>mod_example_hooks Module Content-Handler Output\n", r);
    ap_rputs("  </TITLE>\n", r);
    ap_rputs(" </HEAD>\n", r);
    ap_rputs(" <BODY>\n", r);
    ap_rputs("  <H1><SAMP>mod_example_hooks</SAMP> Module Content-Handler Output\n", r);
    ap_rputs("  </H1>\n", r);
    ap_rputs("  <P>\n", r);
    ap_rprintf(r, "  Apache HTTP Server version: \"%s\"\n",
            ap_get_server_banner());
    ap_rputs("  <BR>\n", r);
    ap_rprintf(r, "  Server built: \"%s\"\n", ap_get_server_built());
    ap_rputs("  </P>\n", r);
    ap_rputs("  <P>\n", r);
    ap_rputs("  The format for the callback trace is:\n", r);
    ap_rputs("  </P>\n", r);
    ap_rputs("  <DL>\n", r);
    ap_rputs("   <DT><EM>n</EM>.<SAMP>&lt;routine-name&gt;", r);
    ap_rputs("(&lt;routine-data&gt;)</SAMP>\n", r);
    ap_rputs("   </DT>\n", r);
    ap_rputs("   <DD><SAMP>[&lt;applies-to&gt;]</SAMP>\n", r);
    ap_rputs("   </DD>\n", r);
    ap_rputs("  </DL>\n", r);
    ap_rputs("  <P>\n", r);
    ap_rputs("  The <SAMP>&lt;routine-data&gt;</SAMP> is supplied by\n", r);
    ap_rputs("  the routine when it requests the trace,\n", r);
    ap_rputs("  and the <SAMP>&lt;applies-to&gt;</SAMP> is extracted\n", r);
    ap_rputs("  from the configuration record at the time of the trace.\n", r);
    ap_rputs("  <STRONG>SVR()</STRONG> indicates a server environment\n", r);
    ap_rputs("  (blank means the main or default server, otherwise it's\n", r);
    ap_rputs("  the name of the VirtualHost); <STRONG>DIR()</STRONG>\n", r);
    ap_rputs("  indicates a location in the URL or filesystem\n", r);
    ap_rputs("  namespace.\n", r);
    ap_rputs("  </P>\n", r);
    ap_rprintf(r, "  <H2>Startup callbacks so far:</H2>\n  <OL>\n%s  </OL>\n",
            trace);
    ap_rputs("  <H2>Connection-specific callbacks so far:</H2>\n", r);

    status =  apr_pool_userdata_get(&conn_data, CONN_NOTE,
                                    r->connection->pool);
    if ((status == APR_SUCCESS) && conn_data) {
        ap_rprintf(r, "  <OL>\n%s  </OL>\n", (char *) conn_data);
    }
    else {
        ap_rputs("  <P>No connection-specific callback information was "
                 "retrieved.</P>\n", r);
    }

    ap_rputs("  <H2>Request-specific callbacks so far:</H2>\n", r);
    ap_rprintf(r, "  <OL>\n%s  </OL>\n", apr_table_get(r->notes, TRACE_NOTE));
    ap_rputs("  <H2>Environment for <EM>this</EM> call:</H2>\n", r);
    ap_rputs("  <UL>\n", r);
    ap_rprintf(r, "   <LI>Applies-to: <SAMP>%s</SAMP>\n   </LI>\n", dcfg->loc);
    ap_rprintf(r, "   <LI>\"Example\" directive declared here: %s\n   </LI>\n",
            (dcfg->local ? "YES" : "NO"));
    ap_rprintf(r, "   <LI>\"Example\" inherited: %s\n   </LI>\n",
            (dcfg->congenital ? "YES" : "NO"));
    ap_rputs("  </UL>\n", r);
    ap_rputs(" </BODY>\n", r);
    ap_rputs("</HTML>\n", r);
    /*
     * We're all done, so cancel the timeout we set.  Since this is probably
     * the end of the request we *could* assume this would be done during
     * post-processing - but it's possible that another handler might be
     * called and inherit our outstanding timer.  Not good; to each its own.
     */
    /*
     * We did what we wanted to do, so tell the rest of the server we
     * succeeded.
     */
    return OK;
}

/*
 * The quick_handler hook presents modules with a very powerful opportunity to
 * serve their content in a very early request phase.  Note that this handler
 * can not serve any requests from the file system because hooks like
 * map_to_storage have not run.  The quick_handler hook also runs before any
 * authentication and access control.
 *
 * This hook is used by mod_cache to serve cached content.
 *
 * This is a RUN_FIRST hook. Return OK if you have served the request,
 * DECLINED if you want processing to continue, or a HTTP_* error code to stop
 * processing the request.
 */
static int x_quick_handler(request_rec *r, int lookup_uri)
{
    /*
     * Log the call and exit.
     */
    trace_request(r, "x_quick_handler()");
    return DECLINED;
}

/*
 * This routine is called just after the server accepts the connection,
 * but before it is handed off to a protocol module to be served.  The point
 * of this hook is to allow modules an opportunity to modify the connection
 * as soon as possible. The core server uses this phase to setup the
 * connection record based on the type of connection that is being used.
 *
 * This is a RUN_ALL hook.
 */
static int x_pre_connection(conn_rec *c, void *csd)
{
    char *note;

    /*
     * Log the call and exit.
     */
    note = apr_psprintf(c->pool, "x_pre_connection(c = %pp, p = %pp)",
                        (void*) c, (void*) c->pool);
    trace_connection(c, note);

    return OK;
}

/* This routine is used to actually process the connection that was received.
 * Only protocol modules should implement this hook, as it gives them an
 * opportunity to replace the standard HTTP processing with processing for
 * some other protocol.  Both echo and POP3 modules are available as
 * examples.
 *
 * This is a RUN_FIRST hook.
 */
static int x_process_connection(conn_rec *c)
{
    trace_connection(c, "x_process_connection()");
    return DECLINED;
}

/*
 * This routine is called after the request has been read but before any other
 * phases have been processed.  This allows us to make decisions based upon
 * the input header fields.
 *
 * This is a HOOK_VOID hook.
 */
static void x_pre_read_request(request_rec *r, conn_rec *c)
{
    /*
     * We don't actually *do* anything here, except note the fact that we were
     * called.
     */
    trace_request(r, "x_pre_read_request()");
}

/*
 * This routine is called after the request has been read but before any other
 * phases have been processed.  This allows us to make decisions based upon
 * the input header fields.
 *
 * This is a RUN_ALL hook.
 */
static int x_post_read_request(request_rec *r)
{
    /*
     * We don't actually *do* anything here, except note the fact that we were
     * called.
     */
    trace_request(r, "x_post_read_request()");
    return DECLINED;
}

/*
 * This routine gives our module an opportunity to translate the URI into an
 * actual filename.  If we don't do anything special, the server's default
 * rules (Alias directives and the like) will continue to be followed.
 *
 * This is a RUN_FIRST hook.
 */
static int x_translate_name(request_rec *r)
{
    /*
     * We don't actually *do* anything here, except note the fact that we were
     * called.
     */
    trace_request(r, "x_translate_name()");
    return DECLINED;
}

/*
 * This routine maps r->filename to a physical file on disk.  Useful for
 * overriding default core behavior, including skipping mapping for
 * requests that are not file based.
 *
 * This is a RUN_FIRST hook.
 */
static int x_map_to_storage(request_rec *r)
{
    /*
     * We don't actually *do* anything here, except note the fact that we were
     * called.
     */
    trace_request(r, "x_map_to_storage()");
    return DECLINED;
}

/*
 * this routine gives our module another chance to examine the request
 * headers and to take special action. This is the first phase whose
 * hooks' configuration directives can appear inside the <Directory>
 * and similar sections, because at this stage the URI has been mapped
 * to the filename. For example this phase can be used to block evil
 * clients, while little resources were wasted on these.
 *
 * This is a RUN_ALL hook.
 */
static int x_header_parser(request_rec *r)
{
    /*
     * We don't actually *do* anything here, except note the fact that we were
     * called.
     */
    trace_request(r, "x_header_parser()");
    return DECLINED;
}


/*
 * This routine is called to check for any module-specific restrictions placed
 * upon the requested resource.  (See the mod_access_compat module for an
 * example.)
 *
 * This is a RUN_ALL hook. The first handler to return a status other than OK
 * or DECLINED (for instance, HTTP_FORBIDDEN) aborts the callback chain.
 */
static int x_check_access(request_rec *r)
{
    trace_request(r, "x_check_access()");
    return DECLINED;
}

/*
 * This routine is called to check the authentication information sent with
 * the request (such as looking up the user in a database and verifying that
 * the [encrypted] password sent matches the one in the database).
 *
 * This is a RUN_FIRST hook. The return value is OK, DECLINED, or some
 * HTTP_mumble error (typically HTTP_UNAUTHORIZED).
 */
static int x_check_authn(request_rec *r)
{
    /*
     * Don't do anything except log the call.
     */
    trace_request(r, "x_check_authn()");
    return DECLINED;
}

/*
 * This routine is called to check to see if the resource being requested
 * requires authorisation.
 *
 * This is a RUN_FIRST hook. The return value is OK, DECLINED, or
 * HTTP_mumble.  If we return OK, no other modules are called during this
 * phase.
 *
 * If *all* modules return DECLINED, the request is aborted with a server
 * error.
 */
static int x_check_authz(request_rec *r)
{
    /*
     * Log the call and return OK, or access will be denied (even though we
     * didn't actually do anything).
     */
    trace_request(r, "x_check_authz()");
    return DECLINED;
}

/*
 * This routine is called to determine and/or set the various document type
 * information bits, like Content-type (via r->content_type), language, et
 * cetera.
 *
 * This is a RUN_FIRST hook.
 */
static int x_type_checker(request_rec *r)
{
    /*
     * Log the call, but don't do anything else - and report truthfully that
     * we didn't do anything.
     */
    trace_request(r, "x_type_checker()");
    return DECLINED;
}

/*
 * This routine is called to perform any module-specific fixing of header
 * fields, et cetera.  It is invoked just before any content-handler.
 *
 * This is a RUN_ALL HOOK.
 */
static int x_fixups(request_rec *r)
{
    /*
     * Log the call and exit.
     */
    trace_request(r, "x_fixups()");
    return DECLINED;
}

/*
 * This routine is called to perform any module-specific logging activities
 * over and above the normal server things.
 *
 * This is a RUN_ALL hook.
 */
static int x_log_transaction(request_rec *r)
{
    trace_request(r, "x_log_transaction()");
    return DECLINED;
}

#ifdef HAVE_UNIX_SUEXEC

/*
 * This routine is called to find out under which user id to run suexec
 * Unless our module runs CGI programs, there is no reason for us to
 * mess with this information.
 *
 * This is a RUN_FIRST hook. The return value is a pointer to an
 * ap_unix_identity_t or NULL.
 */
static ap_unix_identity_t *x_get_suexec_identity(const request_rec *r)
{
    trace_request(r, "x_get_suexec_identity()");
    return NULL;
}
#endif

/*
 * This routine is called to create a connection. This hook is implemented
 * by the Apache core: there is no known reason a module should override
 * it.
 *
 * This is a RUN_FIRST hook.
 *
 * Return NULL to decline, a valid conn_rec pointer to accept.
 */
static conn_rec *x_create_connection(apr_pool_t *p, server_rec *server,
                                     apr_socket_t *csd, long conn_id,
                                     void *sbh, apr_bucket_alloc_t *alloc)
{
    trace_nocontext(p, __FILE__, __LINE__, "x_create_connection()");
    return NULL;
}

/*
 * This hook is defined in server/core.c, but it is not actually called
 * or documented.
 *
 * This is a RUN_ALL hook.
 */
static int x_get_mgmt_items(apr_pool_t *p, const char *val, apr_hash_t *ht)
{
    /* We have nothing to do here but trace the call, and no context
     * in which to trace it.
     */
    trace_nocontext(p, __FILE__, __LINE__, "x_check_config()");
    return DECLINED;
}

/*
 * This routine gets called shortly after the request_rec structure
 * is created. It provides the opportunity to manipulae the request
 * at a very early stage.
 *
 * This is a RUN_ALL hook.
 */
static int x_create_request(request_rec *r)
{
    /*
     * We have a request_rec, but it is not filled in enough to give
     * us a usable configuration. So, add a trace without context.
     */
    trace_nocontext( r->pool, __FILE__, __LINE__, "x_create_request()");
    return DECLINED;
}

/*
 * This routine gets called during the startup of the MPM.
 * No known existing module implements this hook.
 *
 * This is a RUN_ALL hook.
 */
static int x_pre_mpm(apr_pool_t *p, ap_scoreboard_e sb_type)
{
    trace_nocontext(p, __FILE__, __LINE__, "x_pre_mpm()");
    return DECLINED;
}

/*
 * This hook gets run periodically by a maintenance function inside
 * the MPM. Its exact purpose is unknown and undocumented at this time.
 *
 * This is a RUN_ALL hook.
 */
static int x_monitor(apr_pool_t *p, server_rec *s)
{
    trace_nocontext(p, __FILE__, __LINE__, "x_monitor()");
    return DECLINED;
}

/*--------------------------------------------------------------------------*/
/*                                                                          */
/* Which functions are responsible for which hooks in the server.           */
/*                                                                          */
/*--------------------------------------------------------------------------*/
/*
 * Each function our module provides to handle a particular hook is
 * specified here.  The functions are registered using
 * ap_hook_foo(name, predecessors, successors, position)
 * where foo is the name of the hook.
 *
 * The args are as follows:
 * name         -> the name of the function to call.
 * predecessors -> a list of modules whose calls to this hook must be
 *                 invoked before this module.
 * successors   -> a list of modules whose calls to this hook must be
 *                 invoked after this module.
 * position     -> The relative position of this module.  One of
 *                 APR_HOOK_FIRST, APR_HOOK_MIDDLE, or APR_HOOK_LAST.
 *                 Most modules will use APR_HOOK_MIDDLE.  If multiple
 *                 modules use the same relative position, Apache will
 *                 determine which to call first.
 *                 If your module relies on another module to run first,
 *                 or another module running after yours, use the
 *                 predecessors and/or successors.
 *
 * The number in brackets indicates the order in which the routine is called
 * during request processing.  Note that not all routines are necessarily
 * called (such as if a resource doesn't have access restrictions).
 * The actual delivery of content to the browser [9] is not handled by
 * a hook; see the handler declarations below.
 */
static void x_register_hooks(apr_pool_t *p)
{
    ap_hook_pre_config(x_pre_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_check_config(x_check_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_test_config(x_test_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_open_logs(x_open_logs, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_post_config(x_post_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_child_init(x_child_init, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_handler(x_handler, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_quick_handler(x_quick_handler, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_pre_connection(x_pre_connection, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_process_connection(x_process_connection, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_pre_read_request(x_pre_read_request, NULL, NULL,
                              APR_HOOK_MIDDLE);
    /* [1] post read_request handling */
    ap_hook_post_read_request(x_post_read_request, NULL, NULL,
                              APR_HOOK_MIDDLE);
    ap_hook_log_transaction(x_log_transaction, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_http_scheme(x_http_scheme, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_default_port(x_default_port, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_translate_name(x_translate_name, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_map_to_storage(x_map_to_storage, NULL,NULL, APR_HOOK_MIDDLE);
    ap_hook_header_parser(x_header_parser, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_fixups(x_fixups, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_type_checker(x_type_checker, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_check_access(x_check_access, NULL, NULL, APR_HOOK_MIDDLE,
                         AP_AUTH_INTERNAL_PER_CONF);
    ap_hook_check_authn(x_check_authn, NULL, NULL, APR_HOOK_MIDDLE,
                        AP_AUTH_INTERNAL_PER_CONF);
    ap_hook_check_authz(x_check_authz, NULL, NULL, APR_HOOK_MIDDLE,
                        AP_AUTH_INTERNAL_PER_CONF);
    ap_hook_insert_filter(x_insert_filter, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_insert_error_filter(x_insert_error_filter, NULL, NULL, APR_HOOK_MIDDLE);
#ifdef HAVE_UNIX_SUEXEC
    ap_hook_get_suexec_identity(x_get_suexec_identity, NULL, NULL, APR_HOOK_MIDDLE);
#endif
    ap_hook_create_connection(x_create_connection, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_get_mgmt_items(x_get_mgmt_items, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_create_request(x_create_request, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_pre_mpm(x_pre_mpm, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_monitor(x_monitor, NULL, NULL, APR_HOOK_MIDDLE);
}

/*--------------------------------------------------------------------------*/
/*                                                                          */
/* All of the routines have been declared now.  Here's the list of          */
/* directives specific to our module, and information about where they      */
/* may appear and how the command parser should pass them to us for         */
/* processing.  Note that care must be taken to ensure that there are NO    */
/* collisions of directive names between modules.                           */
/*                                                                          */
/*--------------------------------------------------------------------------*/
/*
 * List of directives specific to our module.
 */
static const command_rec x_cmds[] =
{
    AP_INIT_NO_ARGS(
        "Example",                          /* directive name */
        cmd_example,                        /* config action routine */
        NULL,                               /* argument to include in call */
        OR_OPTIONS,                         /* where available */
        "Example directive - no arguments"  /* directive description */
    ),
    {NULL}
};
/*--------------------------------------------------------------------------*/
/*                                                                          */
/* Finally, the list of callback routines and data structures that provide  */
/* the static hooks into our module from the other parts of the server.     */
/*                                                                          */
/*--------------------------------------------------------------------------*/
/*
 * Module definition for configuration.  If a particular callback is not
 * needed, replace its routine name below with the word NULL.
 */
AP_DECLARE_MODULE(example_hooks) =
{
    STANDARD20_MODULE_STUFF,
    x_create_dir_config,    /* per-directory config creator */
    x_merge_dir_config,     /* dir config merger */
    x_create_server_config, /* server config creator */
    x_merge_server_config,  /* server config merger */
    x_cmds,                 /* command table */
    x_register_hooks,       /* set up other request processing hooks */
};
