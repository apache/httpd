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
 */

/* 
 * Apache example module.  Provide demonstrations of how modules do things.
 * It is not meant to be used in a production server.  Since it participates
 * in all of the processing phases, it could conceivable interfere with
 * the proper operation of other modules -- particularly the ones related
 * to security.
 *
 * In the interest of brevity, all functions and structures internal to
 * this module, but which may have counterparts in *real* modules, are
 * prefixed with 'x_' instead of 'example_'.
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
 * Let's set up a module-local static cell to point to the accreting callback
 * trace.  As each API callback is made to us, we'll tack on the particulars
 * to whatever we've already recorded.  To avoid massive memory bloat as
 * directories are walked again and again, we record the routine/environment
 * the first time (non-request context only), and ignore subsequent calls for
 * the same routine/environment.
 */
static const char *trace = NULL;
static apr_table_t *static_calls_made = NULL;

/*
 * To avoid leaking memory from pools other than the per-request one, we
 * allocate a module-private pool, and then use a sub-pool of that which gets
 * freed each time we modify the trace.  That way previous layers of trace
 * data don't get lost.
 */
static apr_pool_t *x_pool = NULL;
static apr_pool_t *x_subpool = NULL;

/*
 * Declare ourselves so the configuration routines can find and know us.
 * We'll fill it in at the end of the module.
 */
module AP_MODULE_DECLARE_DATA example_module;

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
    return (x_cfg *) ap_get_module_config(r->per_dir_config, &example_module);
}

#if 0
/*
 * Locate our server configuration record for the specified server.
 */
static x_cfg *our_sconfig(const server_rec *s)
{
    return (x_cfg *) ap_get_module_config(s->module_config, &example_module);
}

/*
 * Likewise for our configuration record for the specified request.
 */
static x_cfg *our_rconfig(const request_rec *r)
{
    return (x_cfg *) ap_get_module_config(r->request_config, &example_module);
}
#endif

/*
 * Likewise for our configuration record for a connection.
 */
static x_cfg *our_cconfig(const conn_rec *c)
{
    return (x_cfg *) ap_get_module_config(c->conn_config, &example_module);
}

/*
 * This routine sets up some module-wide cells if they haven't been already.
 */
static void setup_module_cells(void)
{
    /*
     * If we haven't already allocated our module-private pool, do so now.
     */
    if (x_pool == NULL) {
        apr_pool_create(&x_pool, NULL);
    };
    /*
     * Likewise for the table of routine/environment pairs we visit outside of
     * request context.
     */
    if (static_calls_made == NULL) {
        static_calls_made = apr_table_make(x_pool, 16);
    };
}

/*
 * This routine is used to add a trace of a callback to the list.  We're
 * passed the server record (if available), the request record (if available),
 * a pointer to our private configuration record (if available) for the
 * environment to which the callback is supposed to apply, and some text.  We
 * turn this into a textual representation and add it to the tail of the list.
 * The list can be displayed by the x_handler() routine.
 *
 * If the call occurs within a request context (i.e., we're passed a request
 * record), we put the trace into the request apr_pool_t and attach it to the
 * request via the notes mechanism.  Otherwise, the trace gets added
 * to the static (non-request-specific) list.
 *
 * Note that the r->notes table is only for storing strings; if you need to
 * maintain per-request data of any other type, you need to use another
 * mechanism.
 */

#define TRACE_NOTE "example-trace"

static void trace_add(server_rec *s, request_rec *r, x_cfg *mconfig,
                      const char *note)
{
    const char *sofar;
    char *addon;
    char *where;
    apr_pool_t *p;
    const char *trace_copy;

    /*
     * Make sure our pools and tables are set up - we need 'em.
     */
    setup_module_cells();
    /*
     * Now, if we're in request-context, we use the request pool.
     */
    if (r != NULL) {
        p = r->pool;
        if ((trace_copy = apr_table_get(r->notes, TRACE_NOTE)) == NULL) {
            trace_copy = "";
        }
    }
    else {
        /*
         * We're not in request context, so the trace gets attached to our
         * module-wide pool.  We do the create/destroy every time we're called
         * in non-request context; this avoids leaking memory in some of
         * the subsequent calls that allocate memory only once (such as the
         * key formation below).
         *
         * Make a new sub-pool and copy any existing trace to it.  Point the
         * trace cell at the copied value.
         */
        apr_pool_create(&p, x_pool);
        if (trace != NULL) {
            trace = apr_pstrdup(p, trace);
        }
        /*
         * Now, if we have a sub-pool from before, nuke it and replace with
         * the one we just allocated.
         */
        if (x_subpool != NULL) {
            apr_pool_destroy(x_subpool);
        }
        x_subpool = p;
        trace_copy = trace;
    }
    /*
     * If we weren't passed a configuration record, we can't figure out to
     * what location this call applies.  This only happens for co-routines
     * that don't operate in a particular directory or server context.  If we
     * got a valid record, extract the location (directory or server) to which
     * it applies.
     */
    where = (mconfig != NULL) ? mconfig->loc : "nowhere";
    where = (where != NULL) ? where : "";
    /*
     * Now, if we're not in request context, see if we've been called with
     * this particular combination before.  The apr_table_t is allocated in the
     * module's private pool, which doesn't get destroyed.
     */
    if (r == NULL) {
        char *key;

        key = apr_pstrcat(p, note, ":", where, NULL);
        if (apr_table_get(static_calls_made, key) != NULL) {
            /*
             * Been here, done this.
             */
            return;
        }
        else {
            /*
             * First time for this combination of routine and environment -
             * log it so we don't do it again.
             */
            apr_table_set(static_calls_made, key, "been here");
        }
    }
    addon = apr_pstrcat(p,
                        "   <li>\n"
                        "    <dl>\n"
                        "     <dt><samp>", note, "</samp></dt>\n"
                        "     <dd><samp>[", where, "]</samp></dd>\n"
                        "    </dl>\n"
                        "   </li>\n",
                        NULL);
    sofar = (trace_copy == NULL) ? "" : trace_copy;
    trace_copy = apr_pstrcat(p, sofar, addon, NULL);
    if (r != NULL) {
        apr_table_set(r->notes, TRACE_NOTE, trace_copy);
    }
    else {
        trace = trace_copy;
    }
    /*
     * You *could* change the following if you wanted to see the calling
     * sequence reported in the server's error_log, but beware - almost all of
     * these co-routines are called for every single request, and the impact
     * on the size (and readability) of the error_log is considerable.
     */
#define EXAMPLE_LOG_EACH 0
    if (EXAMPLE_LOG_EACH && (s != NULL)) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, "mod_example: %s", note);
    }
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
    trace_add(cmd->server, NULL, cfg, "cmd_example()");
    return NULL;
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
 * The return value instructs the caller concerning what happened and what to
 * do next:
 *  OK ("we did our thing")
 *  DECLINED ("this isn't something with which we want to get involved")
 *  HTTP_mumble ("an error status should be reported")
 */
static int x_handler(request_rec *r)
{
    x_cfg *dcfg;

    if (strcmp(r->handler, "example-handler")) {
        return DECLINED;
    }

    dcfg = our_dconfig(r);
    trace_add(r->server, r, dcfg, "x_handler()");
    /*
     * We're about to start sending content, so we need to force the HTTP
     * headers to be sent at this point.  Otherwise, no headers will be sent
     * at all.  We can set any we like first, of course.  **NOTE** Here's
     * where you set the "Content-type" header, and you do so by putting it in
     * r->content_type, *not* r->headers_out("Content-type").  If you don't
     * set it, it will be filled in with the server's default type (typically
     * "text/plain").  You *must* also ensure that r->content_type is lower
     * case.
     *
     * We also need to start a timer so the server can know if the connexion
     * is broken.
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
    ap_rputs("  <TITLE>mod_example Module Content-Handler Output\n", r);
    ap_rputs("  </TITLE>\n", r);
    ap_rputs(" </HEAD>\n", r);
    ap_rputs(" <BODY>\n", r);
    ap_rputs("  <H1><SAMP>mod_example</SAMP> Module Content-Handler Output\n", r);
    ap_rputs("  </H1>\n", r);
    ap_rputs("  <P>\n", r);
    ap_rprintf(r, "  Apache HTTP Server version: \"%s\"\n",
	    ap_get_server_version());
    ap_rputs("  <BR>\n", r);
    ap_rprintf(r, "  Server built: \"%s\"\n", ap_get_server_built());
    ap_rputs("  </P>\n", r);;
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
    ap_rprintf(r, "  <H2>Static callbacks so far:</H2>\n  <OL>\n%s  </OL>\n",
            trace);
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

/*--------------------------------------------------------------------------*/
/*                                                                          */
/* Now let's declare routines for each of the callback phase in order.      */
/* (That's the order in which they're listed in the callback list, *not     */
/* the order in which the server calls them!  See the command_rec           */
/* declaration near the bottom of this file.)  Note that these may be       */
/* called for situations that don't relate primarily to our function - in   */
/* other words, the fixup handler shouldn't assume that the request has     */
/* to do with "example" stuff.                                              */
/*                                                                          */
/* With the exception of the content handler, all of our routines will be   */
/* called for each request, unless an earlier handler from another module   */
/* aborted the sequence.                                                    */
/*                                                                          */
/* Handlers that are declared as "int" can return the following:            */
/*                                                                          */
/*  OK          Handler accepted the request and did its thing with it.     */
/*  DECLINED    Handler took no action.                                     */
/*  HTTP_mumble Handler looked at request and found it wanting.             */
/*                                                                          */
/* What the server does after calling a module handler depends upon the     */
/* handler's return value.  In all cases, if the handler returns            */
/* DECLINED, the server will continue to the next module with an handler    */
/* for the current phase.  However, if the handler return a non-OK,         */
/* non-DECLINED status, the server aborts the request right there.  If      */
/* the handler returns OK, the server's next action is phase-specific;      */
/* see the individual handler comments below for details.                   */
/*                                                                          */
/*--------------------------------------------------------------------------*/
/* 
 * This function is called during server initialisation.  Any information
 * that needs to be recorded must be in static cells, since there's no
 * configuration record.
 *
 * There is no return value.
 */

/* 
 * This function is called when an heavy-weight process (such as a child) is
 * being run down or destroyed.  As with the child initialisation function,
 * any information that needs to be recorded must be in static cells, since
 * there's no configuration record.
 *
 * There is no return value.
 */

/* 
 * This function is called during server initialisation when an heavy-weight
 * process (such as a child) is being initialised.  As with the
 * module initialisation function, any information that needs to be recorded
 * must be in static cells, since there's no configuration record.
 *
 * There is no return value.
 */

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
    trace_add(NULL, NULL, cfg, "x_create_dir_config()");
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
    note = apr_pstrcat(p, "x_merge_dir_config(\"", pconf->loc, "\",\"",
                   nconf->loc, "\")", NULL);
    trace_add(NULL, NULL, merged_config, note);
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
    trace_add(s, NULL, cfg, "x_create_server_config()");
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
    trace_add(NULL, NULL, merged_config, note);
    return (void *) merged_config;
}

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
    trace_add(NULL, NULL, NULL, "x_pre_config()");

    return OK;
}

/*
 * This routine is called to perform any module-specific fixing of header
 * fields, et cetera.  It is invoked just before any content-handler.
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
    trace_add(NULL, NULL, NULL, "x_post_config()");
    return OK;
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
    trace_add(s, NULL, NULL, "x_open_logs()");
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
    trace_add(s, NULL, NULL, note);
    return APR_SUCCESS;
}

/*
 * All our process initialiser does is add its trace to the log.
 */
static void x_child_init(apr_pool_t *p, server_rec *s)
{
    char *note;
    char *sname = s->server_hostname;

    /*
     * Set up any module cells that ought to be initialised.
     */
    setup_module_cells();
    /*
     * The arbitrary text we add to our trace entry indicates for which server
     * we're being called.
     */
    sname = (sname != NULL) ? sname : "";
    note = apr_pstrcat(p, "x_child_init(", sname, ")", NULL);
    trace_add(s, NULL, NULL, note);

    apr_pool_cleanup_register(p, s, x_child_exit, x_child_exit);
}

/*
 * XXX: This routine is called XXX
 *
 * The return value is OK, DECLINED, or HTTP_mumble.  If we return OK, the
 * server will still call any remaining modules with an handler for this
 * phase.
 */
#if 0
static const char *x_http_method(const request_rec *r)
{
    x_cfg *cfg;

    cfg = our_dconfig(r);
    /*
     * Log the call and exit.
     */
    trace_add(r->server, NULL, cfg, "x_http_method()");
    return "foo";
}

/*
 * XXX: This routine is called XXX
 *
 * The return value is OK, DECLINED, or HTTP_mumble.  If we return OK, the
 * server will still call any remaining modules with an handler for this
 * phase.
 */
static apr_port_t x_default_port(const request_rec *r)
{
    x_cfg *cfg;

    cfg = our_dconfig(r);
    /*
     * Log the call and exit.
     */
    trace_add(r->server, NULL, cfg, "x_default_port()");
    return 80;
}
#endif /*0*/

/*
 * XXX: This routine is called XXX
 *
 * The return value is OK, DECLINED, or HTTP_mumble.  If we return OK, the
 * server will still call any remaining modules with an handler for this
 * phase.
 */
static void x_insert_filter(request_rec *r)
{
    x_cfg *cfg;

    cfg = our_dconfig(r);
    /*
     * Log the call and exit.
     */
    trace_add(r->server, NULL, cfg, "x_insert_filter()");
}

/*
 * XXX: This routine is called XXX
 *
 * The return value is OK, DECLINED, or HTTP_mumble.  If we return OK, the
 * server will still call any remaining modules with an handler for this
 * phase.
 */
static int x_quick_handler(request_rec *r, int lookup_uri)
{
    x_cfg *cfg;

    cfg = our_dconfig(r);
    /*
     * Log the call and exit.
     */
    trace_add(r->server, NULL, cfg, "x_post_config()");
    return DECLINED;
}

/*
 * This routine is called just after the server accepts the connection,
 * but before it is handed off to a protocol module to be served.  The point
 * of this hook is to allow modules an opportunity to modify the connection
 * as soon as possible. The core server uses this phase to setup the
 * connection record based on the type of connection that is being used.
 *
 * The return value is OK, DECLINED, or HTTP_mumble.  If we return OK, the
 * server will still call any remaining modules with an handler for this
 * phase.
 */
static int x_pre_connection(conn_rec *c, void *csd)
{
    x_cfg *cfg;

    cfg = our_cconfig(c);
#if 0
    /*
     * Log the call and exit.
     */
    trace_add(r->server, NULL, cfg, "x_post_config()");
#endif
    return OK;
}

/* This routine is used to actually process the connection that was received.
 * Only protocol modules should implement this hook, as it gives them an
 * opportunity to replace the standard HTTP processing with processing for
 * some other protocol.  Both echo and POP3 modules are available as
 * examples.
 *
 * The return VALUE is OK, DECLINED, or HTTP_mumble.  If we return OK, no 
 * further modules are called for this phase.
 */
static int x_process_connection(conn_rec *c)
{
    return DECLINED;
}

/*
 * This routine is called after the request has been read but before any other
 * phases have been processed.  This allows us to make decisions based upon
 * the input header fields.
 *
 * The return value is OK, DECLINED, or HTTP_mumble.  If we return OK, no
 * further modules are called for this phase.
 */
static int x_post_read_request(request_rec *r)
{
    x_cfg *cfg;

    cfg = our_dconfig(r);
    /*
     * We don't actually *do* anything here, except note the fact that we were
     * called.
     */
    trace_add(r->server, r, cfg, "x_post_read_request()");
    return DECLINED;
}

/*
 * This routine gives our module an opportunity to translate the URI into an
 * actual filename.  If we don't do anything special, the server's default
 * rules (Alias directives and the like) will continue to be followed.
 *
 * The return value is OK, DECLINED, or HTTP_mumble.  If we return OK, no
 * further modules are called for this phase.
 */
static int x_translate_handler(request_rec *r)
{

    x_cfg *cfg;

    cfg = our_dconfig(r);
    /*
     * We don't actually *do* anything here, except note the fact that we were
     * called.
     */
    trace_add(r->server, r, cfg, "x_translate_handler()");
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
 * The return value is OK, DECLINED, or HTTP_mumble.  If we return OK,
 * the server will still call any remaining modules with an handler
 * for this phase.
 */
static int x_header_parser_handler(request_rec *r)
{

    x_cfg *cfg;

    cfg = our_dconfig(r);
    /*
     * We don't actually *do* anything here, except note the fact that we were
     * called.
     */
    trace_add(r->server, r, cfg, "header_parser_handler()");
    return DECLINED;
}


/*
 * This routine is called to check the authentication information sent with
 * the request (such as looking up the user in a database and verifying that
 * the [encrypted] password sent matches the one in the database).
 *
 * The return value is OK, DECLINED, or some HTTP_mumble error (typically
 * HTTP_UNAUTHORIZED).  If we return OK, no other modules are given a chance
 * at the request during this phase.
 */
static int x_check_user_id(request_rec *r)
{

    x_cfg *cfg;

    cfg = our_dconfig(r);
    /*
     * Don't do anything except log the call.
     */
    trace_add(r->server, r, cfg, "x_check_user_id()");
    return DECLINED;
}

/*
 * This routine is called to check to see if the resource being requested
 * requires authorisation.
 *
 * The return value is OK, DECLINED, or HTTP_mumble.  If we return OK, no
 * other modules are called during this phase.
 *
 * If *all* modules return DECLINED, the request is aborted with a server
 * error.
 */
static int x_auth_checker(request_rec *r)
{

    x_cfg *cfg;

    cfg = our_dconfig(r);
    /*
     * Log the call and return OK, or access will be denied (even though we
     * didn't actually do anything).
     */
    trace_add(r->server, r, cfg, "x_auth_checker()");
    return DECLINED;
}

/*
 * This routine is called to check for any module-specific restrictions placed
 * upon the requested resource.  (See the mod_access module for an example.)
 *
 * The return value is OK, DECLINED, or HTTP_mumble.  All modules with an
 * handler for this phase are called regardless of whether their predecessors
 * return OK or DECLINED.  The first one to return any other status, however,
 * will abort the sequence (and the request) as usual.
 */
static int x_access_checker(request_rec *r)
{

    x_cfg *cfg;

    cfg = our_dconfig(r);
    trace_add(r->server, r, cfg, "x_access_checker()");
    return DECLINED;
}

/*
 * This routine is called to determine and/or set the various document type
 * information bits, like Content-type (via r->content_type), language, et
 * cetera.
 *
 * The return value is OK, DECLINED, or HTTP_mumble.  If we return OK, no
 * further modules are given a chance at the request for this phase.
 */
static int x_type_checker(request_rec *r)
{

    x_cfg *cfg;

    cfg = our_dconfig(r);
    /*
     * Log the call, but don't do anything else - and report truthfully that
     * we didn't do anything.
     */
    trace_add(r->server, r, cfg, "x_type_checker()");
    return DECLINED;
}

/*
 * This routine is called to perform any module-specific fixing of header
 * fields, et cetera.  It is invoked just before any content-handler.
 *
 * The return value is OK, DECLINED, or HTTP_mumble.  If we return OK, the
 * server will still call any remaining modules with an handler for this
 * phase.
 */
static int x_fixer_upper(request_rec *r)
{

    x_cfg *cfg;

    cfg = our_dconfig(r);
    /*
     * Log the call and exit.
     */
    trace_add(r->server, r, cfg, "x_fixer_upper()");
    return OK;
}

/*
 * This routine is called to perform any module-specific logging activities
 * over and above the normal server things.
 *
 * The return value is OK, DECLINED, or HTTP_mumble.  If we return OK, any
 * remaining modules with an handler for this phase will still be called.
 */
static int x_logger(request_rec *r)
{

    x_cfg *cfg;

    cfg = our_dconfig(r);
    trace_add(r->server, r, cfg, "x_logger()");
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
    ap_hook_post_config(x_post_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_open_logs(x_open_logs, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_child_init(x_child_init, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_handler(x_handler, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_quick_handler(x_quick_handler, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_pre_connection(x_pre_connection, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_process_connection(x_process_connection, NULL, NULL, APR_HOOK_MIDDLE);
    /* [1] post read_request handling */
    ap_hook_post_read_request(x_post_read_request, NULL, NULL,
                              APR_HOOK_MIDDLE);
    ap_hook_log_transaction(x_logger, NULL, NULL, APR_HOOK_MIDDLE);
#if 0
    ap_hook_http_method(x_http_method, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_default_port(x_default_port, NULL, NULL, APR_HOOK_MIDDLE);
#endif
    ap_hook_translate_name(x_translate_handler, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_header_parser(x_header_parser_handler, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_check_user_id(x_check_user_id, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_fixups(x_fixer_upper, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_type_checker(x_type_checker, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_access_checker(x_access_checker, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_auth_checker(x_auth_checker, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_insert_filter(x_insert_filter, NULL, NULL, APR_HOOK_MIDDLE);
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
module AP_MODULE_DECLARE_DATA example_module =
{
    STANDARD20_MODULE_STUFF,
    x_create_dir_config,    /* per-directory config creator */
    x_merge_dir_config,     /* dir config merger */
    x_create_server_config, /* server config creator */
    x_merge_server_config,  /* server config merger */
    x_cmds,                 /* command table */
    x_register_hooks,       /* set up other request processing hooks */
};
