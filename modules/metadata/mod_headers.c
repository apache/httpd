/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000-2001 The Apache Software Foundation.  All rights
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
 * mod_headers.c: Add/append/remove HTTP response headers
 *     Written by Paul Sutton, paul@ukweb.com, 1 Oct 1996
 *
 * The Header directive can be used to add/replace/remove HTTP headers
 * within the response message.  The RequestHeader directive can be used
 * to add/replace/remove HTTP headers before a request message is processed.
 * Valid in both per-server and per-dir configurations.
 *
 * Syntax is:
 *
 *   Header action header value
 *   RequestHeader action header value
 *
 * Where action is one of:
 *     set    - set this header, replacing any old value
 *     add    - add this header, possible resulting in two or more
 *              headers with the same name
 *     append - append this text onto any existing header of this same
 *     unset  - remove this header
 *
 * Where action is unset, the third argument (value) should not be given.
 * The header name can include the colon, or not.
 *
 * The Header and RequestHeader directives can only be used where allowed
 * by the FileInfo override.
 *
 * When the request is processed, the header directives are processed in
 * this order: firstly, the main server, then the virtual server handling
 * this request (if any), then any <Directory> sections (working downwards 
 * from the root dir), then an <Location> sections (working down from 
 * shortest URL component), the any <File> sections. This order is
 * important if any 'set' or 'unset' actions are used. For example,
 * the following two directives have different effect if applied in
 * the reverse order:
 *
 *   Header append Author "John P. Doe"
 *   Header unset Author
 *
 * Examples:
 *
 *  To set the "Author" header, use
 *     Header add Author "John P. Doe"
 *
 *  To remove a header:
 *     Header unset Author
 *
 */

#include "apr.h"
#include "apr_strings.h"
#include "apr_buckets.h"

#define APR_WANT_STRFUNC
#include "apr_want.h"

#include "httpd.h"
#include "http_config.h"
#include "http_request.h"
#include "http_log.h"
#include "util_filter.h"

typedef enum {
    hdr_add = 'a',              /* add header (could mean multiple hdrs) */
    hdr_set = 's',              /* set (replace old value) */
    hdr_append = 'm',           /* append (merge into any old value) */
    hdr_unset = 'u',            /* unset header */
    hdr_echo = 'e'              /* echo headers from request to response */
} hdr_actions;

typedef enum {
    hdr_in = 0,                 /* RequestHeader */
    hdr_out = 1                 /* Header */
} hdr_inout;

typedef struct {
    hdr_actions action;
    char *header;
    const char *value;
    regex_t *regex;
} header_entry;

/* echo_do is used only with Header echo */
typedef struct {
    request_rec *r;
    header_entry *hdr;
} echo_do;

/*
 * headers_conf is our per-module configuration. This is used as both
 * a per-dir and per-server config
 */
typedef struct {
    apr_array_header_t *fixup_in;
    apr_array_header_t *fixup_out;
} headers_conf;

module AP_MODULE_DECLARE_DATA headers_module;

static void *create_headers_config(apr_pool_t *p, server_rec *s)
{
    headers_conf *conf = apr_pcalloc(p, sizeof(*conf));

    conf->fixup_in = apr_array_make(p, 2, sizeof(header_entry));
    conf->fixup_out = apr_array_make(p, 2, sizeof(header_entry));

    return conf;
}

static void *create_headers_dir_config(apr_pool_t *p, char *d)
{
    return create_headers_config(p, NULL);
}

static void *merge_headers_config(apr_pool_t *p, void *basev, void *overridesv)
{
    headers_conf *newconf = apr_pcalloc(p, sizeof(*newconf));
    headers_conf *base = basev;
    headers_conf *overrides = overridesv;

    newconf->fixup_in = apr_array_append(p, base->fixup_in, overrides->fixup_in);
    newconf->fixup_out = apr_array_append(p, base->fixup_out, overrides->fixup_out);

    return newconf;
}


/* handle RequestHeader and Header directive */
static const char *header_inout_cmd(hdr_inout inout, cmd_parms *cmd, void *indirconf,
                              const char *action, const char *inhdr,
                              const char *value)
{
    headers_conf *dirconf = indirconf;
    char *hdr = apr_pstrdup(cmd->pool, inhdr);
    header_entry *new;
    server_rec *s = cmd->server;
    headers_conf *serverconf = ap_get_module_config(s->module_config,
                                                    &headers_module);
    char *colon;

    if (cmd->path) {
        new = (header_entry *) apr_array_push((hdr_in == inout) ? dirconf->fixup_in : dirconf->fixup_out);
    }
    else {
        new = (header_entry *) apr_array_push((hdr_in == inout) ? serverconf->fixup_in : serverconf->fixup_out);
    }

    if (!strcasecmp(action, "set"))
        new->action = hdr_set;
    else if (!strcasecmp(action, "add"))
        new->action = hdr_add;
    else if (!strcasecmp(action, "append"))
        new->action = hdr_append;
    else if (!strcasecmp(action, "unset"))
        new->action = hdr_unset;
    else if (!strcasecmp(action, "echo"))
        new->action = hdr_echo;
    else
        return "first argument must be add, set, append, unset or echo.";

    if (new->action == hdr_unset) {
        if (value)
            return "header unset takes two arguments";
    }
    else if (new->action == hdr_echo) {
        regex_t *regex;
        if (value)
            return "Header echo takes two arguments";
        else if (inout != hdr_out)
            return "Header echo only valid on Header directive";
        else {
            regex = ap_pregcomp(cmd->pool, hdr, REG_EXTENDED | REG_NOSUB);
            if (regex == NULL) {
                return "Header echo regex could not be compiled";
            }
        }
        new->regex = regex;
    }
    else if (!value)
        return "header requires three arguments";

    if ((colon = strchr(hdr, ':')))
        *colon = '\0';

    new->header = hdr;
    new->value = value;

    return NULL;
}

/* handle Header directive */
static const char *header_cmd(cmd_parms *cmd, void *indirconf,
                              const char *action, const char *inhdr,
                              const char *value)
{
    return header_inout_cmd(hdr_out, cmd, indirconf, action, inhdr, value);
}

/* handle RequestHeader directive */
static const char *request_header_cmd(cmd_parms *cmd, void *indirconf,
                              const char *action, const char *inhdr,
                              const char *value)
{
    return header_inout_cmd(hdr_in, cmd, indirconf, action, inhdr, value);
}

static int echo_header(echo_do *v, const char *key, const char *val)
{
    /* If the input header (key) matches the regex, echo it intact to 
     * r->headers_out.
     */
    if (!ap_regexec(v->hdr->regex, key, 0, NULL, 0)) {
        apr_table_addn(v->r->headers_out, key, val);
    }
    
    return 0;
}

static void do_headers_fixup(request_rec *r, hdr_inout inout,
                             apr_array_header_t *fixup)
{
    int i;
    apr_table_t *headers = (hdr_in == inout) ? r->headers_in : r->headers_out;

    for (i = 0; i < fixup->nelts; ++i) {
        header_entry *hdr = &((header_entry *) (fixup->elts))[i];
        switch (hdr->action) {
        case hdr_add:
            apr_table_addn(headers, hdr->header, hdr->value);
            break;
        case hdr_append:
            apr_table_mergen(headers, hdr->header, hdr->value);
            break;
        case hdr_set:
            apr_table_setn(headers, hdr->header, hdr->value);
            break;
        case hdr_unset:
            apr_table_unset(headers, hdr->header);
            break;
        case hdr_echo:
        {
            echo_do v;
            v.r = r;
            v.hdr = hdr;
            apr_table_do((int (*) (void *, const char *, const char *)) 
                         echo_header, (void *) &v, r->headers_in, NULL);
            break;
        }
        }
    }
}

static void ap_headers_insert_output_filter(request_rec *r)
{
    headers_conf *serverconf = ap_get_module_config(r->server->module_config,
                                                    &headers_module);
    headers_conf *dirconf = ap_get_module_config(r->per_dir_config,
                                                 &headers_module);

    if (serverconf->fixup_out->nelts || dirconf->fixup_out->nelts) {
	ap_add_output_filter("FIXUP_HEADERS_OUT", NULL, r, r->connection);
    }
}

static apr_status_t ap_headers_output_filter(ap_filter_t *f,
                                             apr_bucket_brigade *in)
{
    headers_conf *serverconf = ap_get_module_config(f->r->server->module_config,
                                                    &headers_module);
    headers_conf *dirconf = ap_get_module_config(f->r->per_dir_config,
                                                 &headers_module);

    ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, f->r->server,
		 "headers: ap_headers_output_filter()");

    /* do the fixup */
    do_headers_fixup(f->r, hdr_out, serverconf->fixup_out);
    do_headers_fixup(f->r, hdr_out, dirconf->fixup_out);

    /* remove ourselves from the filter chain */
    ap_remove_output_filter(f);

    /* send the data up the stack */
    return ap_pass_brigade(f->next,in);
}

static apr_status_t ap_headers_fixup(request_rec *r)
{
    headers_conf *serverconf = ap_get_module_config(r->server->module_config,
                                                    &headers_module);
    headers_conf *dirconf = ap_get_module_config(r->per_dir_config,
                                                 &headers_module);

    /* do the fixup */
    if (serverconf->fixup_in->nelts || dirconf->fixup_in->nelts) {
        do_headers_fixup(r, hdr_in, serverconf->fixup_in);
        do_headers_fixup(r, hdr_in, dirconf->fixup_in);
    }

    return DECLINED;
}
                                        
static const command_rec headers_cmds[] =
{
    AP_INIT_TAKE23("Header", header_cmd, NULL, OR_FILEINFO,
                   "an action, header and value"),
    AP_INIT_TAKE23("RequestHeader", request_header_cmd, NULL, OR_FILEINFO,
                   "an action, header and value"),
    {NULL}
};

static void register_hooks(apr_pool_t *p)
{
    ap_hook_insert_filter(ap_headers_insert_output_filter, NULL, NULL, APR_HOOK_LAST);
    ap_hook_fixups(ap_headers_fixup, NULL, NULL, APR_HOOK_LAST);
    ap_register_output_filter("FIXUP_HEADERS_OUT", ap_headers_output_filter, AP_FTYPE_HTTP_HEADER);
}

module AP_MODULE_DECLARE_DATA headers_module =
{
    STANDARD20_MODULE_STUFF,
    create_headers_dir_config,  /* dir config creater */
    merge_headers_config,       /* dir merger --- default is to override */
    create_headers_config,      /* server config */
    merge_headers_config,       /* merge server configs */
    headers_cmds,               /* command apr_table_t */
    register_hooks		/* register hooks */
};
