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
#include "apr_lib.h"
#include "apr_strings.h"
#include "apr_buckets.h"

#include "apr_hash.h"
#define APR_WANT_STRFUNC
#include "apr_want.h"

#include "httpd.h"
#include "http_config.h"
#include "http_request.h"
#include "http_log.h"
#include "util_filter.h"
#include "http_protocol.h"

/* format_tag_hash is initialized during pre-config */
static apr_hash_t *format_tag_hash;

typedef enum {
    hdr_add = 'a',              /* add header (could mean multiple hdrs) */
    hdr_set = 's',              /* set (replace old value) */
    hdr_append = 'm',           /* append (merge into any old value) */
    hdr_unset = 'u',            /* unset header */
    hdr_echo = 'e'              /* echo headers from request to response */
} hdr_actions;

typedef enum {
    hdr_in = 0,                 /* RequestHeader */
    hdr_out = 1,                /* Header */
    hdr_err = 2                 /* ErrorHeader */
} hdr_inout;

/*
 * There is an array of struct format_tag per Header/RequestHeader 
 * config directive
 */
typedef struct {
    const char* (*func)(request_rec *r,char *arg);
    char *arg;
} format_tag;

/*
 * There is one "header_entry" per Header/RequestHeader config directive
 */
typedef struct {
    hdr_actions action;
    char *header;
    apr_array_header_t *ta;   /* Array of format_tag structs */
    regex_t *regex;
    const char *condition_var;
} header_entry;

/* echo_do is used for Header echo to iterate through the request headers*/
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
    apr_array_header_t *fixup_err;
} headers_conf;

module AP_MODULE_DECLARE_DATA headers_module;

/*
 * Tag formatting functions
 */
static const char *constant_item(request_rec *r, char *stuff)
{
    return stuff;
}
static const char *header_request_duration(request_rec *r, char *a)
{
    return apr_psprintf(r->pool, "D=%" APR_TIME_T_FMT, 
                        (apr_time_now() - r->request_time)); 
}
static const char *header_request_time(request_rec *r, char *a)
{
    return apr_psprintf(r->pool, "t=%" APR_TIME_T_FMT, r->request_time);
}
static const char *header_request_env_var(request_rec *r, char *a)
{
    const char *s = apr_table_get(r->subprocess_env,a);

    if (s)
        return s;
    else
        return "(null)";
}
/*
 * Config routines
 */
static void *create_headers_config(apr_pool_t *p, server_rec *s)
{
    headers_conf *conf = apr_pcalloc(p, sizeof(*conf));

    conf->fixup_in = apr_array_make(p, 2, sizeof(header_entry));
    conf->fixup_out = apr_array_make(p, 2, sizeof(header_entry));
    conf->fixup_err = apr_array_make(p, 2, sizeof(header_entry));

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
    newconf->fixup_err = apr_array_append(p, base->fixup_err,
                                          overrides->fixup_err);

    return newconf;
}
 
static char *parse_misc_string(apr_pool_t *p, format_tag *tag, const char **sa)
{
    const char *s;
    char *d;

    tag->func = constant_item;

    s = *sa;
    while (*s && *s != '%') {
        s++;
    }
    /*
     * This might allocate a few chars extra if there's a backslash
     * escape in the format string.
     */
    tag->arg = apr_palloc(p, s - *sa + 1);

    d = tag->arg;
    s = *sa;
    while (*s && *s != '%') {
        if (*s != '\\') {
            *d++ = *s++;
        }
        else {
            s++;
            switch (*s) {
            case '\\':
                *d++ = '\\';
                s++;
                break;
            case 'r':
                *d++ = '\r';
                s++;
                break;
            case 'n':
                *d++ = '\n';
                s++;
                break;
            case 't':	
                *d++ = '\t';
                s++;
                break;
            default:
                /* copy verbatim */
                *d++ = '\\';
                /*
                 * Allow the loop to deal with this *s in the normal
                 * fashion so that it handles end of string etc.
                 * properly.
                 */
                break;
            }
        }
    }
    *d = '\0';

    *sa = s;
    return NULL;
}

static char *parse_format_tag(apr_pool_t *p, format_tag *tag, const char **sa)
{ 
    const char *s = *sa;
    const char * (*tag_handler)(request_rec *,char *);

    /* Handle string literal/conditionals */
    if (*s != '%') {
        return parse_misc_string(p, tag, sa);
    }
    s++; /* skip the % */
    tag->arg = '\0';
    /* grab the argument if there is one */
    if (*s == '{') {
        ++s;
        tag->arg = ap_getword(p,&s,'}');
    }

    tag_handler = (const char * (*)(request_rec *,char *))apr_hash_get(format_tag_hash, s++, 1);

    if (!tag_handler) {
        char dummy[2];
        dummy[0] = s[-1];
        dummy[1] = '\0';
        return apr_pstrcat(p, "Unrecognized Header or RequestHeader directive %",
                           dummy, NULL);
    }
    tag->func = tag_handler;

    *sa = s;
    return NULL;
}

/*
 * A format string consists of white space, text and optional format 
 * tags in any order. E.g., 
 *
 * Header add MyHeader "Free form text %D %t more text"
 *
 * Decompose the format string into its tags. Each tag (struct format_tag)
 * contains a pointer to the function used to format the tag. Then save each 
 * tag in the tag array anchored in the header_entry.
 */
static char *parse_format_string(apr_pool_t *p, header_entry *hdr, const char *s)
{
    char *res;

    /* No string to parse with unset and copy commands */
    if (hdr->action == hdr_unset ||
        hdr->action == hdr_echo) {
        return NULL;
    }

    hdr->ta = apr_array_make(p, 10, sizeof(format_tag));

    while (*s) {
        if ((res = parse_format_tag(p, (format_tag *) apr_array_push(hdr->ta), &s))) {
            return res;
        }
    }
    return NULL;
}

/* handle RequestHeader and Header directive */
static const char *header_inout_cmd(hdr_inout inout, cmd_parms *cmd,
                                    void *indirconf,
                                    const char *action, const char *inhdr,
                                    const char *value, const char* envclause)
{
    headers_conf *dirconf = indirconf;
    const char *condition_var = NULL;
    char *colon;
    char *hdr = apr_pstrdup(cmd->pool, inhdr);
    header_entry *new;
    server_rec *s = cmd->server;
    headers_conf *serverconf = ap_get_module_config(s->module_config,
                                                    &headers_module);
    apr_array_header_t *fixup = dirconf->fixup_out;

    switch (inout) {
    case hdr_in:
        fixup = (cmd->path != NULL)
            ? dirconf->fixup_in
            : serverconf->fixup_in;
        break;
    case hdr_out:
        fixup = (cmd->path != NULL)
            ? dirconf->fixup_out
            : serverconf->fixup_out;
        break;
    case hdr_err:
        fixup = (cmd->path != NULL)
            ? dirconf->fixup_err
            : serverconf->fixup_err;
        break;
    }

    if (cmd->path) {
        new = (header_entry *) apr_array_push(fixup);
    }
    else {
        new = (header_entry *) apr_array_push(fixup);
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

    /* Handle the envclause on Header */
    if (envclause != NULL) {
        if (inout == hdr_in) {
            return "error: envclause (env=...) only valid on "
                "Header and ErrorHeader directives";
        }
        if (strncasecmp(envclause, "env=", 4) != 0) {
            return "error: envclause should be in the form env=envar";
        }
        if ((envclause[4] == '\0')
            || ((envclause[4] == '!') && (envclause[5] == '\0'))) {
            return "error: missing environment variable name. "
                "envclause should be in the form env=envar ";
        }
        condition_var = apr_pstrdup(cmd->pool, &envclause[4]);
    }
    
    if ((colon = strchr(hdr, ':')))
        *colon = '\0';

    new->header = hdr;
    new->condition_var = condition_var;

    return parse_format_string(cmd->pool, new, value);
}

/* Handle Header directive */
static const char *header_cmd(cmd_parms *cmd, void *indirconf,
                              const char *args)
{
    const char *s;
    const char *action;
    const char *hdr;
    const char *val;
    const char *envclause;
    hdr_inout outbl;

    s = apr_pstrdup(cmd->pool, args);
    action = ap_getword_conf(cmd->pool, &s);
    hdr = ap_getword_conf(cmd->pool, &s);
    val = *s ? ap_getword_conf(cmd->pool, &s) : NULL;
    envclause = *s ? ap_getword_conf(cmd->pool, &s) : NULL;
    outbl = (cmd->info == NULL) ? hdr_out : hdr_err;

    return header_inout_cmd(outbl, cmd, indirconf, action, hdr, val, envclause);
}

/* handle RequestHeader directive */
static const char *request_header_cmd(cmd_parms *cmd, void *indirconf,
                              const char *action, const char *inhdr,
                              const char *value)
{
    return header_inout_cmd(hdr_in, cmd, indirconf, action, inhdr, value, NULL);
}

/*
 * Process the tags in the format string. Tags may be format specifiers 
 * (%D, %t, etc.), whitespace or text strings. For each tag, run the handler
 * (formatter) specific to the tag. Handlers return text strings.
 * Concatenate the return from each handler into one string that is 
 * returned from this call.
 */
static char* process_tags(header_entry *hdr, request_rec *r) 
{
    int i;
    const char *s;
    char *str = NULL;

    format_tag *tag = (format_tag*) hdr->ta->elts;
 
    for (i = 0; i < hdr->ta->nelts; i++) {
        s = tag[i].func(r, tag[i].arg);
        if (str == NULL) 
            str = apr_pstrdup(r->pool, s);
        else
            str = apr_pstrcat(r->pool, str, s, NULL);
    }
    return str;
}

static int echo_header(echo_do *v, const char *key, const char *val)
{
    /* If the input header (key) matches the regex, echo it intact to 
     * r->headers_out.
     */
    if (!ap_regexec(v->hdr->regex, key, 0, NULL, 0)) {
        apr_table_add(v->r->headers_out, key, val);
    }

    return 1;
}

static void do_headers_fixup(request_rec *r, hdr_inout inout,
                             apr_array_header_t *fixup)
{
    int i;
    apr_table_t *headers = r->headers_out;

    switch (inout) {
    case hdr_in:
        headers = r->headers_in;
        break;
    case hdr_out:
        headers = r->headers_out;
        break;
    case hdr_err:
        headers = r->err_headers_out;
        break;
    }

    for (i = 0; i < fixup->nelts; ++i) {
        header_entry *hdr = &((header_entry *) (fixup->elts))[i];

        /* Have any conditional envar-controlled Header processing to do? */
        if (hdr->condition_var) {
            const char *envar = hdr->condition_var;
            if (*envar != '!') {
                if (apr_table_get(r->subprocess_env, envar) == NULL)
                    continue;
            }
            else {
                if (apr_table_get(r->subprocess_env, &envar[1]) != NULL)
                    continue;
            }
        }

        switch (hdr->action) {
        case hdr_add:
            apr_table_addn(headers, hdr->header, process_tags(hdr, r));
            break;
        case hdr_append:
            apr_table_mergen(headers, hdr->header, process_tags(hdr, r));
            break;
        case hdr_set:
            apr_table_setn(headers, hdr->header, process_tags(hdr, r));
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

    if (serverconf->fixup_out->nelts || dirconf->fixup_out->nelts
        || serverconf->fixup_err->nelts || dirconf->fixup_err->nelts) {
        ap_add_output_filter("FIXUP_HEADERS_OUT", NULL, r, r->connection);
    }
}

/*
 * Make sure our error-path filter is in place.
 */
static void ap_headers_insert_error_filter(request_rec *r)
{
    headers_conf *serverconf = ap_get_module_config(r->server->module_config,
                                                    &headers_module);
    headers_conf *dirconf = ap_get_module_config(r->per_dir_config,
                                                 &headers_module);

    if (serverconf->fixup_err->nelts || dirconf->fixup_err->nelts) {
        ap_add_output_filter("FIXUP_HEADERS_ERR", NULL, r, r->connection);
    }
}

static apr_status_t ap_headers_output_filter(ap_filter_t *f,
                                             apr_bucket_brigade *in)
{
    headers_conf *serverconf = ap_get_module_config(f->r->server->module_config,
                                                    &headers_module);
    headers_conf *dirconf = ap_get_module_config(f->r->per_dir_config,
                                                 &headers_module);

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, f->r->server,
                 "headers: ap_headers_output_filter()");

    /* do the fixup */
    do_headers_fixup(f->r, hdr_err, serverconf->fixup_err);
    do_headers_fixup(f->r, hdr_out, serverconf->fixup_out);
    do_headers_fixup(f->r, hdr_err, dirconf->fixup_err);
    do_headers_fixup(f->r, hdr_out, dirconf->fixup_out);

    /* remove ourselves from the filter chain */
    ap_remove_output_filter(f);

    /* send the data up the stack */
    return ap_pass_brigade(f->next,in);
}

/*
 * Make sure we propagate any ErrorHeader settings on the error
 * path through http_protocol.c.
 */
static apr_status_t ap_headers_error_filter(ap_filter_t *f,
                                            apr_bucket_brigade *in)
{
    headers_conf *serverconf;
    headers_conf *dirconf;

    serverconf = ap_get_module_config(f->r->server->module_config,
                                      &headers_module);
    dirconf = ap_get_module_config(f->r->per_dir_config,
                                    &headers_module);
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, f->r->server,
                 "headers: ap_headers_error_filter()");

    /*
     * Add any header fields defined by ErrorHeader to r->err_headers_out.
     * Server-wide first, then per-directory to allow overriding.
     */
    do_headers_fixup(f->r, hdr_err, serverconf->fixup_err);
    do_headers_fixup(f->r, hdr_err, dirconf->fixup_err);

    /*
     * We've done our bit; remove ourself from the filter chain so there's
     * no possibility we'll be called again.
     */
    ap_remove_output_filter(f);

    /*
     * Pass the buck.  (euro?)
     */
    return ap_pass_brigade(f->next, in);
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
    AP_INIT_RAW_ARGS("Header", header_cmd, NULL, OR_FILEINFO,
                   "an action, header and value followed by optional env clause"),
    AP_INIT_RAW_ARGS("ErrorHeader", header_cmd, "", OR_FILEINFO,
                     "an action, header and value "
                     "followed by optional env clause"),
    AP_INIT_TAKE23("RequestHeader", request_header_cmd, NULL, OR_FILEINFO,
                   "an action, header and value"),
    {NULL}
};

static void register_format_tag_handler(apr_pool_t *p, char *tag, void *tag_handler, int def)
{
    const void *h = apr_palloc(p, sizeof(h));
    h = tag_handler;
    apr_hash_set(format_tag_hash, tag, 1, h);
}
static int header_pre_config(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp)
{
    format_tag_hash = apr_hash_make(p);
    register_format_tag_handler(p, "D", (void*) header_request_duration, 0);
    register_format_tag_handler(p, "t", (void*) header_request_time, 0);
    register_format_tag_handler(p, "e", (void*) header_request_env_var, 0);

    return OK;
}

static void register_hooks(apr_pool_t *p)
{
    ap_register_output_filter("FIXUP_HEADERS_OUT", ap_headers_output_filter,
                              NULL, AP_FTYPE_CONTENT_SET);
    ap_register_output_filter("FIXUP_HEADERS_ERR", ap_headers_error_filter,
                              NULL, AP_FTYPE_CONTENT_SET);
    ap_hook_pre_config(header_pre_config,NULL,NULL,APR_HOOK_MIDDLE);
    ap_hook_insert_filter(ap_headers_insert_output_filter, NULL, NULL, APR_HOOK_LAST);
    ap_hook_insert_error_filter(ap_headers_insert_error_filter,
                                NULL, NULL, APR_HOOK_LAST);
    ap_hook_fixups(ap_headers_fixup, NULL, NULL, APR_HOOK_LAST);
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
