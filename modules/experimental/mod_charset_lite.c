/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000 The Apache Software Foundation.  All rights
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
 * simple hokey charset recoding configuration module
 *
 * See mod_ebcdic and mod_charset for more thought-out examples.  This
 * one is just so Jeff can learn how a module works and experiment with
 * basic character set recoding configuration.
 *
 * !!!This is an extremely cheap ripoff of mod_charset.c from Russian Apache!!!
 */

#include <errno.h>
#include <stdio.h>

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_main.h"
#include "http_protocol.h"
#include "http_request.h"
#include "util_charset.h"

#ifndef APACHE_XLATE
#error mod_charset_lite cannot work without APACHE_XLATE enabled
#endif

typedef struct charset_dir_t {
    enum {NO_DEBUG = 1, DEBUG} debug; /* whether or not verbose logging is enabled; 0
                                        means uninitialized */
    const char *charset_source; /* source encoding */
    const char *charset_default; /* how to ship on wire */
} charset_dir_t;

module charset_lite_module;

static void *create_charset_dir_conf(ap_pool_t *p,char *dummy)
{
  return ap_pcalloc(p,sizeof(charset_dir_t));
}

static void *merge_charset_dir_conf(ap_pool_t *p, void *basev, void *overridesv)
{
    charset_dir_t *a = (charset_dir_t *)ap_pcalloc (p, sizeof(charset_dir_t));
    charset_dir_t *base = (charset_dir_t *)basev,
        *over = (charset_dir_t *)overridesv;

    /* If it is defined in the current container, use it.  Otherwise, use the one
     * from the enclosing container. 
     */

    a->debug = 
        over->debug ? over->debug : base->debug;
    a->charset_default = 
        over->charset_default ? over->charset_default : base->charset_default;
    a->charset_source = 
        over->charset_source ? over->charset_source : base->charset_source;
    return a;
}

/* CharsetSourceEnc charset
 */
static const char *add_charset_source(cmd_parms *cmd, charset_dir_t *dc, 
                                      char *name)
{
    dc->charset_source = name;
    return NULL;
}

/* CharsetDefault charset
 */
static const char *add_charset_default(cmd_parms *cmd, charset_dir_t *dc, 
                                        char *name)
{
    dc->charset_default = name;
    return NULL;
}

/* CharsetDefault charset
 */
static const char *add_charset_debug(cmd_parms *cmd, charset_dir_t *dc, int arg)
{
    if (arg) {
        dc->debug = DEBUG;
    }
    else {
        dc->debug = NO_DEBUG;
    }

    return NULL;
}

/* find_code_page() is a fixup hook that decides if translation should be
 * enabled
 */
static int find_code_page(request_rec *r)
{
    charset_dir_t *dc = ap_get_module_config(r->per_dir_config, &charset_lite_module);
    ap_status_t rv;
    ap_xlate_t *xlate;
    const char *mime_type;
    int debug = dc->debug == DEBUG;

    mime_type = r->content_type ? r->content_type : ap_default_type(r);

    if (debug) {
        ap_log_error(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO, 0, r->server,
                     "Entering handler, URI: %s FILENAME: %s ARGS: %s PATH_INFO: %s "
                     "MIMETYPE: %s FLAGS: %d SUBREQ: %s, REDIR: %s, PROXY: %s",
                     r->uri, r->filename, r->args, r->path_info, mime_type,
                     r->rrx ? 1 : 0,
                     r->main?"YES":"NO",r->prev?"YES":"NO",
                     r->proxyreq ? "YES" : "NO");
    }

    /* catch proxy requests */
    if (r->proxyreq) return DECLINED;
    /* mod_rewrite indicators */
    if (!strncmp(r->filename, "redirect:", 9)) return DECLINED; 
    if (!strncmp(r->filename, "gone:", 5)) return DECLINED; 
    if (!strncmp(r->filename, "passthrough:", 12)) return DECLINED; 
    if (!strncmp(r->filename, "forbidden:", 10)) return DECLINED; 
    
    /* If we don't have a full directory configuration, bail out.
     */
    if (!dc->charset_source || !dc->charset_default) {
        if (debug) {
            ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r->server,
                         "incomplete configuration: src %s, dst %s",
                         dc->charset_source ? dc->charset_source : "unspecified",
                         dc->charset_default ? dc->charset_default : "unspecified");
        }
        return DECLINED;
    }

    /* If this is a subrequest, bail out.  We don't want to be setting up 
     * translation just because something like mod_autoindex wants to find the
     * mime type for directory objects.
     * (I won't swear that there aren't cases where we need to process 
     * subrequests :) ).
     */
    if (r->main) {
        if (debug) {
            ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r->server,
                         "skipping subrequest");
        }
        return DECLINED;
    }

    /* If mime type isn't text or message, bail out.
     */
    if (strncasecmp(mime_type, "text/", 5) &&
        strncasecmp(mime_type, "message/", 8)) {
        if (debug) {
            ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r->server,
                         "mime type is %s; no translation selected",
                         mime_type);
        }
        return DECLINED;
    }

    if (debug) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r->server,
                     "dc: %X charset_source: %s charset_default: %s",
                     (unsigned)dc,
                     dc && dc->charset_source ? dc->charset_source : "(none)",
                     dc && dc->charset_default ? dc->charset_default : "(none)");
    }

    rv = ap_xlate_open(&xlate, dc->charset_default, dc->charset_source, r->pool);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, r->server,
                     "can't open translation %s->%s, error %d\n",
                     dc->charset_source, dc->charset_default, rv);
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    rv = ap_set_content_xlate(r, 1, xlate);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, r->server,
                     "can't set content translation, error %d\n", rv);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    rv = ap_bsetopt(r->connection->client, BO_WXLATE, &r->rrx->to_net);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, r->server,
                     "can't set translation; BO_WXLATE->%d\n", rv);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    return DECLINED;
}

static const command_rec cmds[] =
{
    {
        "CharsetSourceEnc",
        add_charset_source,
        NULL,
        OR_FILEINFO,
        TAKE1,
        "source (html,cgi,ssi) file charset"
    },
    {
        "CharsetDefault", 
        add_charset_default,
        NULL,
        OR_FILEINFO, 
        TAKE1,
        "name of default charset"
    },
    {
        "CharsetDebug",
        add_charset_debug,
        NULL,
        OR_FILEINFO,
        FLAG,
        "mod_charset_lite debug flag"
    },
    {NULL}
};

static void register_hooks(void)
{
    ap_hook_fixups(find_code_page, NULL, NULL, AP_HOOK_MIDDLE);
}

module charset_lite_module =
{
    STANDARD20_MODULE_STUFF,
    create_charset_dir_conf,
    merge_charset_dir_conf,
    NULL, 
    NULL,
    cmds,
    NULL,
    register_hooks,
};

