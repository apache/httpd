/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000-2004 The Apache Software Foundation.  All rights
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

#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "http_log.h"
#include "util_script.h"
#include "http_main.h"
#include "http_request.h"

static int asis_handler(request_rec *r)
{
    FILE *f;
    const char *location;

    r->allowed |= (1 << M_GET);
    if (r->method_number != M_GET)
	return DECLINED;
    if (r->finfo.st_mode == 0) {
	ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
		    "File does not exist: %s", r->filename);
	return NOT_FOUND;
    }

    f = ap_pfopen(r->pool, r->filename, "r");

    if (f == NULL) {
	ap_log_rerror(APLOG_MARK, APLOG_ERR, r,
		    "file permissions deny server access: %s", r->filename);
	return FORBIDDEN;
    }

    ap_scan_script_header_err(r, f, NULL);
    location = ap_table_get(r->headers_out, "Location");

    if (location && location[0] == '/' &&
	((r->status == HTTP_OK) || ap_is_HTTP_REDIRECT(r->status))) {

	ap_pfclose(r->pool, f);

	/* Internal redirect -- fake-up a pseudo-request */
	r->status = HTTP_OK;

	/* This redirect needs to be a GET no matter what the original
	 * method was.
	 */
	r->method = ap_pstrdup(r->pool, "GET");
	r->method_number = M_GET;

	ap_internal_redirect_handler(location, r);
	return OK;
    }

    ap_send_http_header(r);
    if (!r->header_only)
	ap_send_fd(f, r);

    ap_pfclose(r->pool, f);
    return OK;
}

static const handler_rec asis_handlers[] =
{
    {ASIS_MAGIC_TYPE, asis_handler},
    {"send-as-is", asis_handler},
    {NULL}
};

module MODULE_VAR_EXPORT asis_module =
{
    STANDARD_MODULE_STUFF,
    NULL,			/* initializer */
    NULL,			/* create per-directory config structure */
    NULL,			/* merge per-directory config structures */
    NULL,			/* create per-server config structure */
    NULL,			/* merge per-server config structures */
    NULL,			/* command table */
    asis_handlers,		/* handlers */
    NULL,			/* translate_handler */
    NULL,			/* check_user_id */
    NULL,			/* check auth */
    NULL,			/* check access */
    NULL,			/* type_checker */
    NULL,			/* pre-run fixups */
    NULL,			/* logger */
    NULL,			/* header parser */
    NULL,			/* child_init */
    NULL,			/* child_exit */
    NULL			/* post read-request */
};
