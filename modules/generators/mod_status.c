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

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_protocol.h"
#include "mpm_status.h"

#ifndef DEFAULT_TIME_FORMAT 
#define DEFAULT_TIME_FORMAT "%A, %d-%b-%Y %H:%M:%S %Z"
#endif

#define STATUS_MAGIC_TYPE "application/x-httpd-status"

module MODULE_VAR_EXPORT status_module;

static int print_status_value(void *data, const char *key, const char *val)
{
    request_rec *r = (request_rec *) data;

    ap_rprintf(r, "<dt>%s\n<dd>%s\n", key, val);
    return 1;
}

static int status_handler(request_rec *r)
{
    int i;
    apr_array_header_t *server_status;
    ap_status_table_row_t *status_rows;

    r->allowed = (1 << M_GET);
    if (r->method_number != M_GET)
	return DECLINED;

    r->content_type = "text/html";

    ap_send_http_header(r);

    if (r->header_only)
	return 0;

    server_status = ap_get_status_table(r->pool);

    ap_rputs(DOCTYPE_HTML_3_2
    	 "<html><head>\n<title>Apache Status</title>\n</head><body>\n",
    	 r);
    ap_rputs("<H1>Apache Server Status for ", r);
    ap_rvputs(r, ap_get_server_name(r), "</H1>\n\n", NULL);
    ap_rvputs(r, "Server Version: ",
      ap_get_server_version(), "<br>\n", NULL);
    ap_rvputs(r, "Server Built: ",
      ap_get_server_built(), "<br>\n<hr>\n", NULL);
    ap_rvputs(r, "Current Time: ",
      ap_ht_time(r->pool, apr_now(), DEFAULT_TIME_FORMAT, 0), "<br>\n", NULL);
    ap_rprintf(r, "\n%d connections currently being processed\n",
               server_status->nelts);

    status_rows = (ap_status_table_row_t *) server_status->elts;
    for (i = 0; i < server_status->nelts; i++) {
	ap_rprintf(r, "<h2>Connection %ld</h2>\n", status_rows[i].conn_id);
        apr_table_do(print_status_value, (void *) r, status_rows[i].data, NULL);
    }
    ap_rputs("</body></html>\n", r);
    return 0;
}

static const handler_rec status_handlers[] =
{
    {STATUS_MAGIC_TYPE, status_handler},
    {"server-status", status_handler},
    {NULL}
};

module MODULE_VAR_EXPORT status_module =
{
    STANDARD20_MODULE_STUFF,
    NULL,			/* create per-dir config */
    NULL,			/* merge per-dir config */
    NULL,			/* server config */
    NULL,			/* merge server config */
    NULL,			/* command table */
    status_handlers,		/* handlers */
    NULL                        /* register hooks */
};
