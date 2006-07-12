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
