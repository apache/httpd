/* ====================================================================
 * Copyright (c) 1995-1999 The Apache Group.  All rights reserved.
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
 * 5. Products derived from this software may not be called "Apache"
 *    nor may "Apache" appear in their names without prior written
 *    permission of the Apache Group.
 *
 * 6. Redistributions of any form whatsoever must retain the following
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
 * mod_isapi.c - Internet Server Application (ISA) module for Apache
 * by Alexei Kosut <akosut@apache.org>
 *
 * This module implements Microsoft's ISAPI, allowing Apache (when running
 * under Windows) to load Internet Server Applications (ISAPI extensions).
 * It implements all of the ISAPI 2.0 specification, except for the 
 * "Microsoft-only" extensions dealing with asynchronous I/O. All ISAPI
 * extensions that use only synchronous I/O and are compatible with the
 * ISAPI 2.0 specification should work (most ISAPI 1.0 extensions should
 * function as well).
 *
 * To load, simply place the ISA in a location in the document tree.
 * Then add an "AddHandler isapi-isa dll" into your config file.
 * You should now be able to load ISAPI DLLs just be reffering to their
 * URLs. Make sure the ExecCGI option is active in the directory
 * the ISA is in.
 */

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_protocol.h"
#include "http_request.h"
#include "http_log.h"
#include "util_script.h"

/* We use the exact same header file as the original */
#include <HttpExt.h>

/* Seems IIS does not enforce the requirement for \r\n termination on HSE_REQ_SEND_RESPONSE_HEADER,
   define this to conform */
#define RELAX_HEADER_RULE

module isapi_module;

/* Our "Connection ID" structure */

typedef struct {
    LPEXTENSION_CONTROL_BLOCK ecb;
    request_rec *r;
    int status;
} isapi_cid;

/* Declare the ISAPI functions */

BOOL WINAPI GetServerVariable (HCONN hConn, LPSTR lpszVariableName,
			       LPVOID lpvBuffer, LPDWORD lpdwSizeofBuffer);
BOOL WINAPI WriteClient (HCONN ConnID, LPVOID Buffer, LPDWORD lpwdwBytes,
			 DWORD dwReserved);
BOOL WINAPI ReadClient (HCONN ConnID, LPVOID lpvBuffer, LPDWORD lpdwSize);
BOOL WINAPI ServerSupportFunction (HCONN hConn, DWORD dwHSERequest,
				   LPVOID lpvBuffer, LPDWORD lpdwSize,
				   LPDWORD lpdwDataType);

/*
    The optimiser blows it totally here. What happens is that autos are addressed relative to the
    stack pointer, which, of course, moves around. The optimiser seems to lose track of it somewhere
    between setting isapi_entry and calling through it. We work around the problem by forcing it to
    use frame pointers.
*/
#pragma optimize("y",off)

int isapi_handler (request_rec *r) {
    LPEXTENSION_CONTROL_BLOCK ecb =
	ap_pcalloc(r->pool, sizeof(struct _EXTENSION_CONTROL_BLOCK));
    HSE_VERSION_INFO *pVer = ap_pcalloc(r->pool, sizeof(HSE_VERSION_INFO));

    HINSTANCE isapi_handle;
    BOOL (*isapi_version)(HSE_VERSION_INFO *); /* entry point 1 */
    DWORD (*isapi_entry)(LPEXTENSION_CONTROL_BLOCK); /* entry point 2 */
    BOOL (*isapi_term)(DWORD); /* optional entry point 3 */

    isapi_cid *cid = ap_pcalloc(r->pool, sizeof(isapi_cid));
    table *e = r->subprocess_env;
    int retval;

    /* Use similar restrictions as CGIs */

    if (!(ap_allow_options(r) & OPT_EXECCGI))
	return FORBIDDEN;

    if (r->finfo.st_mode == 0)
	return NOT_FOUND;

    if (S_ISDIR(r->finfo.st_mode))
	return FORBIDDEN;

    /* Load the module */

    if (!(isapi_handle = LoadLibraryEx(r->filename, NULL,
				       LOAD_WITH_ALTERED_SEARCH_PATH))) {
	ap_log_rerror(APLOG_MARK, APLOG_ALERT, r,
		    "Could not load DLL: %s", r->filename);
	return SERVER_ERROR;
    }

    if (!(isapi_version =
	  (void *)(GetProcAddress(isapi_handle, "GetExtensionVersion")))) {
	ap_log_rerror(APLOG_MARK, APLOG_ALERT, r,
		    "DLL could not load GetExtensionVersion(): %s", r->filename);
	FreeLibrary(isapi_handle);
	return SERVER_ERROR;
    }

    if (!(isapi_entry =
	  (void *)(GetProcAddress(isapi_handle, "HttpExtensionProc")))) {
	ap_log_rerror(APLOG_MARK, APLOG_ALERT, r,
		    "DLL could not load HttpExtensionProc(): %s", r->filename);
	FreeLibrary(isapi_handle);
	return SERVER_ERROR;
    }

    isapi_term = (void *)(GetProcAddress(isapi_handle, "TerminateExtension"));

    /* Run GetExtensionVersion() */

    if ((*isapi_version)(pVer) != TRUE) {
	ap_log_rerror(APLOG_MARK, APLOG_ALERT, r,
		    "ISAPI GetExtensionVersion() failed: %s", r->filename);
	FreeLibrary(isapi_handle);
	return SERVER_ERROR;
    }

    /* Set up variables */
    ap_add_common_vars(r);
    ap_add_cgi_vars(r);

    /* Set up connection ID */
    ecb->ConnID = (HCONN)cid;
    cid->ecb = ecb;
    cid->r = r;
    cid->status = 0;

    ecb->cbSize = sizeof(struct _EXTENSION_CONTROL_BLOCK);
    ecb->dwVersion = MAKELONG(0, 2);
    ecb->dwHttpStatusCode = 0;
    strcpy(ecb->lpszLogData, "");
    ecb->lpszMethod = r->method;
    ecb->lpszQueryString = ap_table_get(e, "QUERY_STRING");
    ecb->lpszPathInfo = ap_table_get(e, "PATH_INFO");
    ecb->lpszPathTranslated = ap_table_get(e, "PATH_TRANSLATED");
    ecb->lpszContentType = ap_table_get(e, "CONTENT_TYPE");

    /* Set up client input */
    if ((retval = ap_setup_client_block(r, REQUEST_CHUNKED_ERROR))) {
	if (isapi_term) (*isapi_term)(HSE_TERM_MUST_UNLOAD);
	FreeLibrary(isapi_handle);
	return retval;
    }

    if (ap_should_client_block(r)) {
	/* Unlike IIS, which limits this to 48k, we read the whole
	 * sucker in. I suppose this could be bad for memory if someone
	 * uploaded the complete works of Shakespeare. Well, WebSite
	 * does the same thing.
	 */
	long to_read = atol(ap_table_get(e, "CONTENT_LENGTH"));
	long read;

	/* Actually, let's cap it at 48k, until we figure out what
	 * to do with this... we don't want a Content-Length: 1000000000
	 * taking out the machine.
	 */

	if (to_read > 49152) {
	    if (isapi_term) (*isapi_term)(HSE_TERM_MUST_UNLOAD);
	    FreeLibrary(isapi_handle);
	    return HTTP_REQUEST_ENTITY_TOO_LARGE;
	}

	ecb->lpbData = ap_pcalloc(r->pool, 1 + to_read);

	if ((read = ap_get_client_block(r, ecb->lpbData, to_read)) < 0) {
	    if (isapi_term) (*isapi_term)(HSE_TERM_MUST_UNLOAD);
	    FreeLibrary(isapi_handle);
	    return SERVER_ERROR;
	}

	/* Although its not to spec, IIS seems to null-terminate
	 * its lpdData string. So we will too. To make sure
	 * cbAvailable matches cbTotalBytes, we'll up the latter
	 * and equalize them.
	 */
	ecb->cbAvailable = ecb->cbTotalBytes = read + 1;
	ecb->lpbData[read] = '\0';
	}
    else {
	ecb->cbTotalBytes = 0;
	ecb->cbAvailable = 0;
	ecb->lpbData = NULL;
    }

    /* Set up the callbacks */

    ecb->GetServerVariable = &GetServerVariable;
    ecb->WriteClient = &WriteClient;
    ecb->ReadClient = &ReadClient;
    ecb->ServerSupportFunction = &ServerSupportFunction;

    /* All right... try and load the sucker */
    retval = (*isapi_entry)(ecb);

    /* Set the status (for logging) */
    if (ecb->dwHttpStatusCode)
	r->status = ecb->dwHttpStatusCode;

    /* Check for a log message - and log it */
    if (ecb->lpszLogData && strcmp(ecb->lpszLogData, ""))
	ap_log_rerror(APLOG_MARK, APLOG_ERR, r,
		    "%s: %s", ecb->lpszLogData, r->filename);

    /* All done with the DLL... get rid of it */
    if (isapi_term) (*isapi_term)(HSE_TERM_MUST_UNLOAD);
    FreeLibrary(isapi_handle);

    switch(retval) {
    case HSE_STATUS_SUCCESS:
    case HSE_STATUS_SUCCESS_AND_KEEP_CONN:
	/* Ignore the keepalive stuff; Apache handles it just fine without
	 * the ISA's "advice".
	 */

	if (cid->status) /* We have a special status to return */
	    return cid->status;

	return OK;
    case HSE_STATUS_PENDING:	/* We don't support this */
	ap_log_rerror(APLOG_MARK, APLOG_WARNING, r,
		    "ISAPI asynchronous I/O not supported: %s", r->filename);
    case HSE_STATUS_ERROR:
    default:
	return SERVER_ERROR;
    }

}
#pragma optimize("",on)

BOOL WINAPI GetServerVariable (HCONN hConn, LPSTR lpszVariableName,
			       LPVOID lpvBuffer, LPDWORD lpdwSizeofBuffer) {
    request_rec *r = ((isapi_cid *)hConn)->r;
    table *e = r->subprocess_env;
    const char *result;
    
    /* Mostly, we just grab it from the environment, but there are
     * a couple of special cases
     */

    if (!strcasecmp(lpszVariableName, "UNMAPPED_REMOTE_USER")) {
	/* We don't support NT users, so this is always the same as
	 * REMOTE_USER
	 */
	result = ap_table_get(e, "REMOTE_USER");
    }
    else if (!strcasecmp(lpszVariableName, "SERVER_PORT_SECURE")) {
	/* Apache doesn't support secure requests inherently, so
	 * we have no way of knowing. We'll be conservative, and say
	 * all requests are insecure.
	 */
	result = "0";
    }
    else if (!strcasecmp(lpszVariableName, "URL")) {
	result = r->uri;
    }
    else {
	result = ap_table_get(e, lpszVariableName);
    }

    if (result) {
	if (strlen(result) > *lpdwSizeofBuffer) {
	    *lpdwSizeofBuffer = strlen(result);
	    SetLastError(ERROR_INSUFFICIENT_BUFFER);
	    return FALSE;
	}
	strncpy(lpvBuffer, result, *lpdwSizeofBuffer);
	return TRUE;
    }

    /* Didn't find it */
    SetLastError(ERROR_INVALID_INDEX);
    return FALSE;
}

BOOL WINAPI WriteClient (HCONN ConnID, LPVOID Buffer, LPDWORD lpwdwBytes,
			 DWORD dwReserved) {
    request_rec *r = ((isapi_cid *)ConnID)->r;
    int writ;	/* written, actually, but why shouldn't I make up words? */

    /* We only support synchronous writing */
    if (dwReserved && dwReserved != HSE_IO_SYNC) {
	ap_log_rerror(APLOG_MARK, APLOG_WARNING, r,
		    "ISAPI asynchronous I/O not supported: %s", r->filename);
	SetLastError(ERROR_INVALID_PARAMETER);
	return FALSE;
    }

    if ((writ = ap_rwrite(Buffer, *lpwdwBytes, r)) == EOF) {
	SetLastError(ERROR); /* XXX: Find the right error code */
	return FALSE;
    }
   
    *lpwdwBytes = writ;
    return TRUE;
}

BOOL WINAPI ReadClient (HCONN ConnID, LPVOID lpvBuffer, LPDWORD lpdwSize) {
    /* Doesn't need to do anything; we've read all the data already */
    return TRUE;
}

/* XXX: There is an O(n^2) attack possible here. */
BOOL WINAPI ServerSupportFunction (HCONN hConn, DWORD dwHSERequest,
				   LPVOID lpvBuffer, LPDWORD lpdwSize,
				   LPDWORD lpdwDataType) {
    isapi_cid *cid = (isapi_cid *)hConn;
    request_rec *subreq, *r = cid->r;
    char *data;

    switch (dwHSERequest) {
    case HSE_REQ_SEND_URL_REDIRECT_RESP:
	/* Set the status to be returned when the HttpExtensionProc()
	 * is done.
	 */
	ap_table_set (r->headers_out, "Location", lpvBuffer);
	cid->status = cid->r->status = cid->ecb->dwHttpStatusCode = REDIRECT;
	return TRUE;

    case HSE_REQ_SEND_URL:
	/* Read any additional input */

	if (r->remaining > 0) {
	    char argsbuffer[HUGE_STRING_LEN];

	    while (ap_get_client_block(r, argsbuffer, HUGE_STRING_LEN));
	}
	
	/* Reset the method to GET */
	r->method = ap_pstrdup(r->pool, "GET");
	r->method_number = M_GET;

	/* Don't let anyone think there's still data */
	ap_table_unset(r->headers_in, "Content-Length");
	
	ap_internal_redirect((char *)lpvBuffer, r);	
	return TRUE;

    case HSE_REQ_SEND_RESPONSE_HEADER:
	r->status_line = lpvBuffer ? lpvBuffer : ap_pstrdup(r->pool, "200 OK");
	sscanf(r->status_line, "%d", &r->status);
	cid->ecb->dwHttpStatusCode = r->status;

	/* Now fill in the HTTP headers, and the rest of it. Ick.
	 * lpdwDataType contains a string that has headers (in MIME
	 * format), a blank like, then (possibly) data. We need
	 * to parse it.
	 *
	 * Easy case first:
	 */
	if (!lpdwDataType) {
	    ap_send_http_header(r);
	    return TRUE;
	}

	/* Make a copy - don't disturb the original */
	data = ap_pstrdup(r->pool, (char *)lpdwDataType);

	/* We *should* break before this while loop ends */
	while (*data) {
	    char *value, *lf = strchr(data, '\n');
	    int p;

#ifdef RELAX_HEADER_RULE
	    if (lf)
		*lf = '\0';
#else
	    if (!lf) { /* Huh? Invalid data, I think */
		ap_log_rerror(APLOG_MARK, APLOG_ERR, r,
			    "ISA sent invalid headers: %s", r->filename);
		SetLastError(ERROR);	/* XXX: Find right error */
		return FALSE;
	    }

	    /* Get rid of \n and \r */
	    *lf = '\0';
#endif
	    p = strlen(data);
	    if (p > 0 && data[p-1] == '\r') data[p-1] = '\0';
	    
	    /* End of headers */
	    if (*data == '\0') {
#ifdef RELAX_HEADER_RULE
		if (lf)
#endif
		    data = lf + 1;	/* Reset data */
		break;
	    }

	    if (!(value = strchr(data, ':'))) {
		SetLastError(ERROR);	/* XXX: Find right error */
		ap_log_rerror(APLOG_MARK, APLOG_ERR, r,
			    "ISA sent invalid headers", r->filename);
		return FALSE;
	    }

	    *value++ = '\0';
	    while (*value && ap_isspace(*value)) ++value;

	    /* Check all the special-case headers. Similar to what
	     * ap_scan_script_header_err() does (see that function for
	     * more detail)
	     */

	    if (!strcasecmp(data, "Content-Type")) {
		char *tmp;
		/* Nuke trailing whitespace */
		
		char *endp = value + strlen(value) - 1;
		while (endp > value && ap_isspace(*endp)) *endp-- = '\0';
            
		tmp = ap_pstrdup (r->pool, value);
		ap_str_tolower(tmp);
		r->content_type = tmp;
	    }
	    else if (!strcasecmp(data, "Content-Length")) {
		ap_table_set(r->headers_out, data, value);
	    }
	    else if (!strcasecmp(data, "Transfer-Encoding")) {
		ap_table_set(r->headers_out, data, value);
	    }
	    else if (!strcasecmp(data, "Set-Cookie")) {
		ap_table_add(r->err_headers_out, data, value);
	    }
	    else {
		ap_table_merge(r->err_headers_out, data, value);
	    }
	  
	    /* Reset data */
#ifdef RELAX_HEADER_RULE
	    if (!lf) {
		data += p;
		break;
	    }
#endif
	    data = lf + 1;
	}
	
	/* All the headers should be set now */

	ap_send_http_header(r);

	/* Any data left should now be sent directly */
	ap_rputs(data, r);

	return TRUE;

    case HSE_REQ_MAP_URL_TO_PATH:
	/* Map a URL to a filename */
	subreq = ap_sub_req_lookup_uri(ap_pstrndup(r->pool, (char *)lpvBuffer,
					      *lpdwSize), r);

	GetFullPathName(subreq->filename, *lpdwSize - 1, (char *)lpvBuffer, NULL);

	/* IIS puts a trailing slash on directories, Apache doesn't */

	if (S_ISDIR (subreq->finfo.st_mode)) {
		int l = strlen((char *)lpvBuffer);

		((char *)lpvBuffer)[l] = '\\';
		((char *)lpvBuffer)[l + 1] = '\0';
	}
	
	return TRUE;

    case HSE_REQ_DONE_WITH_SESSION:
	/* Do nothing... since we don't support async I/O, they'll
	 * return from HttpExtensionProc soon
	 */
	return TRUE;

    /* We don't support all this async I/O, Microsoft-specific stuff */
    case HSE_REQ_IO_COMPLETION:
    case HSE_REQ_TRANSMIT_FILE:
	ap_log_rerror(APLOG_MARK, APLOG_WARNING, r,
		    "ISAPI asynchronous I/O not supported: %s", r->filename);
    default:
	SetLastError(ERROR_INVALID_PARAMETER);
	return FALSE;
    }
}

handler_rec isapi_handlers[] = {
{ "isapi-isa", isapi_handler },
{ NULL}
};

module isapi_module = {
   STANDARD_MODULE_STUFF,
   NULL,			/* initializer */
   NULL,			/* create per-dir config */
   NULL,			/* merge per-dir config */
   NULL,			/* server config */
   NULL,			/* merge server config */
   NULL,			/* command table */
   isapi_handlers,	       	/* handlers */
   NULL,			/* filename translation */
   NULL,			/* check_user_id */
   NULL,			/* check auth */
   NULL,			/* check access */
   NULL,			/* type_checker */
   NULL,			/* logger */
   NULL				/* header parser */
};
