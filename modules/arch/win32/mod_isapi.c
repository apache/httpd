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

#include "ap_config.h"
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_protocol.h"
#include "http_request.h"
#include "http_log.h"
#include "util_script.h"
#include "apr_portable.h"
#include "apr_strings.h"


/* We use the exact same header file as the original */
#include <HttpExt.h>

/* TODO: Unknown errors that must be researched for correct codes */

#define TODO_ERROR 1

/* Seems IIS does not enforce the requirement for \r\n termination on HSE_REQ_SEND_RESPONSE_HEADER,
   define this to conform */
#define RELAX_HEADER_RULE

module isapi_module;

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
    between setting HttpExtensionProc's address and calling through it. We work around the problem by 
    forcing it to use frame pointers.

    The revisions below may eliminate this artifact.
*/
#pragma optimize("y",off)

/* Our loaded isapi module description structure */

typedef struct {
    HINSTANCE handle;
    HSE_VERSION_INFO *pVer;
    PFN_GETEXTENSIONVERSION GetExtensionVersion;
    PFN_HTTPEXTENSIONPROC   HttpExtensionProc;
    PFN_TERMINATEEXTENSION  TerminateExtension;
    int   refcount;
    DWORD timeout;
    BOOL  fakeasync;
    DWORD reportversion;
} isapi_loaded;

/* Our "Connection ID" structure */

typedef struct {
    LPEXTENSION_CONTROL_BLOCK ecb;
    isapi_loaded *isa;
    request_rec  *r;
    PFN_HSE_IO_COMPLETION completion;
    PVOID  completion_arg;
    HANDLE complete;
    apr_status_t retval;
} isapi_cid;

apr_status_t isapi_handler (request_rec *r)
{
    apr_table_t *e = r->subprocess_env;
    isapi_loaded *isa;
    isapi_cid *cid;

    /* Use similar restrictions as CGIs
     *
     * If this fails, it's pointless to load the isapi dll.
     */
    if (!(ap_allow_options(r) & OPT_EXECCGI))
        return HTTP_FORBIDDEN;

    if (r->finfo.protection == 0)
        return HTTP_NOT_FOUND;

    if (r->finfo.filetype == APR_DIR)
        return HTTP_FORBIDDEN;

    /* Load the module 
     *
     * TODO: Critical section
     *
     * Warning: cid should not be allocated from pool if we 
     * cache the isapi process in-memory.
     *
     * This code could use cacheing... everything that follows
     * should only be performed on the first isapi dll invocation, 
     * not with every HttpExtensionProc()
     */
    isa = apr_pcalloc(r->pool, sizeof(isapi_module));
    isa->pVer = apr_pcalloc(r->pool, sizeof(HSE_VERSION_INFO));
    isa->refcount = 0;

    /* TODO: These may need to become overrideable, so that we
     * assure a given isapi can be fooled into behaving well.
     */
    isa->timeout = INFINITE; /* microsecs */
    isa->fakeasync = TRUE;
    isa->reportversion = MAKELONG(0, 5); /* Revision 5.0 */
    
    if (!(isa->handle = LoadLibraryEx(r->filename, NULL,
                                      LOAD_WITH_ALTERED_SEARCH_PATH))) {
        ap_log_rerror(APLOG_MARK, APLOG_ALERT, GetLastError(), r,
                      "ISAPI %s failed to load", r->filename);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    if (!(isa->GetExtensionVersion =
          (void *)(GetProcAddress(isa->handle, "GetExtensionVersion")))) {
        ap_log_rerror(APLOG_MARK, APLOG_ALERT, GetLastError(), r,
                      "ISAPI %s is missing GetExtensionVersion()",
                      r->filename);
        FreeLibrary(isa->handle);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    if (!(isa->HttpExtensionProc =
          (void *)(GetProcAddress(isa->handle, "HttpExtensionProc")))) {
        ap_log_rerror(APLOG_MARK, APLOG_ALERT, GetLastError(), r,
                      "ISAPI %s is missing HttpExtensionProc()",
                      r->filename);
        FreeLibrary(isa->handle);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    /* TerminateExtension() is an optional interface */

    isa->TerminateExtension = (void *)(GetProcAddress(isa->handle, "TerminateExtension"));

    /* Run GetExtensionVersion() */

    if (!(*isa->GetExtensionVersion)(isa->pVer)) {
        /* ### euh... we're passing the wrong type of error code here */
        ap_log_rerror(APLOG_MARK, APLOG_ALERT, HTTP_INTERNAL_SERVER_ERROR, r,
                      "ISAPI %s call GetExtensionVersion() failed", 
                      r->filename);
        FreeLibrary(isa->handle);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Load of this module completed, this is the point at which *isa
     * could be cached for later invocation.
     *
     * on to invoking this request... 
     */
    
    /* Set up variables */
    ap_add_common_vars(r);
    ap_add_cgi_vars(r);

    /* Set up connection structure and ecb */
    cid = apr_pcalloc(r->pool, sizeof(isapi_cid));
    cid->ecb = apr_pcalloc(r->pool, sizeof(struct _EXTENSION_CONTROL_BLOCK));
    cid->ecb->ConnID = (HCONN)cid;
    /* TODO: Critical section */
    ++isa->refcount;
    cid->isa = isa;
    cid->r = r;
    cid->r->status = 0;
    cid->complete = NULL;
    cid->completion = NULL;
    cid->retval = APR_SUCCESS;

    cid->ecb->cbSize = sizeof(EXTENSION_CONTROL_BLOCK);
    cid->ecb->dwVersion = isa->reportversion;
    cid->ecb->dwHttpStatusCode = 0;
    strcpy(cid->ecb->lpszLogData, "");
    // TODO: are copies really needed here?
    cid->ecb->lpszMethod = apr_pstrdup(r->pool, (char*) r->method);
    cid->ecb->lpszQueryString = apr_pstrdup(r->pool, 
                                (char*) apr_table_get(e, "QUERY_STRING"));
    cid->ecb->lpszPathInfo = apr_pstrdup(r->pool, 
                             (char*) apr_table_get(e, "PATH_INFO"));
    cid->ecb->lpszPathTranslated = apr_pstrdup(r->pool, 
                                   (char*) apr_table_get(e, "PATH_TRANSLATED"));
    cid->ecb->lpszContentType = apr_pstrdup(r->pool, 
                                (char*) apr_table_get(e, "CONTENT_TYPE"));
    /* Set up the callbacks */
    cid->ecb->GetServerVariable = &GetServerVariable;
    cid->ecb->WriteClient = &WriteClient;
    cid->ecb->ReadClient = &ReadClient;
    cid->ecb->ServerSupportFunction = &ServerSupportFunction;

    
    /* Set up client input */
    cid->retval = ap_setup_client_block(r, REQUEST_CHUNKED_ERROR);
    if (cid->retval) {
        if (isa->TerminateExtension) {
            (*isa->TerminateExtension)(HSE_TERM_MUST_UNLOAD);
        }
        FreeLibrary(isa->handle);
        return cid->retval;
    }

    if (ap_should_client_block(r)) {
        /* Unlike IIS, which limits this to 48k, we read the whole
         * sucker in. I suppose this could be bad for memory if someone
         * uploaded the complete works of Shakespeare. Well, WebSite
         * does the same thing.
         *
         * But we can be smarter and read up to our 48k and then allow
         * the ISAPI app to read further blocks as desired.
         */
        long to_read = atol(apr_table_get(e, "CONTENT_LENGTH"));
        long read;

        /* Actually, let's cap it at 48k, until we figure out what
         * to do with this... we don't want a Content-Length: 1000000000
         * taking out the machine.
         */

        if (to_read > 49152) {
            if (isa->TerminateExtension) 
                (*isa->TerminateExtension)(HSE_TERM_MUST_UNLOAD);
            FreeLibrary(isa->handle);
            return HTTP_REQUEST_ENTITY_TOO_LARGE;
        }

        cid->ecb->lpbData = apr_pcalloc(r->pool, 1 + to_read);

        if ((read = ap_get_client_block(r, cid->ecb->lpbData, to_read)) < 0) {
            if (isa->TerminateExtension) 
                (*isa->TerminateExtension)(HSE_TERM_MUST_UNLOAD);
            FreeLibrary(isa->handle);
            return HTTP_INTERNAL_SERVER_ERROR;
        }

        /* Although its not to spec, IIS seems to null-terminate
         * its lpdData string. So we will too. To make sure
         * cbAvailable matches cbTotalBytes, we'll up the latter
         * and equalize them.
         */
        cid->ecb->cbAvailable = cid->ecb->cbTotalBytes = read + 1;
        cid->ecb->lpbData[read] = '\0';
    }
    else {
        cid->ecb->cbTotalBytes = 0;
        cid->ecb->cbAvailable = 0;
        cid->ecb->lpbData = NULL;
    }

    /* All right... try and run the sucker */
    cid->retval = (*isa->HttpExtensionProc)(cid->ecb);

    /* Set the status (for logging) */
    if (cid->ecb->dwHttpStatusCode) {
        cid->r->status = cid->ecb->dwHttpStatusCode;
    }

    /* Check for a log message - and log it */
    if (cid->ecb->lpszLogData && *cid->ecb->lpszLogData)
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                      "ISAPI %s: %s", r->filename, cid->ecb->lpszLogData);

    switch(cid->retval) {
        case HSE_STATUS_SUCCESS:
        case HSE_STATUS_SUCCESS_AND_KEEP_CONN:
            /* Ignore the keepalive stuff; Apache handles it just fine without
             * the ISA's "advice".
             * Per Microsoft: "In IIS versions 4.0 and later, the return
             * values HSE_STATUS_SUCCESS and HSE_STATUS_SUCCESS_AND_KEEP_CONN
             * are functionally identical: Keep-Alive connections are
             * maintained, if supported by the client."
             * ... so we were pat all this time
             */
            break;
            
        case HSE_STATUS_PENDING:    
            /* emulating async behavior...
             *
             * Create a cid->completed event and wait on it for some timeout
             * so that the app thinks is it running async.
             *
             * All async ServerSupportFunction calls will be handled through
             * the registered IO_COMPLETION hook.
             */
            
            if (!isa->fakeasync) {
                ap_log_rerror(APLOG_MARK, APLOG_WARNING, APR_ENOTIMPL, r,
                              "ISAPI %s asynch I/O request refused", 
                              r->filename);
                cid->retval = APR_ENOTIMPL;
            }
            else {
                cid->complete = CreateEvent(NULL, FALSE, FALSE, NULL);
                if (WaitForSingleObject(cid->complete, isa->timeout)
                        == WAIT_TIMEOUT) {
                    /* TODO: Now what... if this hung, then do we kill our own
                     * thread to force it's death?  For now leave timeout = -1
                     */
                }
            }
            break;

        case HSE_STATUS_ERROR:    
            /* end response if we have yet to do so.
             */
            cid->retval = HTTP_INTERNAL_SERVER_ERROR;
            break;

        default:
            /* TODO: log unrecognized retval for debugging 
             */
            cid->retval = HTTP_INTERNAL_SERVER_ERROR;
            break;
    }

    /* All done with the DLL... get rid of it...
     *
     * If optionally cached, pass HSE_TERM_ADVISORY_UNLOAD,
     * and if it returns TRUE, unload, otherwise, cache it.
     */
    if (isa->TerminateExtension) {
        (*isa->TerminateExtension)(HSE_TERM_MUST_UNLOAD);
    }
    FreeLibrary(isa->handle);
    /* TODO: Crit section */
    cid->isa = NULL;
    --isa->refcount;
    isa->handle = NULL;
    
    return cid->retval;
}
#pragma optimize("",on)

BOOL WINAPI GetServerVariable (HCONN hConn, LPSTR lpszVariableName,
                               LPVOID lpvBuffer, LPDWORD lpdwSizeofBuffer)
{
    request_rec *r = ((isapi_cid *)hConn)->r;
    apr_table_t *e = r->subprocess_env;
    const char *result;

    /* Mostly, we just grab it from the environment, but there are
     * a couple of special cases
     */

    if (!strcasecmp(lpszVariableName, "UNMAPPED_REMOTE_USER")) {
        /* We don't support NT users, so this is always the same as
         * REMOTE_USER
         */
        result = apr_table_get(e, "REMOTE_USER");
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
        result = apr_table_get(e, lpszVariableName);
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
                         DWORD dwReserved)
{
    request_rec *r = ((isapi_cid *)ConnID)->r;
    int writ;   /* written, actually, but why shouldn't I make up words? */

    /* We only support synchronous writing */
    if (dwReserved && dwReserved != HSE_IO_SYNC) {
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, ERROR_INVALID_PARAMETER, r,
                      "ISAPI %s asynch write", r->filename);
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    if ((writ = ap_rwrite(Buffer, *lpwdwBytes, r)) == EOF) {
        SetLastError(WSAEDISCON); /* TODO: Find the right error code */
        return FALSE;
    }

    *lpwdwBytes = writ;
    return TRUE;
}

BOOL WINAPI ReadClient (HCONN ConnID, LPVOID lpvBuffer, LPDWORD lpdwSize)
{
    /* TODO: If the request was a huge transmit or chunked, continue piping the
     * request here, but if it's of a sane size, continue to ...
     */
    return TRUE;
}

static char* ComposeHeaders(request_rec *r, char* data)
{
    /* We *should* break before this while loop ends */
    while (*data) 
    {
        char *value, *lf = strchr(data, '\n');
        int p;

#ifdef RELAX_HEADER_RULE
        if (lf)
            *lf = '\0';
#else
        if (!lf) { /* Huh? Invalid data, I think */
            ap_log_rerror(APLOG_MARK, APLOG_ERR, r,
                          "ISAPI %s sent invalid headers", r->filename);
            SetLastError(TODO_ERROR);
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
                data = lf + 1;  /* Reset data */
            break;
        }

        if (!(value = strchr(data, ':'))) {
            SetLastError(TODO_ERROR);
            /* ### euh... we're passing the wrong type of error
               ### code here */
            ap_log_rerror(APLOG_MARK, APLOG_ERR, HTTP_INTERNAL_SERVER_ERROR, r,
                          "ISAPI %s sent invalid headers", r->filename);
            return FALSE;
        }

        *value++ = '\0';
        while (*value && ap_isspace(*value)) ++value;

        /* Check all the special-case headers. Similar to what
         * ap_scan_script_header_err() does (see that function for
         * more detail)
         */

        if (!strcasecmp(data, "Content-Type")) 
        {
            /* Nuke trailing whitespace */    
            char *tmp;
            char *endp = value + strlen(value) - 1;
            while (endp > value && ap_isspace(*endp)) 
                *endp-- = '\0';

            tmp = apr_pstrdup (r->pool, value);
            ap_str_tolower(tmp);
            r->content_type = tmp;
        }
        else if (!strcasecmp(data, "Content-Length")) {
            apr_table_set(r->headers_out, data, value);
        }
        else if (!strcasecmp(data, "Transfer-Encoding")) {
            apr_table_set(r->headers_out, data, value);
        }
        else if (!strcasecmp(data, "Set-Cookie")) {
            apr_table_add(r->err_headers_out, data, value);
        }
        else {
            apr_table_merge(r->err_headers_out, data, value);
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
    return data;
}


/* XXX: There is an O(n^2) attack possible here. */
BOOL WINAPI ServerSupportFunction (HCONN hConn, DWORD dwHSERequest,
                                   LPVOID lpvBuffer, LPDWORD lpdwSize,
                                   LPDWORD lpdwDataType)
{
    isapi_cid *cid = (isapi_cid *)hConn;
    request_rec *r = cid->r;
    request_rec *subreq;
    char *data;

    switch (dwHSERequest) {
        case HSE_REQ_SEND_URL_REDIRECT_RESP:
            /* Set the status to be returned when the HttpExtensionProc()
             * is done.
             */
            apr_table_set (r->headers_out, "Location", lpvBuffer);
            cid->r->status = cid->ecb->dwHttpStatusCode 
                                                   = HTTP_MOVED_TEMPORARILY;
            return TRUE;

        case HSE_REQ_SEND_URL:
            /* Read any additional input */

            if (r->remaining > 0) {
                char argsbuffer[HUGE_STRING_LEN];

                while (ap_get_client_block(r, argsbuffer, HUGE_STRING_LEN));
            }

            /* Reset the method to GET */
            r->method = apr_pstrdup(r->pool, "GET");
            r->method_number = M_GET;

            /* Don't let anyone think there's still data */
            apr_table_unset(r->headers_in, "Content-Length");

            ap_internal_redirect((char *)lpvBuffer, r);
            return TRUE;

        case HSE_REQ_SEND_RESPONSE_HEADER:
            r->status_line = lpvBuffer ? lpvBuffer : apr_pstrdup(r->pool, "200 OK");
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
            data = apr_pstrdup(r->pool, (char *)lpdwDataType);
            
            /* Parse them out, or die trying */
            data = ComposeHeaders(r, data);
            if (!data)
                return FALSE;

            /* All the headers should be set now */
            ap_send_http_header(r);

            /* Any data left should now be sent directly */
            if (*data)
                ap_rputs(data, r);

            return TRUE;

        case HSE_REQ_DONE_WITH_SESSION:
            /* Signal to resume the thread completing this request
             */
            if (cid->complete)
                SetEvent(cid->complete);
            return TRUE;

        case HSE_REQ_MAP_URL_TO_PATH:
            /* Map a URL to a filename */
            subreq = ap_sub_req_lookup_uri(apr_pstrndup(r->pool, (char *)lpvBuffer,
                                           *lpdwSize), r);

            GetFullPathName(subreq->filename, *lpdwSize - 1, (char *)lpvBuffer, NULL);

            /* IIS puts a trailing slash on directories, Apache doesn't */

            if (subreq->finfo.filetype == APR_DIR) {
                int l = strlen((char *)lpvBuffer);

                ((char *)lpvBuffer)[l] = '\\';
                ((char *)lpvBuffer)[l + 1] = '\0';
            }

            return TRUE;

        case HSE_REQ_GET_SSPI_INFO:
            SetLastError(ERROR_INVALID_PARAMETER);
            return FALSE;
        
        case HSE_APPEND_LOG_PARAMETER:
            /* Log lpvBuffer, of lpdwSize bytes, in the URI Query (cs-uri-query) field 
             * This code will do for now...
             */
            ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                      "ISAPI %s: %s", cid->r->filename, 
                      (char*) lpvBuffer);
            return TRUE;
        
        case HSE_REQ_IO_COMPLETION:
            /* TODO: Emulate a completion port, if we can...
             * Record the callback address and user defined argument...
             * we will call this after any async request (e.g. transmitfile)
             * as if the request had completed async execution.
             * Per MS docs... HSE_REQ_IO_COMPLETION replaces any prior call
             * to HSE_REQ_IO_COMPLETION, and lpvBuffer may be set to NULL.
             */
            if (!cid->isa->fakeasync)
                return FALSE;
            cid->completion = (PFN_HSE_IO_COMPLETION) lpvBuffer;
            cid->completion_arg = (PVOID) lpdwDataType;
            return TRUE;

        case HSE_REQ_TRANSMIT_FILE:
            /* Use TransmitFile... nothing wrong with that :)
             */

            /* ### euh... we're passing the wrong type of error code here */
            ap_log_rerror(APLOG_MARK, APLOG_WARNING,
                          HTTP_INTERNAL_SERVER_ERROR, r,
                          "ISAPI asynchronous I/O not supported: %s",
                          r->filename);
            return FALSE;
            
        case HSE_REQ_REFRESH_ISAPI_ACL:
            SetLastError(ERROR_INVALID_PARAMETER);
            return FALSE;

        case HSE_REQ_IS_KEEP_CONN:
            SetLastError(ERROR_INVALID_PARAMETER);
            return FALSE;
        
        case HSE_REQ_ASYNC_READ_CLIENT:
            SetLastError(ERROR_INVALID_PARAMETER);
            return FALSE;
        
        case HSE_REQ_GET_IMPERSONATION_TOKEN:  /* Added in ISAPI 4.0 */
            SetLastError(ERROR_INVALID_PARAMETER);
            return FALSE;

        case HSE_REQ_MAP_URL_TO_PATH_EX:
            SetLastError(ERROR_INVALID_PARAMETER);
            return FALSE;

            /* TODO: Not quite ready for prime time yet */

            /* Map a URL to a filename */
            subreq = ap_sub_req_lookup_uri(apr_pstrndup(r->pool, (char *)lpvBuffer,
                                           *lpdwSize), r);

            GetFullPathName(subreq->filename, *lpdwSize - 1, (char *)lpvBuffer, NULL);

            /* IIS puts a trailing slash on directories, Apache doesn't */

            if (subreq->finfo.filetype == APR_DIR) {
                int l = strlen((char *)lpvBuffer);

                ((char *)lpvBuffer)[l] = '\\';
                ((char *)lpvBuffer)[l + 1] = '\0';
            }

            lpdwDataType = (LPDWORD) apr_palloc(r->pool, sizeof(HSE_URL_MAPEX_INFO));
            strncpy(((LPHSE_URL_MAPEX_INFO)lpdwDataType)->lpszPath,
                    (char *) lpvBuffer, MAX_PATH);
            ((LPHSE_URL_MAPEX_INFO)lpdwDataType)->dwFlags = 0;
            /* is a combination of:
             * HSE_URL_FLAGS_READ       Allow for read. 
             * HSE_URL_FLAGS_WRITE      Allow for write. 
             * HSE_URL_FLAGS_EXECUTE    Allow for execute. 
             * HSE_URL_FLAGS_SSL        Require SSL. 
             * HSE_URL_FLAGS_DONT_CACHE Don't cache (virtual root only). 
             * HSE_URL_FLAGS_NEGO_CERT  Allow client SSL certifications. 
             * HSE_URL_FLAGS_REQUIRE_CERT Require client SSL certifications. 
             * HSE_URL_FLAGS_MAP_CERT   Map SSL certification to a Windows account. 
             * HSE_URL_FLAGS_SSL128     Requires a 128-bit SSL. 
             * HSE_URL_FLAGS_SCRIPT     Allows for script execution. 
             */
            /* (LPHSE_URL_MAPEX_INFO)lpdwDataType)->cchMatchingPath
             * (LPHSE_URL_MAPEX_INFO)lpdwDataType)->cchMatchingURL
             */

            return TRUE;
        
        case HSE_REQ_ABORTIVE_CLOSE:
            SetLastError(ERROR_INVALID_PARAMETER);
            return FALSE;
                
        case HSE_REQ_GET_CERT_INFO_EX:  /* Added in ISAPI 4.0 */
            SetLastError(ERROR_INVALID_PARAMETER);
            return FALSE;

        case HSE_REQ_SEND_RESPONSE_HEADER_EX:  /* Added in ISAPI 4.0 */
            SetLastError(ERROR_INVALID_PARAMETER);
            return FALSE;

            /* TODO: Not quite ready for prime time */

            if (((LPHSE_SEND_HEADER_EX_INFO)lpvBuffer)->pszStatus
                && ((LPHSE_SEND_HEADER_EX_INFO)lpvBuffer)->cchStatus) {
                r->status_line = apr_pstrndup(r->pool, 
                           ((LPHSE_SEND_HEADER_EX_INFO)lpvBuffer)->pszStatus,
                           ((LPHSE_SEND_HEADER_EX_INFO)lpvBuffer)->cchStatus);
            }
            else {
                r->status_line = apr_pstrdup(r->pool, "200 OK");
            }
            sscanf(r->status_line, "%d", &r->status);
            cid->ecb->dwHttpStatusCode = r->status;

            if (((LPHSE_SEND_HEADER_EX_INFO)lpvBuffer)->pszHeader
                && ((LPHSE_SEND_HEADER_EX_INFO)lpvBuffer)->cchHeader)
            {
                /* Make a copy - don't disturb the original */
                data = apr_pstrndup(r->pool, 
                           ((LPHSE_SEND_HEADER_EX_INFO)lpvBuffer)->pszHeader,
                           ((LPHSE_SEND_HEADER_EX_INFO)lpvBuffer)->cchHeader);
                
                /* Parse them out, or die trying */
                data = ComposeHeaders(r, data);
                if (!data)
                    return FALSE;

            }
            else {
                data = "\0";
            }
            
            /* ((LPHSE_SEND_HEADER_EX_INFO)lpvBuffer)->fKeepConn; 
             *
             * Now how are we about to start listening to an ISAPI's
             * idea of keeping or closing a connection?  Seriously :)
             */

            /* All the headers should be set now */
            ap_send_http_header(r);

            /* Any data left should now be sent directly */
            if (*data)
                ap_rputs(data, r);

            return TRUE;

        case HSE_REQ_CLOSE_CONNECTION:  /* Added after ISAPI 4.0 */
            SetLastError(ERROR_INVALID_PARAMETER);
            return FALSE;

        case HSE_REQ_IS_CONNECTED:  /* Added after ISAPI 4.0 */
            /* Returns True if client is connected c.f. Q188346*/
            return TRUE;

     /* case HSE_REQ_EXTENSION_TRIGGER:  
      *     Added after ISAPI 4.0? 
      *      Undocumented - from the Microsoft Jan '00 Platform SDK
      */
        default:
            /* TODO: log unrecognized ServerSupportCommand for debugging 
             */
            SetLastError(ERROR_INVALID_PARAMETER);
            return FALSE;
    }
}

handler_rec isapi_handlers[] = {
    { "isapi-isa", isapi_handler },
    { NULL}
};

module isapi_module = {
   STANDARD20_MODULE_STUFF,
   NULL,                        /* create per-dir config */
   NULL,                        /* merge per-dir config */
   NULL,                        /* server config */
   NULL,                        /* merge server config */
   NULL,                        /* command apr_table_t */
   isapi_handlers,              /* handlers */
   NULL                         /* register hooks */
};
