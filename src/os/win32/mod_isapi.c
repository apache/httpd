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

#ifdef WIN32

/* A lousy hack to include ap_check_cmd_context(): */
#define CORE_PRIVATE 

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_protocol.h"
#include "http_request.h"
#include "http_log.h"
#include "util_script.h"
#include <stdlib.h>
/* We use the exact same header file as the original */
#include <HttpExt.h>

/* Seems IIS does not enforce the requirement for \r\n termination on HSE_REQ_SEND_RESPONSE_HEADER,
   define this to conform */
#define RELAX_HEADER_RULE

#if !defined(HSE_REQ_SEND_RESPONSE_HEADER_EX) \
 || !defined(HSE_REQ_MAP_URL_TO_PATH_EX)
#pragma message("WARNING: This build of Apache is missing the recent changes")
#pragma message("in the Microsoft Win32 Platform SDK; some mod_isapi features")
#pragma message("will be disabled.  To obtain the latest Platform SDK files,")
#pragma message("please refer to:")
#pragma message("http://msdn.microsoft.com/downloads/sdks/platform/platform.asp")
#endif

module isapi_module;

static DWORD ReadAheadBuffer = 49152;
static int LogNotSupported = -1;
static int AppendLogToErrors = 0;
static int AppendLogToQuery = 0;

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
    DWORD read;
    char *p;
    int retval;
    int res;

    /* Use similar restrictions as CGIs */

    if (!(ap_allow_options(r) & OPT_EXECCGI))
        return FORBIDDEN;

    if (r->finfo.st_mode == 0)
        return NOT_FOUND;

    if (S_ISDIR(r->finfo.st_mode))
        return FORBIDDEN;

    if (!(isapi_handle = ap_os_dso_load(r->filename))) {
        ap_log_rerror(APLOG_MARK, APLOG_ALERT, r,
                      "ISAPI Could not load DLL: %s", r->filename);
        return SERVER_ERROR;
    }

    if (!(isapi_version =
          (void *)(ap_os_dso_sym(isapi_handle, "GetExtensionVersion")))) {
        ap_log_rerror(APLOG_MARK, APLOG_ALERT, r,
                      "DLL could not load GetExtensionVersion(): %s", 
                      r->filename);
        ap_os_dso_unload(isapi_handle);
        return SERVER_ERROR;
    }

    if (!(isapi_entry =
          (void *)(ap_os_dso_sym(isapi_handle, "HttpExtensionProc")))) {
        ap_log_rerror(APLOG_MARK, APLOG_ALERT, r,
                      "DLL could not load HttpExtensionProc(): %s", 
                      r->filename);
        ap_os_dso_unload(isapi_handle);
        return SERVER_ERROR;
    }

    isapi_term = (void *)(ap_os_dso_sym(isapi_handle, "TerminateExtension"));

    /* Run GetExtensionVersion() */

    if (!(*isapi_version)(pVer)) {
        ap_log_rerror(APLOG_MARK, APLOG_ALERT, r,
                      "ISAPI GetExtensionVersion() failed: %s", r->filename);
        ap_os_dso_unload(isapi_handle);
        return SERVER_ERROR;
    }

    /* Set up variables.  There are a couple of special cases for ISAPI.
     * XXX: These were taken verbatim from GetServerVariable, and should
     * be reviewed carefully.
     */
    ap_add_common_vars(r);
    ap_add_cgi_vars(r);
    ap_table_setn(r->subprocess_env, "UNMAPPED_REMOTE_USER", "REMOTE_USER");
    ap_table_setn(r->subprocess_env, "SERVER_PORT_SECURE", "0");
    ap_table_setn(r->subprocess_env, "URL", r->uri);

    /* Set up connection ID */
    ecb->ConnID = (HCONN)cid;
    cid->ecb = ecb;
    cid->r = r;
    cid->status = 0;

    ecb->cbSize = sizeof(struct _EXTENSION_CONTROL_BLOCK);
    ecb->dwVersion = MAKELONG(0, 2);
    ecb->dwHttpStatusCode = 0;
    strcpy(ecb->lpszLogData, "");
    ecb->lpszMethod = ap_pstrdup(r->pool, r->method);
    ecb->lpszQueryString = ap_pstrdup(r->pool, ap_table_get(e, "QUERY_STRING"));
    ecb->lpszPathInfo = ap_pstrdup(r->pool, ap_table_get(e, "PATH_INFO"));
    ecb->lpszPathTranslated = ap_pstrdup(r->pool, ap_table_get(e, "PATH_TRANSLATED"));
    ecb->lpszContentType = ap_pstrdup(r->pool, ap_table_get(e, "CONTENT_TYPE"));

    /* Set up client input */
    if ((retval = ap_setup_client_block(r, REQUEST_CHUNKED_ERROR))) {
        if (isapi_term) (*isapi_term)( 2 /* HSE_TERM_MUST_UNLOAD */);
        ap_os_dso_unload(isapi_handle);
        return retval;
    }

    if (ap_should_client_block(r)) {
        /* Time to start reading the appropriate amount of data,
         * and allow the administrator to tweak the number
         * TODO: add the httpd.conf option for ReadAheadBuffer.
         */
        if (r->remaining) {
            ecb->cbTotalBytes = r->remaining;
            if (ecb->cbTotalBytes > ReadAheadBuffer)
                ecb->cbAvailable = ReadAheadBuffer;
            else
                ecb->cbAvailable = ecb->cbTotalBytes;
        }
        else
        {
            ecb->cbTotalBytes = 0xffffffff;
            ecb->cbAvailable = ReadAheadBuffer;
        }

        ecb->lpbData = ap_pcalloc(r->pool, ecb->cbAvailable + 1);

        p = ecb->lpbData;
        read = 0;
        while (read < ecb->cbAvailable &&
               ((res = ap_get_client_block(r, ecb->lpbData + read,
                                           ecb->cbAvailable - read)) > 0)) {
            read += res;
        }

        if (res < 0) {
            if (isapi_term) (*isapi_term)(HSE_TERM_MUST_UNLOAD);
            ap_os_dso_unload(isapi_handle);
            return SERVER_ERROR;
        }

        /* Although its not to spec, IIS seems to null-terminate
         * its lpdData string. So we will too.
         *
         * XXX: This must be an issue... backing out the null
         * from the count of bytes.
         */
        if (res == 0)
            ecb->cbAvailable = ecb->cbTotalBytes = read;
        else
            ecb->cbAvailable = read;
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
        ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
                      "ISAPI: %s: %s", ecb->lpszLogData, r->filename);

    /* Soak up any remaining input */
    if (r->remaining > 0) {
        char argsbuffer[HUGE_STRING_LEN];
        while (ap_get_client_block(r, argsbuffer, HUGE_STRING_LEN) > 0);
    }

    /* All done with the DLL... get rid of it */
    if (isapi_term) (*isapi_term)(HSE_TERM_MUST_UNLOAD);
    ap_os_dso_unload(isapi_handle);

    switch(retval) {
    case 0:  /* Strange, but MS isapi accepts this as success */
    case HSE_STATUS_SUCCESS:
    case HSE_STATUS_SUCCESS_AND_KEEP_CONN:
        /* Ignore the keepalive stuff; Apache handles it just fine without
         * the ISA's "advice".
         */

        if (cid->status) /* We have a special status to return */
            return cid->status;

        return OK;
    case HSE_STATUS_PENDING:   /* We don't support this */
        if (LogNotSupported)
            ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, r,
                         "ISAPI asynchronous I/O not supported: %s", 
                         r->filename);
    case HSE_STATUS_ERROR:
    default:
        return SERVER_ERROR;
    }

}
#pragma optimize("",on)

BOOL WINAPI GetServerVariable (HCONN hConn, LPSTR lpszVariableName,
                               LPVOID lpvBuffer, LPDWORD lpdwSizeofBuffer) {
    request_rec *r = ((isapi_cid *)hConn)->r;
    const char *result;
    DWORD len;

    if (!strcmp(lpszVariableName, "ALL_HTTP")) {
        /* lf delimited, colon split, comma seperated and 
         * null terminated list of HTTP_ vars 
         */
        char **env = (char**) ap_table_elts(r->subprocess_env)->elts;
        int nelts = 2 * ap_table_elts(r->subprocess_env)->nelts;
        int i;

        for (len = 0, i = 0; i < nelts; i += 2)
            if (!strncmp(env[i], "HTTP_", 5))
                len += strlen(env[i]) + strlen(env[i + 1]) + 2;
  
        if (*lpdwSizeofBuffer < len + 1) {
            *lpdwSizeofBuffer = len + 1;
            SetLastError(ERROR_INSUFFICIENT_BUFFER);
            return FALSE;
        }
    
        for (i = 0; i < nelts; i += 2)
            if (!strncmp(env[i], "HTTP_", 5)) {
                strcpy(lpvBuffer, env[i]);
                ((char*)lpvBuffer) += strlen(env[i]);
                *(((char*)lpvBuffer)++) = ':';
                strcpy(lpvBuffer, env[i + 1]);
                ((char*)lpvBuffer) += strlen(env[i + 1]);
                *(((char*)lpvBuffer)++) = '\n';
            }            
        *(((char*)lpvBuffer)++) = '\0';
        *lpdwSizeofBuffer = len;
        return TRUE;
    }

    if (!strcmp(lpszVariableName, "ALL_RAW")) {
        /* lf delimited, colon split, comma seperated and 
         * null terminated list of the raw request header
         */
        char **raw = (char**) ap_table_elts(r->headers_in)->elts;
        int nelts = 2 * ap_table_elts(r->headers_in)->nelts;
        int i;        
        
        for (len = 0, i = 0; i < nelts; i += 2)
            len += strlen(raw[i]) + strlen(raw[i + 1]) + 2;
  
        if (*lpdwSizeofBuffer < len + 1) {
            *lpdwSizeofBuffer = len + 1;
            SetLastError(ERROR_INSUFFICIENT_BUFFER);
            return FALSE;
        }
    
        for (i = 0; i < nelts; i += 2) {
            strcpy(lpvBuffer, raw[i]);
            ((char*)lpvBuffer) += strlen(raw[i]);
            *(((char*)lpvBuffer)++) = ':';
            *(((char*)lpvBuffer)++) = ' ';
            strcpy(lpvBuffer, raw[i + 1]);
            ((char*)lpvBuffer) += strlen(raw[i + 1]);
            *(((char*)lpvBuffer)++) = '\n';
            i += 2;
        }
        *(((char*)lpvBuffer)++) = '\0';
        *lpdwSizeofBuffer = len;
        return TRUE;
    }

    /* Not a special case */
    result = ap_table_get(r->subprocess_env, lpszVariableName);
    if (result) {
        len = strlen(result);
        if (*lpdwSizeofBuffer < len + 1) {
            *lpdwSizeofBuffer = len + 1;
            SetLastError(ERROR_INSUFFICIENT_BUFFER);
            return FALSE;
        }
        strcpy(lpvBuffer, result);
        *lpdwSizeofBuffer = len;
        return TRUE;
    }

    /* Not Found */
    SetLastError(ERROR_INVALID_INDEX);
    return FALSE;
}

BOOL WINAPI WriteClient (HCONN ConnID, LPVOID Buffer, LPDWORD lpwdwBytes,
                         DWORD dwReserved) {
    request_rec *r = ((isapi_cid *)ConnID)->r;

    /* We only support synchronous writing */
    if (dwReserved && dwReserved != HSE_IO_SYNC) {
        if (LogNotSupported)
            ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, r,
                          "ISAPI asynchronous I/O not supported: %s", 
                          r->filename);
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    if ((*lpwdwBytes = ap_rwrite(Buffer, *lpwdwBytes, r)) <= 0) {
        if (!GetLastError())
            SetLastError(ERROR); /* XXX: Find the right error code */
        return FALSE;
    }

    return TRUE;
}

BOOL WINAPI ReadClient (HCONN ConnID, LPVOID lpvBuffer, LPDWORD lpdwSize) {
    request_rec *r = ((isapi_cid *)ConnID)->r;
    DWORD read = 0;
    int res;

    if (r->remaining < (long) *lpdwSize)
        *lpdwSize = r->remaining;

    while (read < *lpdwSize &&
           ((res = ap_get_client_block(r, (char*)lpvBuffer + read,
                                       *lpdwSize - read)) > 0)) {
        if (res < 0) {
            *lpdwSize = 0;
            if (!GetLastError())
                SetLastError(ERROR); /* XXX: Find the right error code */
            return FALSE;
        }

        read += res;
    }

    *lpdwSize = read;
    return TRUE;
}

static BOOL SendResponseHeaderEx(isapi_cid *cid, const char *stat,
                                 const char *head, DWORD statlen,
                                 DWORD headlen)
{
    int termarg;
    char *termch;

    if (!stat || statlen == 0 || !*stat) {
        stat = "Status: 200 OK";
    }
    else {
        char *newstat;
        newstat = ap_palloc(cid->r->pool, statlen + 9);
        strcpy(newstat, "Status: ");
        ap_cpystrn(newstat + 8, stat, statlen + 1);
        stat = newstat;
    }

    if (!head || headlen == 0 || !*head) {
        head = "\r\n";
    }
    else
    {
        if (head[headlen]) {
            /* Whoops... not NULL terminated */
            head = ap_pstrndup(cid->r->pool, head, headlen);
        }
    }

    /* Parse them out, or die trying */
    cid->status = ap_scan_script_header_err_strs(cid->r, NULL, &termch,
                                                 &termarg, stat, head, NULL);
    cid->ecb->dwHttpStatusCode = cid->r->status;

    /* All the headers should be set now */
    ap_send_http_header(cid->r);

    /* Any data left should now be sent directly,
     * it may be raw if headlen was provided.
     */
    if (termch && (termarg == 1)) {
        if (headlen == -1 && *termch)
            ap_rputs(termch, cid->r);
        else if (headlen > (size_t) (termch - head))
            ap_rwrite(termch, headlen - (termch - head), cid->r);
    }

    if (cid->status == HTTP_INTERNAL_SERVER_ERROR)
        return FALSE;
    return TRUE;
}

/* XXX: Is there is still an O(n^2) attack possible here?  Please detail. */
BOOL WINAPI ServerSupportFunction (HCONN hConn, DWORD dwHSERequest,
                                   LPVOID lpvBuffer, LPDWORD lpdwSize,
                                   LPDWORD lpdwDataType) {
    isapi_cid *cid = (isapi_cid *)hConn;
    request_rec *r = cid->r;
    request_rec *subreq;

    switch (dwHSERequest) {
    case 1: /* HSE_REQ_SEND_URL_REDIRECT_RESP */
        /* Set the status to be returned when the HttpExtensionProc()
         * is done.
         * WARNING: Microsoft now advertises HSE_REQ_SEND_URL_REDIRECT_RESP
         *          and HSE_REQ_SEND_URL as equivalant per the Jan 2000 SDK.
         *          They most definately are not, even in their own samples.
         */
        ap_table_set(r->headers_out, "Location", lpvBuffer);
        cid->status = cid->r->status
                    = cid->ecb->dwHttpStatusCode = HTTP_MOVED_TEMPORARILY;
        return TRUE;

    case 2: /* HSE_REQ_SEND_URL */
        /* Soak up remaining input (there should be none) */
        if (r->remaining > 0) {
            char argsbuffer[HUGE_STRING_LEN];
            while (ap_get_client_block(r, argsbuffer, HUGE_STRING_LEN) > 0);
        }

        /* Reset the method to GET */
        r->method = ap_pstrdup(r->pool, "GET");
        r->method_number = M_GET;

        /* Don't let anyone think there's still data */
        ap_table_unset(r->headers_in, "Content-Length");

        /* AV fault per PR3598 - redirected path is lost! */
        (char*)lpvBuffer = ap_pstrdup(r->pool, (char*)lpvBuffer);
        ap_internal_redirect((char*)lpvBuffer, r);
        return TRUE;

    case 3: /* HSE_REQ_SEND_RESPONSE_HEADER */
    {
        /* Parse them out, or die trying */
        DWORD statlen = 0, headlen = 0;
	if (lpvBuffer)
	    statlen = strlen((char*) lpvBuffer);
	if (lpdwDataType)
	    headlen = strlen((char*) lpdwDataType);
        return SendResponseHeaderEx(cid, (char*) lpvBuffer, (char*) lpdwDataType, 
                                    statlen, headlen);
    }

    case 4: /* HSE_REQ_DONE_WITH_SESSION */
        /* Do nothing... since we don't support async I/O, they'll
         * return from HttpExtensionProc soon
         */
        return TRUE;

    case 1001: /* HSE_REQ_MAP_URL_TO_PATH */
    {
        /* Map a URL to a filename */
        char *file = (char *)lpvBuffer;
	DWORD len;
        subreq = ap_sub_req_lookup_uri(ap_pstrndup(r->pool, file, *lpdwSize), r);

        len = ap_cpystrn(file, subreq->filename, *lpdwSize) - file;
	
        /* IIS puts a trailing slash on directories, Apache doesn't */
        if (S_ISDIR (subreq->finfo.st_mode)) {
            if (len < *lpdwSize - 1) {
                file[len++] = '\\';
                file[len] = '\0';
            }
        }
        *lpdwSize = len;
        return TRUE;
    }

    case 1002: /* HSE_REQ_GET_SSPI_INFO */
        if (LogNotSupported)
            ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, r,
                          "ISAPI ServerSupportFunction HSE_REQ_GET_SSPI_INFO "
                          "is not supported: %s", r->filename);
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;

    case 1003: /* HSE_APPEND_LOG_PARAMETER */
        /* Log lpvBuffer, of lpdwSize bytes, in the URI Query (cs-uri-query) field
         * This code will do for now...
         */
        ap_table_set(r->notes, "isapi-parameter", (char*) lpvBuffer);
        if (AppendLogToQuery) {
            if (r->args)
                r->args = ap_pstrcat(r->pool, r->args, (char*) lpvBuffer, NULL);
            else
                r->args = ap_pstrdup(r->pool, (char*) lpvBuffer);
        }
        if (AppendLogToErrors)
            ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_INFO, r,
                          "ISAPI %s: %s", cid->r->filename,
                          (char*) lpvBuffer);
        return TRUE;

    /* We don't support all this async I/O, Microsoft-specific stuff */
    case 1005: /* HSE_REQ_IO_COMPLETION */
    case 1006: /* HSE_REQ_TRANSMIT_FILE */
        if (LogNotSupported)
            ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, r,
                          "ISAPI asynchronous I/O not supported: %s", 
                          r->filename);
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;

    case 1007: /* HSE_REQ_REFRESH_ISAPI_ACL */
        /* Since we don't override the user ID and access, we can't reset.
         */
        if (LogNotSupported)
            ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, r,
                          "ISAPI ServerSupportFunction "
                          "HSE_REQ_REFRESH_ISAPI_ACL "
                          "is not supported: %s", r->filename);
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;

    case 1008: /* HSE_REQ_IS_KEEP_CONN */
        *((LPBOOL) lpvBuffer) = (r->connection->keepalive == 1);
        return TRUE;

    case 1010: /* HSE_REQ_ASYNC_READ_CLIENT */
        if (LogNotSupported)
            ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, r,
                          "ISAPI asynchronous I/O not supported: %s", 
                          r->filename);
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;

    case 1011: /* HSE_REQ_GET_IMPERSONATION_TOKEN  Added in ISAPI 4.0 */
        if (LogNotSupported)
            ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, r,
                          "ISAPI ServerSupportFunction "
                          "HSE_REQ_GET_IMPERSONATION_TOKEN "
                          "is not supported: %s", r->filename);
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;

#ifdef HSE_REQ_MAP_URL_TO_PATH_EX
    case 1012: /* HSE_REQ_MAP_URL_TO_PATH_EX */
    {
        /* Map a URL to a filename */
        LPHSE_URL_MAPEX_INFO info = (LPHSE_URL_MAPEX_INFO) lpdwDataType;
        char* test_uri = ap_pstrndup(r->pool, (char *)lpvBuffer, *lpdwSize);

        subreq = ap_sub_req_lookup_uri(test_uri, r);
        info->cchMatchingURL = strlen(test_uri);        
        info->cchMatchingPath = ap_cpystrn(info->lpszPath, subreq->filename, 
                                           MAX_PATH) - info->lpszPath;
        
        /* Mapping started with assuming both strings matched.
         * Now roll on the path_info as a mismatch and handle
         * terminating slashes for directory matches.
         */
        if (subreq->path_info && *subreq->path_info) {
            ap_cpystrn(info->lpszPath + info->cchMatchingPath, 
                       subreq->path_info, MAX_PATH - info->cchMatchingPath);
            info->cchMatchingURL -= strlen(subreq->path_info);
            if (S_ISDIR(subreq->finfo.st_mode)
                 && info->cchMatchingPath < MAX_PATH - 1) {
                /* roll forward over path_info's first slash */
                ++info->cchMatchingPath;
                ++info->cchMatchingURL;
            }
        }
        else if (S_ISDIR(subreq->finfo.st_mode)
                 && info->cchMatchingPath < MAX_PATH - 1) {
            /* Add a trailing slash for directory */
            info->lpszPath[info->cchMatchingPath++] = '/';
            info->lpszPath[info->cchMatchingPath] = '\0';
        }

        /* If the matched isn't a file, roll match back to the prior slash */
        if (!subreq->finfo.st_mode) {
            while (info->cchMatchingPath && info->cchMatchingURL) {
                if (info->lpszPath[info->cchMatchingPath - 1] == '/') 
                    break;
                --info->cchMatchingPath;
                --info->cchMatchingURL;
            }
        }
        
        /* Paths returned with back slashes */
        for (test_uri = info->lpszPath; *test_uri; ++test_uri)
            if (*test_uri == '/')
                *test_uri = '\\';
        
        /* is a combination of:
         * HSE_URL_FLAGS_READ         0x001 Allow read
         * HSE_URL_FLAGS_WRITE        0x002 Allow write
         * HSE_URL_FLAGS_EXECUTE      0x004 Allow execute
         * HSE_URL_FLAGS_SSL          0x008 Require SSL
         * HSE_URL_FLAGS_DONT_CACHE   0x010 Don't cache (VRoot only)
         * HSE_URL_FLAGS_NEGO_CERT    0x020 Allow client SSL cert
         * HSE_URL_FLAGS_REQUIRE_CERT 0x040 Require client SSL cert
         * HSE_URL_FLAGS_MAP_CERT     0x080 Map client SSL cert to account
         * HSE_URL_FLAGS_SSL128       0x100 Require 128-bit SSL cert
         * HSE_URL_FLAGS_SCRIPT       0x200 Allow script execution
         *
         * XxX: As everywhere, EXEC flags could use some work...
         *      and this could go further with more flags, as desired.
         */ 
        info->dwFlags = (subreq->finfo.st_mode & _S_IREAD  ? 0x001 : 0)
                      | (subreq->finfo.st_mode & _S_IWRITE ? 0x002 : 0)
                      | (subreq->finfo.st_mode & _S_IEXEC  ? 0x204 : 0);
        return TRUE;
    }
#endif

    case 1014: /* HSE_REQ_ABORTIVE_CLOSE */
        if (LogNotSupported)
            ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, r,
                          "ISAPI ServerSupportFunction HSE_REQ_ABORTIVE_CLOSE"
                          " is not supported: %s", r->filename);
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;

    case 1015: /* HSE_REQ_GET_CERT_INFO_EX  Added in ISAPI 4.0 */
        if (LogNotSupported)
            ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, r,
                          "ISAPI ServerSupportFunction "
                          "HSE_REQ_GET_CERT_INFO_EX "
                          "is not supported: %s", r->filename);
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;

#ifdef HSE_REQ_SEND_RESPONSE_HEADER_EX
    case 1016: /* HSE_REQ_SEND_RESPONSE_HEADER_EX  Added in ISAPI 4.0 */
    {
        LPHSE_SEND_HEADER_EX_INFO shi
                                  = (LPHSE_SEND_HEADER_EX_INFO) lpvBuffer;
        /* XXX: ignore shi->fKeepConn?  We shouldn't need the advise */
        /* r->connection->keepalive = shi->fKeepConn; */
        return SendResponseHeaderEx(cid, shi->pszStatus, shi->pszHeader,
                                         shi->cchStatus, shi->cchHeader);
    }
#endif

    case 1017: /* HSE_REQ_CLOSE_CONNECTION  Added after ISAPI 4.0 */
        if (LogNotSupported)
            ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, r,
                          "ISAPI ServerSupportFunction "
                          "HSE_REQ_CLOSE_CONNECTION "
                          "is not supported: %s", r->filename);
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;

    case 1018: /* HSE_REQ_IS_CONNECTED  Added after ISAPI 4.0 */
        /* Returns True if client is connected c.f. MSKB Q188346
         * XXX: That statement is very ambigious... assuming the 
         * identical return mechanism as HSE_REQ_IS_KEEP_CONN.
         */
        *((LPBOOL) lpvBuffer) = (r->connection->aborted == 0);
        return TRUE;

    case 1020: /* HSE_REQ_EXTENSION_TRIGGER  Added after ISAPI 4.0 */
        /*  Undocumented - defined by the Microsoft Jan '00 Platform SDK
         */
        if (LogNotSupported)
            ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, r,
                          "ISAPI ServerSupportFunction "
                          "HSE_REQ_EXTENSION_TRIGGER "
                          "is not supported: %s", r->filename);
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;


    default:
        if (LogNotSupported)
            ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, r,
                          "ISAPI ServerSupportFunction (%d) not supported: "
                          "%s", dwHSERequest, r->filename);
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
}

/*
 * Command handler for the ISAPIReadAheadBuffer directive, which is TAKE1
 */
static const char *isapi_cmd_readaheadbuffer(cmd_parms *cmd, void *config, 
                                             char *arg)
{
    long val;
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    if (((val = ap_strtol(arg, (char **) &err, 10)) <= 0) || *err)
        return "ISAPIReadAheadBuffer must be a legitimate value.";
    
    ReadAheadBuffer = val;
    return NULL;
}

/*
 * Command handler for the ISAPIReadAheadBuffer directive, which is TAKE1
 */
static const char *isapi_cmd_lognotsupported(cmd_parms *cmd, void *config, 
                                             char *arg)
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    if (strcasecmp(arg, "on") == 0) {
        LogNotSupported = -1;
    }
    else if (strcasecmp(arg, "off") == 0) {
        LogNotSupported = 0;
    }
    else {
        return "ISAPILogNotSupported must be on or off";
    }
    return NULL;
}

static const char *isapi_cmd_appendlogtoerrors(cmd_parms *cmd, void *config, 
                                               char *arg)
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    if (strcasecmp(arg, "on") == 0) {
        AppendLogToErrors = -1;
    }
    else if (strcasecmp(arg, "off") == 0) {
        AppendLogToErrors = 0;
    }
    else {
        return "ISAPIAppendLogToErrors must be on or off";
    }
    return NULL;
}

static const char *isapi_cmd_appendlogtoquery(cmd_parms *cmd, void *config, 
                                               char *arg)
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    if (strcasecmp(arg, "on") == 0) {
        AppendLogToQuery = -1;
    }
    else if (strcasecmp(arg, "off") == 0) {
        AppendLogToQuery = 0;
    }
    else {
        return "ISAPIAppendLogToQuery must be on or off";
    }
    return NULL;
}

static const command_rec isapi_cmds[] = {
{ "ISAPIReadAheadBuffer", isapi_cmd_readaheadbuffer, NULL, RSRC_CONF, TAKE1, 
  "Maximum bytes to initially pass to the ISAPI handler" },
{ "ISAPILogNotSupported", isapi_cmd_lognotsupported, NULL, RSRC_CONF, TAKE1, 
  "Log requests not supported by the ISAPI server" },
{ "ISAPIAppendLogToErrors", isapi_cmd_appendlogtoerrors, NULL, RSRC_CONF, TAKE1, 
  "Send all Append Log requests to the error log" },
{ "ISAPIAppendLogToQuery", isapi_cmd_appendlogtoquery, NULL, RSRC_CONF, TAKE1, 
  "Append Log requests are concatinated to the query args" },
{ NULL }
};

handler_rec isapi_handlers[] = {
{ "isapi-isa", isapi_handler },
{ NULL}
};

module isapi_module = {
   STANDARD_MODULE_STUFF,
   NULL,                        /* initializer */
   NULL,                        /* create per-dir config */
   NULL,                        /* merge per-dir config */
   NULL,                        /* server config */
   NULL,                        /* merge server config */
   isapi_cmds,                  /* command table */
   isapi_handlers,              /* handlers */
   NULL,                        /* filename translation */
   NULL,                        /* check_user_id */
   NULL,                        /* check auth */
   NULL,                        /* check access */
   NULL,                        /* type_checker */
   NULL,                        /* logger */
   NULL                         /* header parser */
};

#endif /* WIN32 */
