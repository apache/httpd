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

static DWORD ReadAheadBuffer = 49152;

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
    char *fspec;
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

    /* Load the module...
     * per PR2555, the LoadLibraryEx function is very picky about slashes.
     * Debugging on NT 4 SP 6a reveals First Chance Exception within NTDLL.
     * LoadLibrary in the MS PSDK also reveals that it -explicitly- states
     * that backslashes must be used.
     *
     * Transpose '\' for '/' in the filename.
     */
    p = fspec = ap_pstrdup(r->pool, r->filename);
    while (*p) {
        if (*p == '/')
            *p = '\\';
        ++p;
    }

    if (!(isapi_handle = LoadLibraryEx(fspec, NULL,
                                       LOAD_WITH_ALTERED_SEARCH_PATH))) {
        if (!(isapi_handle = LoadLibraryEx(fspec, NULL, 0))) {
            ap_log_rerror(APLOG_MARK, APLOG_ALERT, r,
                          "Could not load DLL: %s", r->filename);
            return SERVER_ERROR;
        }
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

    if (!(*isapi_version)(pVer)) {
        ap_log_rerror(APLOG_MARK, APLOG_ALERT, r,
                      "ISAPI GetExtensionVersion() failed: %s", r->filename);
        FreeLibrary(isapi_handle);
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
    ecb->lpszMethod = r->method;
    ecb->lpszQueryString = ap_table_get(e, "QUERY_STRING");
    ecb->lpszPathInfo = ap_table_get(e, "PATH_INFO");
    ecb->lpszPathTranslated = ap_table_get(e, "PATH_TRANSLATED");
    ecb->lpszContentType = ap_table_get(e, "CONTENT_TYPE");

    /* Set up client input */
    if ((retval = ap_setup_client_block(r, REQUEST_CHUNKED_ERROR))) {
        if (isapi_term) (*isapi_term)( 2 /* HSE_TERM_MUST_UNLOAD */);
        FreeLibrary(isapi_handle);
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
            FreeLibrary(isapi_handle);
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
    case HSE_STATUS_PENDING:   /* We don't support this */
        ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, r,
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
    const char *result;

    if (!strcmp(lpszVariableName, "ALL_HTTP")) {
        /* lf delimited, colon split, comma seperated and 
         * null terminated list of HTTP_ vars 
         */
        char **env = (char**) ap_table_elts(r->subprocess_env)->elts;
        int n = ap_table_elts(r->subprocess_env)->nelts;
        int len = 0;
        int i = 0;

        while (i < n * 2) {
            if (!strncmp(env[i], "HTTP_", 5))
                len += strlen(env[i]) + strlen(env[i + 1]) + 2;
            i += 2;
        }
  
        if (*lpdwSizeofBuffer < len + 1) {
            SetLastError(ERROR_INSUFFICIENT_BUFFER);
            return FALSE;
        }
    
        i = 0;
        while (i < n * 2) {
            if (!strncmp(env[i], "HTTP_", 5)) {
                strcpy(lpvBuffer, env[i]);
                ((char*)lpvBuffer) += strlen(env[i]);
                *(((char*)lpvBuffer)++) = ':';
                strcpy(lpvBuffer, env[i + 1]);
                ((char*)lpvBuffer) += strlen(env[i + 1]);
                *(((char*)lpvBuffer)++) = '\n';
            }
            i += 2;
        }
        *(((char*)lpvBuffer)++) = '\0';
        *lpdwSizeofBuffer = len;
        return TRUE;
    }
    else if (!strcmp(lpszVariableName, "ALL_RAW")) {
        /* lf delimited, colon split, comma seperated and 
         * null terminated list of the raw request header
         */
        char **raw = (char**) ap_table_elts(r->headers_in)->elts;
        int n = ap_table_elts(r->headers_in)->nelts;
        int len = 0;
        int i = 0;

        while (i < n * 2) {
            len += strlen(raw[i]) + strlen(raw[i + 1]) + 2;
            i += 2;
        }
  
        if (*lpdwSizeofBuffer < len + 1) {
            SetLastError(ERROR_INSUFFICIENT_BUFFER);
            return FALSE;
        }
    
        i = 0;
        while (i < n * 2) {
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
    else {    
        result = ap_table_get(r->subprocess_env, lpszVariableName);
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

    /* Didn't find it - should this be ERROR_NO_DATA? */
    SetLastError(ERROR_INVALID_INDEX);
    return FALSE;
}

BOOL WINAPI WriteClient (HCONN ConnID, LPVOID Buffer, LPDWORD lpwdwBytes,
                         DWORD dwReserved) {
    request_rec *r = ((isapi_cid *)ConnID)->r;

    /* We only support synchronous writing */
    if (dwReserved && dwReserved != HSE_IO_SYNC) {
        ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, r,
                     "ISAPI asynchronous I/O not supported: %s", r->filename);
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
                                 const char *head, size_t statlen,
                                 size_t headlen)
{
    int termarg;
    char *termch;

    if (!stat || !*stat) {
        stat = "Status: 200 OK";
    }
    else {
        char *newstat;
        if (statlen == 0)
            statlen = strlen(stat);
        /* Whoops... not NULL terminated */
        newstat = ap_palloc(cid->r->pool, statlen + 9);
        strcpy(newstat, "Status: ");
        strncpy(newstat + 8, stat, statlen);
        stat = newstat;
    }

    if (!head || !*head) {
        head = "\r\n";
    }
    else if ((headlen >= 0) && head[headlen]) {
        /* Whoops... not NULL terminated */
        head = ap_pstrndup(cid->r->pool, head, headlen);
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
        /* Parse them out, or die trying */
        return SendResponseHeaderEx(cid, (char*) lpvBuffer,
                                    (char*) lpdwDataType, -1, -1);

    case 4: /* HSE_REQ_DONE_WITH_SESSION */
        /* Do nothing... since we don't support async I/O, they'll
         * return from HttpExtensionProc soon
         */
        return TRUE;

    case 1001: /* HSE_REQ_MAP_URL_TO_PATH */
        /* Map a URL to a filename
         */
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

    case 1002: /* HSE_REQ_GET_SSPI_INFO */
        SetLastError(ERROR_INVALID_PARAMETER);
        ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, r,
                      "ISAPI ServerSupportFunction HSE_REQ_GET_SSPI_INFO "
                      "is not supported: %s", r->filename);
        return FALSE;

    case 1003: /* HSE_APPEND_LOG_PARAMETER */
        /* Log lpvBuffer, of lpdwSize bytes, in the URI Query (cs-uri-query) field
         * This code will do for now...
         */
        ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_INFO, r,
                      "ISAPI %s: %s", cid->r->filename,
                      (char*) lpvBuffer);
        return TRUE;

    /* We don't support all this async I/O, Microsoft-specific stuff */
    case 1005: /* HSE_REQ_IO_COMPLETION */
    case 1006: /* HSE_REQ_TRANSMIT_FILE */
        SetLastError(ERROR_INVALID_PARAMETER);
        ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, r,
                     "ISAPI asynchronous I/O not supported: %s", r->filename);
        return FALSE;

    case 1007: /* HSE_REQ_REFRESH_ISAPI_ACL */
        /* Since we don't override the user ID and access, we can't reset.
         */
        SetLastError(ERROR_INVALID_PARAMETER);
        ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, r,
                      "ISAPI ServerSupportFunction HSE_REQ_REFRESH_ISAPI_ACL "
                      "is not supported: %s", r->filename);
        return FALSE;

    case 1008: /* HSE_REQ_IS_KEEP_CONN */
        *((LPBOOL) lpvBuffer) = (r->connection->keepalive == 1);
        return TRUE;

    case 1010: /* HSE_REQ_ASYNC_READ_CLIENT */
        SetLastError(ERROR_INVALID_PARAMETER);
        ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, r,
                     "ISAPI asynchronous I/O not supported: %s", r->filename);
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;

    case 1011: /* HSE_REQ_GET_IMPERSONATION_TOKEN  Added in ISAPI 4.0 */
        SetLastError(ERROR_INVALID_PARAMETER);
        ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, r,
                      "ISAPI ServerSupportFunction HSE_REQ_ABORTIVE_CLOSE "
                      "is not supported: %s", r->filename);
        return FALSE;

    case 1012: /* HSE_REQ_MAP_URL_TO_PATH_EX */
        SetLastError(ERROR_INVALID_PARAMETER);
        ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, r,
                      "ISAPI ServerSupportFunction HSE_REQ_ABORTIVE_CLOSE "
                      "is not supported: %s", r->filename);
        return FALSE;

        /* TODO: Not quite ready for prime time yet */

        /* Map a URL to a filename */
        subreq = ap_sub_req_lookup_uri(ap_pstrndup(r->pool, (char *)lpvBuffer,
                                                   *lpdwSize), r);

        GetFullPathName(subreq->filename, *lpdwSize - 1, (char *)lpvBuffer, NULL);

        /* IIS puts a trailing slash on directories, Apache doesn't */

        if (S_ISDIR(subreq->finfo.st_mode)) {
            int l = strlen((char *)lpvBuffer);

            ((char *)lpvBuffer)[l] = '\\';
            ((char *)lpvBuffer)[l + 1] = '\0';
        }

        lpdwDataType = (LPDWORD) ap_palloc(r->pool, sizeof(HSE_URL_MAPEX_INFO));
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
         *
         * Here we have a headache... MS identifies the significant length
         * of the Path and URL that actually match one another.
         */
        return TRUE;

    case 1014: /* HSE_REQ_ABORTIVE_CLOSE */
        SetLastError(ERROR_INVALID_PARAMETER);
        ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, r,
                      "ISAPI ServerSupportFunction HSE_REQ_ABORTIVE_CLOSE "
                      "is not supported: %s", r->filename);
        return FALSE;

    case 1015: /* HSE_REQ_GET_CERT_INFO_EX  Added in ISAPI 4.0 */
        SetLastError(ERROR_INVALID_PARAMETER);
        ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, r,
                      "ISAPI ServerSupportFunction HSE_REQ_GET_CERT_INFO_EX "
                      "is not supported: %s", r->filename);
        return FALSE;

    case 1016: /* HSE_REQ_SEND_RESPONSE_HEADER_EX  Added in ISAPI 4.0 */
    {
        LPHSE_SEND_HEADER_EX_INFO shi
                                  = (LPHSE_SEND_HEADER_EX_INFO) lpvBuffer;
        /* XXX: ignore shi->fKeepConn?  We shouldn't need the advise */
        /* r->connection->keepalive = shi->fKeepConn; */
        return SendResponseHeaderEx(cid, shi->pszStatus, shi->pszHeader,
                                         shi->cchStatus, shi->cchHeader);
    }

    case 1017: /* HSE_REQ_CLOSE_CONNECTION  Added after ISAPI 4.0 */
        ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, r,
                      "ISAPI ServerSupportFunction HSE_REQ_CLOSE_CONNECTION "
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
        SetLastError(ERROR_INVALID_PARAMETER);
        ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, r,
                      "ISAPI ServerSupportFunction HSE_REQ_EXTENSION_TRIGGER "
                      "is not supported: %s", r->filename);
        return FALSE;


    default:
        SetLastError(ERROR_INVALID_PARAMETER);
        ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, r,
                      "ISAPI ServerSupportFunction (%d) not supported: %s",
                      dwHSERequest, r->filename);
        return FALSE;
    }
}

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
   NULL,                        /* command table */
   isapi_handlers,              /* handlers */
   NULL,                        /* filename translation */
   NULL,                        /* check_user_id */
   NULL,                        /* check auth */
   NULL,                        /* check access */
   NULL,                        /* type_checker */
   NULL,                        /* logger */
   NULL                         /* header parser */
};
