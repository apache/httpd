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

#define INCL_DOS
#define INCL_DOSERRORS
#include <os2.h>
#include "ap_config.h"
#include "httpd.h"
#include "http_log.h"
#include "os.h"
#include <sys/time.h>
#include <sys/signal.h>
#include <ctype.h>
#include <string.h>
#include "apr_strings.h"


AP_DECLARE(char *)ap_os_case_canonical_filename(apr_pool_t *pPool, const char *szFile)
{
    char buf[HUGE_STRING_LEN];
    char buf2[HUGE_STRING_LEN];
    int rc, len; 
    char *pos;
    
/* Remove trailing slash unless it's a root directory */
    strcpy(buf, szFile);
    len = strlen(buf);
    
    if (len > 3 && buf[len-1] == '/')
        buf[--len] = 0;
      
    rc = DosQueryPathInfo(buf, FIL_QUERYFULLNAME, buf2, HUGE_STRING_LEN);

    if (rc) {
        if (rc != ERROR_INVALID_NAME) {
            ap_log_error(APLOG_MARK, APLOG_ERR, APR_OS2_STATUS(rc), NULL, "for file [%s]", szFile);
        }
        apr_cpystrn(buf2, buf, sizeof(buf2));
    }

/* Switch backslashes to forward */
    for (pos=buf2; *pos; pos++)
        if (*pos == '\\')
            *pos = '/';
    
    return apr_pstrdup(pPool, buf2);
}



static void fix_component(char *path, char *lastcomp)
{
    FILEFINDBUF3 fb3;
    HDIR hDir = HDIR_CREATE;
    ULONG numNames = 1;
    ULONG rc = DosFindFirst( (UCHAR *)path, &hDir, FILE_NORMAL|FILE_DIRECTORY, &fb3, sizeof(fb3), &numNames, FIL_STANDARD );

    if (rc == 0)
        strcpy(lastcomp, fb3.achName);

    DosFindClose(hDir);
}



char *ap_os_systemcase_canonical_filename(apr_pool_t *pPool, const char *szFile)
{
    char *szCanonicalFile = ap_os_case_canonical_filename(pPool, szFile);
    int startslash = 2, slashnum=0;
    char *pos, *prevslash = NULL;

    if (szCanonicalFile[0] == '/' && szCanonicalFile[1] == '/') /* a UNC name */
        startslash = 5;

    for (pos = szCanonicalFile; *pos; pos++) {
        if (*pos == '/') {
            slashnum++;
            if (slashnum >= startslash) {
                *pos = 0;
                fix_component(szCanonicalFile, prevslash+1);
                *pos = '/';
            }
            prevslash = pos;
        }
    }

    if (slashnum >= startslash) {
        fix_component(szCanonicalFile, prevslash+1);
    }

    return szCanonicalFile;
}



char *ap_os_canonical_filename(apr_pool_t *pPool, const char *szFile)
{
    char *szCanonicalFile;
    const unsigned char *pos = szFile;

    /* Find any 8 bit characters */
    while (*pos && *pos < 128) {
        pos++;
    }

    /* Only use the very expensive ap_os_systemcase_canonical_filename() if
     * the file name contains non-english characters as they are the only type
     * that can't be made canonical with a simple strlwr() 
     */
    if (*pos < 128) {
        szCanonicalFile = ap_os_case_canonical_filename(pPool, szFile);
    } else {
        szCanonicalFile = ap_os_systemcase_canonical_filename(pPool, szFile);
    }

    strlwr(szCanonicalFile);
    return szCanonicalFile;
}

AP_DECLARE(apr_status_t) ap_os_create_privileged_process(
    const request_rec *r,
    apr_proc_t *newproc, const char *progname,
    const char * const *args,
    const char * const *env,
    apr_procattr_t *attr, apr_pool_t *p)
{
    return apr_proc_create(newproc, progname, args, env, attr, p);
}
