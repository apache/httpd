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


API_EXPORT(char *)ap_os_case_canonical_filename(apr_pool_t *pPool, const char *szFile)
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
        if ( rc != ERROR_INVALID_NAME ) {
            ap_log_error(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, NULL, "OS/2 error %d for file %s", rc, szFile);
            return apr_pstrdup(pPool, "");
        } else {
            return apr_pstrdup(pPool, szFile);
        }
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
    char *szCanonicalFile = ap_os_systemcase_canonical_filename(pPool, szFile);
    strlwr(szCanonicalFile);
    return szCanonicalFile;
}



int ap_os_kill(pid_t pid, int sig)
{
/* SIGTERM's don't work too well in OS/2 (only affects other EMX programs).
   CGIs may not be, esp. REXX scripts, so use a native call instead */
   
    int rc;
    
    if ( sig == SIGTERM ) {
        rc = DosSendSignalException( pid, XCPT_SIGNAL_BREAK );
        
        if ( rc ) {
            errno = ESRCH;
            rc = -1;
        }
    } else {
        rc = kill(pid, sig);
    }
    
    return rc;
}



char *ap_os_error_message(int err)
{
  static char result[200];
  unsigned char message[HUGE_STRING_LEN];
  ULONG len;
  char *pos;
  int c;
  
  if (DosGetMessage(NULL, 0, message, HUGE_STRING_LEN, err, "OSO001.MSG", &len) == 0) {
      len--;
      message[len] = 0;
      pos = result;
  
      if (len >= sizeof(result))
        len = sizeof(result-1);

      for (c=0; c<len; c++) {
          while (isspace(message[c]) && isspace(message[c+1])) /* skip multiple whitespace */
              c++;
          *(pos++) = isspace(message[c]) ? ' ' : message[c];
      }
  
      *pos = 0;
  } else {
      sprintf(result, "OS/2 error %d", err);
  }
  
  return result;
}




static int (*os2_select)( int *, int, int, int, long ) = NULL;
static HMODULE hSO32DLL;

int ap_select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout)
{
    int *fds, s, fd_count=0, rc;
    int num_read, num_write, num_except;
    long ms_timeout = -1;

    if (os2_select == NULL) {
        DosEnterCritSec(); /* Stop two threads doing this at the same time */

        if (os2_select == NULL) {
            hSO32DLL = ap_os_dso_load("SO32DLL");

            if (hSO32DLL) {
                os2_select = ap_os_dso_sym(hSO32DLL, "SELECT");
            }
        }
        DosExitCritSec();
    }

    ap_assert(os2_select != NULL);
    fds = alloca(sizeof(int) * nfds);

    if (readfds) {
        for (s=0; s<nfds; s++)
            if (FD_ISSET(s, readfds))
                fds[fd_count++] = _getsockhandle(s);
    }

    num_read = fd_count;

    if (writefds) {
        for (s=0; s<nfds; s++)
            if (FD_ISSET(s, writefds))
                fds[fd_count++] = _getsockhandle(s);
    }

    num_write = fd_count - num_read;

    if (exceptfds) {
        for (s=0; s<nfds; s++)
            if (FD_ISSET(s, exceptfds))
                fds[fd_count++] = _getsockhandle(s);
    }

    num_except = fd_count - num_read - num_write;

    if (timeout)
        ms_timeout = timeout->tv_usec / 1000 + timeout->tv_sec * 1000;

    rc = os2_select(fds, num_read, num_write, num_except, ms_timeout);

    if (rc > 0) {
        fd_count = 0;

        if (readfds) {
            for (s=0; s<nfds; s++) {
                if (FD_ISSET(s, readfds)) {
                    if (fds[fd_count++] < 0)
                        FD_CLR(s, readfds);
                }
            }
        }

        if (writefds) {
            for (s=0; s<nfds; s++) {
                if (FD_ISSET(s, writefds)) {
                    if (fds[fd_count++] < 0)
                        FD_CLR(s, writefds);
                }
            }
        }

        if (exceptfds) {
            for (s=0; s<nfds; s++) {
                if (FD_ISSET(s, exceptfds)) {
                    if (fds[fd_count++] < 0)
                        FD_CLR(s, exceptfds);
                }
            }
        }
    }

    return rc;
}
