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

#define INCL_DOS
#define INCL_DOSERRORS
#include <os2.h>
#include "httpd.h"
#include "http_log.h"


API_EXPORT(char *)ap_os_case_canonical_filename(pool *pPool, const char *szFile)
{
    char *buf;
    char buf2[CCHMAXPATH];
    int rc, len; 
    char *pos;
    
/* Remove trailing slash unless it's a root directory */
    len = strlen(szFile);
    buf = ap_pstrndup(pPool, szFile, len);
    
    if (len > 3 && buf[len-1] == '/')
        buf[--len] = 0;

    if (buf[0] == '/' && buf[1] == '/') {
        /* A UNC path */
        if (strchr(buf+2, '/') == NULL) {  /* Allow // or //server */
            return ap_pstrdup(pPool, buf);
        }
    }

    rc = DosQueryPathInfo(buf, FIL_QUERYFULLNAME, buf2, sizeof(buf2));

    if (rc) {
        if ( rc != ERROR_INVALID_NAME ) {
            ap_log_error(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, NULL, "OS/2 error %d for file %s", rc, szFile);
        }

        return ap_pstrdup(pPool, szFile);
    }

/* Switch backslashes to forward */
    for (pos=buf2; *pos; pos++)
        if (*pos == '\\')
            *pos = '/';
    
    return ap_pstrdup(pPool, buf2);
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



char *ap_os_systemcase_canonical_filename(pool *pPool, const char *szFile)
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



API_EXPORT(char *)ap_os_canonical_filename(pool *pPool, const char *szFile)
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
  char message[HUGE_STRING_LEN];
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
          while (ap_isspace(message[c]) && ap_isspace(message[c+1])) /* skip multiple whitespace */
              c++;
          *(pos++) = ap_isspace(message[c]) ? ' ' : message[c];
      }
  
      *pos = 0;
  } else {
      sprintf(result, "OS/2 error %d", err);
  }
  
  return result;
}
