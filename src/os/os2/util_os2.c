#define INCL_DOS
#define INCL_DOSERRORS
#include <os2.h>
#include "httpd.h"
#include "http_log.h"


API_EXPORT(char *)ap_os_canonical_filename(pool *pPool, const char *szFile)
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
            ap_log_error(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, NULL, "OS/2 error %d for file %s", rc, szFile);
            return ap_pstrdup(pPool, "");
        } else {
            return ap_pstrdup(pPool, szFile);
        }
    }

    strlwr(buf2);
    
/* Switch backslashes to forward */
    for (pos=buf2; *pos; pos++)
        if (*pos == '\\')
            *pos = '/';
    
    return ap_pstrdup(pPool, buf2);
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
