#define INCL_DOS
#define INCL_DOSERRORS
#include <os2.h>
#include "httpd.h"
#include "http_log.h"


API_EXPORT(char *)ap_os_canonical_filename(ap_context_t *pPool, const char *szFile)
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




int (*os2_select)( int *, int, int, int, long ) = NULL;
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
