#define INCL_DOSFILEMGR
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
    ap_assert(rc == 0);
    strlwr(buf2);
    
/* Switch backslashes to forward */
    for (pos=buf2; *pos; pos++)
        if (*pos == '\\')
            *pos = '/';
    
    return ap_pstrdup(pPool, buf2);
}
