#include <windows.h>
#include <assert.h>
#include <sys/stat.h>
#include <stdarg.h>

#include "httpd.h"

static void sub_canonical_filename(char *szCanon, const char *szFile)
{
    char buf[HUGE_STRING_LEN];
    int n;
    char *szFilePart;
    WIN32_FIND_DATA d;
    HANDLE h;

    n = GetFullPathName(szFile, sizeof buf, buf, &szFilePart);
    assert(n);
    assert(n < sizeof buf);

    if (!strchr(buf, '*') && !strchr(buf, '?')) {
        h = FindFirstFile(buf, &d);
        if(h != INVALID_HANDLE_VALUE)
            FindClose(h);
    }
    else {
        h=INVALID_HANDLE_VALUE;
    }

    if (szFilePart < buf+3) {
        strcpy(szCanon, buf);
        szCanon[2] = '/';
        return;
    }
    if (szFilePart != buf+3) {
        char b2[_MAX_PATH];
        assert(szFilePart > buf+3);

        szFilePart[-1]='\0';
        sub_canonical_filename(b2, buf);

        strcpy(szCanon, b2);
        strcat(szCanon, "/");
    }
    else {
        strcpy(szCanon, buf);
        szCanon[2] = '/';
        szCanon[3] = '\0';
    }
    if (h == INVALID_HANDLE_VALUE)
        strcat(szCanon, szFilePart);
    else {
        strlwr(d.cFileName);
        strcat(szCanon, d.cFileName);
    }
}

API_EXPORT(char *) ap_os_canonical_filename(pool *pPool, const char *szFile)
{
    char buf[HUGE_STRING_LEN];

    sub_canonical_filename(buf, szFile);
    buf[0]=tolower(buf[0]);

    if (*szFile && szFile[strlen(szFile)-1] == '/')
        strcat(buf, "/");

    return ap_pstrdup(pPool, buf);
}

/* Win95 doesn't like trailing /s. NT and Unix don't mind. This works 
 * around the problem
 */

#undef stat
API_EXPORT(int) os_stat(const char *szPath, struct stat *pStat)
{
    int n;

    n = strlen(szPath);
    if(szPath[n-1] == '\\' || szPath[n-1] == '/') {
        char buf[_MAX_PATH];
        
        ap_assert(n < _MAX_PATH);
        strcpy(buf, szPath);
        buf[n-1] = '\0';
        
        return stat(buf, pStat);
    }
    return stat(szPath, pStat);
}

/* Fix two really crap problems with Win32 spawn[lv]e*:
 *
 *  1. Win32 doesn't deal with spaces in argv.
 *  2. Win95 doesn't like / in cmdname.
 */

#undef _spawnv
API_EXPORT(int) os_spawnv(int mode, const char *cmdname, const char *const *argv)
{
    int n;
    char **aszArgs;
    const char *szArg;
    char *szCmd;
    char *s;
    
    szCmd = _alloca(strlen(cmdname)+1);
    strcpy(szCmd, cmdname);
    for (s = szCmd; *s; ++s)
        if (*s == '/')
            *s = '\\';
    
    for (n=0; argv[n]; ++n)
        ;

    aszArgs = _alloca((n+1)*sizeof(const char *));

    for (n = 0; szArg = argv[n]; ++n)
        if (strchr(szArg, ' ')) {
            int l = strlen(szArg);

            aszArgs[n] = _alloca(l+2+1);
            aszArgs[n][0] = '"';
            strcpy(&aszArgs[n][1], szArg);
            aszArgs[n][l+1] = '"';
            aszArgs[n][l+2] = '\0';
        }
        else {
            aszArgs[n] = (char *)szArg;
        }

    aszArgs[n] = NULL;

    return _spawnv(mode, szCmd, aszArgs);
}

#undef _spawnve
API_EXPORT(int) os_spawnve(int mode, const char *cmdname, const char *const *argv, const char *const *envp)
{
    int n;
    char **aszArgs;
    const char *szArg;
    char *szCmd;
    char *s;
    
    szCmd = _alloca(strlen(cmdname)+1);
    strcpy(szCmd, cmdname);
    for (s = szCmd; *s; ++s)
        if (*s == '/')
            *s = '\\';
    
    for (n = 0; argv[n] ; ++n)
        ;

    aszArgs = _alloca((n+1)*sizeof(const char *));

    for (n = 0; szArg=argv[n]; ++n)
        if (strchr(szArg, ' ')) {
            int l = strlen(szArg);

            aszArgs[n] = _alloca(l+2+1);
            aszArgs[n][0] = '"';
            strcpy(&aszArgs[n][1], szArg);
            aszArgs[n][l+1] = '"';
            aszArgs[n][l+2] = '\0';
        }
        else {
            aszArgs[n]=(char *)szArg;
        }

    aszArgs[n] = NULL;

    return _spawnve(mode, szCmd, aszArgs, envp);
}

API_EXPORT(int) os_spawnle(int mode, const char *cmdname,...)
{
    int n;
    va_list vlist;
    char **aszArgs;
    const char *szArg;
    const char *const *aszEnv;
    char *szCmd;
    char *s;
    
    szCmd = _alloca(strlen(cmdname)+1);
    strcpy(szCmd, cmdname);
    for (s = szCmd; *s; ++s)
        if(*s == '/')
            *s = '\\';

    va_start(vlist, cmdname);
    for (n = 0; va_arg(vlist, const char *); ++n)
        ;
    va_end(vlist);

    aszArgs = _alloca((n+1)*sizeof(const char *));

    va_start(vlist, cmdname);
    for (n = 0 ; szArg = va_arg(vlist, const char *) ; ++n)
        if (strchr(szArg,' ')) {
            int l = strlen(szArg);

            aszArgs[n] = _alloca(l+2+1);
            aszArgs[n][0] = '"';
            strcpy(&aszArgs[n][1],szArg);
            aszArgs[n][l+1] = '"';
            aszArgs[n][l+2] = '\0';
        }
        else {
            aszArgs[n]=(char *)szArg;
        }

    aszArgs[n] = NULL;

    aszEnv = va_arg(vlist, const char *const *);
    va_end(vlist);
    
    return _spawnve(mode, szCmd, aszArgs, aszEnv);
}
