#include <windows.h>
#include <sys/stat.h>
#include <stdarg.h>

#include "httpd.h"
#include "http_log.h"

/* Returns TRUE if the path is real, FALSE if it is PATH_INFO */
static BOOL sub_canonical_filename(char *szCanon, unsigned nCanon,
				   const char *szInFile)
{
    char buf[HUGE_STRING_LEN];
    int n;
    char *szFilePart;
    char *s;
    int nSlashes;
    WIN32_FIND_DATA d;
    HANDLE h;
    const char *szFile;

    szFile = szInFile;
    s = strrchr(szFile, '\\');
    for (nSlashes = 0; s > szFile && s[-1] == '\\'; ++nSlashes, --s)
	;

    if (strlen(szFile)==2 && szFile[1]==':') {
        /*
         * If the file name is x:, do not call GetFullPathName
         * because it will use the current path of the executable
         */
        strcpy(buf,szFile);
        n = strlen(buf);
        szFilePart = buf + n;
    }
    else {
        n = GetFullPathName(szFile, sizeof buf, buf, &szFilePart);
    }
    ap_assert(n);
    ap_assert(n < sizeof buf);

    /*
     * There is an implicit assumption that szInFile will contain a '\'.
     * If this is not true (as in the case of <Directory *> or
     * <File .htaccess>) we would assert in some of the code below.  Therefore,
     * if we don't get any '\' in the file name, then use the file name we get
     * from GetFullPathName, because it will have at least one '\'.  If there
     * is no '\' in szInFile, it must just be a file name, so it should be
     * valid to use the name from GetFullPathName.  Be sure to adjust the
     * 's' variable so the rest of the code functions normally.
     * Note it is possible to get here when szFile == 'x:', but that is OK
     * because we will bail out of this routine early.
     */
    if (!s) {
        szFile = buf;
        s = strrchr(szFile, '\\');
    }

    /* If we have \\machine\share, convert to \\machine\share\ */
    if (buf[0] == '\\' && buf[1] == '\\') {
	char *s = strchr(buf + 2, '\\');
	if (s && !strchr(s + 1, '\\')) {
	    strcat(s + 1, "\\");
	}
    }

    if (!strchr(buf, '*') && !strchr(buf, '?')) {
        h = FindFirstFile(buf, &d);
        if (h != INVALID_HANDLE_VALUE) {
            FindClose(h);
	}
    }
    else {
        h = INVALID_HANDLE_VALUE;
    }

    if (szFilePart < buf + 3) {
	ap_assert(strlen(buf) < nCanon);
        strcpy(szCanon, buf);
	/* a \ at the start means it is UNC, otherwise it is x: */
	if (szCanon[0] != '\\') {
	    ap_assert(ap_isalpha(szCanon[0]));
	    ap_assert(szCanon[1] == ':');
	    szCanon[2] = '/';
	}
	else {
	    char *s;

	    ap_assert(szCanon[1] == '\\');
	    for (s = szCanon; *s; ++s) {
		if (*s == '\\') {
		    *s = '/';
		}
	    }
	}
        return TRUE;
    }
    if (szFilePart != buf + 3) {
        char b2[_MAX_PATH];
	char b3[_MAX_PATH];
        ap_assert(szFilePart > buf + 3);
	/* avoid SEGVs on things like "Directory *" */
	ap_assert(s >= szFile && "this is a known bug");

	memcpy(b3, szFile, s - szFile);
	b3[s - szFile] = '\0';

/*        szFilePart[-1] = '\0'; */
        sub_canonical_filename(b2, sizeof b2, b3);

	ap_assert(strlen(b2)+1 < nCanon);
        strcpy(szCanon, b2);
        strcat(szCanon, "/");
    }
    else {
	ap_assert(strlen(buf) < nCanon);
        strcpy(szCanon, buf);
        szCanon[2] = '/';
        szCanon[3] = '\0';
    }
    if (h == INVALID_HANDLE_VALUE) {
	ap_assert(strlen(szCanon) + strlen(szFilePart) + nSlashes < nCanon);
	for (n = 0; n < nSlashes; ++n) {
	    strcat(szCanon, "/");
	}
        strcat(szCanon, szFilePart);
	return FALSE;
    }
    else {
	ap_assert(strlen(szCanon)+strlen(d.cFileName) < nCanon);
        strlwr(d.cFileName);
        strcat(szCanon, d.cFileName);
	return TRUE;
    }
}

/* UNC requires backslashes, hence the conversion before canonicalisation. 
 * Not sure how * many backslashes (could be that 
 * \\machine\share\some/path/is/ok for example). For now, do them all.
 */
API_EXPORT(char *) ap_os_canonical_filename(pool *pPool, const char *szFile)
{
    char buf[HUGE_STRING_LEN];
    char b2[HUGE_STRING_LEN];
    const char *s;
    char *d;
    int nSlashes = 0;

    ap_assert(strlen(szFile) < sizeof b2);

    /* Eliminate directories consisting of three or more dots.
     * These act like ".." but are not detected by other machinery.
     * Also get rid of trailing .s on any path component, which are ignored
     * by the filesystem.  Simultaneously, rewrite / to \.
     * This is a bit of a kludge - Ben.
     */
    if (strlen(szFile) == 1) {
        /*
         * If the file is only one char (like in the case of / or .) then
	 * just pass that through to sub_canonical_filename.  Convert a
	 * '/' to '\\' if necessary.
         */
        if (szFile[0] == '/') {
            b2[0] = '\\';
	}
        else {
            b2[0] = szFile[0];
	}

        b2[1] = '\0';
    }
    else {
        for (s = szFile, d = b2; (*d = *s); ++d, ++s) {
	    if (*s == '/') {
		*d = '\\';
	    }
	    if (*s == '.' && (s[1] == '/' || s[1] == '\\' || !s[1])) {
		while (*d == '.') {
		    --d;
		}
		if (*d == '\\') {
		    --d;
		}
	    }
	}

        /* Finally, a trailing slash(es) screws thing, so blow them away */
        for (nSlashes = 0; d > b2 && d[-1] == '\\'; --d, ++nSlashes)
	    ;
        /* XXXX this breaks '/' and 'c:/' cases */
        *d = '\0';
    }
    sub_canonical_filename(buf, sizeof buf, b2);

    buf[0] = ap_tolower(buf[0]);

    if (nSlashes) {
        /*
         * If there were additional trailing slashes, add them back on.
         * Be sure not to add more than were originally there though,
         * by checking to see if sub_canonical_filename added one;
         * this could happen in cases where the file name is 'd:/'
         */
        ap_assert(strlen(buf)+nSlashes < sizeof buf);

        if (nSlashes && buf[strlen(buf)-1] == '/')
            nSlashes--;

        while (nSlashes--) {
            strcat(buf, "/");
        }
    }

    return ap_pstrdup(pPool, buf);
}

/* Win95 doesn't like trailing /s. NT and Unix don't mind. This works 
 * around the problem.
 * Errr... except if it is UNC and we are referring to the root of 
 * the UNC, we MUST have a trailing \ and we can't use /s. Jeez. 
 * Not sure if this refers to all UNCs or just roots,
 * but I'm going to fix it for all cases for now. (Ben)
 */

#undef stat
API_EXPORT(int) os_stat(const char *szPath, struct stat *pStat)
{
    int n;

    /* be sure it is has a drive letter or is a UNC path; everything
     * _must_ be canonicalized before getting to this point.  
     */
    if (szPath[1] != ':' && szPath[1] != '/') {
	ap_log_error(APLOG_MARK, APLOG_ERR, NULL, 
		     "Invalid path in os_stat: \"%s\", "
		     "should have a drive letter or be a UNC path",
		     szPath);
	return (-1);
    }

    if (szPath[0] == '/') {
	char buf[_MAX_PATH];
	char *s;
	int nSlashes = 0;

	ap_assert(strlen(szPath) < _MAX_PATH);
	strcpy(buf, szPath);
	for (s = buf; *s; ++s) {
	    if (*s == '/') {
		*s = '\\';
		++nSlashes;
	    }
	}
	/* then we need to add one more to get \\machine\share\ */
	if (nSlashes == 3) {
	    *s++ = '\\';
	}
	*s = '\0';
	return stat(buf, pStat);
    }

    /*
     * Below removes the trailing /, however, do not remove
     * it in the case of 'x:/' or stat will fail
     */
    n = strlen(szPath);
    if ((szPath[n - 1] == '\\' || szPath[n - 1] == '/') &&
        !(n == 3 && szPath[1] == ':')) {
        char buf[_MAX_PATH];
        
        ap_assert(n < _MAX_PATH);
        strcpy(buf, szPath);
        buf[n - 1] = '\0';
        
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
API_EXPORT(int) os_spawnv(int mode, const char *cmdname,
			  const char *const *argv)
{
    int n;
    char **aszArgs;
    const char *szArg;
    char *szCmd;
    char *s;
    
    szCmd = _alloca(strlen(cmdname)+1);
    strcpy(szCmd, cmdname);
    for (s = szCmd; *s; ++s) {
        if (*s == '/') {
            *s = '\\';
	}
    }

    for (n = 0; argv[n]; ++n)
        ;

    aszArgs = _alloca((n + 1) * sizeof(const char *));

    for (n = 0; szArg = argv[n]; ++n) {
        if (strchr(szArg, ' ')) {
            int l = strlen(szArg);

            aszArgs[n] = _alloca(l + 2 + 1);
            aszArgs[n][0] = '"';
            strcpy(&aszArgs[n][1], szArg);
            aszArgs[n][l + 1] = '"';
            aszArgs[n][l + 2] = '\0';
        }
        else {
            aszArgs[n] = (char *)szArg;
        }
    }

    aszArgs[n] = NULL;

    return _spawnv(mode, szCmd, aszArgs);
}

#undef _spawnve
API_EXPORT(int) os_spawnve(int mode, const char *cmdname,
			   const char *const *argv, const char *const *envp)
{
    int n;
    char **aszArgs;
    const char *szArg;
    char *szCmd;
    char *s;
    
    szCmd = _alloca(strlen(cmdname)+1);
    strcpy(szCmd, cmdname);
    for (s = szCmd; *s; ++s) {
        if (*s == '/') {
            *s = '\\';
	}
    }
    
    for (n = 0; argv[n]; ++n)
        ;

    aszArgs = _alloca((n + 1)*sizeof(const char *));

    for (n = 0; szArg = argv[n]; ++n){
        if (strchr(szArg, ' ')) {
            int l = strlen(szArg);

            aszArgs[n] = _alloca(l + 2 + 1);
            aszArgs[n][0] = '"';
            strcpy(&aszArgs[n][1], szArg);
            aszArgs[n][l + 1] = '"';
            aszArgs[n][l + 2] = '\0';
        }
        else {
            aszArgs[n] = (char *)szArg;
        }
    }

    aszArgs[n] = NULL;

    return _spawnve(mode, szCmd, aszArgs, envp);
}

API_EXPORT(int) os_spawnle(int mode, const char *cmdname, ...)
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
    for (s = szCmd; *s; ++s) {
        if (*s == '/') {
            *s = '\\';
	}
    }

    va_start(vlist, cmdname);
    for (n = 0; va_arg(vlist, const char *); ++n)
        ;
    va_end(vlist);

    aszArgs = _alloca((n + 1) * sizeof(const char *));

    va_start(vlist, cmdname);
    for (n = 0; szArg = va_arg(vlist, const char *); ++n) {
        if (strchr(szArg, ' ')) {
            int l = strlen(szArg);

            aszArgs[n] = _alloca(l + 2 + 1);
            aszArgs[n][0] = '"';
            strcpy(&aszArgs[n][1], szArg);
            aszArgs[n][l + 1] = '"';
            aszArgs[n][l + 2] = '\0';
        }
        else {
            aszArgs[n] = (char *)szArg;
        }
    }

    aszArgs[n] = NULL;

    aszEnv = va_arg(vlist, const char *const *);
    va_end(vlist);
    
    return _spawnve(mode, szCmd, aszArgs, aszEnv);
}
