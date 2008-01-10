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

/*
 * OS abstraction functions. Small functions should be defined
 * as "__inline" in os.h.
 */

#include <sys/stat.h>
#include <stdio.h>
#include <time.h>
#include "os.h"
#include "errno.h"

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
    int len = strlen(szPath);
    
    if (len == 0) {
        errno = ENOENT;
        return -1;
    }

    if (len >= MAX_PATH) {
        errno = ENAMETOOLONG;
        return -1;
    }

    if (szPath[0] == '/' && szPath[1] == '/') {
	char buf[MAX_PATH];
	char *s;
	int nSlashes = 0;

	strcpy(buf, szPath);
	for (s = buf; *s; ++s) {
	    if (*s == '/') {
		*s = '\\';
		++nSlashes;
	    }
	}
	/* then we need to add one more to get \\machine\share\ */
	if (nSlashes == 3) {
            if (++len >= MAX_PATH) {
                errno = ENAMETOOLONG;
                return -1;
            }
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
        char buf[MAX_PATH];
        
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

API_EXPORT_NONSTD(int) os_spawnle(int mode, const char *cmdname, ...)
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

#undef strftime

/* Partial replacement for strftime. This adds certain expandos to the
 * Windows version
 */

API_EXPORT(int) os_strftime(char *s, size_t max, const char *format,
                            const struct tm *tm) {
   /* If the new format string is bigger than max, the result string probably
    * won't fit anyway. When %-expandos are added, made sure the padding below
    * is enough.
    */
    char *new_format = (char *) _alloca(max + 11);
    size_t i, j, format_length = strlen(format);
    int return_value;
    int length_written;

    for (i = 0, j = 0; (i < format_length && j < max);) {
        if (format[i] != '%') {
            new_format[j++] = format[i++];
            continue;
        }
        switch (format[i+1]) {
            case 'D':
                /* Is this locale dependent? Shouldn't be...
                   Also note the year 2000 exposure here */
                memcpy(new_format + j, "%m/%d/%y", 8);
                i += 2;
                j += 8;
                break;
            case 'r':
                memcpy(new_format + j, "%I:%M:%S %p", 11);
                i += 2;
                j += 11;
                break;
            case 'T':
                memcpy(new_format + j, "%H:%M:%S", 8);
                i += 2;
                j += 8;
                break;
            case 'e':
                length_written = _snprintf(new_format + j, max - j, "%2d",
                    tm->tm_mday);
                j = (length_written == -1) ? max : (j + length_written);
                i += 2;
                break;
            default:
                /* We know we can advance two characters forward here. */
                new_format[j++] = format[i++];
                new_format[j++] = format[i++];
        }
    }
    if (j >= max) {
        *s = '\0';  /* Defensive programming, okay since output is undefined */
        return_value = 0;
    } else {
        new_format[j] = '\0';
        return_value = strftime(s, max, new_format, tm);
    }
    return return_value;
}
