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

#include "httpd.h"
#include "http_log.h"
#include "apr_strings.h"

#include <stdarg.h>
#include <time.h>
#include <stdlib.h>

/* Returns TRUE if the input string is a string
 * of one or more '.' characters.
 */
static BOOL OnlyDots(char *pString)
{
    char *c;

    if (*pString == '\0')
        return FALSE;

    for (c = pString;*c;c++)
        if (*c != '.')
            return FALSE;

    return TRUE;
}

/* Accepts as input a pathname, and tries to match it to an 
 * existing path and return the pathname in the case that
 * is present on the existing path.  This routine also
 * converts alias names to long names.
 */
API_EXPORT(char *) ap_os_systemcase_filename(apr_pool_t *pPool, 
                                             const char *szFile)
{
    char buf[HUGE_STRING_LEN];
    char *pInputName;
    char *p, *q;
    BOOL bDone = FALSE;
    BOOL bFileExists = TRUE;
    HANDLE hFind;
    WIN32_FIND_DATA wfd;

    if (!szFile || strlen(szFile) == 0 || strlen(szFile) >= sizeof(buf))
        return apr_pstrdup(pPool, "");

    buf[0] = '\0';
    pInputName = apr_pstrdup(pPool, szFile);

    /* First convert all slashes to \ so Win32 calls work OK */
    for (p = pInputName; *p; p++) {
        if (*p == '/')
            *p = '\\';
    }
    
    p = pInputName;
    /* If there is drive information, copy it over. */ 
    if (pInputName[1] == ':') {
        buf[0] = tolower(*p++);
        buf[1] = *p++;
        buf[2] = '\0';

        /* If all we have is a drive letter, then we are done */
        if (strlen(pInputName) == 2)
            bDone = TRUE;
    }
    
    q = p;
    if (*p == '\\') {
        p++;
        if (*p == '\\')  /* Possible UNC name */
        {
            p++;
            /* Get past the machine name.  FindFirstFile */
            /* will not find a machine name only */
            p = strchr(p, '\\'); 
            if (p)
            {
                p++;
                /* Get past the share name.  FindFirstFile */
                /* will not find a \\machine\share name only */
                p = strchr(p, '\\'); 
                if (p) {
                    strncat(buf,q,p-q);
                    q = p;
                    p++;
                }
            }

            if (!p)
                p = q;
        }
    }

    p = strchr(p, '\\');

    while (!bDone) {
        if (p)
            *p = '\0';

        if (strchr(q, '*') || strchr(q, '?'))
            bFileExists = FALSE;

        /* If the path exists so far, call FindFirstFile
         * again.  However, if this portion of the path contains
         * only '.' charaters, skip the call to FindFirstFile
         * since it will convert '.' and '..' to actual names.
         * Note: in the call to OnlyDots, we may have to skip
         *       a leading slash.
         */
        if (bFileExists && !OnlyDots((*q == '.' ? q : q+1))) {            
            hFind = FindFirstFile(pInputName, &wfd);
            
            if (hFind == INVALID_HANDLE_VALUE) {
                bFileExists = FALSE;
            }
            else {
                FindClose(hFind);

                if (*q == '\\')
                    strcat(buf,"\\");
                strcat(buf, wfd.cFileName);
            }
        }
        
        if (!bFileExists || OnlyDots((*q == '.' ? q : q+1))) {
            strcat(buf, q);
        }
        
        if (p) {
            q = p;
            *p++ = '\\';
            p = strchr(p, '\\');
        }
        else {
            bDone = TRUE;
        }
    }
    
    /* First convert all slashes to / so server code handles it ok */
    for (p = buf; *p; p++) {
        if (*p == '\\')
            *p = '/';
    }

    return apr_pstrdup(pPool, buf);
}


/*  Perform canonicalization with the exception that the
 *  input case is preserved.
 */
API_EXPORT(char *) ap_os_case_canonical_filename(apr_pool_t *pPool, 
                                                 const char *szFile)
{
    char *pNewStr;
    char *s;
    char *p; 
    char *q;

    if (szFile == NULL || strlen(szFile) == 0)
        return apr_pstrdup(pPool, "");

    pNewStr = apr_pstrdup(pPool, szFile);

    /*  Change all '\' characters to '/' characters.
     *  While doing this, remove any trailing '.'.
     *  Also, blow away any directories with 3 or
     *  more '.'
     */
    for (p = pNewStr,s = pNewStr; *s; s++,p++) {
        if (*s == '\\' || *s == '/') {

            q = p;
            while (p > pNewStr && *(p-1) == '.')
                p--;

            if (p == pNewStr && q-p <= 2 && *p == '.')
                p = q;
            else if (p > pNewStr && p < q && *(p-1) == '/') {
                if (q-p > 2)
                    p--;
                else
                    p = q;
            }

            *p = '/';
        }
        else {
            *p = *s;
        }
    }
    *p = '\0';

    /*  Blow away any final trailing '.' since on Win32
     *  foo.bat == foo.bat. == foo.bat... etc.
     *  Also blow away any trailing spaces since
     *  "filename" == "filename "
     */
    q = p;
    while (p > pNewStr && (*(p-1) == '.' || *(p-1) == ' '))
        p--;
    if ((p > pNewStr) ||
        (p == pNewStr && q-p > 2))
        *p = '\0';
        

    /*  One more security issue to deal with.  Win32 allows
     *  you to create long filenames.  However, alias filenames
     *  are always created so that the filename will
     *  conform to 8.3 rules.  According to the Microsoft
     *  Developer's network CD (1/98) 
     *  "Automatically generated aliases are composed of the 
     *   first six characters of the filename plus ~n 
     *   (where n is a number) and the first three characters 
     *   after the last period."
     *  Here, we attempt to detect and decode these names.
     */
    p = strchr(pNewStr, '~');
    if (p != NULL) {
        char *pConvertedName, *pQstr, *pPstr;
        char buf[HUGE_STRING_LEN];
        /* We potentially have a short name.  Call 
         * ap_os_systemcase_filename to examine the filesystem
         * and possibly extract the long name.
         */
        pConvertedName = ap_os_systemcase_filename(pPool, pNewStr);

        /* Since we want to preserve the incoming case as much
         * as we can, compare for differences in the string and
         * only substitute in the path names that changed.
         */
        if (stricmp(pNewStr, pConvertedName)) {
            buf[0] = '\0';

            q = pQstr = pConvertedName;
            p = pPstr = pNewStr;
            do {
                q = strchr(q,'/');
                p = strchr(p,'/');

                if (p != NULL) {
                    *q = '\0';
                    *p = '\0';
                }

                if (stricmp(pQstr, pPstr)) 
                    strcat(buf, pQstr);   /* Converted name */
                else 
                    strcat(buf, pPstr);   /* Original name  */


                if (p != NULL) {
                    pQstr = q;
                    pPstr = p;
                    *q++ = '/';
                    *p++ = '/';
                }

            } while (p != NULL); 

            pNewStr = apr_pstrdup(pPool, buf);
        }
    }


    return pNewStr;
}

/*  Perform complete canonicalization.
 */
API_EXPORT(char *) ap_os_canonical_filename(apr_pool_t *pPool, const char *szFile)
{
    char *pNewName;
    pNewName = ap_os_case_canonical_filename(pPool, szFile);
    strlwr(pNewName);
    return pNewName;
}

/*
 * ap_os_is_filename_valid is given a filename, and returns 0 if the filename
 * is not valid for use on this system. On Windows, this means it fails any
 * of the tests below. Otherwise returns 1.
 *
 * Test for filename validity on Win32. This is of tests come in part from
 * the MSDN article at "Technical Articles, Windows Platform, Base Services,
 * Guidelines, Making Room for Long Filenames" although the information
 * in MSDN about filename testing is incomplete or conflicting. There is a
 * similar set of tests in "Technical Articles, Windows Platform, Base Services,
 * Guidelines, Moving Unix Applications to Windows NT".
 *
 * The tests are:
 *
 * 1) total path length greater than MAX_PATH
 *
 * 2) anything using the octets 0-31 or characters " < > | :
 *    (these are reserved for Windows use in filenames. In addition
 *     each file system has its own additional characters that are
 *     invalid. See KB article Q100108 for more details).
 *
 * 3) anything ending in "." (no matter how many)
 *    (filename doc, doc. and doc... all refer to the same file)
 *
 * 4) any segment in which the basename (before first period) matches
 *    one of the DOS device names
 *    (the list comes from KB article Q100108 although some people
 *     reports that additional names such as "COM5" are also special
 *     devices).
 *
 * If the path fails ANY of these tests, the result must be to deny access.
 */

API_EXPORT(int) ap_os_is_filename_valid(const char *file)
{
    const char *segstart;
    unsigned int seglength;
    const char *pos;
    static const char * const invalid_characters = "?\"<>*|:";
    static const char * const invalid_filenames[] = { 
	"CON", "AUX", "COM1", "COM2", "COM3", 
	"COM4", "LPT1", "LPT2", "LPT3", "PRN", "NUL", NULL 
    };

    /* Test 1 */
    if (strlen(file) >= MAX_PATH) {
	/* Path too long for Windows. Note that this test is not valid
	 * if the path starts with //?/ or \\?\. */
	return 0;
    }

    pos = file;

    /* Skip any leading non-path components. This can be either a
     * drive letter such as C:, or a UNC path such as \\SERVER\SHARE\.
     * We continue and check the rest of the path based on the rules above.
     * This means we could eliminate valid filenames from servers which
     * are not running NT (such as Samba).
     */

    if (pos[0] && pos[1] == ':') {
	/* Skip leading drive letter */
	pos += 2;
    }
    else {
	if ((pos[0] == '\\' || pos[0] == '/') &&
	    (pos[1] == '\\' || pos[1] == '/')) {
	    /* Is a UNC, so skip the server name and share name */
	    pos += 2;
	    while (*pos && *pos != '/' && *pos != '\\')
		pos++;
	    if (!*pos) {
		/* No share name */
		return 0;
	    }
	    pos++;	/* Move to start of share name */
	    while (*pos && *pos != '/' && *pos != '\\')
		pos++;
	    if (!*pos) {
		/* No path information */
		return 0;
	    }
	}
    }

    while (*pos) {
	unsigned int idx;
	unsigned int baselength;

	while (*pos == '/' || *pos == '\\') {
    	    pos++;
	}
	if (*pos == '\0') {
	    break;
	}
	segstart = pos;	/* start of segment */
	while (*pos && *pos != '/' && *pos != '\\') {
	    pos++;
	}
	seglength = pos - segstart;
	/* 
	 * Now we have a segment of the path, starting at position "segstart"
	 * and length "seglength"
	 */

	/* Test 2 */
	for (idx = 0; idx < seglength; idx++) {
	    if ((segstart[idx] > 0 && segstart[idx] < 32) ||
		strchr(invalid_characters, segstart[idx])) {
		return 0;
	    }
	}

	/* Test 3 */
	if (segstart[seglength-1] == '.') {
	    return 0;
	}

	/* Test 4 */
	for (baselength = 0; baselength < seglength; baselength++) {
	    if (segstart[baselength] == '.') {
		break;
	    }
	}

	/* baselength is the number of characters in the base path of
	 * the segment (which could be the same as the whole segment length,
	 * if it does not include any dot characters). */
	if (baselength == 3 || baselength == 4) {
	    for (idx = 0; invalid_filenames[idx]; idx++) {
		if (strlen(invalid_filenames[idx]) == baselength &&
		    !strnicmp(invalid_filenames[idx], segstart, baselength)) {
		    return 0;
		}
	    }
	}
    }

    return 1;
}
