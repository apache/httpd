/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000-2003 The Apache Software Foundation.  All rights
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

#define WS_SSL

#include "httpd.h"
#include "ap_config.h"
#include "http_config.h"
#include "http_log.h"
#include <dirent.h>

extern char ap_server_root[MAX_STRING_LEN];

void ap_os_dso_init(void)
{
}

void *ap_os_dso_load(const char *path)
{
    unsigned int nlmHandle;
    char *moduleName = NULL;
    
    moduleName = strrchr(path, '/');

    if (moduleName) {
        moduleName++;
    }
    
    nlmHandle = FindNLMHandleInAddressSpace((char*)moduleName, NULL);

    if (nlmHandle == NULL) {
        spawnlp(P_NOWAIT | P_SPAWN_IN_CURRENT_DOMAIN, path, NULL);        
        nlmHandle = FindNLMHandleInAddressSpace((char*)moduleName, NULL);
    }

    return (void *)nlmHandle;
}

void ap_os_dso_unload(void *handle)
{
	KillMe(handle);
}

void *ap_os_dso_sym(void *handle, const char *symname)
{
    return ImportSymbol((int)GetNLMHandle(), (char *)symname);
}

void ap_os_dso_unsym(void *handle, const char *symname)
{
    UnimportSymbol((int)GetNLMHandle(), (char *)symname);
}

const char *ap_os_dso_error(void)
{
    return NULL;
}

char *remove_filename(char* str)
{
    int i, len = strlen(str);    
  
    for (i=len; i; i--) {
        if (str[i] == '\\' || str[i] == '/') {
            str[i] = NULL;
            break;
        }
    }
    return str;
}

char *bslash2slash(char* str)
{
    int i, len = strlen(str);    
  
    for (i=0; i<len; i++) {
        if (str[i] == '\\') {
            str[i] = '/';
            break;
        }
    }
    return str;
}

void check_clean_load(module *top_module)
{
    if (top_module != NULL) {
        module *m;

        ap_log_error(APLOG_MARK, APLOG_CRIT, NULL,
            "abnormal shutdown detected, performing a clean shutdown: please restart apache");
        for (m = top_module; m; m = m->next)
            ap_os_dso_unload((ap_os_dso_handle_t)m->dynamic_load_handle);
        exit(1);
    }
}

void init_name_space()
{
    UnAugmentAsterisk(TRUE);
    SetCurrentNameSpace(NW_NS_LONG);
    SetTargetNameSpace(NW_NS_LONG);
}

/*  Perform complete canonicalization.  On NetWare we are just
	lower casing the file name so that the comparisons will match.
	NetWare assumes that all physical paths are fully qualified.  
	Each file path must include a volume name.
 */
static char *os_canonical_filename(pool *pPool, const char *szFile)
{
    char *pNewName = ap_pstrdup(pPool, szFile);
    char *slash_test;
	
    bslash2slash(pNewName);
    /* Don't try to canonicalize a filename that isn't even valid
        This way we don't mess up proxy requests or other kinds
        of special filenames.
    */
    if (ap_os_is_filename_valid(pNewName)) {
        if ((pNewName[0] == '/') && (strchr (pNewName, ':') == NULL))
        {
            char vol[256];

            _splitpath (ap_server_root, vol, NULL, NULL, NULL);
            pNewName = ap_pstrcat (pPool, vol, pNewName, NULL);
        }
        if ((slash_test = strchr(pNewName, ':')) && (*(slash_test+1) != '/') 
            && (*(slash_test+1) != '\0'))
        {
            char vol[_MAX_VOLUME+1];
        
            _splitpath (pNewName, vol, NULL, NULL, NULL);
            pNewName = ap_pstrcat (pPool, vol, "/", pNewName+strlen(vol), NULL);
        }
    }
    return pNewName;
}

char *ap_os_canonical_filename(pool *pPool, const char *szFile)
{
    char *pNewName = os_canonical_filename(pPool, szFile);

    /* Lower case the name so that the interal string compares work */
    strlwr(pNewName);
    return pNewName;
}


char *ap_os_case_canonical_filename(pool *pPool, const char *szFile)
{
    /* First thing we need to do is get a copy of the 
        canonicalized path */
    char *pNewName = os_canonical_filename(pPool, szFile);
    int	  volnum=0;
    long  dirnum=0;
    long  pathcount=0;
    char *path;
    char  vol[_MAX_VOLUME+1];
    int   retval, x, y;
	    
    /* See if path exists by trying to get the volume and directory number */
    retval = FEMapPathVolumeDirToVolumeDir(pNewName, 0, 0, &volnum, &dirnum);
    if (retval == 0) {
        /* allocate a buffer and ask the file system for the real name of
            the directory and file */
        path = ap_palloc(pPool, strlen(pNewName)+2);
        FEMapVolumeAndDirectoryToPath (volnum, dirnum, path, &pathcount);

        /* The file system gives it back in a lengh preceded string so we
            need to convert it to a null terminated string. */
        x = 0;
        while (pathcount-- > 0) {
            y = path[x];
            path[x] = '/';
            x += y + 1;
        }
        path[x] = '\0';  /* null terminate the full path */

        /* Get the name of the volume so that we can prepend it onto the path */
        FEMapVolumeNumberToName (volnum, vol);
        vol[vol[0]+1] = '\0';
        pNewName = ap_pstrcat (pPool, &(vol[1]), ":", path, NULL);
    }

    /* At this point we either have a real case accurate canonical path or 
        the original name canonicalized */
    return pNewName;
}


/*
 * ap_os_is_filename_valid is given a filename, and returns 0 if the filename
 * is not valid for use on this system. On NetWare, this means it fails any
 * of the tests below. Otherwise returns 1.
 *
 * The tests are:
 *
 * 1) total path length greater than MAX_PATH
 * 
 * 2) the file path must contain a volume specifier and no / or \
 *     can appear before the volume specifier.
 *
 * 3) anything using the octets 0-31 or characters " < > | :
 *    (these are reserved for Windows use in filenames. In addition
 *     each file system has its own additional characters that are
 *     invalid. See KB article Q100108 for more details).
 *
 * 4) anything ending in "." (no matter how many)
 *    (filename doc, doc. and doc... all refer to the same file)
 *
 * 5) any segment in which the basename (before first period) matches
 *    one of the DOS device names
 *    (the list comes from KB article Q100108 although some people
 *     reports that additional names such as "COM5" are also special
 *     devices).
 *
 * If the path fails ANY of these tests, the result must be to deny access.
 */

int ap_os_is_filename_valid(const char *file)
{
    const char *segstart;
    unsigned int seglength;
    const char *pos;
	char *colonpos, *fslashpos, *bslashpos;
    static const char * const invalid_characters = "?\"<>*|:";
    static const char * const invalid_filenames[] = { 
		"CON", "AUX", "COM1", "COM2", "COM3", 
		"COM4", "LPT1", "LPT2", "LPT3", "PRN", "NUL", NULL 
    };

	/* First check to make sure that we have a file so that we don't abend */
	if (file == NULL)
		return 0;

    /* Test 1 */
    if (strlen(file) >= _MAX_PATH) {
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

	colonpos = strchr (file, ':');

	if (!colonpos)
		return 0;

	pos = ++colonpos;
   	if (!*pos) {
		/* No path information */
		/* Same as specifying volume:\ */
		return 1;
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

		/* Test 2.5 */
		if (seglength == 2) {
			if ( (segstart[0] == '.') && (segstart[1] == '.') ) {
					return 1;
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

#undef opendir_411
DIR *os_opendir (const char *pathname)
{
	struct stat s;
	DIR *d = opendir_411 (pathname);

    if (d) {
        strcpy (d->d_name, "<<**");
    }

	if (!d) {
		/* Let's check if this is an empty directory */
		if (stat(pathname, &s) != 0)
			return NULL;
		if (!(S_ISDIR(s.st_mode)))
			return NULL; 
		
		/* If we are here, then this appears to be a directory */
		/* We allocate a name */
		d = NULL;
        d = (DIR *)malloc(sizeof(DIR));
        if (d) {
            memset(d, 0, sizeof(DIR));
            strcpy(d->d_name, "**<<");
			d->d_cdatetime = 50;

        }    

  	}

    return d;

}

#undef readdir_411
DIR *os_readdir (DIR *dirP)
{

/*
 * First three if statements added for empty directory support.
 *
 */
    if (  (dirP->d_cdatetime == 50) && (dirP->d_name[0] == '*') &&
       	  (dirP->d_name[2] == '<') )
    {
        strcpy (dirP->d_name, ".");
        strcpy (dirP->d_nameDOS, ".");
        return (dirP);
    }
    else if ((dirP->d_cdatetime == 50) &&
             (dirP->d_name[0] == '.') &&
             (dirP->d_name[1] == '\0')) {
        strcpy (dirP->d_name, "..");
        strcpy (dirP->d_nameDOS, "..");
        return (dirP);
    }
    else if ( (dirP->d_cdatetime == 50) &&
             (dirP->d_name[0] == '.') &&
             (dirP->d_name[1] == '.') &&
             (dirP->d_name[2] == '\0') ) {
        return (NULL);
    }
    else if ((dirP->d_name[0] == '<') && (dirP->d_name[2] == '*')) {
        strcpy (dirP->d_name, ".");
        strcpy (dirP->d_nameDOS, ".");
        return (dirP);
    }
    else if ((dirP->d_name[0] == '.') && (dirP->d_name[1] == '\0')) {
        strcpy (dirP->d_name, "..");
        strcpy (dirP->d_nameDOS, "..");
        return (dirP);
    }
    else
        return readdir_411 (dirP);
}


#undef closedir_510
int os_closedir (DIR *dirP)
{
/*
 * Modified to handle empty directories.
 *
 */

	if (dirP == NULL) {
		return 0;
	}

    if (  (  (dirP->d_cdatetime == 50) && (dirP->d_name[0] == '*') &&
       	  	 (dirP->d_name[2] == '<') 
       	  ) ||
       	  (	 (dirP->d_cdatetime == 50) && (dirP->d_name[0] == '.') &&
       	     (dirP->d_name[1] == '\0')
       	  ) ||
       	  (	 (dirP->d_cdatetime == 50) && (dirP->d_name[0] == '.') &&
       	     (dirP->d_name[1] == '.') && (dirP->d_name[2] == '\0')
       	  )
       )
	{

 	       free(dirP); 
 	       dirP = NULL;
 	       return 0;
 	}
 	else {
	       return closedir_510(dirP);
	}
		

}

char *ap_os_http_method(void *r)
{
    int s = ((request_rec*)r)->connection->client->fd;
    unsigned int optParam;

    if (!WSAIoctl(s, SO_SSL_GET_FLAGS, NULL, 0, &optParam, sizeof(optParam), NULL, NULL, NULL))
        if (optParam & (SO_SSL_ENABLE | SO_SSL_SERVER)) return "https";
    return "http";
}

unsigned short ap_os_default_port(void *r)
{
  return ap_default_port_for_scheme(ap_os_http_method(r));
}
