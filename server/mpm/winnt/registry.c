/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000-2002 The Apache Software Foundation.  All rights
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

/*
 * Functions to handle interacting with the Win32 registry
 */

/*
 * Apache registry key structure
 *
 * Apache's registry information is stored in the HKEY_LOCAL_MACHINE
 * key, under
 *
 *  HKLM\SOFTWARE\Apache Software Foundation\Apache\version
 *
 * These keys are defined in this file. The definition of the "version" part
 * will need updating each time Apache moves from beta to non-beta or from a
 * release to a development or beta version.
 */

#include "httpd.h"
#include "http_log.h"
#include "mpm_winnt.h"
#include "apr_strings.h"

/* bet you are looking to change revisions to roll the tarball...
 * Guess what, you already did.  Revised May '00 to save you from 
 * searching all over creation for every revision tag.
 */

#define VENDOR   AP_SERVER_BASEVENDOR
#define SOFTWARE AP_SERVER_BASEPRODUCT
#define VERSION  AP_SERVER_BASEREVISION

#define REGKEY "SOFTWARE\\" VENDOR "\\" SOFTWARE "\\" VERSION

/*
 * The Windows API registry key functions don't set the last error
 * value (the windows equivalent of errno). So we need to set it
 * with SetLastError() before calling the aplog_error() function.
 * Because this is common, let's have a macro.
 */
#define return_error(rv) return (apr_set_os_error(APR_FROM_OS_ERROR(rv)),\
                                 APR_FROM_OS_ERROR(rv));

apr_status_t ap_registry_create_key(const char *key)
{
    HKEY hKey = HKEY_LOCAL_MACHINE;
    HKEY hKeyNext;
    char keystr[MAX_PATH + 1];        
    char *parsekey = keystr;
    char *nextkey = keystr;
    DWORD result;
    int rv;

    apr_cpystrn(keystr, key, sizeof(keystr) - 1);
    	
    /* Walk the tree, creating at each stage if necessary */
    while (parsekey) {
        if (nextkey = strchr(parsekey, '\\'))
            *(nextkey++) = '\0';

        rv = RegCreateKeyEx(hKey,
			    parsekey,    /* subkey */
			    0,	         /* reserved */
			    NULL,        /* class */
			    REG_OPTION_NON_VOLATILE,
			    KEY_WRITE,
			    NULL,
			    &hKeyNext,
			    &result);

    	/* Close the old key */
        if (hKey != HKEY_LOCAL_MACHINE)
	    RegCloseKey(hKey);
        hKey = hKeyNext;
        
        if (rv != ERROR_SUCCESS)
	    break;

        parsekey = nextkey;
    }

    if (hKey != HKEY_LOCAL_MACHINE)
        RegCloseKey(hKey);

    return_error(rv);
}

apr_status_t ap_registry_delete_key(const char *key)
{
    apr_status_t rv;
    HKEY hKey;
    int nSize = 0;
    char tempkey[MAX_PATH + 1];
    char *parsekey;

    apr_cpystrn(tempkey, key, sizeof(parsekey) - 1);
    parsekey = strrchr(tempkey, '\\');
    
    if (parsekey) {
        *(parsekey++) = '\0';
        rv = RegOpenKeyEx(HKEY_LOCAL_MACHINE,
                          tempkey,
		          0,
		          KEY_WRITE,
		          &hKey);

        if (rv != ERROR_SUCCESS)
            return_error(rv);
    }
    else {
        parsekey = tempkey;
        hKey = HKEY_LOCAL_MACHINE;
    }
    
    rv = RegDeleteKey(hKey, key);

    if (hKey != HKEY_LOCAL_MACHINE)
        RegCloseKey(hKey);

    return_error(rv);
}

/* Clean up a way over complicated process.
 *
 * The return value is APR_SUCCESS, APR_ENOENT, APR_NOTFOUND, or the OS error
 */

apr_status_t ap_registry_get_value(apr_pool_t *p, const char *key, const char *name, char **ppValue)
{
    apr_status_t rv;
    HKEY hKey;
    int nSize = 0;

    rv = RegOpenKeyEx(HKEY_LOCAL_MACHINE,
                      key,
		      0,
		      KEY_READ,
		      &hKey);

    if (rv != ERROR_SUCCESS)
        return_error(rv);

    /* Find the size required for the data by passing NULL as the buffer
     * pointer. On return nSize will contain the size required for the
     * buffer if the return value is ERROR_SUCCESS.
     */
    rv = RegQueryValueEx(hKey, 
			 name,		/* key name */
			 NULL,		/* reserved */
			 NULL,		/* type */
			 NULL,		/* for value */
			 &nSize);		/* for size of "value" */

    if (rv != ERROR_SUCCESS)
	return_error(rv);

    *ppValue = apr_palloc(p, nSize + 1);
    (*ppValue)[nSize] = '\0';

    rv = RegQueryValueEx(hKey, 
			 name,		/* key name */
			 NULL,		/* reserved */
			 NULL,		/* type */
			 *ppValue,      /* for value */
			 &nSize);	/* for size of "value" */

    RegCloseKey(hKey);

    return_error(rv);
}

apr_status_t ap_registry_get_array(apr_pool_t *p, const char *key, const char *name, apr_array_header_t **parray)
{
    char *pValue;
    char *tmp;
    char **newelem;
    apr_status_t rv;
    HKEY hKey;
    int nSize = 0;

    rv = RegOpenKeyEx(HKEY_LOCAL_MACHINE,
                      key,
		      0,
		      KEY_READ,
		      &hKey);

    if (rv != ERROR_SUCCESS)
        return_error(rv);

    /* Find the size required for the data by passing NULL as the buffer
     * pointer. On return nSize will contain the size required for the
     * buffer if the return value is ERROR_SUCCESS.
     */
    rv = RegQueryValueEx(hKey, 
			 name,		/* key name */
			 NULL,		/* reserved */
			 NULL,		/* type */
			 NULL,		/* for value */
			 &nSize);		/* for size of "value" */

    if (rv != ERROR_SUCCESS) {
	return_error(rv);
    }
    else 
    {
        /* Small possiblity the array is either unterminated 
         * or single NULL terminated.  Avert.
         */
        pValue = apr_palloc(p, nSize + 2);
        pValue[nSize + 1] = '\0';
        pValue[nSize] = '\0';
        
        rv = RegQueryValueEx(hKey, 
			     name,		/* key name */
			     NULL,		/* reserved */
			     NULL,		/* type */
			     pValue,        /* for value */
			     &nSize);	/* for size of "value" */

        nSize = 0;    /* Element Count */
        for (tmp = pValue; *tmp; ++tmp) {
            ++nSize;
            while (*tmp) {
                ++tmp;
            }
        }

        *parray = apr_array_make(p, nSize, sizeof(char *));
        for (tmp = pValue; *tmp; ++tmp) {
            newelem = (char **) apr_array_push(*parray);
            *newelem = tmp;
            while (*tmp) {
                ++tmp;
            }
        }
    }    
    
    RegCloseKey(hKey);

    return_error(rv);
}

/*
 * ap_registry_store_key_value() stores a value name and value under the
 * Apache registry key. If the Apache key does not exist it is created
 * first. This function is intended to be called from a wrapper function
 * in this file to set particular data values, such as 
 * ap_registry_set_server_root() below.
 *
 * Returns 0 if the value name and data was stored successfully, or
 * returns -1 if the Apache key does not exist (since we try to create 
 * this key, this should never happen), or -4 if any other error occurred
 * (these values are consistent with ap_registry_get_key_value()).
 * If the return value is negative then the error will already have been
 * logged via aplog_error().
 */

apr_status_t ap_registry_store_value(const char *key, const char *name, const char *value)
{
    long rv;
    HKEY hKey;

    rv = RegOpenKeyEx(HKEY_LOCAL_MACHINE,
		      key,
		      0,
	 	      KEY_WRITE,
		      &hKey);

    if (rv == ERROR_FILE_NOT_FOUND) 
    {
	rv = ap_registry_create_key(key);

        if (rv != APR_SUCCESS)
	    return_error(rv);
	
	rv = RegOpenKeyEx(HKEY_LOCAL_MACHINE,
		          key,
		          0,
	 	          KEY_WRITE,
		          &hKey);
    }

    if (rv != ERROR_SUCCESS)
        return_error(rv);

    /* Now set the value and data */
    rv = RegSetValueEx(hKey, 
                       name,	/* value key name */
		       0,	/* reserved */
		       REG_SZ,	/* type */
		       value,	/* value data */
		       (DWORD) strlen(value) + 1); /* for size of "value" */

    if (rv == ERROR_SUCCESS) {
	ap_log_error(APLOG_MARK,APLOG_INFO,rv,NULL,
	    "Registry stored HKLM\\" REGKEY "\\%s value %s", key, value);
    }

    /* Make sure we close the key even if there was an error storing
     * the data
     */
    RegCloseKey(hKey);
    
    return_error(rv);
}

apr_status_t ap_registry_store_array(apr_pool_t *p,
                                     const char *key, const char *name,
                                     int nelts, const char * const * elts)
{
    int  bufsize, i;
    char *buf, *tmp;
    long rv;
    HKEY hKey;

    rv = RegOpenKeyEx(HKEY_LOCAL_MACHINE,
		      key,
		      0,
	 	      KEY_WRITE,
		      &hKey);

    if (rv == ERROR_FILE_NOT_FOUND) 
    {
	rv = ap_registry_create_key(key);

        if (rv != APR_SUCCESS)
	    return_error(rv);
	
	rv = RegOpenKeyEx(HKEY_LOCAL_MACHINE,
		          key,
		          0,
	 	          KEY_WRITE,
		          &hKey);
    }

    if (rv != ERROR_SUCCESS)
        return_error(rv);

    bufsize = 1; /* For trailing second null */
    for (i = 0; i < nelts; ++i)
    {
        bufsize += strlen(elts[i]) + 1;
    }
    if (!nelts) 
        ++bufsize;

    buf = apr_palloc(p, bufsize);
    tmp = buf;
    for (i = 0; i < nelts; ++i)
    {
        strcpy(tmp, elts[i]);
        tmp += strlen(elts[i]) + 1;
    }
    if (!nelts) 
        (*tmp++) = '\0';
    *tmp = '\0'; /* Trailing second null */

    /* Now set the value and data */
    rv = RegSetValueEx(hKey, 
                       name,	     /* value key name */
		       0,	     /* reserved */
		       REG_MULTI_SZ, /* type */
		       buf,	     /* value data */
		       (DWORD) bufsize); /* for size of "value" */

    if (rv == ERROR_SUCCESS) {
	ap_log_error(APLOG_MARK,APLOG_INFO,rv,NULL,
	    "Registry stored HKLM\\" REGKEY "\\%s", key);
    }

    /* Make sure we close the key even if there was an error storing
     * the data
     */
    RegCloseKey(hKey);
    
    return_error(rv);
}

/* A key or value that does not exist is _not_ an error while deleting. */

apr_status_t ap_registry_delete_value(const char *key, const char *name)
{
    apr_status_t rv;
    HKEY hKey;
    
    rv = RegOpenKeyEx(HKEY_LOCAL_MACHINE,
                      key,
		      0,
		      KEY_WRITE,
		      &hKey);

    if (rv == ERROR_FILE_NOT_FOUND)
        return APR_SUCCESS;
    
    if (rv != ERROR_SUCCESS)
        return_error(rv);

    rv = RegDeleteValue(hKey, name);

    if (rv == ERROR_FILE_NOT_FOUND)
        rv = APR_SUCCESS;
    
    RegCloseKey(hKey);
    return_error(rv);
}

/*
 * Get the server root from the registry into 'dir' which is
 * size bytes long. Returns 0 if the server root was found
 * or if the serverroot key does not exist (in which case
 * dir will contain an empty string), or -1 if there was
 * an error getting the key.
 */
apr_status_t ap_registry_get_server_root(apr_pool_t *p, char **buf)
{
    apr_status_t rv;

    rv = ap_registry_get_value(p, REGKEY, "ServerRoot", buf);
    if (rv) 
        *buf = NULL;

    return rv;
}


/*
 * Sets the serverroot value within the registry. Returns 0 on success
 * or -1 on error. If -1 is return the error will already have been
 * logged via aplog_error().
 */

apr_status_t ap_registry_set_server_root(char *dir)
{
    return ap_registry_store_value(REGKEY, "ServerRoot", dir);
}
