/*
 * Functions to handle interacting with the Win32 registry
 */

/*
 * Apache registry key structure
 *
 * Apache's registry information is stored in the HKEY_LOCAL_MACHINE
 * key, under
 *
 *  HKLM\SOFTWARE\Apache Group\Apache\version
 *
 * These keys are defined in this file. The definition of the "version" part
 * will need updating each time Apache moves from beta to non-beta or from a
 * release to a development or beta version.
 */

#include <windows.h>
#include <stdio.h>

#include "httpd.h"
#include "http_log.h"

/* Define where the Apache values are stored in the registry. In general
 * VERSION will be the same across all beta releases for a particular
 * major release, but will change when the final release is made.
 */

#define VENDOR   "Apache Group"
#define SOFTWARE "Apache"
#define VERSION  "1.3.2"

#define REGKEY "SOFTWARE\\" VENDOR "\\" SOFTWARE "\\" VERSION

/*
 * The Windows API registry key functions don't set the last error
 * value (the windows equivalent of errno). So we need to set it
 * with SetLastError() before calling the aplog_error() function.
 * Because this is common, let's have a macro.
 */
#define do_error(rv,fmt,arg) do { \
	SetLastError(rv); \
	ap_log_error(APLOG_MARK, APLOG_WIN32ERROR|APLOG_ERR, NULL, fmt,arg); \
    } while (0);

/*
 * Get the data for registry key value. This is a generic function that
 * can either get a value into a caller-supplied buffer, or it can
 * allocate space for the value from the pass-in pool. It will normally
 * be used by other functions within this file to get specific key values
 * (e.g. registry_get_server_root()). This function returns a number of
 * different error statuses, allowing the caller to differentiate
 * between a key or value not existing and other kinds of errors. Depending
 * on the type of data being obtained the caller can then either ignore
 * the key-not-existing error, or treat it as a real error.
 *
 * If ppValue is NULL, allocate space for the value and return it in
 * *pValue. The return value is the number of bytes in the value.
 * The first argument is the pool to use to allocate space for the value.
 *
 * If pValue is not NULL, assume it is a buffer of nSizeValue bytes,
 * and write the value into the buffer. The return value is the number
 * of bytes in the value (so if the return value is greater than
 * the supplied nSizeValue, the caller knows that *pValue is truncated).
 * The pool argument is ignored.
 *
 * The return value is the number of bytes in the successfully retreived
 * key if everything worked, or:
 *
 *  -1 the key does not exists
 *  -2 if out of memory during the function
 *  -3 if the buffer specified by *pValue/nSizeValue was not large enough 
 *     for the value.
 *  -4 if an error occurred
 *
 * If the return value is negative a message will be logged to the error
 * log (aplog_error) function. If the return value is -2, -3 or -4 the message
 * will be logged at priority "error", while if the return value is -1 the
 * message will be logged at priority "warning".
 */

static int ap_registry_get_key_int(pool *p, char *key, char *pBuffer, int nSizeBuffer, char **ppValue)
{
    long rv;
    HKEY hKey;
    char *pValue;
    int nSize;
    int retval;

    rv = RegOpenKeyEx(HKEY_LOCAL_MACHINE,
		      REGKEY,
		      0,
		      KEY_READ,
		      &hKey);

    if (rv == ERROR_FILE_NOT_FOUND) {
	ap_log_error(APLOG_MARK,APLOG_WARNING|APLOG_NOERRNO,NULL,
	    "Registry does not contain key " REGKEY);
	return -1;
    }
    if (rv != ERROR_SUCCESS) {
	do_error(rv, "RegOpenKeyEx HKLM\\" REGKEY,
		 NULL);
	return -4;
    }

    if (pBuffer == NULL) {
	/* Find the size required for the data by passing NULL as the buffer
	 * pointer. On return nSize will contain the size required for the
	 * buffer if the return value is ERROR_SUCCESS.
	 */
	rv = RegQueryValueEx(hKey, 
			     key,		/* key name */
			     NULL,		/* reserved */
			     NULL,		/* type */
			     NULL,		/* for value */
			     &nSize);		/* for size of "value" */

	if (rv != ERROR_SUCCESS) {
	    do_error(rv, "RegQueryValueEx(key %s)", key);
	    return -1;
	}

	pValue = ap_palloc(p, nSize);
	*ppValue = pValue;
	if (!pValue) {
	    /* Eek, out of memory, probably not worth trying to carry on,
	     * but let's give it a go
	     */
	    ap_log_error(APLOG_MARK,APLOG_ERR|APLOG_NOERRNO,NULL,
		"Error getting registry key: out of memory");
	    return -2;
	}
    }
    else {
	/* Get the value into the existing buffer of length nSizeBuffer */
	pValue = pBuffer;
	nSize = nSizeBuffer;
    }

    rv = RegQueryValueEx(hKey, 
			 key,		/* key name */
			 NULL,		/* reserved */
			 NULL,		/* type */
			 pValue,		/* for value */
			 &nSize);		/* for size of "value" */

    retval = 0;	    /* Return value */

    if (rv == ERROR_FILE_NOT_FOUND) {
	ap_log_error(APLOG_MARK,APLOG_WARNING|APLOG_NOERRNO,NULL,
	    "Registry does not contain value " REGKEY "\\%s", key);
	retval = -1;
    }
    else if (rv == ERROR_MORE_DATA) {
	/* This should only happen if we got passed a pre-existing buffer
	 * (pBuffer, nSizeBuffer). But I suppose it could also happen if we
	 * allocate a buffer if another process changed the length of the
	 * value since we found out its length above. Umm.
	 */
	ap_log_error(APLOG_MARK,APLOG_ERR|APLOG_NOERRNO,NULL,
	    "Error getting registry value %s: buffer not big enough", key);
	retval = -3;
    }
    else if (rv != ERROR_SUCCESS) {
	do_error(rv, "RegQueryValueEx(key %s)", key);
	retval = -4;
    }

    rv = RegCloseKey(hKey);
    if (rv != ERROR_SUCCESS) {
	do_error(rv, "RegCloseKey HKLM\\" REGKEY, NULL);
	if (retval == 0) {
	    /* Keep error status from RegQueryValueEx, if any */
	    retval = -4;  
	}
    }

    return retval < 0 ? retval : nSize;
}

/*
 * Get the server root from the registry into 'dir' which is
 * size bytes long. Returns 0 if the server root was found
 * or if the serverroot key does not exist (in which case
 * dir will contain an empty string), or -1 if there was
 * an error getting the key.
 */

int ap_registry_get_server_root(pool *p, char *dir, int size)
{
    int rv;

    rv = ap_registry_get_key_int(p, "ServerRoot", dir, size, NULL);
    if (rv < 0) {
	dir[0] = '\0';
    }

    return (rv < -1) ? -1 : 0;
}

/**********************************************************************
 * The rest of this file deals with storing keys or values in the registry
 */

/*
 * ap_registry_create_apache_key() creates the Apache registry key
 * (HLKM\SOFTWARE\Apache Group\Apache\version, as defined at the start
 * of this file), if it does not already exist. It will be called by
 * ap_registry_store_key_int() if it cannot open this key. This 
 * function is intended to be called by ap_registry_store_key_int() if
 * the Apache key does not exist when it comes to store a data item.
 *
 * Returns 0 on success or -1 on error. If -1 is returned, the error will
 * already have been logged.
 */

static int ap_registry_create_apache_key(void)
{
    static char *keys[] = 
    { "SOFTWARE",
	VENDOR,
	SOFTWARE,
	VERSION,
	NULL
    };
    int index;
    HKEY hKey;
    HKEY hKeyNext;
    int retval;
    int rv;

    hKey = HKEY_LOCAL_MACHINE;
    index = 0;
    retval = 0;

    /* Walk the tree, creating at each stage if necessary */
    while (keys[index]) {
	int result;

	rv = RegCreateKeyEx(hKey,
			    keys[index], /* subkey */
			    0,	         /* reserved */
			    NULL,        /* class */
			    REG_OPTION_NON_VOLATILE,
			    KEY_WRITE,
			    NULL,
			    &hKeyNext,
			    &result);
	if (rv != ERROR_SUCCESS) {
	    do_error(rv, "RegCreateKeyEx(%s)", keys[index]);
	    retval = -4;
	}

	/* Close the old key */
	rv = RegCloseKey(hKey);
	if (rv != ERROR_SUCCESS) {
	    do_error(rv, "RegCloseKey", NULL);
	    if (retval == 0) {
		/* Keep error status from RegCreateKeyEx, if any */
		retval = -4;  
	    }
	}

	if (retval) {
	    break;
	}

	hKey = hKeyNext;
	index++;
    }

    if (keys[index] == NULL) {
	/* Close the final key we opened, if we walked the entire
	 * tree
	 */
	rv = RegCloseKey(hKey);
	if (rv != ERROR_SUCCESS) {
	    do_error(rv, "RegCloseKey", NULL);
	    if (retval == 0) {
		/* Keep error status from RegCreateKeyEx, if any */
		retval = -4;  
	    }
	}
    }

    return retval;
}

/*
 * ap_registry_store_key_int() stores a value name and value under the
 * Apache registry key. If the Apache key does not exist it is created
 * first. This function is intended to be called from a wrapper function
 * in this file to set particular data values, such as 
 * ap_registry_set_server_root() below.
 *
 * Returns 0 if the value name and data was stored successfully, or
 * returns -1 if the Apache key does not exist (since we try to create 
 * this key, this should never happen), or -4 if any other error occurred
 * (these values are consistent with ap_registry_get_key_int()).
 * If the return value is negative then the error will already have been
 * logged via aplog_error().
 */

static int ap_registry_store_key_int(char *key, DWORD type, void *value, int value_size)
{
    long rv;
    HKEY hKey;
    int retval;

    rv = RegOpenKeyEx(HKEY_LOCAL_MACHINE,
		      REGKEY,
		      0,
	 	      KEY_WRITE,
		      &hKey);

    if (rv == ERROR_FILE_NOT_FOUND) {
	/* Key could not be opened -- try to create it 
	 */
	if (ap_registry_create_apache_key() < 0) {
	    /* Creation failed (error already reported) */
	    return -4;
	}
	
	/* Now it has been created we should be able to open it
	 */
	rv = RegOpenKeyEx(HKEY_LOCAL_MACHINE,
		  REGKEY,
		  0,
	 	  KEY_WRITE,
		  &hKey);

	if (rv == ERROR_FILE_NOT_FOUND) {
	    ap_log_error(APLOG_MARK,APLOG_WARNING|APLOG_NOERRNO,NULL,
		"Registry does not contain key " REGKEY " after creation");

	    return -1;
	}
    }

    if (rv != ERROR_SUCCESS) {
	do_error(rv, "RegOpenKeyEx HKLM\\" REGKEY,
		 NULL);
	return -4;
    }

    /* Now set the value and data */
    rv = RegSetValueEx(hKey, 
		       key,	/* value key name */
		       0,	/* reserved */
		       type,	/* type */
		       value,	/* value data */
		       (DWORD)value_size); /* for size of "value" */

    retval = 0;	    /* Return value */

    if (rv != ERROR_SUCCESS) {
	do_error(rv, "RegQueryValueEx(key %s)", key);
	retval = -4;
    }
    else {
	ap_log_error(APLOG_MARK,APLOG_INFO|APLOG_NOERRNO,NULL,
	    "Registry stored HKLM\\" REGKEY "\\%s value %s", key, 
	    type == REG_SZ ? value : "(not displayable)");
    }

    /* Make sure we close the key even if there was an error storing
     * the data
     */
    rv = RegCloseKey(hKey);
    if (rv != ERROR_SUCCESS) {
	do_error(rv, "RegCloseKey HKLM\\" REGKEY, NULL);
	if (retval == 0) {
	    /* Keep error status from RegQueryValueEx, if any */
	    retval = -4;  
	}
    }

    return retval;
}

/*
 * Sets the serverroot value within the registry. Returns 0 on success
 * or -1 on error. If -1 is return the error will already have been
 * logged via aplog_error().
 */

int ap_registry_set_server_root(char *dir)
{
    int rv;

    rv = ap_registry_store_key_int("ServerRoot", REG_SZ, dir, strlen(dir)+1);

    return rv < 0 ? -1 : 0;
}
