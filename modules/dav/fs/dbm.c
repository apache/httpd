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
 */

/*
** DAV extension module for Apache 2.0.*
**  - Database support using DBM-style databases,
**    part of the filesystem repository implementation
*/

/*
** This implementation uses a SDBM database per file and directory to
** record the properties. These databases are kept in a subdirectory (of
** the directory in question or the directory that holds the file in
** question) named by the macro DAV_FS_STATE_DIR (.DAV). The filename of the
** database is equivalent to the target filename, and is
** DAV_FS_STATE_FILE_FOR_DIR (.state_for_dir) for the directory itself.
*/

#include "sdbm.h"

#include "mod_dav.h"
#include "repos.h"

struct dav_db {
    apr_pool_t *pool;
    SDBM *file;
};

#define D2G(d)	(*(sdbm_datum*)&(d))


void dav_dbm_get_statefiles(apr_pool_t *p, const char *fname,
			    const char **state1, const char **state2)
{
    char *work;
    int extension;

    if (fname == NULL)
	fname = DAV_FS_STATE_FILE_FOR_DIR;

    fname = apr_pstrcat(p, fname, SDBM_DIRFEXT, NULL);

    *state1 = fname;

    work = apr_pstrdup(p, fname);

    /* we know the extension is 4 characters -- len(DIRFEXT) */
    extension = strlen(work) - 4;
    memcpy(&work[extension], SDBM_PAGFEXT, 4);
    *state2 = work;

}

static dav_error * dav_fs_dbm_error(dav_db *db, apr_pool_t *p)
{
    int save_errno = errno;
    int errcode;
    const char *errstr;
    dav_error *err;

    p = db ? db->pool : p;

    /* There might not be a <db> if we had problems creating it. */
    errcode = !db || sdbm_error(db->file);
    if (errcode)
	errstr = "I/O error occurred.";
    else
	errstr = "No error.";

    err = dav_new_error(p, HTTP_INTERNAL_SERVER_ERROR, errcode, errstr);
    err->save_errno = save_errno;
    return err;
}

/* ensure that our state subdirectory is present */
/* ### does this belong here or in dav_fs_repos.c ?? */
void dav_fs_ensure_state_dir(apr_pool_t * p, const char *dirname)
{
    const char *pathname = apr_pstrcat(p, dirname, "/" DAV_FS_STATE_DIR, NULL);

    /* ### do we need to deal with the umask? */

    /* just try to make it, ignoring any resulting errors */
    (void) apr_make_dir(pathname, APR_OS_DEFAULT, p);
}

/* dav_dbm_open_direct:  Opens a *dbm database specified by path.
 *    ro = boolean read-only flag.
 */
dav_error * dav_dbm_open_direct(apr_pool_t *p, const char *pathname, int ro,
				dav_db **pdb)
{
    SDBM *file;

    *pdb = NULL;

    /* NOTE: stupid cast to get rid of "const" on the pathname */
    if (sdbm_open(&file, pathname,
		  APR_READ | (ro ? 0 : (APR_WRITE | APR_CREATE)),
		  APR_OS_DEFAULT, p) != APR_SUCCESS && !ro) {
	/* we can't continue if we couldn't open the file 
	   and we need to write */
	return dav_fs_dbm_error(NULL, p);
    }

    /* may be NULL if we tried to open a non-existent db as read-only */
    if (file != NULL) {
	/* we have an open database... return it */
	*pdb = apr_pcalloc(p, sizeof(**pdb));
	(*pdb)->pool = p;
	(*pdb)->file = file;
    }

    return NULL;
}

static dav_error * dav_dbm_open(apr_pool_t * p, const dav_resource *resource,
                                int ro, dav_db **pdb)
{
    const char *dirpath;
    const char *fname;
    const char *pathname;

    /* Get directory and filename for resource */
    dav_fs_dir_file_name(resource, &dirpath, &fname);

    /* If not opening read-only, ensure the state dir exists */
    if (!ro) {
	/* ### what are the perf implications of always checking this? */
        dav_fs_ensure_state_dir(p, dirpath);
    }

    pathname = apr_pstrcat(p,
			  dirpath,
			  "/" DAV_FS_STATE_DIR "/",
			  fname ? fname : DAV_FS_STATE_FILE_FOR_DIR,
			  NULL);

    /* ### readers cannot open while a writer has this open; we should
       ### perform a few retries with random pauses. */

    /* ### do we need to deal with the umask? */

    return dav_dbm_open_direct(p, pathname, ro, pdb);
}

static void dav_dbm_close(dav_db *db)
{
    sdbm_close(db->file);
}

static dav_error * dav_dbm_fetch(dav_db *db, dav_datum key, dav_datum *pvalue)
{
    *(sdbm_datum *) pvalue = sdbm_fetch(db->file, D2G(key));

    /* we don't need the error; we have *pvalue to tell */
    sdbm_clearerr(db->file);

    return NULL;
}

static dav_error * dav_dbm_store(dav_db *db, dav_datum key, dav_datum value)
{
    apr_status_t status;

    status = sdbm_store(db->file, D2G(key), D2G(value), SDBM_REPLACE);

    /* ### fetch more specific error information? */

    /* we don't need the error; we have rv to tell */
    sdbm_clearerr(db->file);

    if (status != APR_SUCCESS) {
	return dav_fs_dbm_error(db, NULL);
    }
    return NULL;
}

static dav_error * dav_dbm_delete(dav_db *db, dav_datum key)
{
    int rv;

    rv = sdbm_delete(db->file, D2G(key));

    /* ### fetch more specific error information? */

    /* we don't need the error; we have rv to tell */
    sdbm_clearerr(db->file);

    if (rv == -1) {
	return dav_fs_dbm_error(db, NULL);
    }
    return NULL;
}

static int dav_dbm_exists(dav_db *db, dav_datum key)
{
    int exists;
    sdbm_datum value = sdbm_fetch(db->file, D2G(key));

    sdbm_clearerr(db->file);	/* unneeded */
    exists = value.dptr != NULL;

    return exists;
}

static dav_error * dav_dbm_firstkey(dav_db *db, dav_datum *pkey)
{
    *(sdbm_datum *) pkey = sdbm_firstkey(db->file);

    /* we don't need the error; we have *pkey to tell */
    sdbm_clearerr(db->file);

    return NULL;
}

static dav_error * dav_dbm_nextkey(dav_db *db, dav_datum *pkey)
{
    *(sdbm_datum *) pkey = sdbm_nextkey(db->file);

    /* we don't need the error; we have *pkey to tell */
    sdbm_clearerr(db->file);

    return NULL;
}

static void dav_dbm_freedatum(dav_db *db, dav_datum data)
{
    /* nothing */
}

const dav_hooks_db dav_hooks_db_dbm =
{
    dav_dbm_open,
    dav_dbm_close,
    dav_dbm_fetch,
    dav_dbm_store,
    dav_dbm_delete,
    dav_dbm_exists,
    dav_dbm_firstkey,
    dav_dbm_nextkey,
    dav_dbm_freedatum,
};
