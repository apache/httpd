/*
** Copyright (C) 1998-2000 Greg Stein. All Rights Reserved.
**
** By using this file, you agree to the terms and conditions set forth in
** the LICENSE.html file which can be found at the top level of the mod_dav
** distribution or at http://www.webdav.org/mod_dav/license-1.html.
**
** Contact information:
**   Greg Stein, PO Box 760, Palo Alto, CA, 94302
**   gstein@lyra.org, http://www.webdav.org/mod_dav/
*/

/*
** DAV extension module for Apache 1.3.*
**  - Database support using DBM-style databases,
**    part of the filesystem repository implementation
**
** Written by Greg Stein, gstein@lyra.org, http://www.lyra.org/
*/

/*
** This implementation uses a SDBM or GDBM database per file and directory to
** record the properties. These databases are kept in a subdirectory (of
** the directory in question or the directory that holds the file in
** question) named by the macro DAV_FS_STATE_DIR (.DAV). The filename of the
** database is equivalent to the target filename, and is
** DAV_FS_STATE_FILE_FOR_DIR (.state_for_dir) for the directory itself.
*/

#ifdef DAV_USE_GDBM
#include <gdbm.h>
#else
#include <fcntl.h>		/* for O_RDONLY, O_WRONLY */
#include "sdbm/sdbm.h"
#endif

#include "mod_dav.h"
#include "dav_fs_repos.h"


#ifdef DAV_USE_GDBM

typedef GDBM_FILE dav_dbm_file;

#define DAV_DBM_CLOSE(f)	gdbm_close(f)
#define DAV_DBM_FETCH(f, k)	gdbm_fetch((f), (k))
#define DAV_DBM_STORE(f, k, v)	gdbm_store((f), (k), (v), GDBM_REPLACE)
#define DAV_DBM_DELETE(f, k)	gdbm_delete((f), (k))
#define DAV_DBM_FIRSTKEY(f)	gdbm_firstkey(f)
#define DAV_DBM_NEXTKEY(f, k)	gdbm_nextkey((f), (k))
#define DAV_DBM_CLEARERR(f)	if (0) ; else	/* stop "no effect" warning */
#define DAV_DBM_FREEDATUM(f, d)	((d).dptr ? free((d).dptr) : 0)

#else

typedef DBM *dav_dbm_file;

#define DAV_DBM_CLOSE(f)	sdbm_close(f)
#define DAV_DBM_FETCH(f, k)	sdbm_fetch((f), (k))
#define DAV_DBM_STORE(f, k, v)	sdbm_store((f), (k), (v), DBM_REPLACE)
#define DAV_DBM_DELETE(f, k)	sdbm_delete((f), (k))
#define DAV_DBM_FIRSTKEY(f)	sdbm_firstkey(f)
#define DAV_DBM_NEXTKEY(f, k)	sdbm_nextkey(f)
#define DAV_DBM_CLEARERR(f)	sdbm_clearerr(f)
#define DAV_DBM_FREEDATUM(f, d)	if (0) ; else	/* stop "no effect" warning */

#endif

struct dav_db {
    pool *pool;
    dav_dbm_file file;
};

#define D2G(d)	(*(datum*)&(d))


void dav_dbm_get_statefiles(pool *p, const char *fname,
			    const char **state1, const char **state2)
{
    char *work;

    if (fname == NULL)
	fname = DAV_FS_STATE_FILE_FOR_DIR;

#ifndef DAV_USE_GDBM
    fname = ap_pstrcat(p, fname, DIRFEXT, NULL);
#endif

    *state1 = fname;

#ifdef DAV_USE_GDBM
    *state2 = NULL;
#else
    {
	int extension;

	work = ap_pstrdup(p, fname);

	/* we know the extension is 4 characters -- len(DIRFEXT) */
	extension = strlen(work) - 4;
	memcpy(&work[extension], PAGFEXT, 4);
	*state2 = work;
    }
#endif
}

static dav_error * dav_fs_dbm_error(dav_db *db, pool *p)
{
    int save_errno = errno;
    int errcode;
    const char *errstr;
    dav_error *err;

    p = db ? db->pool : p;

#ifdef DAV_USE_GDBM
    errcode = gdbm_errno;
    errstr = gdbm_strerror(gdbm_errno);
#else
    /* There might not be a <db> if we had problems creating it. */
    errcode = !db || sdbm_error(db->file);
    if (errcode)
	errstr = "I/O error occurred.";
    else
	errstr = "No error.";
#endif

    err = dav_new_error(p, HTTP_INTERNAL_SERVER_ERROR, errcode, errstr);
    err->save_errno = save_errno;
    return err;
}

/* ensure that our state subdirectory is present */
/* ### does this belong here or in dav_fs_repos.c ?? */
void dav_fs_ensure_state_dir(pool * p, const char *dirname)
{
    const char *pathname = ap_pstrcat(p, dirname, "/" DAV_FS_STATE_DIR, NULL);

    /* ### do we need to deal with the umask? */

    /* just try to make it, ignoring any resulting errors */
    mkdir(pathname, DAV_FS_MODE_DIR);
}

/* dav_dbm_open_direct:  Opens a *dbm database specified by path.
 *    ro = boolean read-only flag.
 */
dav_error * dav_dbm_open_direct(pool *p, const char *pathname, int ro,
				dav_db **pdb)
{
    dav_dbm_file file;

    *pdb = NULL;

    /* NOTE: stupid cast to get rid of "const" on the pathname */
#ifdef DAV_USE_GDBM
    file = gdbm_open((char *) pathname,
		     0,
		     ro ? GDBM_READER : GDBM_WRCREAT,
		     DAV_FS_MODE_FILE,
		     NULL);
#else
    file = sdbm_open((char *) pathname,
		     ro ? O_RDONLY : (O_RDWR | O_CREAT),
		     DAV_FS_MODE_FILE);
#endif

    /* we can't continue if we couldn't open the file and we need to write */
    if (file == NULL && !ro) {
	return dav_fs_dbm_error(NULL, p);
    }

    /* may be NULL if we tried to open a non-existent db as read-only */
    if (file != NULL) {
	/* we have an open database... return it */
	*pdb = ap_pcalloc(p, sizeof(**pdb));
	(*pdb)->pool = p;
	(*pdb)->file = file;
    }

    return NULL;
}

static dav_error * dav_dbm_open(pool * p, const dav_resource *resource, int ro,
				dav_db **pdb)
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

    pathname = ap_pstrcat(p,
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
    DAV_DBM_CLOSE(db->file);
}

static dav_error * dav_dbm_fetch(dav_db *db, dav_datum key, dav_datum *pvalue)
{
    *(datum *) pvalue = DAV_DBM_FETCH(db->file, D2G(key));

    /* we don't need the error; we have *pvalue to tell */
    DAV_DBM_CLEARERR(db->file);

    return NULL;
}

static dav_error * dav_dbm_store(dav_db *db, dav_datum key, dav_datum value)
{
    int rv;

    rv = DAV_DBM_STORE(db->file, D2G(key), D2G(value));

    /* ### fetch more specific error information? */

    /* we don't need the error; we have rv to tell */
    DAV_DBM_CLEARERR(db->file);

    if (rv == -1) {
	return dav_fs_dbm_error(db, NULL);
    }
    return NULL;
}

static dav_error * dav_dbm_delete(dav_db *db, dav_datum key)
{
    int rv;

    rv = DAV_DBM_DELETE(db->file, D2G(key));

    /* ### fetch more specific error information? */

    /* we don't need the error; we have rv to tell */
    DAV_DBM_CLEARERR(db->file);

    if (rv == -1) {
	return dav_fs_dbm_error(db, NULL);
    }
    return NULL;
}

static int dav_dbm_exists(dav_db *db, dav_datum key)
{
    int exists;

#ifdef DAV_USE_GDBM
    exists = gdbm_exists(db->file, D2G(key)) != 0;
#else
    {
	datum value = sdbm_fetch(db->file, D2G(key));
	sdbm_clearerr(db->file);	/* unneeded */
	exists = value.dptr != NULL;
    }
#endif
    return exists;
}

static dav_error * dav_dbm_firstkey(dav_db *db, dav_datum *pkey)
{
    *(datum *) pkey = DAV_DBM_FIRSTKEY(db->file);

    /* we don't need the error; we have *pkey to tell */
    DAV_DBM_CLEARERR(db->file);

    return NULL;
}

static dav_error * dav_dbm_nextkey(dav_db *db, dav_datum *pkey)
{
    *(datum *) pkey = DAV_DBM_NEXTKEY(db->file, D2G(*pkey));

    /* we don't need the error; we have *pkey to tell */
    DAV_DBM_CLEARERR(db->file);

    return NULL;
}

static void dav_dbm_freedatum(dav_db *db, dav_datum data)
{
    DAV_DBM_FREEDATUM(db, data);
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
