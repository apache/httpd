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
** Declarations for the filesystem repository implementation
**
** Written by John Vasta, vasta@rational.com, by separating from mod_dav.h
*/

#ifndef _DAV_FS_REPOS_H_
#define _DAV_FS_REPOS_H_

/* the subdirectory to hold all DAV-related information for a directory */
#define DAV_FS_STATE_DIR		".DAV"
#define DAV_FS_STATE_FILE_FOR_DIR	".state_for_dir"
#define DAV_FS_LOCK_NULL_FILE	        ".locknull"

#ifndef WIN32

#define DAV_FS_MODE_DIR		(S_IRWXU | S_IRWXG)
#define DAV_FS_MODE_FILE	(S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP)
#define DAV_FS_MODE_XUSR    (S_IXUSR)

#else /* WIN32 */

#define DAV_FS_MODE_DIR		(_S_IREAD | _S_IWRITE)
#define DAV_FS_MODE_FILE	(_S_IREAD | _S_IWRITE)
#define DAV_FS_MODE_XUSR    (_S_IEXEC)

#include <limits.h>

typedef int ssize_t;

#define mkdir(p,m)		_mkdir(p)

#endif /* WIN32 */

/* ensure that our state subdirectory is present */
void dav_fs_ensure_state_dir(pool *p, const char *dirname);

/* return the storage pool associated with a resource */
pool *dav_fs_pool(const dav_resource *resource);

/* return the full pathname for a resource */
const char *dav_fs_pathname(const dav_resource *resource);

/* return the directory and filename for a resource */
void dav_fs_dir_file_name(const dav_resource *resource,
			  const char **dirpath,
			  const char **fname);

/* return the list of locknull members in this resource's directory */
dav_error * dav_fs_get_locknull_members(const dav_resource *resource,
                                        dav_buffer *pbuf);


/* DBM functions used by the repository and locking providers */
extern const dav_hooks_db dav_hooks_db_dbm;

dav_error * dav_dbm_open_direct(pool *p, const char *pathname, int ro,
				dav_db **pdb);
void dav_dbm_get_statefiles(pool *p, const char *fname,
			    const char **state1, const char **state2);


#endif /* _DAV_FS_REPOS_H_ */
