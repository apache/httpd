#ifndef APACHE_OS_H
#define APACHE_OS_H

#define PLATFORM "BS2000"

/*
 * This file in included in all Apache source code. It contains definitions
 * of facilities available on _this_ operating system (HAVE_* macros),
 * and prototypes of OS specific functions defined in os.c or os-inline.c
 */

#if !defined(INLINE) && defined(USE_GNU_INLINE)
/* Compiler supports inline, so include the inlineable functions as
 * part of the header
 */
#define INLINE extern ap_inline

INLINE int ap_os_is_path_absolute(const char *file);

#include "os-inline.c"
#endif

#ifndef INLINE
/* Compiler does not support inline, so prototype the inlineable functions
 * as normal
 */
extern int ap_os_is_path_absolute(const char *file);
#endif

/* Other ap_os_ routines not used by this platform */

#define ap_os_is_filename_valid(f)          (1)
#define ap_os_kill(pid, sig)                kill(pid, sig)

#if !defined(_POSIX_SOURCE) && !defined(_XOPEN_SOURCE) && !defined(HAVE_RINI_STRUCT)
typedef struct {           
    char    *username;     
    char    *account;      
    char    *processor_name;
}  _rini_struct;           

extern int _rini(_rini_struct *);
#endif /* !defined(_POSIX_SOURCE) && !defined(_XOPEN_SOURCE) */

extern pid_t os_fork(const char *user);
#ifdef _OSD_POSIX
struct pool;
extern const char *os_set_account(struct pool *p, const char *account);
struct server_rec;
extern int os_init_job_environment(struct server_rec *s, const char *user_name, int one_process);
#endif

#ifdef HAVE_DLFCN_H
#include <dlfcn.h>
#define     ap_os_dso_handle_t  void *
void        ap_os_dso_init(void);
void *      ap_os_dso_load(const char *);
void        ap_os_dso_unload(void *);
void *      ap_os_dso_sym(void *, const char *);
const char *ap_os_dso_error(void);
#endif

#endif /*! APACHE_OS_H*/
