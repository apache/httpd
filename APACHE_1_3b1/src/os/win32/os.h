/*
 * This file in included in all Apache source code. It contains definitions
 * of facilities available on _this_ operating system (HAVE_* macros),
 * and prototypes of OS specific functions defined in os.c
 */

/* temporarily replace crypt */
/* char *crypt(const char *pw, const char *salt); */
#define crypt(buf,salt)	    (buf)

/* Although DIR_TYPE is dirent (see nt/readdir.h) we need direct.h for
   chdir() */
#include <direct.h>

#define STATUS
#define WIN32_LEAN_AND_MEAN
#define STRICT
#define NO_UNISTD_H
#define NO_WRITEV
#define NO_SETSID
#define NO_USE_SIGACTION
#define NO_TIMES
#define NO_GETTIMEOFDAY
#define NEED_PROCESS_H
#define USE_LONGJMP
#define HAVE_MMAP
#define MULTITHREAD
#define HAVE_CANONICAL_FILENAME
typedef int uid_t;
typedef int gid_t;
typedef int pid_t;
typedef int mode_t;
typedef char * caddr_t;

/*
Define export types. API_EXPORT_NONSTD is a nasty hack to avoid having to declare
every configuration function as __stdcall.
*/

#define API_EXPORT(type)    __declspec(dllexport) type __stdcall
#define API_EXPORT_NONSTD(type)    __declspec(dllexport) type
#ifdef IS_MODULE
# define API_VAR_EXPORT		__declspec(dllimport)
#else
# define API_VAR_EXPORT		__declspec(dllexport)
#endif
#define MODULE_VAR_EXPORT   __declspec(dllexport)

#define strcasecmp(s1, s2) stricmp(s1, s2)
#define strncasecmp(s1, s2, n) strnicmp(s1, s2, n)
#define lstat(x, y) stat(x, y)
#define S_ISLNK(m) (0)
#define S_ISREG(m) ((m & _S_IFREG) == _S_IFREG)
#ifndef S_ISDIR
#define S_ISDIR(m) (((m) & S_IFDIR) == S_IFDIR)
#endif
#ifndef S_ISREG
#define S_ISREG(m)      (((m)&(S_IFREG)) == (S_IFREG))
#endif
#define STDIN_FILENO  0
#define STDOUT_FILENO 1
#define STDERR_FILENO 2
#define JMP_BUF jmp_buf
#define sleep(t) Sleep(t*1000)
#define O_CREAT _O_CREAT
#define O_RDWR _O_RDWR
#define SIGPIPE 17
/* Seems Windows is not a subgenius */
#define NO_SLACK
#include <stddef.h>

#define NO_OTHER_CHILD
#define NO_RELIABLE_PIPED_LOGS

__inline int os_is_path_absolute(char *file)
{
  /* For now, just do the same check that http_request.c and mod_alias.c
   * do. 
   */
  return file && (file[0] == '/' || file[1] == ':');
}

