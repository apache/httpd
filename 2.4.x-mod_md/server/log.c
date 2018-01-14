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
 * http_log.c: Dealing with the logs and errors
 *
 * Rob McCool
 *
 */

#include "apr.h"
#include "apr_general.h"        /* for signal stuff */
#include "apr_strings.h"
#include "apr_errno.h"
#include "apr_thread_proc.h"
#include "apr_lib.h"
#include "apr_signal.h"
#include "apr_portable.h"
#include "apr_base64.h"

#define APR_WANT_STDIO
#define APR_WANT_STRFUNC
#include "apr_want.h"

#if APR_HAVE_STDARG_H
#include <stdarg.h>
#endif
#if APR_HAVE_UNISTD_H
#include <unistd.h>
#endif
#if APR_HAVE_PROCESS_H
#include <process.h>            /* for getpid() on Win32 */
#endif

#include "ap_config.h"
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_main.h"
#include "util_time.h"
#include "ap_mpm.h"
#include "ap_listen.h"

#if HAVE_GETTID
#include <sys/syscall.h>
#include <sys/types.h>
#endif

/* we know core's module_index is 0 */
#undef APLOG_MODULE_INDEX
#define APLOG_MODULE_INDEX AP_CORE_MODULE_INDEX

typedef struct {
    const char *t_name;
    int t_val;
} TRANS;

APR_HOOK_STRUCT(
    APR_HOOK_LINK(error_log)
    APR_HOOK_LINK(generate_log_id)
)

int AP_DECLARE_DATA ap_default_loglevel = DEFAULT_LOGLEVEL;

#ifdef HAVE_SYSLOG

static const TRANS facilities[] = {
    {"auth",    LOG_AUTH},
#ifdef LOG_AUTHPRIV
    {"authpriv",LOG_AUTHPRIV},
#endif
#ifdef LOG_CRON
    {"cron",    LOG_CRON},
#endif
#ifdef LOG_DAEMON
    {"daemon",  LOG_DAEMON},
#endif
#ifdef LOG_FTP
    {"ftp", LOG_FTP},
#endif
#ifdef LOG_KERN
    {"kern",    LOG_KERN},
#endif
#ifdef LOG_LPR
    {"lpr", LOG_LPR},
#endif
#ifdef LOG_MAIL
    {"mail",    LOG_MAIL},
#endif
#ifdef LOG_NEWS
    {"news",    LOG_NEWS},
#endif
#ifdef LOG_SYSLOG
    {"syslog",  LOG_SYSLOG},
#endif
#ifdef LOG_USER
    {"user",    LOG_USER},
#endif
#ifdef LOG_UUCP
    {"uucp",    LOG_UUCP},
#endif
#ifdef LOG_LOCAL0
    {"local0",  LOG_LOCAL0},
#endif
#ifdef LOG_LOCAL1
    {"local1",  LOG_LOCAL1},
#endif
#ifdef LOG_LOCAL2
    {"local2",  LOG_LOCAL2},
#endif
#ifdef LOG_LOCAL3
    {"local3",  LOG_LOCAL3},
#endif
#ifdef LOG_LOCAL4
    {"local4",  LOG_LOCAL4},
#endif
#ifdef LOG_LOCAL5
    {"local5",  LOG_LOCAL5},
#endif
#ifdef LOG_LOCAL6
    {"local6",  LOG_LOCAL6},
#endif
#ifdef LOG_LOCAL7
    {"local7",  LOG_LOCAL7},
#endif
    {NULL,      -1},
};
#endif

static const TRANS priorities[] = {
    {"emerg",   APLOG_EMERG},
    {"alert",   APLOG_ALERT},
    {"crit",    APLOG_CRIT},
    {"error",   APLOG_ERR},
    {"warn",    APLOG_WARNING},
    {"notice",  APLOG_NOTICE},
    {"info",    APLOG_INFO},
    {"debug",   APLOG_DEBUG},
    {"trace1",  APLOG_TRACE1},
    {"trace2",  APLOG_TRACE2},
    {"trace3",  APLOG_TRACE3},
    {"trace4",  APLOG_TRACE4},
    {"trace5",  APLOG_TRACE5},
    {"trace6",  APLOG_TRACE6},
    {"trace7",  APLOG_TRACE7},
    {"trace8",  APLOG_TRACE8},
    {NULL,      -1},
};

static apr_pool_t *stderr_pool = NULL;

static apr_file_t *stderr_log = NULL;

/* track pipe handles to close in child process */
typedef struct read_handle_t {
    struct read_handle_t *next;
    apr_file_t *handle;
} read_handle_t;

static read_handle_t *read_handles;

/**
 * @brief The piped logging structure.
 *
 * Piped logs are used to move functionality out of the main server.
 * For example, log rotation is done with piped logs.
 */
struct piped_log {
    /** The pool to use for the piped log */
    apr_pool_t *p;
    /** The pipe between the server and the logging process */
    apr_file_t *read_fd, *write_fd;
#ifdef AP_HAVE_RELIABLE_PIPED_LOGS
    /** The name of the program the logging process is running */
    char *program;
    /** The pid of the logging process */
    apr_proc_t *pid;
    /** How to reinvoke program when it must be replaced */
    apr_cmdtype_e cmdtype;
#endif
};

AP_DECLARE(apr_file_t *) ap_piped_log_read_fd(piped_log *pl)
{
    return pl->read_fd;
}

AP_DECLARE(apr_file_t *) ap_piped_log_write_fd(piped_log *pl)
{
    return pl->write_fd;
}

/* remember to close this handle in the child process
 *
 * On Win32 this makes zero sense, because we don't
 * take the parent process's child procs.
 * If the win32 parent instead passed each and every
 * logger write handle from itself down to the child,
 * and the parent manages all aspects of keeping the
 * reliable pipe log children alive, this would still
 * make no sense :)  Cripple it on Win32.
 */
static void close_handle_in_child(apr_pool_t *p, apr_file_t *f)
{
#ifndef WIN32
    read_handle_t *new_handle;

    new_handle = apr_pcalloc(p, sizeof(read_handle_t));
    new_handle->next = read_handles;
    new_handle->handle = f;
    read_handles = new_handle;
#endif
}

void ap_logs_child_init(apr_pool_t *p, server_rec *s)
{
    read_handle_t *cur = read_handles;

    while (cur) {
        apr_file_close(cur->handle);
        cur = cur->next;
    }
}

AP_DECLARE(void) ap_open_stderr_log(apr_pool_t *p)
{
    apr_file_open_stderr(&stderr_log, p);
}

AP_DECLARE(apr_status_t) ap_replace_stderr_log(apr_pool_t *p,
                                               const char *fname)
{
    apr_file_t *stderr_file;
    apr_status_t rc;
    char *filename = ap_server_root_relative(p, fname);
    if (!filename) {
        ap_log_error(APLOG_MARK, APLOG_STARTUP|APLOG_CRIT,
                     APR_EBADPATH, NULL, APLOGNO(00085) "Invalid -E error log file %s",
                     fname);
        return APR_EBADPATH;
    }
    if ((rc = apr_file_open(&stderr_file, filename,
                            APR_APPEND | APR_WRITE | APR_CREATE | APR_LARGEFILE,
                            APR_OS_DEFAULT, p)) != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_STARTUP, rc, NULL, APLOGNO(00086)
                     "%s: could not open error log file %s.",
                     ap_server_argv0, fname);
        return rc;
    }
    if (!stderr_pool) {
        /* This is safe provided we revert it when we are finished.
         * We don't manager the callers pool!
         */
        stderr_pool = p;
    }
    if ((rc = apr_file_open_stderr(&stderr_log, stderr_pool))
            == APR_SUCCESS) {
        apr_file_flush(stderr_log);
        if ((rc = apr_file_dup2(stderr_log, stderr_file, stderr_pool))
                == APR_SUCCESS) {
            apr_file_close(stderr_file);
            /*
             * You might ponder why stderr_pool should survive?
             * The trouble is, stderr_pool may have s_main->error_log,
             * so we aren't in a position to destory stderr_pool until
             * the next recycle.  There's also an apparent bug which
             * is not; if some folk decided to call this function before
             * the core open error logs hook, this pool won't survive.
             * Neither does the stderr logger, so this isn't a problem.
             */
        }
    }
    /* Revert, see above */
    if (stderr_pool == p)
        stderr_pool = NULL;

    if (rc != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rc, NULL, APLOGNO(00087)
                     "unable to replace stderr with error log file");
    }
    return rc;
}

static void log_child_errfn(apr_pool_t *pool, apr_status_t err,
                            const char *description)
{
    ap_log_error(APLOG_MARK, APLOG_ERR, err, NULL, APLOGNO(00088)
                 "%s", description);
}

/* Create a child process running PROGNAME with a pipe connected to
 * the childs stdin.  The write-end of the pipe will be placed in
 * *FPIN on successful return.  If dummy_stderr is non-zero, the
 * stderr for the child will be the same as the stdout of the parent.
 * Otherwise the child will inherit the stderr from the parent. */
static int log_child(apr_pool_t *p, const char *progname,
                     apr_file_t **fpin, apr_cmdtype_e cmdtype,
                     int dummy_stderr)
{
    /* Child process code for 'ErrorLog "|..."';
     * may want a common framework for this, since I expect it will
     * be common for other foo-loggers to want this sort of thing...
     */
    apr_status_t rc;
    apr_procattr_t *procattr;
    apr_proc_t *procnew;
    apr_file_t *errfile;

    if (((rc = apr_procattr_create(&procattr, p)) == APR_SUCCESS)
        && ((rc = apr_procattr_dir_set(procattr,
                                       ap_server_root)) == APR_SUCCESS)
        && ((rc = apr_procattr_cmdtype_set(procattr, cmdtype)) == APR_SUCCESS)
        && ((rc = apr_procattr_io_set(procattr,
                                      APR_FULL_BLOCK,
                                      APR_NO_PIPE,
                                      APR_NO_PIPE)) == APR_SUCCESS)
        && ((rc = apr_procattr_error_check_set(procattr, 1)) == APR_SUCCESS)
        && ((rc = apr_procattr_child_errfn_set(procattr, log_child_errfn))
                == APR_SUCCESS)) {
        char **args;

        apr_tokenize_to_argv(progname, &args, p);
        procnew = (apr_proc_t *)apr_pcalloc(p, sizeof(*procnew));

        if (dummy_stderr) {
            if ((rc = apr_file_open_stdout(&errfile, p)) == APR_SUCCESS)
                rc = apr_procattr_child_err_set(procattr, errfile, NULL);
        }

        rc = apr_proc_create(procnew, args[0], (const char * const *)args,
                             NULL, procattr, p);

        if (rc == APR_SUCCESS) {
            apr_pool_note_subprocess(p, procnew, APR_KILL_AFTER_TIMEOUT);
            (*fpin) = procnew->in;
            /* read handle to pipe not kept open, so no need to call
             * close_handle_in_child()
             */
        }
    }

    return rc;
}

/* Open the error log for the given server_rec.  If IS_MAIN is
 * non-zero, s is the main server. */
static int open_error_log(server_rec *s, int is_main, apr_pool_t *p)
{
    const char *fname;
    int rc;

    if (*s->error_fname == '|') {
        apr_file_t *dummy = NULL;
        apr_cmdtype_e cmdtype = APR_PROGRAM_ENV;
        fname = s->error_fname + 1;

        /* In 2.4 favor PROGRAM_ENV, accept "||prog" syntax for compatibility
         * and "|$cmd" to override the default.
         * Any 2.2 backport would continue to favor SHELLCMD_ENV so there
         * accept "||prog" to override, and "|$cmd" to ease conversion.
         */
        if (*fname == '|')
            ++fname;
        if (*fname == '$') {
            cmdtype = APR_SHELLCMD_ENV;
            ++fname;
        }

        /* Spawn a new child logger.  If this is the main server_rec,
         * the new child must use a dummy stderr since the current
         * stderr might be a pipe to the old logger.  Otherwise, the
         * child inherits the parents stderr. */
        rc = log_child(p, fname, &dummy, cmdtype, is_main);
        if (rc != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_STARTUP, rc, NULL, APLOGNO(00089)
                         "Couldn't start ErrorLog process '%s'.",
                         s->error_fname + 1);
            return DONE;
        }

        s->error_log = dummy;
    }

#ifdef HAVE_SYSLOG
    else if (!strncasecmp(s->error_fname, "syslog", 6)) {
        if ((fname = strchr(s->error_fname, ':'))) {
            /* s->error_fname could be [level]:[tag] (see #60525) */
            const char *tag;
            apr_size_t flen;
            const TRANS *fac;

            fname++;
            tag = ap_strchr_c(fname, ':');
            if (tag) {
                flen = tag - fname;
                tag++;
                if (*tag == '\0') {
                    tag = ap_server_argv0;
                }
            } else {
                flen = strlen(fname);
                tag = ap_server_argv0;
            }
            if (flen == 0) {
                /* Was something like syslog::foobar */
                openlog(tag, LOG_NDELAY|LOG_CONS|LOG_PID, LOG_LOCAL7);
            } else {
                for (fac = facilities; fac->t_name; fac++) {
                    if (!strncasecmp(fname, fac->t_name, flen)) {
                        openlog(tag, LOG_NDELAY|LOG_CONS|LOG_PID,
                                fac->t_val);
                        s->error_log = NULL;
                        return OK;
                    }
                }
                /* Huh? Invalid level name? */
                ap_log_error(APLOG_MARK, APLOG_STARTUP, APR_EBADPATH, NULL, APLOGNO(10036)
                             "%s: could not open syslog error log %s.",
                              ap_server_argv0, fname);
                return DONE;
            }
        }
        else {
            openlog(ap_server_argv0, LOG_NDELAY|LOG_CONS|LOG_PID, LOG_LOCAL7);
        }

        s->error_log = NULL;
    }
#endif
    else {
        fname = ap_server_root_relative(p, s->error_fname);
        if (!fname) {
            ap_log_error(APLOG_MARK, APLOG_STARTUP, APR_EBADPATH, NULL, APLOGNO(00090)
                         "%s: Invalid error log path %s.",
                         ap_server_argv0, s->error_fname);
            return DONE;
        }
        if ((rc = apr_file_open(&s->error_log, fname,
                               APR_APPEND | APR_WRITE | APR_CREATE | APR_LARGEFILE,
                               APR_OS_DEFAULT, p)) != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_STARTUP, rc, NULL, APLOGNO(00091)
                         "%s: could not open error log file %s.",
                         ap_server_argv0, fname);
            return DONE;
        }
    }

    return OK;
}

int ap_open_logs(apr_pool_t *pconf, apr_pool_t *p /* plog */,
                 apr_pool_t *ptemp, server_rec *s_main)
{
    apr_pool_t *stderr_p;
    server_rec *virt, *q;
    int replace_stderr;


    /* Register to throw away the read_handles list when we
     * cleanup plog.  Upon fork() for the apache children,
     * this read_handles list is closed so only the parent
     * can relaunch a lost log child.  These read handles
     * are always closed on exec.
     * We won't care what happens to our stderr log child
     * between log phases, so we don't mind losing stderr's
     * read_handle a little bit early.
     */
    apr_pool_cleanup_register(p, &read_handles, ap_pool_cleanup_set_null,
                              apr_pool_cleanup_null);

    /* HERE we need a stdout log that outlives plog.
     * We *presume* the parent of plog is a process
     * or global pool which spans server restarts.
     * Create our stderr_pool as a child of the plog's
     * parent pool.
     */
    apr_pool_create(&stderr_p, apr_pool_parent_get(p));
    apr_pool_tag(stderr_p, "stderr_pool");

    if (open_error_log(s_main, 1, stderr_p) != OK) {
        return DONE;
    }

    replace_stderr = 1;
    if (s_main->error_log) {
        apr_status_t rv;

        /* Replace existing stderr with new log. */
        apr_file_flush(s_main->error_log);
        rv = apr_file_dup2(stderr_log, s_main->error_log, stderr_p);
        if (rv != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s_main, APLOGNO(00092)
                         "unable to replace stderr with error_log");
        }
        else {
            /* We are done with stderr_pool, close it, killing
             * the previous generation's stderr logger
             */
            if (stderr_pool)
                apr_pool_destroy(stderr_pool);
            stderr_pool = stderr_p;
            replace_stderr = 0;
            /*
             * Now that we have dup'ed s_main->error_log to stderr_log
             * close it and set s_main->error_log to stderr_log. This avoids
             * this fd being inherited by the next piped logger who would
             * keep open the writing end of the pipe that this one uses
             * as stdin. This in turn would prevent the piped logger from
             * exiting.
             */
            apr_file_close(s_main->error_log);
            s_main->error_log = stderr_log;
        }
    }
    /* note that stderr may still need to be replaced with something
     * because it points to the old error log, or back to the tty
     * of the submitter.
     * XXX: This is BS - /dev/null is non-portable
     *      errno-as-apr_status_t is also non-portable
     */

#ifdef WIN32
#define NULL_DEVICE "nul"
#else
#define NULL_DEVICE "/dev/null"
#endif

    if (replace_stderr && freopen(NULL_DEVICE, "w", stderr) == NULL) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, errno, s_main, APLOGNO(00093)
                     "unable to replace stderr with %s", NULL_DEVICE);
    }

    for (virt = s_main->next; virt; virt = virt->next) {
        if (virt->error_fname) {
            for (q=s_main; q != virt; q = q->next) {
                if (q->error_fname != NULL
                    && strcmp(q->error_fname, virt->error_fname) == 0) {
                    break;
                }
            }

            if (q == virt) {
                if (open_error_log(virt, 0, p) != OK) {
                    return DONE;
                }
            }
            else {
                virt->error_log = q->error_log;
            }
        }
        else {
            virt->error_log = s_main->error_log;
        }
    }
    return OK;
}

AP_DECLARE(void) ap_error_log2stderr(server_rec *s) {
    apr_file_t *errfile = NULL;

    apr_file_open_stderr(&errfile, s->process->pool);
    if (s->error_log != NULL) {
        apr_file_dup2(s->error_log, errfile, s->process->pool);
    }
}

static int cpystrn(char *buf, const char *arg, int buflen)
{
    char *end;
    if (!arg)
        return 0;
    end = apr_cpystrn(buf, arg, buflen);
    return end - buf;
}


static int log_remote_address(const ap_errorlog_info *info, const char *arg,
                              char *buf, int buflen)
{
    if (info->r && !(arg && *arg == 'c'))
        return apr_snprintf(buf, buflen, "%s:%d", info->r->useragent_ip,
                            info->r->useragent_addr ? info->r->useragent_addr->port : 0);
    else if (info->c)
        return apr_snprintf(buf, buflen, "%s:%d", info->c->client_ip,
                            info->c->client_addr ? info->c->client_addr->port : 0);
    else
        return 0;
}

static int log_local_address(const ap_errorlog_info *info, const char *arg,
                             char *buf, int buflen)
{
    if (info->c)
        return apr_snprintf(buf, buflen, "%s:%d", info->c->local_ip,
                            info->c->local_addr->port);
    else
        return 0;
}

static int log_pid(const ap_errorlog_info *info, const char *arg,
                   char *buf, int buflen)
{
    pid_t pid = getpid();
    return apr_snprintf(buf, buflen, "%" APR_PID_T_FMT, pid);
}

static int log_tid(const ap_errorlog_info *info, const char *arg,
                   char *buf, int buflen)
{
#if APR_HAS_THREADS
    int result;
#endif
#if HAVE_GETTID
    if (arg && *arg == 'g') {
        pid_t tid = syscall(SYS_gettid);
        if (tid == -1)
            return 0;
        return apr_snprintf(buf, buflen, "%"APR_PID_T_FMT, tid);
    }
#endif
#if APR_HAS_THREADS
    if (ap_mpm_query(AP_MPMQ_IS_THREADED, &result) == APR_SUCCESS
        && result != AP_MPMQ_NOT_SUPPORTED)
    {
        apr_os_thread_t tid = apr_os_thread_current();
        return apr_snprintf(buf, buflen, "%pT", &tid);
    }
#endif
    return 0;
}

static int log_ctime(const ap_errorlog_info *info, const char *arg,
                     char *buf, int buflen)
{
    int time_len = buflen;
    int option = AP_CTIME_OPTION_NONE;

    while (arg && *arg) {
        switch (*arg) {
            case 'u':   option |= AP_CTIME_OPTION_USEC;
                        break;
            case 'c':   option |= AP_CTIME_OPTION_COMPACT;
                        break;
        }
        arg++;
    }

    ap_recent_ctime_ex(buf, apr_time_now(), option, &time_len);

    /* ap_recent_ctime_ex includes the trailing \0 in time_len */
    return time_len - 1;
}

static int log_loglevel(const ap_errorlog_info *info, const char *arg,
                        char *buf, int buflen)
{
    if (info->level < 0)
        return 0;
    else
        return cpystrn(buf, priorities[info->level].t_name, buflen);
}

static int log_log_id(const ap_errorlog_info *info, const char *arg,
                      char *buf, int buflen)
{
    /*
     * C: log conn log_id if available,
     * c: log conn log id if available and not a once-per-request log line
     * else: log request log id if available
     */
    if (arg && !strcasecmp(arg, "c")) {
        if (info->c && (*arg != 'C' || !info->r)) {
            return cpystrn(buf, info->c->log_id, buflen);
        }
    }
    else if (info->rmain) {
        return cpystrn(buf, info->rmain->log_id, buflen);
    }
    return 0;
}

static int log_keepalives(const ap_errorlog_info *info, const char *arg,
                          char *buf, int buflen)
{
    if (!info->c)
        return 0;

    return apr_snprintf(buf, buflen, "%d", info->c->keepalives);
}

static int log_module_name(const ap_errorlog_info *info, const char *arg,
                           char *buf, int buflen)
{
    return cpystrn(buf, ap_find_module_short_name(info->module_index), buflen);
}

static int log_file_line(const ap_errorlog_info *info, const char *arg,
                         char *buf, int buflen)
{
    if (info->file == NULL) {
        return 0;
    }
    else {
        const char *file = info->file;
#if defined(_OSD_POSIX) || defined(WIN32) || defined(__MVS__)
        char tmp[256];
        char *e = strrchr(file, '/');
#ifdef WIN32
        if (!e) {
            e = strrchr(file, '\\');
        }
#endif

        /* In OSD/POSIX, the compiler returns for __FILE__
         * a string like: __FILE__="*POSIX(/usr/include/stdio.h)"
         * (it even returns an absolute path for sources in
         * the current directory). Here we try to strip this
         * down to the basename.
         */
        if (e != NULL && e[1] != '\0') {
            apr_snprintf(tmp, sizeof(tmp), "%s", &e[1]);
            e = &tmp[strlen(tmp)-1];
            if (*e == ')') {
                *e = '\0';
            }
            file = tmp;
        }
#else /* _OSD_POSIX || WIN32 */
        const char *p;
        /* On Unix, __FILE__ may be an absolute path in a
         * VPATH build. */
        if (file[0] == '/' && (p = ap_strrchr_c(file, '/')) != NULL) {
            file = p + 1;
        }
#endif /*_OSD_POSIX || WIN32 */
        return apr_snprintf(buf, buflen, "%s(%d)", file, info->line);
    }
}

static int log_apr_status(const ap_errorlog_info *info, const char *arg,
                          char *buf, int buflen)
{
    apr_status_t status = info->status;
    int len;
    if (!status)
        return 0;

    if (status < APR_OS_START_EAIERR) {
        len = apr_snprintf(buf, buflen, "(%d)", status);
    }
    else if (status < APR_OS_START_SYSERR) {
        len = apr_snprintf(buf, buflen, "(EAI %d)",
                           status - APR_OS_START_EAIERR);
    }
    else if (status < 100000 + APR_OS_START_SYSERR) {
        len = apr_snprintf(buf, buflen, "(OS %d)",
                           status - APR_OS_START_SYSERR);
    }
    else {
        len = apr_snprintf(buf, buflen, "(os 0x%08x)",
                           status - APR_OS_START_SYSERR);
    }
    apr_strerror(status, buf + len, buflen - len);
    len += strlen(buf + len);
    return len;
}

static int log_server_name(const ap_errorlog_info *info, const char *arg,
                           char *buf, int buflen)
{
    if (info->r)
        return cpystrn(buf, ap_get_server_name((request_rec *)info->r), buflen);

    return 0;
}

static int log_virtual_host(const ap_errorlog_info *info, const char *arg,
                            char *buf, int buflen)
{
    if (info->s)
        return cpystrn(buf, info->s->server_hostname, buflen);

    return 0;
}


static int log_table_entry(const apr_table_t *table, const char *name,
                           char *buf, int buflen)
{
#ifndef AP_UNSAFE_ERROR_LOG_UNESCAPED
    const char *value;
    char scratch[MAX_STRING_LEN];

    if ((value = apr_table_get(table, name)) != NULL) {
        ap_escape_errorlog_item(scratch, value, MAX_STRING_LEN);
        return cpystrn(buf, scratch, buflen);
    }

    return 0;
#else
    return cpystrn(buf, apr_table_get(table, name), buflen);
#endif
}

static int log_header(const ap_errorlog_info *info, const char *arg,
                      char *buf, int buflen)
{
    if (info->r)
        return log_table_entry(info->r->headers_in, arg, buf, buflen);

    return 0;
}

static int log_note(const ap_errorlog_info *info, const char *arg,
                      char *buf, int buflen)
{
    /* XXX: maybe escaping the entry is not necessary for notes? */
    if (info->r)
        return log_table_entry(info->r->notes, arg, buf, buflen);

    return 0;
}

static int log_env_var(const ap_errorlog_info *info, const char *arg,
                      char *buf, int buflen)
{
    if (info->r)
        return log_table_entry(info->r->subprocess_env, arg, buf, buflen);

    return 0;
}

static int core_generate_log_id(const conn_rec *c, const request_rec *r,
                                 const char **idstring)
{
    apr_uint64_t id, tmp;
    pid_t pid;
    int len;
    char *encoded;

    if (r && r->request_time) {
        id = (apr_uint64_t)r->request_time;
    }
    else {
        id = (apr_uint64_t)apr_time_now();
    }

    pid = getpid();
    if (sizeof(pid_t) > 2) {
        tmp = pid;
        tmp = tmp << 40;
        id ^= tmp;
        pid = pid >> 24;
        tmp = pid;
        tmp = tmp << 56;
        id ^= tmp;
    }
    else {
        tmp = pid;
        tmp = tmp << 40;
        id ^= tmp;
    }
#if APR_HAS_THREADS
    {
        apr_uintptr_t tmp2 = (apr_uintptr_t)c->current_thread;
        tmp = tmp2;
        tmp = tmp << 32;
        id ^= tmp;
    }
#endif

    len = apr_base64_encode_len(sizeof(id)); /* includes trailing \0 */
    encoded = apr_palloc(r ? r->pool : c->pool, len);
    apr_base64_encode(encoded, (char *)&id, sizeof(id));

    /* Skip the last char, it is always '=' */
    encoded[len - 2] = '\0';

    *idstring = encoded;

    return OK;
}

static void add_log_id(const conn_rec *c, const request_rec *r)
{
    const char **id;
    /* need to cast const away */
    if (r) {
        id = &((request_rec *)r)->log_id;
    }
    else {
        id = &((conn_rec *)c)->log_id;
    }

    ap_run_generate_log_id(c, r, id);
}

AP_DECLARE(void) ap_register_log_hooks(apr_pool_t *p)
{
    ap_hook_generate_log_id(core_generate_log_id, NULL, NULL,
                            APR_HOOK_REALLY_LAST);

    ap_register_errorlog_handler(p, "a", log_remote_address, 0);
    ap_register_errorlog_handler(p, "A", log_local_address, 0);
    ap_register_errorlog_handler(p, "e", log_env_var, 0);
    ap_register_errorlog_handler(p, "E", log_apr_status, 0);
    ap_register_errorlog_handler(p, "F", log_file_line, 0);
    ap_register_errorlog_handler(p, "i", log_header, 0);
    ap_register_errorlog_handler(p, "k", log_keepalives, 0);
    ap_register_errorlog_handler(p, "l", log_loglevel, 0);
    ap_register_errorlog_handler(p, "L", log_log_id, 0);
    ap_register_errorlog_handler(p, "m", log_module_name, 0);
    ap_register_errorlog_handler(p, "n", log_note, 0);
    ap_register_errorlog_handler(p, "P", log_pid, 0);
    ap_register_errorlog_handler(p, "t", log_ctime, 0);
    ap_register_errorlog_handler(p, "T", log_tid, 0);
    ap_register_errorlog_handler(p, "v", log_virtual_host, 0);
    ap_register_errorlog_handler(p, "V", log_server_name, 0);
}

/*
 * This is used if no error log format is defined and during startup.
 * It automatically omits the timestamp if logging to syslog.
 */
static int do_errorlog_default(const ap_errorlog_info *info, char *buf,
                               int buflen, int *errstr_start, int *errstr_end,
                               const char *errstr_fmt, va_list args)
{
    int len = 0;
    int field_start = 0;
    int item_len;
#ifndef AP_UNSAFE_ERROR_LOG_UNESCAPED
    char scratch[MAX_STRING_LEN];
#endif

    if (!info->using_syslog && !info->startup) {
        buf[len++] = '[';
        len += log_ctime(info, "u", buf + len, buflen - len);
        buf[len++] = ']';
        buf[len++] = ' ';
    }

    if (!info->startup) {
        buf[len++] = '[';
        len += log_module_name(info, NULL, buf + len, buflen - len);
        buf[len++] = ':';
        len += log_loglevel(info, NULL, buf + len, buflen - len);
        len += cpystrn(buf + len, "] [pid ", buflen - len);

        len += log_pid(info, NULL, buf + len, buflen - len);
#if APR_HAS_THREADS
        field_start = len;
        len += cpystrn(buf + len, ":tid ", buflen - len);
        item_len = log_tid(info, NULL, buf + len, buflen - len);
        if (!item_len)
            len = field_start;
        else
            len += item_len;
#endif
        buf[len++] = ']';
        buf[len++] = ' ';
    }

    if (info->level >= APLOG_DEBUG) {
        item_len = log_file_line(info, NULL, buf + len, buflen - len);
        if (item_len) {
            len += item_len;
            len += cpystrn(buf + len, ": ", buflen - len);
        }
    }

    if (info->status) {
        item_len = log_apr_status(info, NULL, buf + len, buflen - len);
        if (item_len) {
            len += item_len;
            len += cpystrn(buf + len, ": ", buflen - len);
        }
    }

    /*
     * useragent_ip/client_ip can be client or backend server. If we have
     * a scoreboard handle, it is likely a client.
     */
    if (info->r) {
        len += apr_snprintf(buf + len, buflen - len,
                            info->r->connection->sbh ? "[client %s:%d] " : "[remote %s:%d] ",
                            info->r->useragent_ip,
                            info->r->useragent_addr ? info->r->useragent_addr->port : 0);
    }
    else if (info->c) {
        len += apr_snprintf(buf + len, buflen - len,
                            info->c->sbh ? "[client %s:%d] " : "[remote %s:%d] ",
                            info->c->client_ip,
                            info->c->client_addr ? info->c->client_addr->port : 0);
    }

    /* the actual error message */
    *errstr_start = len;
#ifndef AP_UNSAFE_ERROR_LOG_UNESCAPED
    if (apr_vsnprintf(scratch, MAX_STRING_LEN, errstr_fmt, args)) {
        len += ap_escape_errorlog_item(buf + len, scratch,
                                       buflen - len);

    }
#else
    len += apr_vsnprintf(buf + len, buflen - len, errstr_fmt, args);
#endif
    *errstr_end = len;

    field_start = len;
    len += cpystrn(buf + len, ", referer: ", buflen - len);
    item_len = log_header(info, "Referer", buf + len, buflen - len);
    if (item_len)
        len += item_len;
    else
        len = field_start;

    return len;
}

static int do_errorlog_format(apr_array_header_t *fmt, ap_errorlog_info *info,
                              char *buf, int buflen, int *errstr_start,
                              int *errstr_end, const char *err_fmt, va_list args)
{
#ifndef AP_UNSAFE_ERROR_LOG_UNESCAPED
    char scratch[MAX_STRING_LEN];
#endif
    int i;
    int len = 0;
    int field_start = 0;
    int skipping = 0;
    ap_errorlog_format_item *items = (ap_errorlog_format_item *)fmt->elts;

    AP_DEBUG_ASSERT(fmt->nelts > 0);
    for (i = 0; i < fmt->nelts; ++i) {
        ap_errorlog_format_item *item = &items[i];
        if (item->flags & AP_ERRORLOG_FLAG_FIELD_SEP) {
            if (skipping) {
                skipping = 0;
            }
            else {
                field_start = len;
            }
        }

        if (item->flags & AP_ERRORLOG_FLAG_MESSAGE) {
            /* the actual error message */
            *errstr_start = len;
#ifndef AP_UNSAFE_ERROR_LOG_UNESCAPED
            if (apr_vsnprintf(scratch, MAX_STRING_LEN, err_fmt, args)) {
                len += ap_escape_errorlog_item(buf + len, scratch,
                                               buflen - len);

            }
#else
            len += apr_vsnprintf(buf + len, buflen - len, err_fmt, args);
#endif
            *errstr_end = len;
        }
        else if (skipping) {
            continue;
        }
        else if (info->level != -1 && (int)item->min_loglevel > info->level) {
            len = field_start;
            skipping = 1;
        }
        else {
            int item_len = (*item->func)(info, item->arg, buf + len,
                                         buflen - len);
            if (!item_len) {
                if (item->flags & AP_ERRORLOG_FLAG_REQUIRED) {
                    /* required item is empty. skip whole line */
                    buf[0] = '\0';
                    return 0;
                }
                else if (item->flags & AP_ERRORLOG_FLAG_NULL_AS_HYPHEN) {
                    buf[len++] = '-';
                }
                else {
                    len = field_start;
                    skipping = 1;
                }
            }
            else {
                len += item_len;
            }
        }
    }
    return len;
}

static void write_logline(char *errstr, apr_size_t len, apr_file_t *logf,
                          int level)
{
    /* NULL if we are logging to syslog */
    if (logf) {
        /* Truncate for the terminator (as apr_snprintf does) */
        if (len > MAX_STRING_LEN - sizeof(APR_EOL_STR)) {
            len = MAX_STRING_LEN - sizeof(APR_EOL_STR);
        }
        strcpy(errstr + len, APR_EOL_STR);
        apr_file_puts(errstr, logf);
        apr_file_flush(logf);
    }
#ifdef HAVE_SYSLOG
    else {
        syslog(level < LOG_PRIMASK ? level : APLOG_DEBUG, "%.*s",
               (int)len, errstr);
    }
#endif
}

static void log_error_core(const char *file, int line, int module_index,
                           int level,
                           apr_status_t status, const server_rec *s,
                           const conn_rec *c,
                           const request_rec *r, apr_pool_t *pool,
                           const char *fmt, va_list args)
{
    char errstr[MAX_STRING_LEN];
    apr_file_t *logf = NULL;
    int level_and_mask = level & APLOG_LEVELMASK;
    const request_rec *rmain = NULL;
    core_server_config *sconf = NULL;
    ap_errorlog_info info;

    /* do we need to log once-per-req or once-per-conn info? */
    int log_conn_info = 0, log_req_info = 0;
    apr_array_header_t **lines = NULL;
    int done = 0;
    int line_number = 0;

    if (r) {
        AP_DEBUG_ASSERT(r->connection != NULL);
        c = r->connection;
    }

    if (s == NULL) {
        /*
         * If we are doing stderr logging (startup), don't log messages that are
         * above the default server log level unless it is a startup/shutdown
         * notice
         */
#ifndef DEBUG
        if ((level_and_mask != APLOG_NOTICE)
            && (level_and_mask > ap_default_loglevel)) {
            return;
        }
#endif

        logf = stderr_log;
    }
    else {
        int configured_level = r ? ap_get_request_module_loglevel(r, module_index)        :
                               c ? ap_get_conn_server_module_loglevel(c, s, module_index) :
                                   ap_get_server_module_loglevel(s, module_index);
        if (s->error_log) {
            /*
             * If we are doing normal logging, don't log messages that are
             * above the module's log level unless it is a startup/shutdown notice
             */
            if ((level_and_mask != APLOG_NOTICE)
                && (level_and_mask > configured_level)) {
                return;
            }

            logf = s->error_log;
        }
        else {
            /*
             * If we are doing syslog logging, don't log messages that are
             * above the module's log level (including a startup/shutdown notice)
             */
            if (level_and_mask > configured_level) {
                return;
            }
        }

        /* the faked server_rec from mod_cgid does not have s->module_config */
        if (s->module_config) {
            sconf = ap_get_core_module_config(s->module_config);
            if (c && !c->log_id) {
                add_log_id(c, NULL);
                if (sconf->error_log_conn && sconf->error_log_conn->nelts > 0)
                    log_conn_info = 1;
            }
            if (r) {
                if (r->main)
                    rmain = r->main;
                else
                    rmain = r;

                if (!rmain->log_id) {
                    /* XXX: do we need separate log ids for subrequests? */
                    if (sconf->error_log_req && sconf->error_log_req->nelts > 0)
                        log_req_info = 1;
                    /*
                     * XXX: potential optimization: only create log id if %L is
                     * XXX: actually used
                     */
                    add_log_id(c, rmain);
                }
            }
        }
    }

    info.s             = s;
    info.c             = c;
    info.pool          = pool;
    info.file          = NULL;
    info.line          = 0;
    info.status        = 0;
    info.using_syslog  = (logf == NULL);
    info.startup       = ((level & APLOG_STARTUP) == APLOG_STARTUP);
    info.format        = fmt;

    while (!done) {
        apr_array_header_t *log_format;
        int len = 0, errstr_start = 0, errstr_end = 0;
        /* XXX: potential optimization: format common prefixes only once */
        if (log_conn_info) {
            /* once-per-connection info */
            if (line_number == 0) {
                lines = (apr_array_header_t **)sconf->error_log_conn->elts;
                info.r = NULL;
                info.rmain = NULL;
                info.level = -1;
                info.module_index = APLOG_NO_MODULE;
            }

            log_format = lines[line_number++];

            if (line_number == sconf->error_log_conn->nelts) {
                /* this is the last line of once-per-connection info */
                line_number = 0;
                log_conn_info = 0;
            }
        }
        else if (log_req_info) {
            /* once-per-request info */
            if (line_number == 0) {
                lines = (apr_array_header_t **)sconf->error_log_req->elts;
                info.r = rmain;
                info.rmain = rmain;
                info.level = -1;
                info.module_index = APLOG_NO_MODULE;
            }

            log_format = lines[line_number++];

            if (line_number == sconf->error_log_req->nelts) {
                /* this is the last line of once-per-request info */
                line_number = 0;
                log_req_info = 0;
            }
        }
        else {
            /* the actual error message */
            info.r            = r;
            info.rmain        = rmain;
            info.level        = level_and_mask;
            info.module_index = module_index;
            info.file         = file;
            info.line         = line;
            info.status       = status;
            log_format = sconf ? sconf->error_log_format : NULL;
            done = 1;
        }

        /*
         * prepare and log one line
         */

        if (log_format && !info.startup) {
            len += do_errorlog_format(log_format, &info, errstr + len,
                                      MAX_STRING_LEN - len,
                                      &errstr_start, &errstr_end, fmt, args);
        }
        else {
            len += do_errorlog_default(&info, errstr + len, MAX_STRING_LEN - len,
                                       &errstr_start, &errstr_end, fmt, args);
        }

        if (!*errstr) {
            /*
             * Don't log empty lines. This can happen with once-per-conn/req
             * info if an item with AP_ERRORLOG_FLAG_REQUIRED is NULL.
             */
            continue;
        }
        write_logline(errstr, len, logf, level_and_mask);

        if (done) {
            /*
             * We don't call the error_log hook for per-request/per-conn
             * lines, and we only pass the actual log message, not the
             * prefix and suffix.
             */
            errstr[errstr_end] = '\0';
            ap_run_error_log(&info, errstr + errstr_start);
        }

        *errstr = '\0';
    }
}

/* For internal calls to log_error_core with self-composed arg lists */
static void log_error_va_glue(const char *file, int line, int module_index,
                              int level, apr_status_t status,
                              const server_rec *s, const conn_rec *c,
                              const request_rec *r, apr_pool_t *pool,
                              const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    log_error_core(file, line, module_index, level, status, s, c, r, pool,
                   fmt, args);
    va_end(args);
}

AP_DECLARE(void) ap_log_error_(const char *file, int line, int module_index,
                               int level, apr_status_t status,
                               const server_rec *s, const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    log_error_core(file, line, module_index, level, status, s, NULL, NULL,
                   NULL, fmt, args);
    va_end(args);
}

AP_DECLARE(void) ap_log_perror_(const char *file, int line, int module_index,
                                int level, apr_status_t status, apr_pool_t *p,
                                const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    log_error_core(file, line, module_index, level, status, NULL, NULL, NULL,
                   p, fmt, args);
    va_end(args);
}

AP_DECLARE(void) ap_log_rerror_(const char *file, int line, int module_index,
                                int level, apr_status_t status,
                                const request_rec *r, const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    log_error_core(file, line, module_index, level, status, r->server, NULL, r,
                   NULL, fmt, args);

    /*
     * IF APLOG_TOCLIENT is set,
     * AND the error level is 'warning' or more severe,
     * AND there isn't already error text associated with this request,
     * THEN make the message text available to ErrorDocument and
     * other error processors.
     */
    va_end(args);
    va_start(args,fmt);
    if ((level & APLOG_TOCLIENT)
        && ((level & APLOG_LEVELMASK) <= APLOG_WARNING)
        && (apr_table_get(r->notes, "error-notes") == NULL)) {
        apr_table_setn(r->notes, "error-notes",
                       ap_escape_html(r->pool, apr_pvsprintf(r->pool, fmt,
                                                             args)));
    }
    va_end(args);
}

AP_DECLARE(void) ap_log_cserror_(const char *file, int line, int module_index,
                                 int level, apr_status_t status,
                                 const conn_rec *c, const server_rec *s,
                                 const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    log_error_core(file, line, module_index, level, status, s, c,
                   NULL, NULL, fmt, args);
    va_end(args);
}

AP_DECLARE(void) ap_log_cerror_(const char *file, int line, int module_index,
                                int level, apr_status_t status,
                                const conn_rec *c, const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    log_error_core(file, line, module_index, level, status, c->base_server, c,
                   NULL, NULL, fmt, args);
    va_end(args);
}

#define BYTES_LOGGED_PER_LINE 16
#define LOG_BYTES_BUFFER_SIZE (BYTES_LOGGED_PER_LINE * 3 + 2)

static void fmt_data(unsigned char *buf, const void *vdata, apr_size_t len, apr_size_t *off)
{
    const unsigned char *data = (const unsigned char *)vdata;
    unsigned char *chars;
    unsigned char *hex;
    apr_size_t this_time = 0;

    memset(buf, ' ', LOG_BYTES_BUFFER_SIZE - 1);
    buf[LOG_BYTES_BUFFER_SIZE - 1] = '\0';
    
    chars = buf; /* start character dump here */
    hex   = buf + BYTES_LOGGED_PER_LINE + 1; /* start hex dump here */
    while (*off < len && this_time < BYTES_LOGGED_PER_LINE) {
        unsigned char c = data[*off];

        if (apr_isprint(c)
            && c != '\\') {  /* backslash will be escaped later, which throws
                              * off the formatting
                              */
            *chars = c;
        }
        else {
            *chars = '.';
        }

        if ((c >> 4) >= 10) {
            *hex = 'a' + ((c >> 4) - 10);
        }
        else {
            *hex = '0' + (c >> 4);
        }

        if ((c & 0x0F) >= 10) {
            *(hex + 1) = 'a' + ((c & 0x0F) - 10);
        }
        else {
            *(hex + 1) = '0' + (c & 0x0F);
        }

        chars += 1;
        hex += 2;
        *off += 1;
        ++this_time;
    }
}

static void log_data_core(const char *file, int line, int module_index,
                          int level, const server_rec *s,
                          const conn_rec *c, const request_rec *r,
                          const char *label, const void *data, apr_size_t len,
                          unsigned int flags)
{
    unsigned char buf[LOG_BYTES_BUFFER_SIZE];
    apr_size_t off;
    char prefix[20];

    if (!(flags & AP_LOG_DATA_SHOW_OFFSET)) {
        prefix[0] = '\0';
    }

    if (len > 0xffff) { /* bug in caller? */
        len = 0xffff;
    }

    if (label) {
        log_error_va_glue(file, line, module_index, level, APR_SUCCESS, s,
                          c, r, NULL, "%s (%" APR_SIZE_T_FMT " bytes)",
                          label, len);
    }

    off = 0;
    while (off < len) {
        if (flags & AP_LOG_DATA_SHOW_OFFSET) {
            apr_snprintf(prefix, sizeof prefix, "%04x: ", (unsigned int)off);
        }
        fmt_data(buf, data, len, &off);
        log_error_va_glue(file, line, module_index, level, APR_SUCCESS, s,
                          c, r, NULL, "%s%s", prefix, buf);
    }
}

AP_DECLARE(void) ap_log_data_(const char *file, int line, 
                              int module_index, int level,
                              const server_rec *s, const char *label,
                              const void *data, apr_size_t len,
                              unsigned int flags)
{
    log_data_core(file, line, module_index, level, s, NULL, NULL, label,
                  data, len, flags);
}

AP_DECLARE(void) ap_log_rdata_(const char *file, int line,
                               int module_index, int level,
                               const request_rec *r, const char *label,
                               const void *data, apr_size_t len,
                               unsigned int flags)
{
    log_data_core(file, line, module_index, level, r->server, NULL, r, label,
                  data, len, flags);
}

AP_DECLARE(void) ap_log_cdata_(const char *file, int line,
                               int module_index, int level,
                               const conn_rec *c, const char *label,
                               const void *data, apr_size_t len,
                               unsigned int flags)
{
    log_data_core(file, line, module_index, level, c->base_server, c, NULL,
                  label, data, len, flags);
}

AP_DECLARE(void) ap_log_csdata_(const char *file, int line, int module_index,
                                int level, const conn_rec *c, const server_rec *s,
                                const char *label, const void *data,
                                apr_size_t len, unsigned int flags)
{
    log_data_core(file, line, module_index, level, s, c, NULL, label, data,
                  len, flags);
}

AP_DECLARE(void) ap_log_command_line(apr_pool_t *plog, server_rec *s)
{
    int i;
    process_rec *process = s->process;
    char *result;
    int len_needed = 0;

    /* Piece together the command line from the pieces
     * in process->argv, with spaces in between.
     */
    for (i = 0; i < process->argc; i++) {
        len_needed += strlen(process->argv[i]) + 1;
    }

    result = (char *) apr_palloc(plog, len_needed);
    *result = '\0';

    for (i = 0; i < process->argc; i++) {
        strcat(result, process->argv[i]);
        if ((i+1)< process->argc) {
            strcat(result, " ");
        }
    }
    ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s, APLOGNO(00094)
                 "Command line: '%s'", result);
}

/* grab bag function to log commonly logged and shared info */
AP_DECLARE(void) ap_log_mpm_common(server_rec *s)
{
    ap_log_error(APLOG_MARK, APLOG_DEBUG , 0, s, APLOGNO(02639)
                 "Using SO_REUSEPORT: %s (%d)",
                 ap_have_so_reuseport ? "yes" : "no",
                 ap_num_listen_buckets);
}

AP_DECLARE(void) ap_remove_pid(apr_pool_t *p, const char *rel_fname)
{
    apr_status_t rv;
    const char *fname = ap_server_root_relative(p, rel_fname);

    if (fname != NULL) {
        rv = apr_file_remove(fname, p);
        if (rv != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_ERR, rv, ap_server_conf, APLOGNO(00095)
                         "failed to remove PID file %s", fname);
        }
        else {
            ap_log_error(APLOG_MARK, APLOG_INFO, 0, ap_server_conf, APLOGNO(00096)
                         "removed PID file %s (pid=%" APR_PID_T_FMT ")",
                         fname, getpid());
        }
    }
}

AP_DECLARE(void) ap_log_pid(apr_pool_t *p, const char *filename)
{
    apr_file_t *pid_file = NULL;
    apr_finfo_t finfo;
    static pid_t saved_pid = -1;
    pid_t mypid;
    apr_status_t rv;
    const char *fname;

    if (!filename) {
        return;
    }

    fname = ap_server_root_relative(p, filename);
    if (!fname) {
        ap_log_error(APLOG_MARK, APLOG_STARTUP|APLOG_CRIT, APR_EBADPATH,
                     NULL, APLOGNO(00097) "Invalid PID file path %s, ignoring.", filename);
        return;
    }

    mypid = getpid();
    if (mypid != saved_pid
        && apr_stat(&finfo, fname, APR_FINFO_MTIME, p) == APR_SUCCESS) {
        /* AP_SIG_GRACEFUL and HUP call this on each restart.
         * Only warn on first time through for this pid.
         *
         * XXX: Could just write first time through too, although
         *      that may screw up scripts written to do something
         *      based on the last modification time of the pid file.
         */
        ap_log_perror(APLOG_MARK, APLOG_WARNING, 0, p, APLOGNO(00098)
                      "pid file %s overwritten -- Unclean "
                      "shutdown of previous Apache run?",
                      fname);
    }

    if ((rv = apr_file_open(&pid_file, fname,
                            APR_WRITE | APR_CREATE | APR_TRUNCATE,
                            APR_UREAD | APR_UWRITE | APR_GREAD | APR_WREAD, p))
        != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, NULL, APLOGNO(00099)
                     "could not create %s", fname);
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, APLOGNO(00100)
                     "%s: could not log pid to file %s",
                     ap_server_argv0, fname);
        exit(1);
    }
    apr_file_printf(pid_file, "%" APR_PID_T_FMT APR_EOL_STR, mypid);
    apr_file_close(pid_file);
    saved_pid = mypid;
}

AP_DECLARE(apr_status_t) ap_read_pid(apr_pool_t *p, const char *filename,
                                     pid_t *mypid)
{
    const apr_size_t BUFFER_SIZE = sizeof(long) * 3 + 2; /* see apr_ltoa */
    apr_file_t *pid_file = NULL;
    apr_status_t rv;
    const char *fname;
    char *buf, *endptr;
    apr_size_t bytes_read;

    if (!filename) {
        return APR_EGENERAL;
    }

    fname = ap_server_root_relative(p, filename);
    if (!fname) {
        ap_log_error(APLOG_MARK, APLOG_STARTUP|APLOG_CRIT, APR_EBADPATH,
                     NULL, APLOGNO(00101) "Invalid PID file path %s, ignoring.", filename);
        return APR_EGENERAL;
    }

    rv = apr_file_open(&pid_file, fname, APR_READ, APR_OS_DEFAULT, p);
    if (rv != APR_SUCCESS) {
        return rv;
    }

    buf = apr_palloc(p, BUFFER_SIZE);

    rv = apr_file_read_full(pid_file, buf, BUFFER_SIZE - 1, &bytes_read);
    if (rv != APR_SUCCESS && rv != APR_EOF) {
        return rv;
    }

    /* If we fill the buffer, we're probably reading a corrupt pid file.
     * To be nice, let's also ensure the first char is a digit. */
    if (bytes_read == 0 || bytes_read == BUFFER_SIZE - 1 || !apr_isdigit(*buf)) {
        return APR_EGENERAL;
    }

    buf[bytes_read] = '\0';
    *mypid = strtol(buf, &endptr, 10);

    apr_file_close(pid_file);
    return APR_SUCCESS;
}

AP_DECLARE(void) ap_log_assert(const char *szExp, const char *szFile,
                               int nLine)
{
    char time_str[APR_CTIME_LEN];

    apr_ctime(time_str, apr_time_now());
    ap_log_error(APLOG_MARK, APLOG_CRIT, 0, NULL, APLOGNO(00102)
                 "[%s] file %s, line %d, assertion \"%s\" failed",
                 time_str, szFile, nLine, szExp);
#if defined(WIN32)
    DebugBreak();
#else
    /* unix assert does an abort leading to a core dump */
    abort();
#endif
}

/* piped log support */

#ifdef AP_HAVE_RELIABLE_PIPED_LOGS
/* forward declaration */
static void piped_log_maintenance(int reason, void *data, apr_wait_t status);

/* Spawn the piped logger process pl->program. */
static apr_status_t piped_log_spawn(piped_log *pl)
{
    apr_procattr_t *procattr;
    apr_proc_t *procnew = NULL;
    apr_status_t status;

    if (((status = apr_procattr_create(&procattr, pl->p)) != APR_SUCCESS) ||
        ((status = apr_procattr_dir_set(procattr, ap_server_root))
         != APR_SUCCESS) ||
        ((status = apr_procattr_cmdtype_set(procattr, pl->cmdtype))
         != APR_SUCCESS) ||
        ((status = apr_procattr_child_in_set(procattr,
                                             pl->read_fd,
                                             pl->write_fd))
         != APR_SUCCESS) ||
        ((status = apr_procattr_child_errfn_set(procattr, log_child_errfn))
         != APR_SUCCESS) ||
        ((status = apr_procattr_error_check_set(procattr, 1)) != APR_SUCCESS)) {
        /* Something bad happened, give up and go away. */
        ap_log_error(APLOG_MARK, APLOG_STARTUP, status, NULL, APLOGNO(00103)
                     "piped_log_spawn: unable to setup child process '%s'",
                     pl->program);
    }
    else {
        char **args;

        apr_tokenize_to_argv(pl->program, &args, pl->p);
        procnew = apr_pcalloc(pl->p, sizeof(apr_proc_t));
        status = apr_proc_create(procnew, args[0], (const char * const *) args,
                                 NULL, procattr, pl->p);

        if (status == APR_SUCCESS) {
            pl->pid = procnew;
            /* procnew->in was dup2'd from pl->write_fd;
             * since the original fd is still valid, close the copy to
             * avoid a leak. */
            apr_file_close(procnew->in);
            procnew->in = NULL;
            apr_proc_other_child_register(procnew, piped_log_maintenance, pl,
                                          pl->write_fd, pl->p);
            close_handle_in_child(pl->p, pl->read_fd);
        }
        else {
            /* Something bad happened, give up and go away. */
            ap_log_error(APLOG_MARK, APLOG_STARTUP, status, NULL, APLOGNO(00104)
                         "unable to start piped log program '%s'",
                         pl->program);
        }
    }

    return status;
}


static void piped_log_maintenance(int reason, void *data, apr_wait_t status)
{
    piped_log *pl = data;
    apr_status_t rv;
    int mpm_state;

    switch (reason) {
    case APR_OC_REASON_DEATH:
    case APR_OC_REASON_LOST:
        pl->pid = NULL; /* in case we don't get it going again, this
                         * tells other logic not to try to kill it
                         */
        apr_proc_other_child_unregister(pl);
        rv = ap_mpm_query(AP_MPMQ_MPM_STATE, &mpm_state);
        if (rv != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL, APLOGNO(00105)
                         "can't query MPM state; not restarting "
                         "piped log program '%s'",
                         pl->program);
        }
        else if (mpm_state != AP_MPMQ_STOPPING) {
            ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL, APLOGNO(00106)
                         "piped log program '%s' failed unexpectedly",
                         pl->program);
            if ((rv = piped_log_spawn(pl)) != APR_SUCCESS) {
                /* what can we do?  This could be the error log we're having
                 * problems opening up... */
                ap_log_error(APLOG_MARK, APLOG_STARTUP, rv, NULL, APLOGNO(00107)
                             "piped_log_maintenance: unable to respawn '%s'",
                             pl->program);
            }
        }
        break;

    case APR_OC_REASON_UNWRITABLE:
        /* We should not kill off the pipe here, since it may only be full.
         * If it really is locked, we should kill it off manually. */
    break;

    case APR_OC_REASON_RESTART:
        if (pl->pid != NULL) {
            apr_proc_kill(pl->pid, SIGTERM);
            pl->pid = NULL;
        }
        break;

    case APR_OC_REASON_UNREGISTER:
        break;
    }
}


static apr_status_t piped_log_cleanup_for_exec(void *data)
{
    piped_log *pl = data;

    apr_file_close(pl->read_fd);
    apr_file_close(pl->write_fd);
    return APR_SUCCESS;
}


static apr_status_t piped_log_cleanup(void *data)
{
    piped_log *pl = data;

    if (pl->pid != NULL) {
        apr_proc_kill(pl->pid, SIGTERM);
    }
    return piped_log_cleanup_for_exec(data);
}


AP_DECLARE(piped_log *) ap_open_piped_log_ex(apr_pool_t *p,
                                             const char *program,
                                             apr_cmdtype_e cmdtype)
{
    piped_log *pl;

    pl = apr_palloc(p, sizeof (*pl));
    pl->p = p;
    pl->program = apr_pstrdup(p, program);
    pl->pid = NULL;
    pl->cmdtype = cmdtype;
    if (apr_file_pipe_create_ex(&pl->read_fd,
                                &pl->write_fd,
                                APR_FULL_BLOCK, p) != APR_SUCCESS) {
        return NULL;
    }
    apr_pool_cleanup_register(p, pl, piped_log_cleanup,
                              piped_log_cleanup_for_exec);
    if (piped_log_spawn(pl) != APR_SUCCESS) {
        apr_pool_cleanup_kill(p, pl, piped_log_cleanup);
        apr_file_close(pl->read_fd);
        apr_file_close(pl->write_fd);
        return NULL;
    }
    return pl;
}

#else /* !AP_HAVE_RELIABLE_PIPED_LOGS */

static apr_status_t piped_log_cleanup(void *data)
{
    piped_log *pl = data;

    apr_file_close(pl->write_fd);
    return APR_SUCCESS;
}

AP_DECLARE(piped_log *) ap_open_piped_log_ex(apr_pool_t *p,
                                             const char *program,
                                             apr_cmdtype_e cmdtype)
{
    piped_log *pl;
    apr_file_t *dummy = NULL;
    int rc;

    rc = log_child(p, program, &dummy, cmdtype, 0);
    if (rc != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_STARTUP, rc, NULL, APLOGNO(00108)
                     "Couldn't start piped log process '%s'.",
                     (program == NULL) ? "NULL" : program);
        return NULL;
    }

    pl = apr_palloc(p, sizeof (*pl));
    pl->p = p;
    pl->read_fd = NULL;
    pl->write_fd = dummy;
    apr_pool_cleanup_register(p, pl, piped_log_cleanup, piped_log_cleanup);

    return pl;
}

#endif

AP_DECLARE(piped_log *) ap_open_piped_log(apr_pool_t *p,
                                          const char *program)
{
    apr_cmdtype_e cmdtype = APR_PROGRAM_ENV;

    /* In 2.4 favor PROGRAM_ENV, accept "||prog" syntax for compatibility
     * and "|$cmd" to override the default.
     * Any 2.2 backport would continue to favor SHELLCMD_ENV so there
     * accept "||prog" to override, and "|$cmd" to ease conversion.
     */
    if (*program == '|')
        ++program;
    if (*program == '$') {
        cmdtype = APR_SHELLCMD_ENV;
        ++program;
    }

    return ap_open_piped_log_ex(p, program, cmdtype);
}

AP_DECLARE(void) ap_close_piped_log(piped_log *pl)
{
    apr_pool_cleanup_run(pl->p, pl, piped_log_cleanup);
}

AP_DECLARE(const char *) ap_parse_log_level(const char *str, int *val)
{
    char *err = "Log level keyword must be one of emerg/alert/crit/error/warn/"
                "notice/info/debug/trace1/.../trace8";
    int i = 0;

    if (str == NULL)
        return err;

    while (priorities[i].t_name != NULL) {
        if (!strcasecmp(str, priorities[i].t_name)) {
            *val = priorities[i].t_val;
            return NULL;
        }
        i++;
    }
    return err;
}

AP_IMPLEMENT_HOOK_VOID(error_log,
                       (const ap_errorlog_info *info, const char *errstr),
                       (info, errstr))

AP_IMPLEMENT_HOOK_RUN_FIRST(int, generate_log_id,
                            (const conn_rec *c, const request_rec *r,
                             const char **id),
                            (c, r, id), DECLINED)
