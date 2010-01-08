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

#if !defined(__linux__) && !defined(__FreeBSD__)
#error This module is currently only implemented for Linux and FreeBSD.
#endif

/*
 * Documentation:
 *
 * mod_backtrace is an experimental module for Apache httpd 1.3 which
 * collects backtraces when a child process crashes.  Currently it is
 * implemented only on Linux and FreeBSD, but other platforms could be
 * supported in the future.  You should verify that it works reasonably
 * on your system before putting it in production.
 *
 * It implements a fatal exception hook that will be called when a child
 * process crashes.  In the exception hook it uses system library routines
 * to obtain information about the call stack, and it writes the call
 * stack to a log file or the web server error log.  The backtrace is a
 * critical piece of information when determining the failing software
 * component that caused the crash.  Note that the backtrace written by
 * mod_backtrace may not have as much information as a debugger can
 * display from a core dump.
 *
 * Apache httpd requirements for mod_backtrace:
 *
 *   Apache httpd >= 1.3.30 must be built with the AP_ENABLE_EXCEPTION_HOOK
 *   symbol defined and mod_so enabled.  AP_ENABLE_EXCEPTION_HOOK is already
 *   defined in ap_config.h for some platforms, including AIX, Linux,
 *   Solaris, and HP-UX.  It can be enabled for other platforms by including
 *   -DAP_ENABLE_EXCEPTION_HOOK in CFLAGS when the configure script is
 *   invoked.
 *
 * Compiling mod_backtrace:
 *
 *   Linux:
 *     apxs -ci mod_backtrace.c
 *
 *   FreeBSD:
 *     install libexecinfo from the Ports system then
 *     apxs -ci -L/usr/local/lib -lexecinfo mod_backtrace.c
 *
 * Activating mod_backtrace:
 *
 *   1. Load it like any other DSO:
 *        LoadModule backtrace_module libexec/mod_backtrace.so
 *        ...
 *        AddModule mod_backtrace.c
 *
 *   2. Enable exception hooks for modules like mod_backtrace:
 *        EnableExceptionHook On
 *
 *   3. Choose where backtrace information should be written.
 *      If you want backtraces from crashes to be reported some place other
 *      than the error log, use the BacktraceLog directive to specify a
 *      fully-qualified filename for the log to which backtraces will be
 *      written.  Note that the web server user id (e.g., "nobody") must
 *      be able to create or append to this log file, as the log file is
 *      not opened until a crash occurs.
 */

#include "httpd.h"
#include "http_config.h"
#include "http_log.h"

#include <fcntl.h>
#include <unistd.h>
#include <execinfo.h>

static char *log_fname;

static void bt_show_backtrace(int sig)
{
    char msgbuf[128];
    size_t size;
    void *array[20];
    extern int main();
    int logfd;
    time_t now;
    char msg_prefix[60];
    char *newline;
    int using_errorlog = 1;

    time(&now);
    ap_snprintf(msg_prefix, sizeof msg_prefix,
                "[%s pid %ld mod_backtrace",
                asctime(localtime(&now)),
                (long)getpid());
    newline = strchr(msg_prefix, '\n'); /* dang asctime() */
    if (newline) {                      /* silly we are */
        *newline = ']';
    }

    if (log_fname) {
        logfd = open(log_fname, O_WRONLY|O_APPEND|O_CREAT, 0644);
        if (logfd == -1) {
            logfd = 2; /* unix, so fd 2 is the web server error log */
            ap_snprintf(msgbuf, sizeof msgbuf,
                        "%s error %d opening %s\n",
                        msg_prefix, errno, log_fname);
            write(logfd, msgbuf, strlen(msgbuf));
        }
        else {
            using_errorlog = 0;
        }
    }
    else {
        logfd = 2;
    }
    
    ap_snprintf(msgbuf, sizeof msgbuf,
                "%s backtrace for signal %d\n",
                msg_prefix, sig);
    write(logfd, msgbuf, strlen(msgbuf));

    /* the address of main() can be useful if we're on old 
     * glibc and get only addresses for stack frames... knowing
     * where main() is then is a useful clue
     */
    ap_snprintf(msgbuf, sizeof msgbuf,
                "%s main() is at %pp\n",
                msg_prefix,
                main);/* don't you DARE put parens after "main" */
    write(logfd, msgbuf, strlen(msgbuf));

    size = backtrace(array, sizeof array / sizeof array[0]);
    backtrace_symbols_fd(array, size, logfd);
    ap_snprintf(msgbuf, sizeof msgbuf,
                "%s end of report\n",
                msg_prefix);
    write(logfd, msgbuf, strlen(msgbuf));
    if (!using_errorlog) {
        close(logfd);
    }
}

static void bt_exception_hook(ap_exception_info_t *ei)
{
    bt_show_backtrace(ei->sig);
}

static void bt_init(server_rec *s, pool *p)
{
    int rc = ap_add_fatal_exception_hook(bt_exception_hook);
    
    if (rc) {
        ap_log_error(APLOG_MARK, APLOG_ALERT|APLOG_NOERRNO, s,
                     "fatal exception hooks are not enabled; please "
                     "enable them with the EnableExceptionHook directive "
                     "or disable mod_backtrace");
    }
}

static const char *bt_cmd_file(cmd_parms *cmd, void *dconf, char *fname)
{
    log_fname = ap_pstrdup(cmd->pool, fname);
    return NULL;
}

static const command_rec bt_command_table[] = {
    {
        "BacktraceLog", bt_cmd_file, NULL, RSRC_CONF, TAKE1, "the fully-qualified filename of the mod_backtrace logfile"
    }
    ,
    {
        NULL
    }
};

module MODULE_VAR_EXPORT backtrace_module = {
    STANDARD_MODULE_STUFF,
    bt_init,                    /* initializer */
    NULL,                       /* dir config creater */
    NULL,                       /* dir merger --- default is to override */
    NULL,                       /* server config */
    NULL,                       /* merge server config */
    bt_command_table,           /* command table */
    NULL,                       /* handlers */
    NULL,                       /* filename translation */
    NULL,                       /* check_user_id */
    NULL,                       /* check auth */
    NULL,                       /* check access */
    NULL,                       /* type_checker */
    NULL,                       /* fixups */
    NULL,                       /* logger */
    NULL,                       /* header parser */
    NULL,                       /* child init */
    NULL,                       /* child exit */
    NULL                        /* post read request */
};
