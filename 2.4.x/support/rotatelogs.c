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

#include "apr.h"
#include "apr_lib.h"
#include "apr_strings.h"
#include "apr_errno.h"
#include "apr_file_io.h"
#include "apr_file_info.h"
#include "apr_general.h"
#include "apr_time.h"
#include "apr_getopt.h"
#include "apr_thread_proc.h"
#include "apr_signal.h"
#if APR_FILES_AS_SOCKETS
#include "apr_poll.h"
#endif

#if APR_HAVE_STDLIB_H
#include <stdlib.h>
#endif
#define APR_WANT_STRFUNC
#include "apr_want.h"

#define BUFSIZE         65536
#define ERRMSGSZ        256

#define ROTATE_NONE     0
#define ROTATE_NEW      1
#define ROTATE_TIME     2
#define ROTATE_SIZE     3
#define ROTATE_FORCE    4

static const char *const ROTATE_REASONS[] = {
    "None",
    "Open a new file",
    "Time interval expired",
    "Maximum size reached",
    "Forced rotation",
    NULL
};

typedef struct rotate_config rotate_config_t;

struct rotate_config {
    unsigned int sRotation;
    int tRotation;
    int utc_offset;
    int use_localtime;
    int use_strftime;
    int force_open;
    int verbose;
    int echo;
    const char *szLogRoot;
    int truncate;
    const char *linkfile;
    const char *postrotate_prog;
#if APR_FILES_AS_SOCKETS
    int create_empty;
#endif
    int num_files;
};

typedef struct rotate_status rotate_status_t;

/* Structure to contain relevant logfile state: fd, pool and
 * filename. */
struct logfile {
    apr_pool_t *pool;
    apr_file_t *fd;
    char name[APR_PATH_MAX];
};

struct rotate_status {
    struct logfile current; /* current logfile. */
    apr_pool_t *pool; /* top-level pool */
    char errbuf[ERRMSGSZ];
    int rotateReason;
    int tLogEnd;
    int nMessCount;
    int fileNum;
};

static rotate_config_t config;
static rotate_status_t status;

static void usage(const char *argv0, const char *reason)
{
    if (reason) {
        fprintf(stderr, "%s\n", reason);
    }
    fprintf(stderr,
#if APR_FILES_AS_SOCKETS
            "Usage: %s [-v] [-l] [-L linkname] [-p prog] [-f] [-t] [-e] [-c] [-n number] <logfile> "
#else
            "Usage: %s [-v] [-l] [-L linkname] [-p prog] [-f] [-t] [-e] [-n number] <logfile> "
#endif
            "{<rotation time in seconds>|<rotation size>(B|K|M|G)} "
            "[offset minutes from UTC]\n\n",
            argv0);
#ifdef OS2
    fprintf(stderr,
            "Add this:\n\nTransferLog \"|%s.exe /some/where 86400\"\n\n",
            argv0);
#else
    fprintf(stderr,
            "Add this:\n\nTransferLog \"|%s /some/where 86400\"\n\n",
            argv0);
    fprintf(stderr,
            "or \n\nTransferLog \"|%s /some/where 5M\"\n\n", argv0);
#endif
    fprintf(stderr,
            "to httpd.conf. By default, the generated name will be\n"
            "<logfile>.nnnn where nnnn is the system time at which the log\n"
            "nominally starts (N.B. if using a rotation time, the time will\n"
            "always be a multiple of the rotation time, so you can synchronize\n"
            "cron scripts with it). If <logfile> contains strftime conversion\n"
            "specifications, those will be used instead. At the end of each\n"
            "rotation time or when the file size is reached a new log is\n"
            "started.\n"
            "\n"
            "Options:\n"
            "  -v       Verbose operation. Messages are written to stderr.\n"
            "  -l       Base rotation on local time instead of UTC.\n"
            "  -L path  Create hard link from current log to specified path.\n"
            "  -p prog  Run specified program after opening a new log file. See below.\n"
            "  -f       Force opening of log on program start.\n"
            "  -t       Truncate logfile instead of rotating, tail friendly.\n"
            "  -e       Echo log to stdout for further processing.\n"
#if APR_FILES_AS_SOCKETS
            "  -c       Create log even if it is empty.\n"
#endif
            "\n"
            "The program is invoked as \"[prog] <curfile> [<prevfile>]\"\n"
            "where <curfile> is the filename of the newly opened logfile, and\n"
            "<prevfile>, if given, is the filename of the previously used logfile.\n"
            "\n");
    exit(1);
}

/*
 * Get the unix time with timezone corrections
 * given in the config struct.
 */
static int get_now(rotate_config_t *config)
{
    apr_time_t tNow = apr_time_now();
    int utc_offset = config->utc_offset;
    if (config->use_localtime) {
        /* Check for our UTC offset before using it, since it might
         * change if there's a switch between standard and daylight
         * savings time.
         */
        apr_time_exp_t lt;
        apr_time_exp_lt(&lt, tNow);
        utc_offset = lt.tm_gmtoff;
    }
    return (int)apr_time_sec(tNow) + utc_offset;
}

/*
 * Close a file and destroy the associated pool.
 */
static void close_logfile(rotate_config_t *config, struct logfile *logfile)
{
    if (config->verbose) {
        fprintf(stderr, "Closing file %s\n", logfile->name);
    }
    apr_file_close(logfile->fd);
    apr_pool_destroy(logfile->pool);
}

/*
 * Dump the configuration parsing result to STDERR.
 */
static void dumpConfig (rotate_config_t *config)
{
    fprintf(stderr, "Rotation time interval:      %12d\n", config->tRotation);
    fprintf(stderr, "Rotation size interval:      %12d\n", config->sRotation);
    fprintf(stderr, "Rotation time UTC offset:    %12d\n", config->utc_offset);
    fprintf(stderr, "Rotation based on localtime: %12s\n", config->use_localtime ? "yes" : "no");
    fprintf(stderr, "Rotation file date pattern:  %12s\n", config->use_strftime ? "yes" : "no");
    fprintf(stderr, "Rotation file forced open:   %12s\n", config->force_open ? "yes" : "no");
    fprintf(stderr, "Rotation verbose:            %12s\n", config->verbose ? "yes" : "no");
#if APR_FILES_AS_SOCKETS
    fprintf(stderr, "Rotation create empty logs:  %12s\n", config->create_empty ? "yes" : "no");
#endif
    fprintf(stderr, "Rotation file name: %21s\n", config->szLogRoot);
    fprintf(stderr, "Post-rotation prog: %21s\n", config->postrotate_prog);
}

/*
 * Check whether we need to rotate.
 * Possible reasons are:
 * - No log file open (ROTATE_NEW)
 * - User forces us to rotate (ROTATE_FORCE)
 * - Our log file size is already bigger than the
 *   allowed maximum (ROTATE_SIZE)
 * - The next log time interval expired (ROTATE_TIME)
 *
 * When size and time constraints are both given,
 * it suffices that one of them is fulfilled.
 */
static void checkRotate(rotate_config_t *config, rotate_status_t *status)
{
    if (status->current.fd == NULL) {
        status->rotateReason = ROTATE_NEW;
    }
    else if (config->sRotation) {
        apr_finfo_t finfo;
        apr_off_t current_size = -1;

        if (apr_file_info_get(&finfo, APR_FINFO_SIZE, status->current.fd) == APR_SUCCESS) {
            current_size = finfo.size;
        }

        if (current_size > config->sRotation) {
            status->rotateReason = ROTATE_SIZE;
        }
        else if (config->tRotation) {
            if (get_now(config) >= status->tLogEnd) {
                status->rotateReason = ROTATE_TIME;
            }
        }
    }
    else if (config->tRotation) {
        if (get_now(config) >= status->tLogEnd) {
            status->rotateReason = ROTATE_TIME;
        }
    }
    else {
        fprintf(stderr, "No rotation time or size specified\n");
        exit(2);
    }

    if (status->rotateReason != ROTATE_NONE && config->verbose) {
        fprintf(stderr, "File rotation needed, reason: %s\n", ROTATE_REASONS[status->rotateReason]);
    }
}

/*
 * Handle post-rotate processing.
 */
static void post_rotate(apr_pool_t *pool, struct logfile *newlog,
                        rotate_config_t *config, rotate_status_t *status)
{
    apr_status_t rv;
    char error[120];
    apr_procattr_t *pattr;
    const char *argv[4];
    apr_proc_t proc;

    /* Handle link file, if configured. */
    if (config->linkfile) {
        apr_file_remove(config->linkfile, newlog->pool);
        if (config->verbose) {
            fprintf(stderr,"Linking %s to %s\n", newlog->name, config->linkfile);
        }
        rv = apr_file_link(newlog->name, config->linkfile);
        if (rv != APR_SUCCESS) {
            apr_strerror(rv, error, sizeof error);
            fprintf(stderr, "Error linking file %s to %s (%s)\n",
                    newlog->name, config->linkfile, error);
            exit(2);
        }
    }

    if (!config->postrotate_prog) {
        /* Nothing more to do. */
        return;
    }

    /* Collect any zombies from a previous run, but don't wait. */
    while (apr_proc_wait_all_procs(&proc, NULL, NULL, APR_NOWAIT, pool) == APR_CHILD_DONE)
        /* noop */;

    if ((rv = apr_procattr_create(&pattr, pool)) != APR_SUCCESS) {
        fprintf(stderr,
                "post_rotate: apr_procattr_create failed for '%s': %s\n",
                config->postrotate_prog,
                apr_strerror(rv, error, sizeof(error)));
        return;
    }

    rv = apr_procattr_error_check_set(pattr, 1);
    if (rv == APR_SUCCESS)
        rv = apr_procattr_cmdtype_set(pattr, APR_PROGRAM_ENV);

    if (rv != APR_SUCCESS) {
        fprintf(stderr,
                "post_rotate: could not set up process attributes for '%s': %s\n",
                config->postrotate_prog,
                apr_strerror(rv, error, sizeof(error)));
        return;
    }

    argv[0] = config->postrotate_prog;
    argv[1] = newlog->name;
    if (status->current.fd) {
        argv[2] = status->current.name;
        argv[3] = NULL;
    }
    else {
        argv[2] = NULL;
    }

    if (config->verbose)
        fprintf(stderr, "Calling post-rotate program: %s\n", argv[0]);

    rv = apr_proc_create(&proc, argv[0], argv, NULL, pattr, pool);
    if (rv != APR_SUCCESS) {
        fprintf(stderr, "Could not spawn post-rotate process '%s': %s\n",
                config->postrotate_prog,
                apr_strerror(rv, error, sizeof(error)));
        return;
    }
}

/* After a error, truncate the current file and write out an error
 * message, which must be contained in status->errbuf.  The process is
 * terminated on failure.  */
static void truncate_and_write_error(rotate_status_t *status)
{
    apr_size_t buflen = strlen(status->errbuf);

    if (apr_file_trunc(status->current.fd, 0) != APR_SUCCESS) {
        fprintf(stderr, "Error truncating the file %s\n", status->current.name);
        exit(2);
    }
    if (apr_file_write_full(status->current.fd, status->errbuf, buflen, NULL) != APR_SUCCESS) {
        fprintf(stderr, "Error writing error (%s) to the file %s\n", 
                status->errbuf, status->current.name);
        exit(2);
    }
}

/*
 * Open a new log file, and if successful
 * also close the old one.
 *
 * The timestamp for the calculation of the file
 * name of the new log file will be the actual millisecond
 * timestamp, except when a regular rotation based on a time
 * interval is configured and the previous interval
 * is over. Then the timestamp is the starting time
 * of the actual interval.
 */
static void doRotate(rotate_config_t *config, rotate_status_t *status)
{

    int now = get_now(config);
    int tLogStart;
    apr_status_t rv;
    struct logfile newlog;
    int thisLogNum = -1;

    status->rotateReason = ROTATE_NONE;

    if (config->tRotation) {
        int tLogEnd;
        tLogStart = (now / config->tRotation) * config->tRotation;
        tLogEnd = tLogStart + config->tRotation;
        /*
         * Check if rotation was forced and the last rotation
         * interval is not yet over. Use the value of now instead
         * of the time interval boundary for the file name then.
         */
        if (tLogStart < status->tLogEnd) {
            tLogStart = now;
        }
        status->tLogEnd = tLogEnd;
    }
    else {
        tLogStart = now;
    }

    if (config->use_strftime) {
        apr_time_t tNow = apr_time_from_sec(tLogStart);
        apr_time_exp_t e;
        apr_size_t rs;

        apr_time_exp_gmt(&e, tNow);
        apr_strftime(newlog.name, &rs, sizeof(newlog.name), config->szLogRoot, &e);
    }
    else {
        if (config->truncate) {
            apr_snprintf(newlog.name, sizeof(newlog.name), "%s", config->szLogRoot);
        }
        else if (config->num_files > 0) { 
            if (status->fileNum == -1 || status->fileNum == (config->num_files - 1)) {
                thisLogNum = 0;
                apr_snprintf(newlog.name, sizeof(newlog.name), "%s", config->szLogRoot);
            }
            else { 
                thisLogNum = status->fileNum + 1;
                apr_snprintf(newlog.name, sizeof(newlog.name), "%s.%d", config->szLogRoot, thisLogNum);
            }
        }
        else {
            apr_snprintf(newlog.name, sizeof(newlog.name), "%s.%010d", config->szLogRoot,
                         tLogStart);
        }
    }
    apr_pool_create(&newlog.pool, status->pool);
    if (config->verbose) {
        fprintf(stderr, "Opening file %s\n", newlog.name);
    }
    rv = apr_file_open(&newlog.fd, newlog.name, APR_WRITE | APR_CREATE | APR_APPEND
                       | (config->truncate || (config->num_files > 0 && status->current.fd) ? APR_TRUNCATE : 0), 
                       APR_OS_DEFAULT, newlog.pool);
    if (rv == APR_SUCCESS) {
        /* Handle post-rotate processing. */
        post_rotate(newlog.pool, &newlog, config, status);

        status->fileNum = thisLogNum;
        /* Close out old (previously 'current') logfile, if any. */
        if (status->current.fd) {
            close_logfile(config, &status->current);
        }

        /* New log file is now 'current'. */
        status->current = newlog;
    }
    else {
        char error[120];

        apr_strerror(rv, error, sizeof error);

        /* Uh-oh. Failed to open the new log file. Try to clear
         * the previous log file, note the lost log entries,
         * and keep on truckin'. */
        if (status->current.fd == NULL) {
            fprintf(stderr, "Could not open log file '%s' (%s)\n", newlog.name, error);
            exit(2);
        }

        /* Throw away new state; it isn't going to be used. */
        apr_pool_destroy(newlog.pool);

        /* Try to keep this error message constant length
         * in case it occurs several times. */
        apr_snprintf(status->errbuf, sizeof status->errbuf,
                     "Resetting log file due to error opening "
                     "new log file, %10d messages lost: %-25.25s\n",
                     status->nMessCount, error);

        truncate_and_write_error(status);
    }

    status->nMessCount = 0;
}

/*
 * Get a size or time param from a string.
 * Parameter 'last' indicates, whether the
 * argument is the last commadnline argument.
 * UTC offset is only allowed as a last argument
 * in order to make is distinguishable from the
 * rotation interval time.
 */
static const char *get_time_or_size(rotate_config_t *config,
                                    const char *arg, int last) {
    char *ptr = NULL;
    /* Byte multiplier */
    unsigned int mult = 1;
    if ((ptr = strchr(arg, 'B')) != NULL) { /* Found KB size */
        mult = 1;
    }
    else if ((ptr = strchr(arg, 'K')) != NULL) { /* Found KB size */
        mult = 1024;
    }
    else if ((ptr = strchr(arg, 'M')) != NULL) { /* Found MB size */
        mult = 1024 * 1024;
    }
    else if ((ptr = strchr(arg, 'G')) != NULL) { /* Found GB size */
        mult = 1024 * 1024 * 1024;
    }
    if (ptr) { /* rotation based on file size */
        if (config->sRotation > 0) {
            return "Rotation size parameter allowed only once";
        }
        if (*(ptr+1) == '\0') {
            config->sRotation = atoi(arg) * mult;
        }
        if (config->sRotation == 0) {
            return "Invalid rotation size parameter";
        }
    }
    else if ((config->sRotation > 0 || config->tRotation > 0) && last) {
        /* rotation based on elapsed time */
        if (config->use_localtime) {
            return "UTC offset parameter is not valid with -l";
        }
        config->utc_offset = atoi(arg) * 60;
    }
    else { /* rotation based on elapsed time */
        if (config->tRotation > 0) {
            return "Rotation time parameter allowed only once";
        }
        config->tRotation = atoi(arg);
        if (config->tRotation <= 0) {
            return "Invalid rotation time parameter";
        }
    }
    return NULL;
}

int main (int argc, const char * const argv[])
{
    char buf[BUFSIZE];
    apr_size_t nRead, nWrite;
    apr_file_t *f_stdin;
    apr_file_t *f_stdout;
    apr_getopt_t *opt;
    apr_status_t rv;
    char c;
    const char *opt_arg;
    const char *err = NULL;
#if APR_FILES_AS_SOCKETS
    apr_pollfd_t pollfd = { 0 };
    apr_status_t pollret = APR_SUCCESS;
    int polltimeout;
#endif

    apr_app_initialize(&argc, &argv, NULL);
    atexit(apr_terminate);

    memset(&config, 0, sizeof config);
    memset(&status, 0, sizeof status);
    status.rotateReason = ROTATE_NONE;

    apr_pool_create(&status.pool, NULL);
    apr_getopt_init(&opt, status.pool, argc, argv);
#if APR_FILES_AS_SOCKETS
    while ((rv = apr_getopt(opt, "lL:p:ftvecn:", &c, &opt_arg)) == APR_SUCCESS) {
#else
    while ((rv = apr_getopt(opt, "lL:p:ftven:", &c, &opt_arg)) == APR_SUCCESS) {
#endif
        switch (c) {
        case 'l':
            config.use_localtime = 1;
            break;
        case 'L':
            config.linkfile = opt_arg;
            break;
        case 'p':
            config.postrotate_prog = opt_arg;
#ifdef SIGCHLD
            /* Prevent creation of zombies (on modern Unix systems). */
            apr_signal(SIGCHLD, SIG_IGN);
#endif
            break;
        case 'f':
            config.force_open = 1;
            break;
        case 't':
            config.truncate = 1;
            break;
        case 'v':
            config.verbose = 1;
            break;
        case 'e':
            config.echo = 1;
            break;
#if APR_FILES_AS_SOCKETS
        case 'c':
            config.create_empty = 1;
            break;
#endif
        case 'n':
            config.num_files = atoi(opt_arg);
            status.fileNum = -1;
            break;
        }
    }

    if (rv != APR_EOF) {
        usage(argv[0], NULL /* specific error message already issued */ );
    }

    /*
     * After the initial flags we need 2 to 4 arguments,
     * the file name, either the rotation interval time or size
     * or both of them, and optionally the UTC offset.
     */
    if ((argc - opt->ind < 2) || (argc - opt->ind > 4) ) {
        usage(argv[0], "Incorrect number of arguments");
    }

    config.szLogRoot = argv[opt->ind++];

    /* Read in the remaining flags, namely time, size and UTC offset. */
    for(; opt->ind < argc; opt->ind++) {
        if ((err = get_time_or_size(&config, argv[opt->ind],
                                    opt->ind < argc - 1 ? 0 : 1)) != NULL) {
            usage(argv[0], err);
        }
    }

    config.use_strftime = (strchr(config.szLogRoot, '%') != NULL);

    if (config.use_strftime && config.num_files > 0) { 
        fprintf(stderr, "Cannot use -n with %% in filename\n");
        exit(1);
    }

    if (status.fileNum == -1 && config.num_files < 1) { 
        fprintf(stderr, "Invalid -n argument\n");
        exit(1);
    }

    if (apr_file_open_stdin(&f_stdin, status.pool) != APR_SUCCESS) {
        fprintf(stderr, "Unable to open stdin\n");
        exit(1);
    }

    if (apr_file_open_stdout(&f_stdout, status.pool) != APR_SUCCESS) {
        fprintf(stderr, "Unable to open stdout\n");
        exit(1);
    }

    /*
     * Write out result of config parsing if verbose is set.
     */
    if (config.verbose) {
        dumpConfig(&config);
    }

#if APR_FILES_AS_SOCKETS
    if (config.create_empty && config.tRotation) {
        pollfd.p = status.pool;
        pollfd.desc_type = APR_POLL_FILE;
        pollfd.reqevents = APR_POLLIN;
        pollfd.desc.f = f_stdin;
    }
#endif

    /*
     * Immediately open the logfile as we start, if we were forced
     * to do so via '-f'.
     */
    if (config.force_open) {
        doRotate(&config, &status);
    }

    for (;;) {
        nRead = sizeof(buf);
#if APR_FILES_AS_SOCKETS
        if (config.create_empty && config.tRotation) {
            polltimeout = status.tLogEnd ? status.tLogEnd - get_now(&config) : config.tRotation;
            if (polltimeout <= 0) {
                pollret = APR_TIMEUP;
            }
            else {
                pollret = apr_poll(&pollfd, 1, &pollret, apr_time_from_sec(polltimeout));
            }
        }
        if (pollret == APR_SUCCESS) {
            rv = apr_file_read(f_stdin, buf, &nRead);
            if (APR_STATUS_IS_EOF(rv)) {
                break;
            }
            else if (rv != APR_SUCCESS) {
                exit(3);
            }
        }
        else if (pollret == APR_TIMEUP) {
            *buf = 0;
            nRead = 0;
        }
        else {
            fprintf(stderr, "Unable to poll stdin\n");
            exit(5);
        }
#else /* APR_FILES_AS_SOCKETS */
        rv = apr_file_read(f_stdin, buf, &nRead);
        if (APR_STATUS_IS_EOF(rv)) {
            break;
        }
        else if (rv != APR_SUCCESS) {
            exit(3);
        }
#endif /* APR_FILES_AS_SOCKETS */
        checkRotate(&config, &status);
        if (status.rotateReason != ROTATE_NONE) {
            doRotate(&config, &status);
        }

        nWrite = nRead;
        rv = apr_file_write_full(status.current.fd, buf, nWrite, &nWrite);
        if (nWrite != nRead) {
            apr_off_t cur_offset;

            cur_offset = 0;
            if (apr_file_seek(status.current.fd, APR_CUR, &cur_offset) != APR_SUCCESS) {
                cur_offset = -1;
            }
            status.nMessCount++;
            apr_snprintf(status.errbuf, sizeof status.errbuf,
                         "Error %d writing to log file at offset %" APR_OFF_T_FMT ". "
                         "%10d messages lost (%pm)\n",
                         rv, cur_offset, status.nMessCount, &rv);

            truncate_and_write_error(&status);
        }
        else {
            status.nMessCount++;
        }
        if (config.echo) {
            if (apr_file_write_full(f_stdout, buf, nRead, &nWrite)) {
                fprintf(stderr, "Unable to write to stdout\n");
                exit(4);
            }
        }
    }

    return 0; /* reached only at stdin EOF. */
}
