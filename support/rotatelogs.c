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
 * Simple program to rotate Apache logs without having to kill the server.
 *
 * Contributed by Ben Laurie <ben algroup.co.uk>
 *
 * 12 Mar 1996
 *
 * Ported to APR by Mladen Turk <mturk mappingsoft.com>
 *
 * 23 Sep 2001
 *
 * -l option added 2004-06-11
 *
 * -l causes the use of local time rather than GMT as the base for the
 * interval.  NB: Using -l in an environment which changes the GMT offset
 * (such as for BST or DST) can lead to unpredictable results!
 *
 * -f option added Feb, 2008. This causes rotatelog to open/create
 *    the logfile as soon as it's started, not as soon as it sees
 *    data.
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
#include "apr_signal.h"

#if APR_HAVE_STDLIB_H
#include <stdlib.h>
#endif
#define APR_WANT_STRFUNC
#include "apr_want.h"

#define BUFSIZE         65536
#define ERRMSGSZ        256

#ifndef MAX_PATH
#define MAX_PATH        1024
#endif

#ifdef SIGHUP
#ifdef SIGINT
#define HAVE_SIGNALS    1
#define SIG_CHECK       SIGHUP
#define SIG_FORCE       SIGINT
#endif
#endif

#define CHECK_LOG       0
#define CHECK_SIG_CHECK 1
#define CHECK_SIG_FORCE 2

#define ROTATE_NONE     0
#define ROTATE_NEW      1
#define ROTATE_TIME     2
#define ROTATE_SIZE     3
#define ROTATE_FORCE    4

typedef struct rotate_config rotate_config_t;

struct rotate_config {
    unsigned int sRotation;
    int tRotation;
    int utc_offset;
    int use_localtime;
    int use_strftime;
    int force_open;
    const char *szLogRoot;
};

typedef struct rotate_status rotate_status_t;

struct rotate_status {
    apr_pool_t *pool;
    apr_pool_t *pfile;
    apr_pool_t *pfile_prev;
    apr_file_t *nLogFD;
    apr_file_t *nLogFDprev;
    char filename[MAX_PATH];
    char errbuf[ERRMSGSZ];
    int rotateReason;
    int checkReason;
    int tLogEnd;
    int nMessCount;
};

static rotate_config_t config;
static rotate_status_t status;

static void usage(const char *argv0, const char *reason)
{
    if (reason) {
        fprintf(stderr, "%s\n", reason);
    }
    fprintf(stderr,
            "Usage: %s [-l] [-f] <logfile> "
            "{<rotation time in seconds>|<rotation size in megabytes>} "
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
            "to httpd.conf. The generated name will be /some/where.nnnn "
            "where nnnn is the\nsystem time at which the log nominally "
            "starts (N.B. if using a rotation time,\nthe time will always "
            "be a multiple of the rotation time, so you can synchronize\n"
            "cron scripts with it). At the end of each rotation time or "
            "when the file size\nis reached a new log is started.\n");
    exit(1);
}

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

static void closeFile(apr_pool_t *pool, apr_file_t *file)
{
    if (file != NULL) {
        apr_file_close(file);
        if (pool) {
            apr_pool_destroy(pool);
        }
    }
}

static void checkRotate(rotate_config_t *config, rotate_status_t *status)
{

    if (status->nLogFD == NULL) {
        status->rotateReason = ROTATE_NEW;
    }
    else if (status->checkReason == CHECK_SIG_FORCE) {
        status->rotateReason = ROTATE_FORCE;
    }
    else if (config->tRotation) {
        if (get_now(config) >= status->tLogEnd) {
            status->rotateReason = ROTATE_TIME;
        }
    }
    else if (config->sRotation) {
        apr_finfo_t finfo;
        apr_off_t current_size = -1;

        if (apr_file_info_get(&finfo, APR_FINFO_SIZE, status->nLogFD) == APR_SUCCESS) {
            current_size = finfo.size;
        }

        if (current_size > config->sRotation) {
            status->rotateReason = ROTATE_SIZE;
        }
    }
    else {
        fprintf(stderr, "No rotation time or size specified\n");
        exit(2);
    }

    /*
     * Let's close the file before immediately
     * if we got here via a signal.
     */
    if ((status->rotateReason != ROTATE_NONE) &&
        (status->checkReason != CHECK_LOG)) {
        closeFile(status->pfile, status->nLogFD);
        status->nLogFD = NULL;
        status->pfile = NULL;
    }
    return;
}

static void doRotate(rotate_config_t *config, rotate_status_t *status)
{

    int now = get_now(config);
    int tLogStart;
    apr_status_t rv;

    status->rotateReason = ROTATE_NONE;
    status->nLogFDprev = status->nLogFD;
    status->nLogFD = NULL;
    status->pfile_prev = status->pfile;

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
        apr_strftime(status->filename, &rs, sizeof(status->filename), config->szLogRoot, &e);
    }
    else {
        sprintf(status->filename, "%s.%010d", config->szLogRoot, tLogStart);
    }
    apr_pool_create(&status->pfile, status->pool);
    rv = apr_file_open(&status->nLogFD, status->filename, APR_WRITE | APR_CREATE | APR_APPEND,
                       APR_OS_DEFAULT, status->pfile);
    if (rv != APR_SUCCESS) {
        char error[120];

        apr_strerror(rv, error, sizeof error);

        /* Uh-oh. Failed to open the new log file. Try to clear
         * the previous log file, note the lost log entries,
         * and keep on truckin'. */
        if (status->nLogFDprev == NULL) {
            fprintf(stderr, "Could not open log file '%s' (%s)\n", status->filename, error);
            exit(2);
        }
        else {
            apr_size_t nWrite;
            status->nLogFD = status->nLogFDprev;
            apr_pool_destroy(status->pfile);
            status->pfile = status->pfile_prev;
            /* Try to keep this error message constant length
             * in case it occurs several times. */
            apr_snprintf(status->errbuf, sizeof status->errbuf,
                         "Resetting log file due to error opening "
                         "new log file, %10d messages lost: %-25.25s\n",
                         status->nMessCount, error);
            nWrite = strlen(status->errbuf);
            apr_file_trunc(status->nLogFD, 0);
            if (apr_file_write(status->nLogFD, status->errbuf, &nWrite) != APR_SUCCESS) {
                fprintf(stderr, "Error writing to the file %s\n", status->filename);
                exit(2);
            }
        }
    }
    else {
        closeFile(status->pfile_prev, status->nLogFDprev);
        status->nLogFDprev = NULL;
        status->pfile_prev = NULL;
    }
    status->nMessCount = 0;
    /*
     * Reset marker for signal triggered rotation
     */
    status->checkReason = CHECK_LOG;
}

#ifdef HAVE_SIGNALS
/*
 * called on SIG_CHECK and SIG_FORCE
 */
static void external_rotate(int signal)
{
    /*
     * Set marker for signal triggered rotation
     */
    if (signal == SIG_FORCE) {
        status.checkReason = CHECK_SIG_FORCE;
    }
    else {
        status.checkReason = CHECK_SIG_CHECK;
    }
    /*
     * Close old file conditionally
     */
    checkRotate(&config, &status);
    /*
     * Open new file if force flag was set
     */
    if (config.force_open && (status.rotateReason != ROTATE_NONE)) {
        doRotate(&config, &status);
    }
}
#endif

int main (int argc, const char * const argv[])
{
    char buf[BUFSIZE];
    apr_size_t nRead, nWrite;
    apr_file_t *f_stdin;
    apr_getopt_t *opt;
    apr_status_t rv;
    char c;
    const char *optarg;
    char *ptr = NULL;

    apr_app_initialize(&argc, &argv, NULL);
    atexit(apr_terminate);

    config.sRotation = 0;
    config.tRotation = 0;
    config.utc_offset = 0;
    config.use_localtime = 0;
    config.use_strftime = 0;
    config.force_open = 0;
    status.pool = NULL;
    status.pfile = NULL;
    status.pfile_prev = NULL;
    status.nLogFD = NULL;
    status.nLogFDprev = NULL;
    status.tLogEnd = 0;
    status.rotateReason = ROTATE_NONE;
    status.checkReason = CHECK_LOG;
    status.nMessCount = 0;

    apr_pool_create(&status.pool, NULL);
    apr_getopt_init(&opt, status.pool, argc, argv);
    while ((rv = apr_getopt(opt, "lf", &c, &optarg)) == APR_SUCCESS) {
        switch (c) {
        case 'l':
            config.use_localtime = 1;
            break;
        case 'f':
            config.force_open = 1;
            break;
        }
    }

    if (rv != APR_EOF) {
        usage(argv[0], NULL /* specific error message already issued */ );
    }

    if ((argc - opt->ind < 2) || (argc - opt->ind > 3) ) {
        usage(argv[0], "Incorrect number of arguments");
    }

    config.szLogRoot = argv[opt->ind++];

    ptr = strchr(argv[opt->ind], 'M');
    if (ptr) { /* rotation based on file size */
        if (*(ptr+1) == '\0') {
            config.sRotation = atoi(argv[opt->ind]) * 1048576;
        }
        if (config.sRotation == 0) {
            usage(argv[0], "Invalid rotation size parameter");
        }
    }
    else { /* rotation based on elapsed time */
        config.tRotation = atoi(argv[opt->ind]);
        if (config.tRotation <= 0) {
            usage(argv[0], "Invalid rotation time parameter");
        }
    }
    opt->ind++;

    if (opt->ind < argc) { /* have UTC offset */
        if (config.use_localtime) {
            usage(argv[0], "UTC offset parameter is not valid with -l");
        }
        config.utc_offset = atoi(argv[opt->ind]) * 60;
    }

    config.use_strftime = (strchr(config.szLogRoot, '%') != NULL);
    if (apr_file_open_stdin(&f_stdin, status.pool) != APR_SUCCESS) {
        fprintf(stderr, "Unable to open stdin\n");
        exit(1);
    }

    /*
     * Immediately open the logfile as we start, if we were forced
     * to do so via '-f'.
     */
    if (config.force_open) {
        doRotate(&config, &status);
    }

#ifdef HAVE_SIGNALS
    apr_signal(SIG_CHECK, external_rotate);
    apr_signal(SIG_FORCE, external_rotate);
#endif

    for (;;) {
        nRead = sizeof(buf);
#ifdef HAVE_SIGNALS
        apr_signal_unblock(SIG_CHECK);
        apr_signal_unblock(SIG_FORCE);
#endif
        rv = apr_file_read(f_stdin, buf, &nRead);
#ifdef HAVE_SIGNALS
        apr_signal_block(SIG_FORCE);
        apr_signal_block(SIG_CHECK);
#endif
        if (rv != APR_SUCCESS) {
            exit(3);
        }
        checkRotate(&config, &status);
        if (status.rotateReason != ROTATE_NONE) {
            doRotate(&config, &status);
        }

        nWrite = nRead;
        rv = apr_file_write(status.nLogFD, buf, &nWrite);
        if (rv == APR_SUCCESS && nWrite != nRead) {
            /* buffer partially written, which for rotatelogs means we encountered
             * an error such as out of space or quota or some other limit reached;
             * try to write the rest so we get the real error code
             */
            apr_size_t nWritten = nWrite;

            nRead  = nRead - nWritten;
            nWrite = nRead;
            rv = apr_file_write(status.nLogFD, buf + nWritten, &nWrite);
        }
        if (nWrite != nRead) {
            char strerrbuf[120];
            apr_off_t cur_offset;

            cur_offset = 0;
            if (apr_file_seek(status.nLogFD, APR_CUR, &cur_offset) != APR_SUCCESS) {
                cur_offset = -1;
            }
            apr_strerror(rv, strerrbuf, sizeof strerrbuf);
            status.nMessCount++;
            apr_snprintf(status.errbuf, sizeof status.errbuf,
                         "Error %d writing to log file at offset %" APR_OFF_T_FMT ". "
                         "%10d messages lost (%s)\n",
                         rv, cur_offset, status.nMessCount, strerrbuf);
            nWrite = strlen(status.errbuf);
            apr_file_trunc(status.nLogFD, 0);
            if (apr_file_write(status.nLogFD, status.errbuf, &nWrite) != APR_SUCCESS) {
                fprintf(stderr, "Error writing to the file %s\n", status.filename);
                exit(2);
            }
        }
        else {
            status.nMessCount++;
        }
    }
    /* Of course we never, but prevent compiler warnings */
    return 0;
}
