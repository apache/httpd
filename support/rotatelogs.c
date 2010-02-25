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
 *
 * -v option added Feb, 2008. Verbose output of command line parsing.
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

#define ROTATE_NONE     0
#define ROTATE_NEW      1
#define ROTATE_TIME     2
#define ROTATE_SIZE     3
#define ROTATE_FORCE    4

static const char *ROTATE_REASONS[] = {
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
    const char *szLogRoot;
    int truncate;
    const char *linkfile;
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
            "Usage: %s [-v] [-l] [-L linkname] [-f] [-t] <logfile> "
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
            "to httpd.conf. The generated name will be /some/where.nnnn "
            "where nnnn is the\nsystem time at which the log nominally "
            "starts (N.B. if using a rotation time,\nthe time will always "
            "be a multiple of the rotation time, so you can synchronize\n"
            "cron scripts with it). At the end of each rotation time or "
            "when the file size\nis reached a new log is started. If the "
            "-t option is specified, the specified\nfile will be truncated "
            "instead of rotated, and is useful where tail is used to\n"
            "process logs in real time.  If the -L option is specified, "
            "a hard link will be\nmade from the current log file to the "
            "specified filename.\n");
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
static void closeFile(rotate_config_t *config, apr_pool_t *pool, apr_file_t *file)
{
    if (file != NULL) {
        if (config->verbose) {
            apr_finfo_t finfo;
            apr_int32_t wanted = APR_FINFO_NAME;
            if (apr_file_info_get(&finfo, wanted, file) == APR_SUCCESS) {
                fprintf(stderr, "Closing file %s (%s)\n", finfo.name, finfo.fname);
            }
        }
        apr_file_close(file);
        if (pool) {
            apr_pool_destroy(pool);
        }
    }
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
    fprintf(stderr, "Rotation file name: %21s\n", config->szLogRoot);
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

    if (status->nLogFD == NULL) {
        status->rotateReason = ROTATE_NEW;
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

    return;
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
        if (config->truncate) {
            snprintf(status->filename, sizeof(status->filename), "%s", config->szLogRoot);
        }
        else {
            snprintf(status->filename, sizeof(status->filename), "%s.%010d", config->szLogRoot,
                    tLogStart);
        }
    }
    apr_pool_create(&status->pfile, status->pool);
    if (config->verbose) {
        fprintf(stderr, "Opening file %s\n", status->filename);
    }
    rv = apr_file_open(&status->nLogFD, status->filename, APR_WRITE | APR_CREATE | APR_APPEND
                       | (config->truncate ? APR_TRUNCATE : 0), APR_OS_DEFAULT, status->pfile);
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
        closeFile(config, status->pfile_prev, status->nLogFDprev);
        status->nLogFDprev = NULL;
        status->pfile_prev = NULL;
    }
    status->nMessCount = 0;
    if (config->linkfile) {
        apr_file_remove(config->linkfile, status->pfile);
        if (config->verbose) {
            fprintf(stderr,"Linking %s to %s\n", status->filename, config->linkfile);
        }
        rv = apr_file_link(status->filename, config->linkfile);
        if (rv != APR_SUCCESS) {
            char error[120];
            apr_strerror(rv, error, sizeof error);
            fprintf(stderr, "Error linking file %s to %s (%s)\n",
                    status->filename, config->linkfile, error);
            exit(2);
        }
    }
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
    apr_getopt_t *opt;
    apr_status_t rv;
    char c;
    const char *optarg;
    const char *err = NULL;

    apr_app_initialize(&argc, &argv, NULL);
    atexit(apr_terminate);

    config.sRotation = 0;
    config.tRotation = 0;
    config.utc_offset = 0;
    config.use_localtime = 0;
    config.use_strftime = 0;
    config.force_open = 0;
    config.verbose = 0;
    status.pool = NULL;
    status.pfile = NULL;
    status.pfile_prev = NULL;
    status.nLogFD = NULL;
    status.nLogFDprev = NULL;
    status.tLogEnd = 0;
    status.rotateReason = ROTATE_NONE;
    status.nMessCount = 0;

    apr_pool_create(&status.pool, NULL);
    apr_getopt_init(&opt, status.pool, argc, argv);
    while ((rv = apr_getopt(opt, "lL:ftv", &c, &optarg)) == APR_SUCCESS) {
        switch (c) {
        case 'l':
            config.use_localtime = 1;
            break;
        case 'L':
            config.linkfile = optarg;
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

    if (apr_file_open_stdin(&f_stdin, status.pool) != APR_SUCCESS) {
        fprintf(stderr, "Unable to open stdin\n");
        exit(1);
    }

    /*
     * Write out result of config parsing if verbose is set.
     */
    if (config.verbose) {
        dumpConfig(&config);
    }

    /*
     * Immediately open the logfile as we start, if we were forced
     * to do so via '-f'.
     */
    if (config.force_open) {
        doRotate(&config, &status);
    }

    for (;;) {
        nRead = sizeof(buf);
        rv = apr_file_read(f_stdin, buf, &nRead);
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
