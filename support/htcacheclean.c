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
 * htcacheclean.c: simple program for cleaning of
 * the disk cache of the Apache HTTP server
 *
 * Contributed by Andreas Steinmetz <ast domdv.de>
 * 8 Oct 2004
 */

#include "apr.h"
#include "apr_lib.h"
#include "apr_strings.h"
#include "apr_file_io.h"
#include "apr_file_info.h"
#include "apr_pools.h"
#include "apr_hash.h"
#include "apr_thread_proc.h"
#include "apr_signal.h"
#include "apr_getopt.h"
#include "apr_ring.h"
#include "apr_date.h"
#include "../modules/cache/mod_disk_cache.h"

#if APR_HAVE_UNISTD_H
#include <unistd.h>
#endif
#if APR_HAVE_STDLIB_H
#include <stdlib.h>
#endif

/* define the following for debugging */
#undef DEBUG

/*
 * Note: on Linux delays <= 2ms are busy waits without
 *       scheduling, so never use a delay <= 2ms below
 */

#define NICE_DELAY    10000     /* usecs */
#define DELETE_NICE   10        /* be nice after this amount of delete ops */
#define STAT_ATTEMPTS 10        /* maximum stat attempts for a file */
#define STAT_DELAY    5000      /* usecs */
#define HEADER        1         /* headers file */
#define DATA          2         /* body file */
#define TEMP          4         /* temporary file */
#define HEADERDATA    (HEADER|DATA)
#define MAXDEVIATION  3600      /* secs */
#define SECS_PER_MIN  60
#define KBYTE         1024
#define MBYTE         1048576
#define GBYTE         1073741824

#define DIRINFO (APR_FINFO_MTIME|APR_FINFO_SIZE|APR_FINFO_TYPE|APR_FINFO_LINK)

typedef struct _direntry {
    APR_RING_ENTRY(_direntry) link;
    int type;         /* type of file/fileset: TEMP, HEADER, DATA, HEADERDATA */
    apr_time_t htime; /* headers file modification time */
    apr_time_t dtime; /* body file modification time */
    apr_off_t hsize;  /* headers file size */
    apr_off_t dsize;  /* body or temporary file size */
    char *basename;   /* file/fileset base name */
} DIRENTRY;

typedef struct _entry {
    APR_RING_ENTRY(_entry) link;
    apr_time_t expire;        /* cache entry exiration time */
    apr_time_t response_time; /* cache entry time of last response to client */
    apr_time_t htime;         /* headers file modification time */
    apr_time_t dtime;         /* body file modification time */
    apr_off_t hsize;          /* headers file size */
    apr_off_t dsize;          /* body or temporary file size */
    char *basename;           /* fileset base name */
} ENTRY;


static int delcount;    /* file deletion count for nice mode */
static int interrupted; /* flag: true if SIGINT or SIGTERM occurred */
static int realclean;   /* flag: true means user said apache is not running */
static int verbose;     /* flag: true means print statistics */
static int benice;      /* flag: true means nice mode is activated */
static int dryrun;      /* flag: true means dry run, don't actually delete
                                 anything */
static int deldirs;     /* flag: true means directories should be deleted */
static int baselen;     /* string length of the path to the proxy directory */
static apr_time_t now;  /* start time of this processing run */

static apr_file_t *errfile;   /* stderr file handle */
static apr_off_t unsolicited; /* file size summary for deleted unsolicited
                                 files */
static APR_RING_ENTRY(_entry) root; /* ENTRY ring anchor */

/* short program name as called */
static const char *shortname = "htcacheclean";

#ifdef DEBUG
/*
 * fake delete for debug purposes
 */
#define apr_file_remove fake_file_remove
static void fake_file_remove(char *pathname, apr_pool_t *p)
{
    apr_finfo_t info;

    /* stat and printing to simulate some deletion system load and to
       display what would actually have happened */
    apr_stat(&info, pathname, DIRINFO, p);
    apr_file_printf(errfile, "would delete %s" APR_EOL_STR, pathname);
}
#endif

/*
 * called on SIGINT or SIGTERM
 */
static void setterm(int unused)
{
#ifdef DEBUG
    apr_file_printf(errfile, "interrupt" APR_EOL_STR);
#endif
    interrupted = 1;
}

/*
 * called in out of memory condition
 */
static int oom(int unused)
{
    static int called = 0;

    /* be careful to call exit() only once */
    if (!called) {
        called = 1;
        exit(1);
    }
    return APR_ENOMEM;
}

/*
 * print purge statistics
 */
static void printstats(apr_off_t total, apr_off_t sum, apr_off_t max,
                       apr_off_t etotal, apr_off_t entries)
{
    char ttype, stype, mtype, utype;
    apr_off_t tfrag, sfrag, ufrag;

    if (!verbose) {
        return;
    }

    ttype = 'K';
    tfrag = ((total * 10) / KBYTE) % 10;
    total /= KBYTE;
    if (total >= KBYTE) {
        ttype = 'M';
        tfrag = ((total * 10) / KBYTE) % 10;
        total /= KBYTE;
    }

    stype = 'K';
    sfrag = ((sum * 10) / KBYTE) % 10;
    sum /= KBYTE;
    if (sum >= KBYTE) {
        stype = 'M';
        sfrag = ((sum * 10) / KBYTE) % 10;
        sum /= KBYTE;
    }

    mtype = 'K';
    max /= KBYTE;
    if (max >= KBYTE) {
        mtype = 'M';
        max /= KBYTE;
    }

    apr_file_printf(errfile, "Statistics:" APR_EOL_STR);
    if (unsolicited) {
        utype = 'K';
        ufrag = ((unsolicited * 10) / KBYTE) % 10;
        unsolicited /= KBYTE;
        if (unsolicited >= KBYTE) {
            utype = 'M';
            ufrag = ((unsolicited * 10) / KBYTE) % 10;
            unsolicited /= KBYTE;
        }
        if (!unsolicited && !ufrag) {
            ufrag = 1;
        }
        apr_file_printf(errfile, "unsolicited size %d.%d%c" APR_EOL_STR,
                        (int)(unsolicited), (int)(ufrag), utype);
     }
     apr_file_printf(errfile, "size limit %d.0%c" APR_EOL_STR,
                     (int)(max), mtype);
     apr_file_printf(errfile, "total size was %d.%d%c, total size now "
                              "%d.%d%c" APR_EOL_STR,
                     (int)(total), (int)(tfrag), ttype, (int)(sum),
                     (int)(sfrag), stype);
     apr_file_printf(errfile, "total entries was %d, total entries now %d"
                              APR_EOL_STR, (int)(etotal), (int)(entries));
}

/*
 * delete a single file
 */
static void delete_file(char *path, char *basename, apr_pool_t *pool)
{
    char *nextpath;
    apr_pool_t *p;

    if (dryrun) {
        return;
    }

    /* temp pool, otherwise lots of memory could be allocated */
    apr_pool_create(&p, pool);
    nextpath = apr_pstrcat(p, path, "/", basename, NULL);
    apr_file_remove(nextpath, p);
    apr_pool_destroy(p);

    if (benice) {
        if (++delcount >= DELETE_NICE) {
            apr_sleep(NICE_DELAY);
            delcount = 0;
        }
    }
}

/*
 * delete cache file set
 */
static void delete_entry(char *path, char *basename, apr_pool_t *pool)
{
    char *nextpath;
    apr_pool_t *p;

    if (dryrun) {
        return;
    }

    /* temp pool, otherwise lots of memory could be allocated */
    apr_pool_create(&p, pool);

    nextpath = apr_pstrcat(p, path, "/", basename, CACHE_HEADER_SUFFIX, NULL);
    apr_file_remove(nextpath, p);

    nextpath = apr_pstrcat(p, path, "/", basename, CACHE_DATA_SUFFIX, NULL);
    apr_file_remove(nextpath, p);

    apr_pool_destroy(p);

    if (benice) {
        delcount += 2;
        if (delcount >= DELETE_NICE) {
            apr_sleep(NICE_DELAY);
            delcount = 0;
        }
    }
}

/*
 * walk the cache directory tree
 */
static int process_dir(char *path, apr_pool_t *pool)
{
    apr_dir_t *dir;
    apr_pool_t *p;
    apr_hash_t *h;
    apr_hash_index_t *i;
    apr_file_t *fd;
    apr_status_t status;
    apr_finfo_t info;
    apr_size_t len;
    apr_time_t current, deviation;
    char *nextpath, *base, *ext, *orig_basename;
    APR_RING_ENTRY(_direntry) anchor;
    DIRENTRY *d, *t, *n;
    ENTRY *e;
    int skip, retries;
    disk_cache_info_t disk_info;

    APR_RING_INIT(&anchor, _direntry, link);
    apr_pool_create(&p, pool);
    h = apr_hash_make(p);
    fd = NULL;
    skip = 0;
    deviation = MAXDEVIATION * APR_USEC_PER_SEC;

    if (apr_dir_open(&dir, path, p) != APR_SUCCESS) {
        return 1;
    }

    while (apr_dir_read(&info, 0, dir) == APR_SUCCESS && !interrupted) {
        if (!strcmp(info.name, ".") || !strcmp(info.name, "..")) {
            continue;
        }
        d = apr_pcalloc(p, sizeof(DIRENTRY));
        d->basename = apr_pstrcat(p, path, "/", info.name, NULL);
        APR_RING_INSERT_TAIL(&anchor, d, _direntry, link);
    }

    apr_dir_close(dir);

    if (interrupted) {
        return 1;
    }

    skip = baselen + 1;

    for (d = APR_RING_FIRST(&anchor);
         !interrupted && d != APR_RING_SENTINEL(&anchor, _direntry, link);
         d=n) {
        n = APR_RING_NEXT(d, link);
        base = strrchr(d->basename, '/');
        if (!base++) {
            base = d->basename;
        }
        ext = strchr(base, '.');

        /* there may be temporary files which may be gone before
         * processing, always skip these if not in realclean mode
         */
        if (!ext && !realclean) {
            if (!strncasecmp(base, AP_TEMPFILE_BASE, AP_TEMPFILE_BASELEN)
                && strlen(base) == AP_TEMPFILE_NAMELEN) {
                continue;
            }
        }

        /* this may look strange but apr_stat() may return errno which
         * is system dependent and there may be transient failures,
         * so just blindly retry for a short while
         */
        retries = STAT_ATTEMPTS;
        status = APR_SUCCESS;
        do {
            if (status != APR_SUCCESS) {
                apr_sleep(STAT_DELAY);
            }
            status = apr_stat(&info, d->basename, DIRINFO, p);
        } while (status != APR_SUCCESS && !interrupted && --retries);

        /* what may happen here is that apache did create a file which
         * we did detect but then does delete the file before we can
         * get file information, so if we don't get any file information
         * we will ignore the file in this case
         */
        if (status != APR_SUCCESS) {
            if (!realclean && !interrupted) {
                continue;
            }
            return 1;
        }

        if (info.filetype == APR_DIR) {
            /* Make a copy of the basename, as process_dir modifies it */
            orig_basename = apr_pstrdup(pool, d->basename);
            if (process_dir(d->basename, pool)) {
                return 1;
            }

            /* If asked to delete dirs, do so now. We don't care if it fails.
             * If it fails, it likely means there was something else there.
             */
            if (deldirs && !dryrun) {
                apr_dir_remove(orig_basename, pool);
            }
            continue;
        }

        if (info.filetype != APR_REG) {
            continue;
        }

        if (!ext) {
            if (!strncasecmp(base, AP_TEMPFILE_BASE, AP_TEMPFILE_BASELEN)
                && strlen(base) == AP_TEMPFILE_NAMELEN) {
                d->basename += skip;
                d->type = TEMP;
                d->dsize = info.size;
                apr_hash_set(h, d->basename, APR_HASH_KEY_STRING, d);
            }
            continue;
        }

        if (!strcasecmp(ext, CACHE_HEADER_SUFFIX)) {
            *ext = '\0';
            d->basename += skip;
            /* if a user manually creates a '.header' file */
            if (d->basename[0] == '\0') {
                continue;
            }
            t = apr_hash_get(h, d->basename, APR_HASH_KEY_STRING);
            if (t) {
                d = t;
            }
            d->type |= HEADER;
            d->htime = info.mtime;
            d->hsize = info.size;
            apr_hash_set(h, d->basename, APR_HASH_KEY_STRING, d);
            continue;
        }

        if (!strcasecmp(ext, CACHE_DATA_SUFFIX)) {
            *ext = '\0';
            d->basename += skip;
            /* if a user manually creates a '.data' file */
            if (d->basename[0] == '\0') {
                continue;
            }
            t = apr_hash_get(h, d->basename, APR_HASH_KEY_STRING);
            if (t) {
                d = t;
            }
            d->type |= DATA;
            d->dtime = info.mtime;
            d->dsize = info.size;
            apr_hash_set(h, d->basename, APR_HASH_KEY_STRING, d);
        }
    }

    if (interrupted) {
        return 1;
    }

    path[baselen] = '\0';

    for (i = apr_hash_first(p, h); i && !interrupted; i = apr_hash_next(i)) {
        void *hvalue;
        apr_uint32_t format;

        apr_hash_this(i, NULL, NULL, &hvalue);
        d = hvalue;

        switch(d->type) {
        case HEADERDATA:
            nextpath = apr_pstrcat(p, path, "/", d->basename,
                                   CACHE_HEADER_SUFFIX, NULL);
            if (apr_file_open(&fd, nextpath, APR_FOPEN_READ | APR_FOPEN_BINARY,
                              APR_OS_DEFAULT, p) == APR_SUCCESS) {
                len = sizeof(format);
                if (apr_file_read_full(fd, &format, len,
                                       &len) == APR_SUCCESS) {
                    if (format == DISK_FORMAT_VERSION) {
                        apr_off_t offset = 0;

                        apr_file_seek(fd, APR_SET, &offset);

                        len = sizeof(disk_cache_info_t);

                        if (apr_file_read_full(fd, &disk_info, len,
                                               &len) == APR_SUCCESS) {
                            apr_file_close(fd);
                            e = apr_palloc(pool, sizeof(ENTRY));
                            APR_RING_INSERT_TAIL(&root, e, _entry, link);
                            e->expire = disk_info.expire;
                            e->response_time = disk_info.response_time;
                            e->htime = d->htime;
                            e->dtime = d->dtime;
                            e->hsize = d->hsize;
                            e->dsize = d->dsize;
                            e->basename = apr_pstrdup(pool, d->basename);
                            break;
                        }
                        else {
                            apr_file_close(fd);
                        }
                    }
                    else if (format == VARY_FORMAT_VERSION) {
                        /* This must be a URL that added Vary headers later,
                         * so kill the orphaned .data file
                         */
                        apr_file_close(fd);
                        apr_file_remove(apr_pstrcat(p, path, "/", d->basename,
                                                    CACHE_DATA_SUFFIX, NULL),
                                        p);
                    }
                }
                else {
                    apr_file_close(fd);
                }

            }
            /* we have a somehow unreadable headers file which is associated
             * with a data file. this may be caused by apache currently
             * rewriting the headers file. thus we may delete the file set
             * either in realclean mode or if the headers file modification
             * timestamp is not within a specified positive or negative offset
             * to the current time.
             */
            current = apr_time_now();
            if (realclean || d->htime < current - deviation
                || d->htime > current + deviation) {
                delete_entry(path, d->basename, p);
                unsolicited += d->hsize;
                unsolicited += d->dsize;
            }
            break;

        /* single data and header files may be deleted either in realclean
         * mode or if their modification timestamp is not within a
         * specified positive or negative offset to the current time.
         * this handling is necessary due to possible race conditions
         * between apache and this process
         */
        case HEADER:
            current = apr_time_now();
            nextpath = apr_pstrcat(p, path, "/", d->basename,
                                   CACHE_HEADER_SUFFIX, NULL);
            if (apr_file_open(&fd, nextpath, APR_FOPEN_READ | APR_FOPEN_BINARY,
                              APR_OS_DEFAULT, p) == APR_SUCCESS) {
                len = sizeof(format);
                if (apr_file_read_full(fd, &format, len,
                                       &len) == APR_SUCCESS) {
                    if (format == VARY_FORMAT_VERSION) {
                        apr_time_t expires;

                        len = sizeof(expires);

                        apr_file_read_full(fd, &expires, len, &len);

                        apr_file_close(fd);

                        if (expires < current) {
                            delete_entry(path, d->basename, p);
                        }
                        break;
                    }
                }
                apr_file_close(fd);
            }

            if (realclean || d->htime < current - deviation
                || d->htime > current + deviation) {
                delete_entry(path, d->basename, p);
                unsolicited += d->hsize;
            }
            break;

        case DATA:
            current = apr_time_now();
            if (realclean || d->dtime < current - deviation
                || d->dtime > current + deviation) {
                delete_entry(path, d->basename, p);
                unsolicited += d->dsize;
            }
            break;

        /* temp files may only be deleted in realclean mode which
         * is asserted above if a tempfile is in the hash array
         */
        case TEMP:
            delete_file(path, d->basename, p);
            unsolicited += d->dsize;
            break;
        }
    }

    if (interrupted) {
        return 1;
    }

    apr_pool_destroy(p);

    if (benice) {
        apr_sleep(NICE_DELAY);
    }

    if (interrupted) {
        return 1;
    }

    return 0;
}

/*
 * purge cache entries
 */
static void purge(char *path, apr_pool_t *pool, apr_off_t max)
{
    apr_off_t sum, total, entries, etotal;
    ENTRY *e, *n, *oldest;

    sum = 0;
    entries = 0;

    for (e = APR_RING_FIRST(&root);
         e != APR_RING_SENTINEL(&root, _entry, link);
         e = APR_RING_NEXT(e, link)) {
        sum += e->hsize;
        sum += e->dsize;
        entries++;
    }

    total = sum;
    etotal = entries;

    if (sum <= max) {
        printstats(total, sum, max, etotal, entries);
        return;
    }

    /* process all entries with a timestamp in the future, this may
     * happen if a wrong system time is corrected
     */

    for (e = APR_RING_FIRST(&root);
         e != APR_RING_SENTINEL(&root, _entry, link) && !interrupted;) {
        n = APR_RING_NEXT(e, link);
        if (e->response_time > now || e->htime > now || e->dtime > now) {
            delete_entry(path, e->basename, pool);
            sum -= e->hsize;
            sum -= e->dsize;
            entries--;
            APR_RING_REMOVE(e, link);
            if (sum <= max) {
                if (!interrupted) {
                    printstats(total, sum, max, etotal, entries);
                }
                return;
            }
        }
        e = n;
    }

    if (interrupted) {
        return;
    }

    /* process all entries with are expired */
    for (e = APR_RING_FIRST(&root);
         e != APR_RING_SENTINEL(&root, _entry, link) && !interrupted;) {
        n = APR_RING_NEXT(e, link);
        if (e->expire != APR_DATE_BAD && e->expire < now) {
            delete_entry(path, e->basename, pool);
            sum -= e->hsize;
            sum -= e->dsize;
            entries--;
            APR_RING_REMOVE(e, link);
            if (sum <= max) {
                if (!interrupted) {
                    printstats(total, sum, max, etotal, entries);
                }
                return;
            }
        }
        e = n;
    }

    if (interrupted) {
         return;
    }

    /* process remaining entries oldest to newest, the check for an emtpy
     * ring actually isn't necessary except when the compiler does
     * corrupt 64bit arithmetics which happend to me once, so better safe
     * than sorry
     */
    while (sum > max && !interrupted && !APR_RING_EMPTY(&root, _entry, link)) {
        oldest = APR_RING_FIRST(&root);

        for (e = APR_RING_NEXT(oldest, link);
             e != APR_RING_SENTINEL(&root, _entry, link);
             e = APR_RING_NEXT(e, link)) {
            if (e->dtime < oldest->dtime) {
                oldest = e;
            }
        }

        delete_entry(path, oldest->basename, pool);
        sum -= oldest->hsize;
        sum -= oldest->dsize;
        entries--;
        APR_RING_REMOVE(oldest, link);
    }

    if (!interrupted) {
        printstats(total, sum, max, etotal, entries);
    }
}

/*
 * usage info
 */
#define NL APR_EOL_STR
static void usage(void)
{
    apr_file_printf(errfile,
    "%s -- program for cleaning the disk cache."                             NL
    "Usage: %s [-Dvtrn] -pPATH -lLIMIT"                                      NL
    "       %s [-nti] -dINTERVAL -pPATH -lLIMIT"                             NL
                                                                             NL
    "Options:"                                                               NL
    "  -d   Daemonize and repeat cache cleaning every INTERVAL minutes."     NL
    "       This option is mutually exclusive with the -D, -v and -r"        NL
    "       options."                                                        NL
                                                                             NL
    "  -D   Do a dry run and don't delete anything. This option is mutually" NL
    "       exclusive with the -d option."                                   NL
                                                                             NL
    "  -v   Be verbose and print statistics. This option is mutually"        NL
    "       exclusive with the -d option."                                   NL
                                                                             NL
    "  -r   Clean thoroughly. This assumes that the Apache web server is "   NL
    "       not running. This option is mutually exclusive with the -d"      NL
    "       option and implies -t."                                          NL
                                                                             NL
    "  -n   Be nice. This causes slower processing in favour of other"       NL
    "       processes."                                                      NL
                                                                             NL
    "  -t   Delete all empty directories. By default only cache files are"   NL
    "       removed, however with some configurations the large number of"   NL
    "       directories created may require attention."                      NL
                                                                             NL
    "  -p   Specify PATH as the root directory of the disk cache."           NL
                                                                             NL
    "  -l   Specify LIMIT as the total disk cache size limit. Attach 'K'"    NL
    "       or 'M' to the number for specifying KBytes or MBytes."           NL
                                                                             NL
    "  -i   Be intelligent and run only when there was a modification of"    NL
    "       the disk cache. This option is only possible together with the"  NL
    "       -d option."                                                      NL,
    shortname,
    shortname,
    shortname
    );

    exit(1);
}
#undef NL

/*
 * main
 */
int main(int argc, const char * const argv[])
{
    apr_off_t max;
    apr_time_t current, repeat, delay, previous;
    apr_status_t status;
    apr_pool_t *pool, *instance;
    apr_getopt_t *o;
    apr_finfo_t info;
    int retries, isdaemon, limit_found, intelligent, dowork;
    char opt;
    const char *arg;
    char *proxypath, *path;

    interrupted = 0;
    repeat = 0;
    isdaemon = 0;
    dryrun = 0;
    limit_found = 0;
    max = 0;
    verbose = 0;
    realclean = 0;
    benice = 0;
    deldirs = 0;
    intelligent = 0;
    previous = 0; /* avoid compiler warning */
    proxypath = NULL;

    if (apr_app_initialize(&argc, &argv, NULL) != APR_SUCCESS) {
        return 1;
    }
    atexit(apr_terminate);

    if (argc) {
        shortname = apr_filepath_name_get(argv[0]);
    }

    if (apr_pool_create(&pool, NULL) != APR_SUCCESS) {
        return 1;
    }
    apr_pool_abort_set(oom, pool);
    apr_file_open_stderr(&errfile, pool);
    apr_signal(SIGINT, setterm);
    apr_signal(SIGTERM, setterm);

    apr_getopt_init(&o, pool, argc, argv);

    while (1) {
        status = apr_getopt(o, "iDnvrtd:l:L:p:", &opt, &arg);
        if (status == APR_EOF) {
            break;
        }
        else if (status != APR_SUCCESS) {
            usage();
        }
        else {
            switch (opt) {
            case 'i':
                if (intelligent) {
                    usage();
                }
                intelligent = 1;
                break;

            case 'D':
                if (dryrun) {
                    usage();
                }
                dryrun = 1;
                break;

            case 'n':
                if (benice) {
                    usage();
                }
                benice = 1;
                break;

            case 't':
                if (deldirs) {
                    usage();
                }
                deldirs = 1;
                break;

            case 'v':
                if (verbose) {
                    usage();
                }
                verbose = 1;
                break;

            case 'r':
                if (realclean) {
                    usage();
                }
                realclean = 1;
                deldirs = 1;
                break;

            case 'd':
                if (isdaemon) {
                    usage();
                }
                isdaemon = 1;
                repeat = apr_atoi64(arg);
                repeat *= SECS_PER_MIN;
                repeat *= APR_USEC_PER_SEC;
                break;

            case 'l':
                if (limit_found) {
                    usage();
                }
                limit_found = 1;

                do {
                    apr_status_t rv;
                    char *end;

                    rv = apr_strtoff(&max, arg, &end, 10);
                    if (rv == APR_SUCCESS) {
                        if ((*end == 'K' || *end == 'k') && !end[1]) {
                            max *= KBYTE;
                        }
                        else if ((*end == 'M' || *end == 'm') && !end[1]) {
                            max *= MBYTE;
                        }
                        else if ((*end == 'G' || *end == 'g') && !end[1]) {
                            max *= GBYTE;
                        }
                        else if (*end &&        /* neither empty nor [Bb] */
                                 ((*end != 'B' && *end != 'b') || end[1])) {
                            rv = APR_EGENERAL;
                        }
                    }
                    if (rv != APR_SUCCESS) {
                        apr_file_printf(errfile, "Invalid limit: %s"
                                                 APR_EOL_STR APR_EOL_STR, arg);
                        usage();
                    }
                } while(0);
                break;

            case 'p':
                if (proxypath) {
                    usage();
                }
                proxypath = apr_pstrdup(pool, arg);
                if (apr_filepath_set(proxypath, pool) != APR_SUCCESS) {
                    usage();
                }
                break;
            } /* switch */
        } /* else */
    } /* while */

    if (o->ind != argc) {
         usage();
    }

    if (isdaemon && (repeat <= 0 || verbose || realclean || dryrun)) {
         usage();
    }

    if (!isdaemon && intelligent) {
         usage();
    }

    if (!proxypath || max <= 0) {
         usage();
    }

    if (apr_filepath_get(&path, 0, pool) != APR_SUCCESS) {
        usage();
    }
    baselen = strlen(path);

#ifndef DEBUG
    if (isdaemon) {
        apr_file_close(errfile);
        apr_proc_detach(APR_PROC_DETACH_DAEMONIZE);
    }
#endif

    do {
        apr_pool_create(&instance, pool);

        now = apr_time_now();
        APR_RING_INIT(&root, _entry, link);
        delcount = 0;
        unsolicited = 0;
        dowork = 0;

        switch (intelligent) {
        case 0:
            dowork = 1;
            break;

        case 1:
            retries = STAT_ATTEMPTS;
            status = APR_SUCCESS;

            do {
                if (status != APR_SUCCESS) {
                    apr_sleep(STAT_DELAY);
                }
                status = apr_stat(&info, path, APR_FINFO_MTIME, instance);
            } while (status != APR_SUCCESS && !interrupted && --retries);

            if (status == APR_SUCCESS) {
                previous = info.mtime;
                intelligent = 2;
            }
            dowork = 1;
            break;

        case 2:
            retries = STAT_ATTEMPTS;
            status = APR_SUCCESS;

            do {
                if (status != APR_SUCCESS) {
                    apr_sleep(STAT_DELAY);
                }
                status = apr_stat(&info, path, APR_FINFO_MTIME, instance);
            } while (status != APR_SUCCESS && !interrupted && --retries);

            if (status == APR_SUCCESS) {
                if (previous != info.mtime) {
                    dowork = 1;
                }
                previous = info.mtime;
                break;
            }
            intelligent = 1;
            dowork = 1;
            break;
        }

        if (dowork && !interrupted) {
            if (!process_dir(path, instance) && !interrupted) {
                purge(path, instance, max);
            }
            else if (!isdaemon && !interrupted) {
                apr_file_printf(errfile, "An error occurred, cache cleaning "
                                         "aborted." APR_EOL_STR);
                return 1;
            }

            if (intelligent && !interrupted) {
                retries = STAT_ATTEMPTS;
                status = APR_SUCCESS;
                do {
                    if (status != APR_SUCCESS) {
                        apr_sleep(STAT_DELAY);
                    }
                    status = apr_stat(&info, path, APR_FINFO_MTIME, instance);
                } while (status != APR_SUCCESS && !interrupted && --retries);

                if (status == APR_SUCCESS) {
                    previous = info.mtime;
                    intelligent = 2;
                }
                else {
                    intelligent = 1;
                }
            }
        }

        apr_pool_destroy(instance);

        current = apr_time_now();
        if (current < now) {
            delay = repeat;
        }
        else if (current - now >= repeat) {
            delay = repeat;
        }
        else {
            delay = now + repeat - current;
        }

        /* we can't sleep the whole delay time here apiece as this is racy
         * with respect to interrupt delivery - think about what happens
         * if we have tested for an interrupt, then get scheduled
         * before the apr_sleep() call and while waiting for the cpu
         * we do get an interrupt
         */
        if (isdaemon) {
            while (delay && !interrupted) {
                if (delay > APR_USEC_PER_SEC) {
                    apr_sleep(APR_USEC_PER_SEC);
                    delay -= APR_USEC_PER_SEC;
                }
                else {
                    apr_sleep(delay);
                    delay = 0;
                }
            }
        }
    } while (isdaemon && !interrupted);

    if (!isdaemon && interrupted) {
        apr_file_printf(errfile, "Cache cleaning aborted due to user "
                                 "request." APR_EOL_STR);
        return 1;
    }

    return 0;
}
