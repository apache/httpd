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
#include "apr_md5.h"
#include "apr_ring.h"
#include "apr_date.h"
#include "apr_buckets.h"

#include "../modules/cache/cache_common.h"
#include "../modules/cache/cache_disk_common.h"

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
static int listurls;    /* flag: true means list cached urls */
static int listextended;/* flag: true means list cached urls */
static int baselen;     /* string length of the path to the proxy directory */
static apr_time_t now;  /* start time of this processing run */

static apr_file_t *errfile;   /* stderr file handle */
static apr_file_t *outfile;   /* stdout file handle */
static apr_off_t unsolicited; /* file size summary for deleted unsolicited
                                 files */
static ENTRY root; /* ENTRY ring anchor */

/* short program name as called */
static const char *shortname = "htcacheclean";

/* what did we clean? */
struct stats {
    apr_off_t total;
    apr_off_t sum;
    apr_off_t max;
    apr_off_t ntotal;
    apr_off_t nodes;
    apr_off_t inodes;
    apr_off_t etotal;
    apr_off_t entries;
    apr_off_t dfuture;
    apr_off_t dexpired;
    apr_off_t dfresh;
};


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
static void printstats(char *path, struct stats *s)
{
    char ttype, stype, mtype, utype;
    apr_off_t tfrag, sfrag, ufrag;

    if (!verbose) {
        return;
    }

    ttype = 'K';
    tfrag = ((s->total * 10) / KBYTE) % 10;
    s->total /= KBYTE;
    if (s->total >= KBYTE) {
        ttype = 'M';
        tfrag = ((s->total * 10) / KBYTE) % 10;
        s->total /= KBYTE;
    }

    stype = 'K';
    sfrag = ((s->sum * 10) / KBYTE) % 10;
    s->sum /= KBYTE;
    if (s->sum >= KBYTE) {
        stype = 'M';
        sfrag = ((s->sum * 10) / KBYTE) % 10;
        s->sum /= KBYTE;
    }

    mtype = 'K';
    s->max /= KBYTE;
    if (s->max >= KBYTE) {
        mtype = 'M';
        s->max /= KBYTE;
    }

    apr_file_printf(errfile, "Cleaned %s. Statistics:" APR_EOL_STR, path);
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
    apr_file_printf(errfile, "size limit %" APR_OFF_T_FMT ".0%c" APR_EOL_STR,
            s->max, mtype);
    apr_file_printf(errfile, "inodes limit %" APR_OFF_T_FMT APR_EOL_STR,
            s->inodes);
    apr_file_printf(
            errfile,
            "total size was %" APR_OFF_T_FMT ".%" APR_OFF_T_FMT "%c, total size now "
            "%" APR_OFF_T_FMT ".%" APR_OFF_T_FMT "%c" APR_EOL_STR, s->total,
            tfrag, ttype, s->sum, sfrag, stype);
    apr_file_printf(errfile, "total inodes was %" APR_OFF_T_FMT
            ", total %sinodes now "
            "%" APR_OFF_T_FMT APR_EOL_STR, s->ntotal, dryrun && deldirs ? "estimated "
            : "", s->nodes);
    apr_file_printf(
            errfile,
            "total entries was %" APR_OFF_T_FMT ", total entries now %" APR_OFF_T_FMT
            APR_EOL_STR, s->etotal, s->entries);
    apr_file_printf(
            errfile,
            "%" APR_OFF_T_FMT " entries deleted (%" APR_OFF_T_FMT " from future, %"
            APR_OFF_T_FMT " expired, %" APR_OFF_T_FMT " fresh)" APR_EOL_STR,
            (s->etotal - s->entries), s->dfuture, s->dexpired, s->dfresh);
}

/**
 * Round the value up to the given threshold.
 */
static apr_size_t round_up(apr_size_t val, apr_off_t round)
{
    if (round > 1) {
        return (apr_size_t)(((val + round - 1) / round) * round);
    }
    return val;
}

/*
 * delete parent directories
 */
static void delete_parent(const char *path, const char *basename,
        apr_off_t *nodes, apr_pool_t *pool)
{
    char *nextpath, *name;
    apr_pool_t *p;

    /* temp pool, otherwise lots of memory could be allocated */
    apr_pool_create(&p, pool);
    name = apr_pstrdup(p, basename);

    /* If asked to delete dirs, do so now. We don't care if it fails.
     * If it fails, it likely means there was something else there.
     */
    if (deldirs && !dryrun) {
        const char *vary;
        char *end = strrchr(name, '/');
        while (end) {
            *end = 0;

            /* remove the directory */
            nextpath = apr_pstrcat(p, path, "/", name, NULL);
            if (!apr_dir_remove(nextpath, p)) {
                (*nodes)--;

                /* vary directory found? */
                vary = strstr(name, CACHE_VDIR_SUFFIX);
                if (vary && !vary[sizeof(CACHE_VDIR_SUFFIX) - 1]) {
                    nextpath = apr_pstrcat(p, path, "/", apr_pstrndup(p, name, vary
                            - name), NULL);
                    if (!apr_file_remove(nextpath, p)) {
                        (*nodes)--;
                    }
                }

            }
            else {
                break;
            }
            end = strrchr(name, '/');
        }
    }

    apr_pool_destroy(p);

    if (benice) {
        if (++delcount >= DELETE_NICE) {
            apr_sleep(NICE_DELAY);
            delcount = 0;
        }
    }

}

/*
 * delete a single file
 */
static void delete_file(char *path, char *basename, apr_off_t *nodes,
        apr_pool_t *pool)
{
    char *nextpath;
    apr_pool_t *p;

    /* temp pool, otherwise lots of memory could be allocated */
    apr_pool_create(&p, pool);
    nextpath = apr_pstrcat(p, path, "/", basename, NULL);

    if (dryrun) {
        apr_finfo_t finfo;
        if (!apr_stat(&finfo, nextpath, APR_FINFO_NLINK, p)) {
            (*nodes)--;
        }
    }
    else if (!apr_file_remove(nextpath, p)) {
        (*nodes)--;
    }

    apr_pool_destroy(p);

    if (benice) {
        if (++delcount >= DELETE_NICE) {
            apr_sleep(NICE_DELAY);
            delcount = 0;
        }
    }

    delete_parent(path, basename, nodes, pool);

}

/*
 * delete cache file set
 */
static void delete_entry(char *path, char *basename, apr_off_t *nodes,
        apr_pool_t *pool)
{
    char *nextpath;
    apr_pool_t *p;

    /* temp pool, otherwise lots of memory could be allocated */
    apr_pool_create(&p, pool);

    nextpath = apr_pstrcat(p, path, "/", basename, CACHE_HEADER_SUFFIX, NULL);
    if (dryrun) {
        apr_finfo_t finfo;
        if (!apr_stat(&finfo, nextpath, APR_FINFO_NLINK, p)) {
            (*nodes)--;
        }
    }
    else if (!apr_file_remove(nextpath, p)) {
        (*nodes)--;
    }

    nextpath = apr_pstrcat(p, path, "/", basename, CACHE_DATA_SUFFIX, NULL);
    if (dryrun) {
        apr_finfo_t finfo;
        if (!apr_stat(&finfo, nextpath, APR_FINFO_NLINK, p)) {
            (*nodes)--;
        }
    }
    else if (!apr_file_remove(nextpath, p)) {
        (*nodes)--;
    }

    apr_pool_destroy(p);

    if (benice) {
        delcount += 2;
        if (delcount >= DELETE_NICE) {
            apr_sleep(NICE_DELAY);
            delcount = 0;
        }
    }

    delete_parent(path, basename, nodes, pool);

}

/*
 * list the cache directory tree
 */
static int list_urls(char *path, apr_pool_t *pool, apr_off_t round)
{
    apr_dir_t *dir;
    apr_finfo_t info;
    apr_size_t len;
    apr_pool_t *p;
    apr_file_t *fd;
    const char *ext, *nextpath;
    char *url;
    apr_uint32_t format;
    disk_cache_info_t disk_info;

    apr_pool_create(&p, pool);

    if (apr_dir_open(&dir, path, p) != APR_SUCCESS) {
        return 1;
    }

    while (apr_dir_read(&info, APR_FINFO_TYPE, dir) == APR_SUCCESS && !interrupted) {

        if (info.filetype == APR_DIR) {
            if (!strcmp(info.name, ".") || !strcmp(info.name, "..")) {
                continue;
            }

            if (list_urls(apr_pstrcat(p, path, "/", info.name, NULL), pool, round)) {
                return 1;
            }
        }

        else if (info.filetype == APR_REG) {

            ext = strchr(info.name, '.');

            if (ext && !strcasecmp(ext, CACHE_HEADER_SUFFIX)) {

                nextpath = apr_pstrcat(p, path, "/", info.name, NULL);

                if (apr_file_open(&fd, nextpath, APR_FOPEN_READ
                        | APR_FOPEN_BINARY, APR_OS_DEFAULT, p) == APR_SUCCESS) {
                    len = sizeof(format);
                    if (apr_file_read_full(fd, &format, len, &len)
                            == APR_SUCCESS) {
                        if (format == DISK_FORMAT_VERSION) {
                            apr_off_t offset = 0;

                            apr_file_seek(fd, APR_SET, &offset);

                            len = sizeof(disk_cache_info_t);

                            if (apr_file_read_full(fd, &disk_info, len, &len)
                                    == APR_SUCCESS) {
                                len = disk_info.name_len;
                                url = apr_palloc(p, len + 1);
                                url[len] = 0;

                                if (apr_file_read_full(fd, url, len, &len)
                                        == APR_SUCCESS) {

                                    if (listextended) {
                                        apr_finfo_t hinfo, dinfo;

                                        /* stat the header file */
                                        if (APR_SUCCESS != apr_file_info_get(
                                                &hinfo, APR_FINFO_SIZE, fd)) {
                                            /* ignore the file */
                                        }
                                        else if (disk_info.has_body && APR_SUCCESS
                                                != apr_stat(
                                                        &dinfo,
                                                        apr_pstrcat(
                                                                p,
                                                                path,
                                                                "/",
                                                                apr_pstrndup(
                                                                        p,
                                                                        info.name,
                                                                        ext
                                                                                - info.name),
                                                                CACHE_DATA_SUFFIX,
                                                                NULL),
                                                        APR_FINFO_SIZE
                                                                | APR_FINFO_IDENT,
                                                        p)) {
                                            /* ignore the file */
                                        }
                                        else if (disk_info.has_body && (dinfo.device
                                                != disk_info.device
                                                || dinfo.inode
                                                        != disk_info.inode)) {
                                            /* ignore the file */
                                        }
                                        else {

                                            apr_file_printf(
                                                    outfile,
                                                    "%s %" APR_SIZE_T_FMT
                                                    " %" APR_SIZE_T_FMT
                                                    " %d %" APR_SIZE_T_FMT
                                                    " %" APR_TIME_T_FMT
                                                    " %" APR_TIME_T_FMT
                                                    " %" APR_TIME_T_FMT
                                                    " %" APR_TIME_T_FMT
                                                    " %d %d\n",
                                                    url,
                                                    round_up((apr_size_t)hinfo.size, round),
                                                    round_up(
                                                            disk_info.has_body ? (apr_size_t)dinfo.size
                                                                    : 0, round),
                                                    disk_info.status,
                                                    disk_info.entity_version,
                                                    disk_info.date,
                                                    disk_info.expire,
                                                    disk_info.request_time,
                                                    disk_info.response_time,
                                                    disk_info.has_body,
                                                    disk_info.header_only);
                                        }
                                    }
                                    else {
                                        apr_finfo_t dinfo;

                                        /* stat the data file */
                                        if (disk_info.has_body && APR_SUCCESS
                                                != apr_stat(
                                                        &dinfo,
                                                        apr_pstrcat(
                                                                p,
                                                                path,
                                                                "/",
                                                                apr_pstrndup(
                                                                        p,
                                                                        info.name,
                                                                        ext
                                                                                - info.name),
                                                                CACHE_DATA_SUFFIX,
                                                                NULL),
                                                        APR_FINFO_SIZE
                                                                | APR_FINFO_IDENT,
                                                        p)) {
                                            /* ignore the file */
                                        }
                                        else if (disk_info.has_body && (dinfo.device
                                                != disk_info.device
                                                || dinfo.inode
                                                        != disk_info.inode)) {
                                            /* ignore the file */
                                        }
                                        else {
                                            apr_file_printf(outfile, "%s\n",
                                                    url);
                                        }
                                    }
                                }

                                break;
                            }
                        }
                    }
                    apr_file_close(fd);

                }
            }
        }

    }

    apr_dir_close(dir);

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
 * walk the cache directory tree
 */
static int process_dir(char *path, apr_pool_t *pool, apr_off_t *nodes)
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
    char *nextpath, *base, *ext;
    DIRENTRY *d, *t, *n, anchor;
    ENTRY *e;
    int skip, retries;
    disk_cache_info_t disk_info;

    APR_RING_INIT(&anchor.link, _direntry, link);
    apr_pool_create(&p, pool);
    h = apr_hash_make(p);
    fd = NULL;
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
        APR_RING_INSERT_TAIL(&anchor.link, d, _direntry, link);
        (*nodes)++;
    }

    apr_dir_close(dir);

    if (interrupted) {
        return 1;
    }

    skip = baselen + 1;

    for (d = APR_RING_FIRST(&anchor.link);
         !interrupted && d != APR_RING_SENTINEL(&anchor.link, _direntry, link);
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

        /* this may look strange but apr_stat() may return an error which
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
            char *dirpath = apr_pstrdup(p, d->basename);

            if (process_dir(d->basename, pool, nodes)) {
                return 1;
            }
            /* When given the -t option htcacheclean does not
             * delete directories that are already empty, so we'll do that here
             * since process_dir checks all the directories.
             * If it fails, it likely means there was something else there.
             */
            if (deldirs && !dryrun) {
                apr_dir_remove(dirpath, p);
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
                            APR_RING_INSERT_TAIL(&root.link, e, _entry, link);
                            e->expire = disk_info.expire;
                            e->response_time = disk_info.response_time;
                            e->htime = d->htime;
                            e->dtime = d->dtime;
                            e->hsize = d->hsize;
                            e->dsize = d->dsize;
                            e->basename = apr_pstrdup(pool, d->basename);
                            if (!disk_info.has_body) {
                                delete_file(path, apr_pstrcat(p, path, "/",
                                        d->basename, CACHE_DATA_SUFFIX, NULL),
                                        nodes, p);
                            }
                            break;
                        }
                        else {
                            apr_file_close(fd);
                        }
                    }
                    else if (format == VARY_FORMAT_VERSION) {
                        apr_finfo_t finfo;

                        /* This must be a URL that added Vary headers later,
                         * so kill the orphaned .data file
                         */
                        apr_file_close(fd);

                        if (apr_stat(&finfo, apr_pstrcat(p, nextpath,
                                CACHE_VDIR_SUFFIX, NULL), APR_FINFO_TYPE, p)
                                || finfo.filetype != APR_DIR) {
                            delete_entry(path, d->basename, nodes, p);
                        }
                        else {
                            delete_file(path, apr_pstrcat(p, path, "/",
                                    d->basename, CACHE_DATA_SUFFIX, NULL),
                                    nodes, p);
                        }
                        break;
                    }
                    else {
                        /* We didn't recognise the format, kill the files */
                        apr_file_close(fd);
                        delete_entry(path, d->basename, nodes, p);
                        break;
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
                delete_entry(path, d->basename, nodes, p);
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

                        if (apr_file_read_full(fd, &expires, len,
                                               &len) == APR_SUCCESS) {
                            apr_finfo_t finfo;

                            apr_file_close(fd);

                            if (apr_stat(&finfo, apr_pstrcat(p, nextpath,
                                    CACHE_VDIR_SUFFIX, NULL), APR_FINFO_TYPE, p)
                                    || finfo.filetype != APR_DIR) {
                                delete_entry(path, d->basename, nodes, p);
                            }
                            else if (expires < current) {
                                delete_entry(path, d->basename, nodes, p);
                            }

                            break;
                        }
                    }
                    else if (format == DISK_FORMAT_VERSION) {
                        apr_off_t offset = 0;

                        apr_file_seek(fd, APR_SET, &offset);

                        len = sizeof(disk_cache_info_t);

                        if (apr_file_read_full(fd, &disk_info, len,
                                               &len) == APR_SUCCESS) {
                            apr_file_close(fd);
                            e = apr_palloc(pool, sizeof(ENTRY));
                            APR_RING_INSERT_TAIL(&root.link, e, _entry, link);
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
                    else {
                        apr_file_close(fd);
                        delete_entry(path, d->basename, nodes, p);
                        break;
                    }
                }
                else {
                    apr_file_close(fd);
                }
            }

            if (realclean || d->htime < current - deviation
                || d->htime > current + deviation) {
                delete_entry(path, d->basename, nodes, p);
                unsolicited += d->hsize;
            }
            break;

        case DATA:
            current = apr_time_now();
            if (realclean || d->dtime < current - deviation
                || d->dtime > current + deviation) {
                delete_entry(path, d->basename, nodes, p);
                unsolicited += d->dsize;
            }
            break;

        /* temp files may only be deleted in realclean mode which
         * is asserted above if a tempfile is in the hash array
         */
        case TEMP:
            delete_file(path, d->basename, nodes, p);
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
static void purge(char *path, apr_pool_t *pool, apr_off_t max,
        apr_off_t inodes, apr_off_t nodes, apr_off_t round)
{
    ENTRY *e, *n, *oldest;

    struct stats s;
    s.sum = 0;
    s.entries = 0;
    s.dfuture = 0;
    s.dexpired = 0;
    s.dfresh = 0;
    s.max = max;
    s.nodes = nodes;
    s.inodes = inodes;
    s.ntotal = nodes;

    for (e = APR_RING_FIRST(&root.link);
         e != APR_RING_SENTINEL(&root.link, _entry, link);
         e = APR_RING_NEXT(e, link)) {
        s.sum += round_up((apr_size_t)e->hsize, round);
        s.sum += round_up((apr_size_t)e->dsize, round);
        s.entries++;
    }

    s.total = s.sum;
    s.etotal = s.entries;

    if ((!s.max || s.sum <= s.max) && (!s.inodes || s.nodes <= s.inodes)) {
        printstats(path, &s);
        return;
    }

    /* process all entries with a timestamp in the future, this may
     * happen if a wrong system time is corrected
     */

    for (e = APR_RING_FIRST(&root.link);
         e != APR_RING_SENTINEL(&root.link, _entry, link) && !interrupted;) {
        n = APR_RING_NEXT(e, link);
        if (e->response_time > now || e->htime > now || e->dtime > now) {
            delete_entry(path, e->basename, &s.nodes, pool);
            s.sum -= round_up((apr_size_t)e->hsize, round);
            s.sum -= round_up((apr_size_t)e->dsize, round);
            s.entries--;
            s.dfuture++;
            APR_RING_REMOVE(e, link);
            if ((!s.max || s.sum <= s.max) && (!s.inodes || s.nodes <= s.inodes)) {
                if (!interrupted) {
                    printstats(path, &s);
                }
                return;
            }
        }
        e = n;
    }

    if (interrupted) {
        return;
    }

    /* process all entries which are expired */
    for (e = APR_RING_FIRST(&root.link);
         e != APR_RING_SENTINEL(&root.link, _entry, link) && !interrupted;) {
        n = APR_RING_NEXT(e, link);
        if (e->expire != APR_DATE_BAD && e->expire < now) {
            delete_entry(path, e->basename, &s.nodes, pool);
            s.sum -= round_up((apr_size_t)e->hsize, round);
            s.sum -= round_up((apr_size_t)e->dsize, round);
            s.entries--;
            s.dexpired++;
            APR_RING_REMOVE(e, link);
            if ((!s.max || s.sum <= s.max) && (!s.inodes || s.nodes <= s.inodes)) {
                if (!interrupted) {
                    printstats(path, &s);
                }
                return;
            }
        }
        e = n;
    }

    if (interrupted) {
         return;
    }

    /* process remaining entries oldest to newest, the check for an empty
     * ring actually isn't necessary except when the compiler does
     * corrupt 64bit arithmetics which happened to me once, so better safe
     * than sorry
     */
    while (!((!s.max || s.sum <= s.max) && (!s.inodes || s.nodes <= s.inodes))
            && !interrupted && !APR_RING_EMPTY(&root.link, _entry, link)) {
        oldest = APR_RING_FIRST(&root.link);

        for (e = APR_RING_NEXT(oldest, link);
             e != APR_RING_SENTINEL(&root.link, _entry, link);
             e = APR_RING_NEXT(e, link)) {
            if (e->dtime < oldest->dtime) {
                oldest = e;
            }
        }

        delete_entry(path, oldest->basename, &s.nodes, pool);
        s.sum -= round_up((apr_size_t)oldest->hsize, round);
        s.sum -= round_up((apr_size_t)oldest->dsize, round);
        s.entries--;
        s.dfresh++;
        APR_RING_REMOVE(oldest, link);
    }

    if (!interrupted) {
        printstats(path, &s);
    }
}

static apr_status_t remove_directory(apr_pool_t *pool, const char *dir)
{
    apr_status_t rv;
    apr_dir_t *dirp;
    apr_finfo_t dirent;

    rv = apr_dir_open(&dirp, dir, pool);
    if (APR_STATUS_IS_ENOENT(rv)) {
        return rv;
    }
    if (rv != APR_SUCCESS) {
        apr_file_printf(errfile, "Could not open directory %s: %pm" APR_EOL_STR,
                dir, &rv);
        return rv;
    }

    while (apr_dir_read(&dirent, APR_FINFO_DIRENT | APR_FINFO_TYPE, dirp)
            == APR_SUCCESS) {
        if (dirent.filetype == APR_DIR) {
            if (strcmp(dirent.name, ".") && strcmp(dirent.name, "..")) {
                rv = remove_directory(pool, apr_pstrcat(pool, dir, "/",
                        dirent.name, NULL));
                /* tolerate the directory not being empty, the cache may have
                 * attempted to recreate the directory in the mean time.
                 */
                if (APR_SUCCESS != rv && APR_ENOTEMPTY != rv) {
                    break;
                }
            }
        } else {
            const char *file = apr_pstrcat(pool, dir, "/", dirent.name, NULL);
            rv = apr_file_remove(file, pool);
            if (APR_SUCCESS != rv) {
                apr_file_printf(errfile,
                        "Could not remove file '%s': %pm" APR_EOL_STR, file,
                        &rv);
                break;
            }
        }
    }

    apr_dir_close(dirp);

    if (rv == APR_SUCCESS) {
        rv = apr_dir_remove(dir, pool);
        if (APR_ENOTEMPTY == rv) {
            rv = APR_SUCCESS;
        }
        if (rv != APR_SUCCESS) {
            apr_file_printf(errfile, "Could not remove directory %s: %pm" APR_EOL_STR,
                    dir, &rv);
        }
    }

    return rv;
}

static apr_status_t find_directory(apr_pool_t *pool, const char *base,
        const char *rest)
{
    apr_status_t rv;
    apr_dir_t *dirp;
    apr_finfo_t dirent;
    int found = 0, files = 0;
    const char *header = apr_pstrcat(pool, rest, CACHE_HEADER_SUFFIX, NULL);
    const char *data = apr_pstrcat(pool, rest, CACHE_DATA_SUFFIX, NULL);
    const char *vdir = apr_pstrcat(pool, rest, CACHE_HEADER_SUFFIX,
            CACHE_VDIR_SUFFIX, NULL);
    const char *dirname = NULL;

    rv = apr_dir_open(&dirp, base, pool);
    if (rv != APR_SUCCESS) {
        apr_file_printf(errfile, "Could not open directory %s: %pm" APR_EOL_STR,
                base, &rv);
        return rv;
    }

    rv = APR_ENOENT;

    while (apr_dir_read(&dirent, APR_FINFO_DIRENT | APR_FINFO_TYPE, dirp)
            == APR_SUCCESS) {
        int len = strlen(dirent.name);
        int restlen = strlen(rest);
        if (dirent.filetype == APR_DIR && !strncmp(rest, dirent.name, len)) {
            dirname = apr_pstrcat(pool, base, "/", dirent.name, NULL);
            rv = find_directory(pool, dirname, rest + (len < restlen ? len
                    : restlen));
            if (APR_SUCCESS == rv) {
                found = 1;
            }
        }
        if (dirent.filetype == APR_DIR) {
            if (!strcmp(dirent.name, vdir)) {
                files = 1;
            }
        }
        if (dirent.filetype == APR_REG) {
            if (!strcmp(dirent.name, header) || !strcmp(dirent.name, data)) {
                files = 1;
            }
        }
    }

    apr_dir_close(dirp);

    if (files) {
        rv = APR_SUCCESS;
        if (!dryrun) {
            const char *remove;
            apr_status_t status;

            remove = apr_pstrcat(pool, base, "/", header, NULL);
            status = apr_file_remove(remove, pool);
            if (status != APR_SUCCESS && !APR_STATUS_IS_ENOENT(status)) {
                apr_file_printf(errfile, "Could not remove file %s: %pm" APR_EOL_STR,
                        remove, &status);
                rv = status;
            }

            remove = apr_pstrcat(pool, base, "/", data, NULL);
            status = apr_file_remove(remove, pool);
            if (status != APR_SUCCESS && !APR_STATUS_IS_ENOENT(status)) {
                apr_file_printf(errfile, "Could not remove file %s: %pm" APR_EOL_STR,
                        remove, &status);
                rv = status;
            }

            status = remove_directory(pool, apr_pstrcat(pool, base, "/", vdir, NULL));
            if (status != APR_SUCCESS && !APR_STATUS_IS_ENOENT(status)) {
                rv = status;
            }
        }
    }

    /* If asked to delete dirs, do so now. We don't care if it fails.
     * If it fails, it likely means there was something else there.
     */
    if (dirname && deldirs && !dryrun) {
        apr_dir_remove(dirname, pool);
    }

    if (found) {
        return APR_SUCCESS;
    }

    return rv;
}

/**
 * Delete a specific URL from the cache.
 */
static apr_status_t delete_url(apr_pool_t *pool, const char *proxypath, const char *url)
{
    apr_md5_ctx_t context;
    unsigned char digest[16];
    char tmp[23];
    int i, k;
    unsigned int x;
    static const char enc_table[64] =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_@";

    apr_md5_init(&context);
    apr_md5_update(&context, (const unsigned char *) url, strlen(url));
    apr_md5_final(digest, &context);

    /* encode 128 bits as 22 characters, using a modified uuencoding
     * the encoding is 3 bytes -> 4 characters* i.e. 128 bits is
     * 5 x 3 bytes + 1 byte -> 5 * 4 characters + 2 characters
     */
    for (i = 0, k = 0; i < 15; i += 3) {
        x = (digest[i] << 16) | (digest[i + 1] << 8) | digest[i + 2];
        tmp[k++] = enc_table[x >> 18];
        tmp[k++] = enc_table[(x >> 12) & 0x3f];
        tmp[k++] = enc_table[(x >> 6) & 0x3f];
        tmp[k++] = enc_table[x & 0x3f];
    }

    /* one byte left */
    x = digest[15];
    tmp[k++] = enc_table[x >> 2]; /* use up 6 bits */
    tmp[k++] = enc_table[(x << 4) & 0x3f];
    tmp[k] = 0;

    /* automatically find the directory levels */
    return find_directory(pool, proxypath, tmp);
}

/*
 * usage info
 */
#define NL APR_EOL_STR
static void usage(const char *error)
{
    if (error) {
        apr_file_printf(errfile, "%s error: %s\n", shortname, error);
    }
    apr_file_printf(errfile,
    "%s -- program for cleaning the disk cache."                             NL
    "Usage: %s [-Dvtrn] -pPATH [-lLIMIT] [-LLIMIT] [-PPIDFILE]"              NL
    "       %s [-nti] -dINTERVAL -pPATH [-lLIMIT] [-LLIMIT] [-PPIDFILE]"     NL
    "       %s [-Dvt] -pPATH URL ..."                                        NL
                                                                             NL
    "Options:"                                                               NL
    "  -d   Daemonize and repeat cache cleaning every INTERVAL minutes."     NL
    "       This option is mutually exclusive with the -D, -v and -r"        NL
    "       options."                                                        NL
                                                                             NL
    "  -D   Do a dry run and don't delete anything. This option is mutually" NL
    "       exclusive with the -d option. When doing a dry run and deleting" NL
    "       directories with -t, the inodes reported deleted in the stats"   NL
    "       cannot take into account the directories deleted, and will be"   NL
    "       marked as an estimate."                                          NL
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
    "  -P   Specify PIDFILE as the file to write the pid to."                NL
                                                                             NL
    "  -R   Specify amount to round sizes up to."                            NL
                                                                             NL
    "  -l   Specify LIMIT as the total disk cache size limit. Attach 'K',"   NL
    "       'M' or 'G' to the number for specifying KBytes, MBytes or"       NL
    "        GBytes."                                                        NL
                                                                             NL
    "  -L   Specify LIMIT as the total disk cache inode limit. 'K', 'M' or"  NL
    "       'G' suffix can also be used."                                    NL
                                                                             NL
    "  -i   Be intelligent and run only when there was a modification of"    NL
    "       the disk cache. This option is only possible together with the"  NL
    "       -d option."                                                      NL
                                                                             NL
    "  -a   List the URLs currently stored in the cache. Variants of the"    NL
    "       same URL will be listed once for each variant."                  NL
                                                                             NL
    "  -A   List the URLs currently stored in the cache, along with their"   NL
    "       attributes in the following order: url, header size, body size," NL
    "       status, entity version, date, expiry, request time,"             NL
    "       response time, body present, head request."                      NL
                                                                             NL
    "Should an URL be provided on the command line, the URL will be"         NL
    "deleted from the cache. A reverse proxied URL is made up as follows:"   NL
    "http://<hostname>:<port><path>?[query]. So, for the path \"/\" on the"  NL
    "host \"localhost\" and port 80, the URL to delete becomes"              NL
    "\"http://localhost:80/?\". Note the '?' in the URL must always be"      NL
    "specified explicitly, whether a query string is present or not."        NL,
    shortname,
    shortname,
    shortname,
    shortname
    );

    exit(1);
}
#undef NL

static void usage_repeated_arg(apr_pool_t *pool, char option)
{
    usage(apr_psprintf(pool,
                       "The option '%c' cannot be specified more than once",
                       option));
}

static void log_pid(apr_pool_t *pool, const char *pidfilename, apr_file_t **pidfile)
{
    apr_status_t status;
    pid_t mypid = getpid();

    if (APR_SUCCESS == (status = apr_file_open(pidfile, pidfilename,
                APR_FOPEN_WRITE | APR_FOPEN_CREATE | APR_FOPEN_TRUNCATE |
                APR_FOPEN_DELONCLOSE, APR_FPROT_UREAD | APR_FPROT_UWRITE |
                APR_FPROT_GREAD | APR_FPROT_WREAD, pool))) {
        apr_file_printf(*pidfile, "%" APR_PID_T_FMT APR_EOL_STR, mypid);
    }
    else {
        if (errfile) {
            apr_file_printf(errfile,
                            "Could not write the pid file '%s': %pm" APR_EOL_STR,
                            pidfilename, &status);
        }
        exit(1);
    }
}

/*
 * main
 */
int main(int argc, const char * const argv[])
{
    apr_off_t max, inodes, round;
    apr_time_t current, repeat, delay, previous;
    apr_status_t status;
    apr_pool_t *pool, *instance;
    apr_getopt_t *o;
    apr_finfo_t info;
    apr_file_t *pidfile;
    int retries, isdaemon, limit_found, inodes_found, intelligent, dowork;
    char opt;
    const char *arg;
    char *proxypath, *path, *pidfilename;

    interrupted = 0;
    repeat = 0;
    isdaemon = 0;
    dryrun = 0;
    limit_found = 0;
    inodes_found = 0;
    max = 0;
    inodes = 0;
    round = 0;
    verbose = 0;
    realclean = 0;
    benice = 0;
    deldirs = 0;
    intelligent = 0;
    previous = 0; /* avoid compiler warning */
    proxypath = NULL;
    pidfilename = NULL;

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
    apr_file_open_stdout(&outfile, pool);
    apr_signal(SIGINT, setterm);
    apr_signal(SIGTERM, setterm);

    apr_getopt_init(&o, pool, argc, argv);

    while (1) {
        status = apr_getopt(o, "iDnvrtd:l:L:p:P:R:aA", &opt, &arg);
        if (status == APR_EOF) {
            break;
        }
        else if (status != APR_SUCCESS) {
            usage(NULL);
        }
        else {
            char *end;
            apr_status_t rv;
            switch (opt) {
            case 'i':
                if (intelligent) {
                    usage_repeated_arg(pool, opt);
                }
                intelligent = 1;
                break;

            case 'D':
                if (dryrun) {
                    usage_repeated_arg(pool, opt);
                }
                dryrun = 1;
                break;

            case 'n':
                if (benice) {
                    usage_repeated_arg(pool, opt);
                }
                benice = 1;
                break;

            case 't':
                if (deldirs) {
                    usage_repeated_arg(pool, opt);
                }
                deldirs = 1;
                break;

            case 'v':
                if (verbose) {
                    usage_repeated_arg(pool, opt);
                }
                verbose = 1;
                break;

            case 'r':
                if (realclean) {
                    usage_repeated_arg(pool, opt);
                }
                realclean = 1;
                deldirs = 1;
                break;

            case 'd':
                if (isdaemon) {
                    usage_repeated_arg(pool, opt);
                }
                isdaemon = 1;
                repeat = apr_atoi64(arg);
                repeat *= SECS_PER_MIN;
                repeat *= APR_USEC_PER_SEC;
                break;

            case 'l':
                if (limit_found) {
                    usage_repeated_arg(pool, opt);
                }
                limit_found = 1;

                do {
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
                        usage(apr_psprintf(pool, "Invalid limit: %s"
                                                 APR_EOL_STR APR_EOL_STR, arg));
                    }
                } while (0);
                break;

            case 'L':
                if (inodes_found) {
                    usage_repeated_arg(pool, opt);
                }
                inodes_found = 1;

                do {
                    rv = apr_strtoff(&inodes, arg, &end, 10);
                    if (rv == APR_SUCCESS) {
                        if ((*end == 'K' || *end == 'k') && !end[1]) {
                            inodes *= KBYTE;
                        }
                        else if ((*end == 'M' || *end == 'm') && !end[1]) {
                            inodes *= MBYTE;
                        }
                        else if ((*end == 'G' || *end == 'g') && !end[1]) {
                            inodes *= GBYTE;
                        }
                        else if (*end &&        /* neither empty nor [Bb] */
                                 ((*end != 'B' && *end != 'b') || end[1])) {
                            rv = APR_EGENERAL;
                        }
                    }
                    if (rv != APR_SUCCESS) {
                        usage(apr_psprintf(pool, "Invalid limit: %s"
                                                 APR_EOL_STR APR_EOL_STR, arg));
                    }
                } while (0);
                break;

            case 'a':
                if (listurls) {
                    usage_repeated_arg(pool, opt);
                }
                listurls = 1;
                break;

            case 'A':
                if (listurls) {
                    usage_repeated_arg(pool, opt);
                }
                listurls = 1;
                listextended = 1;
                break;

            case 'p':
                if (proxypath) {
                    usage_repeated_arg(pool, opt);
                }
                proxypath = apr_pstrdup(pool, arg);
                if ((status = apr_filepath_set(proxypath, pool)) != APR_SUCCESS) {
                    usage(apr_psprintf(pool, "Could not set filepath to '%s': %pm",
                                       proxypath, &status));
                }
                break;

            case 'P':
                if (pidfilename) {
                    usage_repeated_arg(pool, opt);
                }
                pidfilename = apr_pstrdup(pool, arg);
                break;

            case 'R':
                if (round) {
                    usage_repeated_arg(pool, opt);
                }
                rv = apr_strtoff(&round, arg, &end, 10);
                if (rv == APR_SUCCESS) {
                    if (*end) {
                        usage(apr_psprintf(pool, "Invalid round value: %s"
                                                 APR_EOL_STR APR_EOL_STR, arg));
                    }
                    else if (round < 0) {
                        usage(apr_psprintf(pool, "Round value must be positive: %s"
                                                 APR_EOL_STR APR_EOL_STR, arg));
                    }
                }
                if (rv != APR_SUCCESS) {
                    usage(apr_psprintf(pool, "Invalid round value: %s"
                                             APR_EOL_STR APR_EOL_STR, arg));
                }
                break;

            } /* switch */
        } /* else */
    } /* while */

    if (argc <= 1) {
        usage(NULL);
    }

    if (!proxypath) {
         usage("Option -p must be specified");
    }

    if (o->ind < argc) {
        int deleted = 0;
        int error = 0;
        if (isdaemon) {
            usage("Option -d cannot be used with URL arguments, aborting");
        }
        if (intelligent) {
            usage("Option -i cannot be used with URL arguments, aborting");
        }
        if (limit_found) {
            usage("Option -l and -L cannot be used with URL arguments, aborting");
        }
        while (o->ind < argc) {
            status = delete_url(pool, proxypath, argv[o->ind]);
            if (APR_SUCCESS == status) {
                if (verbose) {
                    apr_file_printf(errfile, "Removed: %s" APR_EOL_STR,
                            argv[o->ind]);
                }
                deleted = 1;
            }
            else if (APR_ENOENT == status) {
                if (verbose) {
                    apr_file_printf(errfile, "Not cached: %s" APR_EOL_STR,
                            argv[o->ind]);
                }
            }
            else {
                if (verbose) {
                    apr_file_printf(errfile, "Error while removed: %s" APR_EOL_STR,
                            argv[o->ind]);
                }
                error = 1;
            }
            o->ind++;
        }
        return error ? 1 : deleted ? 0 : 2;
    }

    if (isdaemon && repeat <= 0) {
         usage("Option -d must be greater than zero");
    }

    if (isdaemon && (verbose || realclean || dryrun || listurls)) {
         usage("Option -d cannot be used with -v, -r, -L or -D");
    }

    if (!isdaemon && intelligent) {
         usage("Option -i cannot be used without -d");
    }

    if (!listurls && max <= 0 && inodes <= 0) {
         usage("At least one of option -l or -L must be greater than zero");
    }

    if (apr_filepath_get(&path, 0, pool) != APR_SUCCESS) {
        usage(apr_psprintf(pool, "Could not get the filepath: %pm", &status));
    }
    baselen = strlen(path);

    if (pidfilename) {
        log_pid(pool, pidfilename, &pidfile); /* before daemonizing, so we
                                               * can report errors
                                               */
    }

    if (listurls) {
        list_urls(path, pool, round);
        return (interrupted != 0);
    }

#ifndef DEBUG
    if (isdaemon) {
        apr_file_close(errfile);
        errfile = NULL;
        if (pidfilename) {
            apr_file_close(pidfile); /* delete original pidfile only in parent */
        }
        apr_proc_detach(APR_PROC_DETACH_DAEMONIZE);
        if (pidfilename) {
            log_pid(pool, pidfilename, &pidfile);
        }
    }
#endif

    do {
        apr_pool_create(&instance, pool);

        now = apr_time_now();
        APR_RING_INIT(&root.link, _entry, link);
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
            apr_off_t nodes = 0;
            if (!process_dir(path, instance, &nodes) && !interrupted) {
                purge(path, instance, max, inodes, nodes, round);
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
