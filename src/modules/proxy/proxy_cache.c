/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000-2004 The Apache Software Foundation.  All rights
 * reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The end-user documentation included with the redistribution,
 *    if any, must include the following acknowledgment:
 *       "This product includes software developed by the
 *        Apache Software Foundation (http://www.apache.org/)."
 *    Alternately, this acknowledgment may appear in the software itself,
 *    if and wherever such third-party acknowledgments normally appear.
 *
 * 4. The names "Apache" and "Apache Software Foundation" must
 *    not be used to endorse or promote products derived from this
 *    software without prior written permission. For written
 *    permission, please contact apache@apache.org.
 *
 * 5. Products derived from this software may not be called "Apache",
 *    nor may "Apache" appear in their name, without prior written
 *    permission of the Apache Software Foundation.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE APACHE SOFTWARE FOUNDATION OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Software Foundation.  For more
 * information on the Apache Software Foundation, please see
 * <http://www.apache.org/>.
 *
 * Portions of this software are based upon public domain software
 * originally written at the National Center for Supercomputing Applications,
 * University of Illinois, Urbana-Champaign.
 */

/* Cache and garbage collection routines for Apache proxy */

#include "mod_proxy.h"
#include "http_conf_globals.h"
#include "http_log.h"
#include "http_main.h"
#include "http_core.h"
#include "util_date.h"
#ifdef WIN32
#include <sys/utime.h>
#else
#include <utime.h>
#endif                          /* WIN32 */
#include "multithread.h"
#include "ap_md5.h"
#ifdef __TANDEM
#include <sys/types.h>
#include <sys/stat.h>
#endif
#ifdef TPF
#include "os.h"
#endif

struct gc_ent {
    unsigned long int len;
    time_t expire;
    char file[HASH_LEN + 1];
};

/* Poor man's 61 bit arithmetic */
typedef struct {
    long lower;                 /* lower 30 bits of result */
    long upper;                 /* upper 31 bits of result */
} long61_t;

/* FIXME: The block size can be different on a `per file system' base.
 * This would make automatic detection highly OS specific.
 * In the GNU fileutils code for du(1), you can see how complicated it can
 * become to detect the block size. And, with BSD-4.x fragments, it
 * it even more difficult to get precise results.
 * As a compromise (and to improve on the incorrect counting of cache
 * size on byte level, omitting directory sizes entirely, which was
 * used up to apache-1.3b7) we're rounding to multiples of 512 here.
 * Your file system may be using larger blocks (I certainly hope so!)
 * but it will hardly use smaller blocks.
 * (So this approximation is still closer to reality than the old behavior).
 * The best solution would be automatic detection, the next best solution
 * IMHO is a sensible default and the possibility to override it.
 */

#define ROUNDUP2BLOCKS(_bytes) (((_bytes)+block_size-1) & ~(block_size-1))
static long block_size = 512;   /* this must be a power of 2 */
static long61_t curbytes, cachesize;
static time_t garbage_now, garbage_expire;
static mutex *garbage_mutex = NULL;


int ap_proxy_garbage_init(server_rec *r, pool *p)
{
    if (!garbage_mutex)
        garbage_mutex = ap_create_mutex(NULL);

    return (0);
}


static int sub_garbage_coll(request_rec *r, array_header *files,
                             const char *cachedir, const char *cachesubdir);
static void help_proxy_garbage_coll(request_rec *r);
static int should_proxy_garbage_coll(request_rec *r);
#if !defined(WIN32) && !defined(MPE) && !defined(OS2) && !defined(NETWARE) && !defined(TPF)
static void detached_proxy_garbage_coll(request_rec *r);
#endif


void ap_proxy_garbage_coll(request_rec *r)
{
    static int inside = 0;

    (void)ap_acquire_mutex(garbage_mutex);
    if (inside == 1) {
        (void)ap_release_mutex(garbage_mutex);
        return;
    }
    else
        inside = 1;
    (void)ap_release_mutex(garbage_mutex);

    ap_block_alarms();          /* avoid SIGALRM on big cache cleanup */
    if (should_proxy_garbage_coll(r))
#if !defined(WIN32) && !defined(MPE) && !defined(OS2) && !defined(NETWARE) && !defined(TPF)
        detached_proxy_garbage_coll(r);
#else
        help_proxy_garbage_coll(r);
#endif
    ap_unblock_alarms();

    (void)ap_acquire_mutex(garbage_mutex);
    inside = 0;
    (void)ap_release_mutex(garbage_mutex);
}


static void add_long61(long61_t *accu, long val)
{
    /* Add in lower 30 bits */
    accu->lower += (val & 0x3FFFFFFFL);
    /* add in upper bits, and carry */
    accu->upper += (val >> 30) + ((accu->lower & ~0x3FFFFFFFL) != 0L);
    /* Clear carry */
    accu->lower &= 0x3FFFFFFFL;
}

static void sub_long61(long61_t *accu, long val)
{
    int carry = (val & 0x3FFFFFFFL) > accu->lower;
    /* Subtract lower 30 bits */
    accu->lower = accu->lower - (val & 0x3FFFFFFFL) + ((carry) ? 0x40000000 : 0);
    /* add in upper bits, and carry */
    accu->upper -= (val >> 30) + carry;
}

/* Compare two long61's:
 * return <0 when left < right
 * return  0 when left == right
 * return >0 when left > right
 */
static long cmp_long61(long61_t *left, long61_t *right)
{
    return (left->upper == right->upper) ? (left->lower - right->lower)
    : (left->upper - right->upper);
}

/* Compare two gc_ent's, sort them by expiration date */
static int gcdiff(const void *ap, const void *bp)
{
    const struct gc_ent *a = (const struct gc_ent *) ap;
    const struct gc_ent *b = (const struct gc_ent *) bp;

    if (a->expire > b->expire)
        return 1;
    else if (a->expire < b->expire)
        return -1;
    else
        return 0;
}

#if !defined(WIN32) && !defined(MPE) && !defined(OS2) && !defined(NETWARE) && !defined(TPF)
static void detached_proxy_garbage_coll(request_rec *r)
{
    pid_t pid;
    int status;
    pid_t pgrp;

#if 0
    ap_log_error(APLOG_MARK, APLOG_DEBUG, r->server,
                 "proxy: Guess what; we fork() again...");
#endif
    switch (pid = fork()) {
    case -1:
        ap_log_error(APLOG_MARK, APLOG_ERR, r->server,
                     "proxy: fork() for cache cleanup failed");
        return;

    case 0:                     /* Child */

        /* close all sorts of things, including the socket fd */
        ap_cleanup_for_exec();

        /* Fork twice to disassociate from the child */
        switch (pid = fork()) {
        case -1:
            ap_log_error(APLOG_MARK, APLOG_ERR, r->server,
                         "proxy: fork(2nd) for cache cleanup failed");
            exit(1);

        case 0:         /* Child */
            /* The setpgrp() stuff was snarfed from http_main.c */
#ifndef NO_SETSID
            if ((pgrp = setsid()) == -1) {
                perror("setsid");
                fprintf(stderr, "%s: setsid failed\n",
                        ap_server_argv0);
                exit(1);
            }
#elif defined(NEXT) || defined(NEWSOS)
            if (setpgrp(0, getpid()) == -1 || (pgrp = getpgrp(0)) == -1) {
                perror("setpgrp");
                fprintf(stderr, "%S: setpgrp or getpgrp failed\n",
                        ap_server_argv0);
                exit(1);
            }
#elif defined(CYGWIN)
            /* Cygwin does not take any argument for setpgrp() */
            if ((pgrp = setpgrp()) == -1) {
                perror("setpgrp");
                fprintf(stderr, "%S: setpgrp failed\n",
                        ap_server_argv0);
                exit(1);
            }
#else
            if ((pgrp = setpgrp(getpid(), 0)) == -1) {
                perror("setpgrp");
                fprintf(stderr, "%s: setpgrp failed\n",
                        ap_server_argv0);
                exit(1);
            }
#endif
            help_proxy_garbage_coll(r);
            exit(0);

        default:                /* Father */
            /* After grandson has been forked off, */
            /* there's nothing else to do. */
            exit(0);
        }
    default:
        /* Wait until grandson has been forked off */
        /* (without wait we'd leave a zombie) */
        waitpid(pid, &status, 0);
        return;
    }
}
#endif                          /* ndef WIN32 */

#define DOT_TIME "/.time"       /* marker */

static int should_proxy_garbage_coll(request_rec *r)
{
    void *sconf = r->server->module_config;
    proxy_server_conf *pconf =
    (proxy_server_conf *)ap_get_module_config(sconf, &proxy_module);
    const struct cache_conf *conf = &pconf->cache;

    const char *cachedir = conf->root;
    char *filename;
    struct stat buf;
    int timefd;
    time_t every = conf->gcinterval;
    static time_t lastcheck = BAD_DATE; /* static (per-process) data!!! */

    if (cachedir == NULL || every == -1)
        return 0;

    filename = ap_palloc(r->pool, strlen(cachedir) + strlen(DOT_TIME) + 1);

    garbage_now = time(NULL);
    /*
     * Usually, the modification time of <cachedir>/.time can only increase.
     * Thus, even with several child processes having their own copy of
     * lastcheck, if time(NULL) still < lastcheck then it's not time for GC
     * yet.
     */
    if (garbage_now != -1 && lastcheck != BAD_DATE && garbage_now < lastcheck + every)
        return 0;

    strcpy(filename, cachedir);
    strcat(filename, DOT_TIME);

    /*
     * At this point we have a bit of an engineering compromise. We could
     * either create and/or mark the .time file  (prior to the fork which
     * might fail on a resource issue) or wait until we are safely forked.
     * The advantage of doing it now in this process is that we get some
     * usefull live out of the global last check variable. (XXX which should
     * go scoreboard IMHO.) Note that the actual counting is at a later
     * moment.
     */
    if (stat(filename, &buf) == -1) {   /* does not exist */
        if (errno != ENOENT) {
            ap_log_error(APLOG_MARK, APLOG_ERR, r->server,
                         "proxy: stat(%s)", filename);
            return 0;
        }
        if ((timefd = creat(filename, 0666)) == -1) {
            if (errno != EEXIST)
                ap_log_error(APLOG_MARK, APLOG_ERR, r->server,
                             "proxy: creat(%s)", filename);
            else
                lastcheck = garbage_now;        /* someone else got in there */
            return 0;
        }
        close(timefd);
    }
    else {
        lastcheck = buf.st_mtime;       /* save the time */
        if (garbage_now < lastcheck + every) {
            return 0;
        }
        if (utime(filename, NULL) == -1)
            ap_log_error(APLOG_MARK, APLOG_ERR, r->server,
                         "proxy: utimes(%s)", filename);
    }

    return 1;
}

static void help_proxy_garbage_coll(request_rec *r)
{
    const char *cachedir;
    void *sconf = r->server->module_config;
    proxy_server_conf *pconf =
    (proxy_server_conf *)ap_get_module_config(sconf, &proxy_module);
    const struct cache_conf *conf = &pconf->cache;
    array_header *files;
    struct gc_ent *fent;
    char *filename;
    int i;

    cachedir = conf->root;
    filename = ap_palloc(r->pool, strlen(cachedir) + HASH_LEN + 2);
    /* configured size is given in kB. Make it bytes, convert to long61_t: */
    cachesize.lower = cachesize.upper = 0;
    add_long61(&cachesize, conf->space << 10);

    ap_block_alarms();          /* avoid SIGALRM on big cache cleanup */

    files = ap_make_array(r->pool, 100, sizeof(struct gc_ent));
    curbytes.upper = curbytes.lower = 0L;

    sub_garbage_coll(r, files, cachedir, "/");

    if (cmp_long61(&curbytes, &cachesize) < 0L) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, r->server,
                     "proxy GC: Cache is %ld%% full (nothing deleted)",
                     (long)(((curbytes.upper << 20) | (curbytes.lower >> 10)) * 100 / conf->space));
        ap_unblock_alarms();
        return;
    }

    /* sort the files we found by expiration date */
    qsort(files->elts, files->nelts, sizeof(struct gc_ent), gcdiff);

    for (i = 0; i < files->nelts; i++) {
        fent = &((struct gc_ent *) files->elts)[i];
        sprintf(filename, "%s%s", cachedir, fent->file);
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, r->server, "GC Unlinking %s (expiry %ld, garbage_now %ld)", filename, (long)fent->expire, (long)garbage_now);
#if TESTING
        fprintf(stderr, "Would unlink %s\n", filename);
#else
        if (unlink(filename) == -1) {
            if (errno != ENOENT)
                ap_log_error(APLOG_MARK, APLOG_ERR, r->server,
                             "proxy gc: unlink(%s)", filename);
        }
        else
#endif
        {
            sub_long61(&curbytes, ROUNDUP2BLOCKS(fent->len));
            if (cmp_long61(&curbytes, &cachesize) < 0)
                break;
        }
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, r->server,
                 "proxy GC: Cache is %ld%% full (%d deleted)",
                 (long)(((curbytes.upper << 20) | (curbytes.lower >> 10)) * 100 / conf->space), i);
    ap_unblock_alarms();
}

static int sub_garbage_coll(request_rec *r, array_header *files,
                          const char *cachebasedir, const char *cachesubdir)
{
    char line[17 * (3)];
    char cachedir[HUGE_STRING_LEN];
    struct stat buf;
    int fd, i;
    DIR *dir;
#if defined(NEXT) || defined(WIN32)
    struct DIR_TYPE *ent;
#else
    struct dirent *ent;
#endif
    struct gc_ent *fent;
    int nfiles = 0;
    char *filename;

    ap_snprintf(cachedir, sizeof(cachedir), "%s%s", cachebasedir, cachesubdir);
    filename = ap_palloc(r->pool, strlen(cachedir) + HASH_LEN + 2);
    ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, r->server, "GC Examining directory %s", cachedir);
    dir = opendir(cachedir);
    if (dir == NULL) {
        ap_log_error(APLOG_MARK, APLOG_ERR, r->server,
                     "proxy gc: opendir(%s)", cachedir);
        return 0;
    }

    while ((ent = readdir(dir)) != NULL) {
        if (ent->d_name[0] == '.')
            continue;
        sprintf(filename, "%s%s", cachedir, ent->d_name);
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, r->server, "GC Examining file %s", filename);
/* is it a temporary file? */
        if (strncmp(ent->d_name, "tmp", 3) == 0) {
/* then stat it to see how old it is; delete temporary files > 1 day old */
            if (stat(filename, &buf) == -1) {
                if (errno != ENOENT)
                    ap_log_error(APLOG_MARK, APLOG_ERR, r->server,
                                 "proxy gc: stat(%s)", filename);
            }
            else if (garbage_now != -1 && buf.st_atime < garbage_now - SEC_ONE_DAY &&
                     buf.st_mtime < garbage_now - SEC_ONE_DAY) {
                ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, r->server, "GC unlink %s", filename);
                ap_log_error(APLOG_MARK, APLOG_INFO | APLOG_NOERRNO, r->server,
                     "proxy gc: deleting orphaned cache file %s", filename);
#if TESTING
                fprintf(stderr, "Would unlink %s\n", filename);
#else
                unlink(filename);
#endif
            }
            continue;
        }
        ++nfiles;
/* is it another file? */
        /* FIXME: Shouldn't any unexpected files be deleted? */
        /* if (strlen(ent->d_name) != HASH_LEN) continue; */

/* under OS/2 use dirent's d_attr to identify a diretory */
/* under TPF use stat to identify a directory */
#if defined(OS2) || defined(TPF)
/* is it a directory? */
#ifdef OS2
        if (ent->d_attr & A_DIR)
#elif defined(TPF)
            if (stat(filename, &buf) == -1) {
                if (errno != ENOENT)
                    ap_log_error(APLOG_MARK, APLOG_ERR, r->server,
                                 "proxy gc: stat(%s)", filename);
            }
        if (S_ISDIR(buf.st_mode))
#endif
        {
            char newcachedir[HUGE_STRING_LEN];
            ap_snprintf(newcachedir, sizeof(newcachedir),
                        "%s%s/", cachesubdir, ent->d_name);
            if (!sub_garbage_coll(r, files, cachebasedir, newcachedir)) {
                ap_snprintf(newcachedir, sizeof(newcachedir),
                            "%s%s", cachedir, ent->d_name);
#if TESTING
                fprintf(stderr, "Would remove directory %s\n", newcachedir);
#else
                rmdir(newcachedir);
#endif
                --nfiles;
            }
            continue;
        }
#endif

/* read the file */
#if defined(WIN32)
        /*
         * On WIN32 open does not work for directories, so we us stat instead
         * of fstat to determine if the file is a directory
         */
        if (stat(filename, &buf) == -1) {
            ap_log_error(APLOG_MARK, APLOG_ERR, r->server,
                         "proxy gc: stat(%s)", filename);
            continue;
        }
        fd = -1;
#else
        fd = open(filename, O_RDONLY | O_BINARY);
        if (fd == -1) {
            if (errno != ENOENT)
                ap_log_error(APLOG_MARK, APLOG_ERR, r->server,
                             "proxy gc: open(%s)", filename);
            continue;
        }
        if (fstat(fd, &buf) == -1) {
            ap_log_error(APLOG_MARK, APLOG_ERR, r->server,
                         "proxy gc: fstat(%s)", filename);
            close(fd);
            continue;
        }
#endif

/* In OS/2 and TPF this has already been done above */
#if !defined(OS2) && !defined(TPF)
        if (S_ISDIR(buf.st_mode)) {
            char newcachedir[HUGE_STRING_LEN];
#if !defined(WIN32)
            /* Win32 used stat, no file to close */
            close(fd);
#endif
            ap_snprintf(newcachedir, sizeof(newcachedir),
                        "%s%s/", cachesubdir, ent->d_name);
            if (!sub_garbage_coll(r, files, cachebasedir, newcachedir)) {
                ap_snprintf(newcachedir, sizeof(newcachedir),
                            "%s%s", cachedir, ent->d_name);
#if TESTING
                fprintf(stderr, "Would remove directory %s\n", newcachedir);
#else
                rmdir(newcachedir);
#endif
                --nfiles;
            }
            else {
                /* Directory is not empty. Account for its size: */
                add_long61(&curbytes, ROUNDUP2BLOCKS(buf.st_size));
            }
            continue;
        }
#endif

#if defined(WIN32)
        /*
         * Since we have determined above that the file is not a directory,
         * it should be safe to open it now
         */
        fd = open(filename, O_RDONLY | O_BINARY);
        if (fd == -1) {
            if (errno != ENOENT)
                ap_log_error(APLOG_MARK, APLOG_ERR, r->server,
                             "proxy gc: open(%s) = %d", filename, errno);
            continue;
        }
#endif

        i = read(fd, line, 17 * (3) - 1);
        close(fd);
        if (i == -1) {
            ap_log_error(APLOG_MARK, APLOG_ERR, r->server,
                         "proxy gc: read(%s)", filename);
            continue;
        }
        line[i] = '\0';
        garbage_expire = ap_proxy_hex2sec(line + 17 * (2));
        if (!ap_checkmask(line, "&&&&&&&&&&&&&&&& &&&&&&&&&&&&&&&& &&&&&&&&&&&&&&&&") ||
            garbage_expire == BAD_DATE) {
            /* bad file */
            if (garbage_now != -1 && buf.st_atime > garbage_now + SEC_ONE_DAY &&
                buf.st_mtime > garbage_now + SEC_ONE_DAY) {
                ap_log_error(APLOG_MARK, APLOG_WARNING | APLOG_NOERRNO, r->server,
                             "proxy: deleting bad cache file with future date: %s", filename);
#if TESTING
                fprintf(stderr, "Would unlink bad file %s\n", filename);
#else
                unlink(filename);
#endif
            }
            continue;
        }

/*
 * we need to calculate an 'old' factor, and remove the 'oldest' files
 * so that the space requirement is met; sort by the expires date of the
 * file.
 *
 */
        fent = (struct gc_ent *) ap_push_array(files);
        fent->len = buf.st_size;
        fent->expire = garbage_expire;
        strcpy(fent->file, cachesubdir);
        strcat(fent->file, ent->d_name);

/* accumulate in blocks, to cope with directories > 4Gb */
        add_long61(&curbytes, ROUNDUP2BLOCKS(buf.st_size));
    }

    closedir(dir);

    return nfiles;

}


/*
 * Read a cache file;
 * returns 1 on success,
 *         0 on failure (bad file or wrong URL)
 *        -1 on UNIX error
 *
 * We read the cache hex header, then the message response line and
 * response headers, and finally we return with the filepointer
 * pointing at the start of the message body itself, ready to be
 * shipped to the client later on, if appropriate.
 */
static int rdcache(request_rec *r, BUFF *cachefp, cache_req *c)
{
    char urlbuff[HUGE_STRING_LEN], *strp;
    int len;

    /* read the data from the cache file */

    /*
     * Format:
     * 
     * The cache needs to keep track of the following information: - Date,
     * LastMod, Version, ReqTime, RespTime, ContentLength - The original
     * request headers (for Vary) - The original response headers (for
     * returning with a cached response) - The body of the message
     * 
     * date SP lastmod SP expire SP count SP request-time SP response-time SP
     * content-lengthCRLF (dates are stored as hex seconds since 1970)
     * Original URLCRLF Original Request Headers CRLF Original Response
     * Headers CRLF Body
     * 
     */

    /* retrieve cachefile information values */
    len = ap_bgets(urlbuff, sizeof urlbuff, cachefp);
    if (len == -1) {
        /* Delete broken cache file */
        unlink(c->filename);
        return -1;
    }
    if (len == 0 || urlbuff[len - 1] != '\n')
        return 0;
    urlbuff[len - 1] = '\0';

    if (!ap_checkmask(urlbuff,
                      "&&&&&&&&&&&&&&&& &&&&&&&&&&&&&&&& &&&&&&&&&&&&&&&& &&&&&&&&&&&&&&&& &&&&&&&&&&&&&&&& &&&&&&&&&&&&&&&& &&&&&&&&&&&&&&&&"))
        return 0;

    c->date = ap_proxy_hex2sec(urlbuff + 17 * (0));
    c->lmod = ap_proxy_hex2sec(urlbuff + 17 * (1));
    c->expire = ap_proxy_hex2sec(urlbuff + 17 * (2));
    c->version = ap_proxy_hex2sec(urlbuff + 17 * (3));
    c->req_time = ap_proxy_hex2sec(urlbuff + 17 * (4));
    c->resp_time = ap_proxy_hex2sec(urlbuff + 17 * (5));
    c->len = ap_proxy_hex2sec(urlbuff + 17 * (6));

    /* check that we have the same URL */
    len = ap_bgets(urlbuff, sizeof urlbuff, cachefp);
    if (len == -1) {
        /* Delete broken cache file */
        unlink(c->filename);
        return -1;
    }
    if (len == 0 || strncmp(urlbuff, "X-URL: ", 7) != 0 ||
        urlbuff[len - 1] != '\n')
        return 0;
    urlbuff[len - 1] = '\0';
    if (strcmp(urlbuff + 7, c->url) != 0)
        return 0;

    /* then the original request headers */
    c->req_hdrs = ap_proxy_read_headers(r, urlbuff, sizeof urlbuff, cachefp);
    if (c->req_hdrs == NULL) {
        /* Delete broken cache file */
        unlink(c->filename);
        return -1;
    }

    /* then the original response headers */
    len = ap_bgets(urlbuff, sizeof urlbuff, cachefp);
    if (len == -1) {
        /* Delete broken cache file */
        unlink(c->filename);
        return -1;
    }
    if (len == 0 || urlbuff[len - 1] != '\n')
        return 0;
    urlbuff[--len] = '\0';

    c->resp_line = ap_pstrdup(r->pool, urlbuff);
    strp = strchr(urlbuff, ' ');
    if (strp == NULL)
        return 0;

    c->status = atoi(strp);
    c->hdrs = ap_proxy_read_headers(r, urlbuff, sizeof urlbuff, cachefp);
    if (c->hdrs == NULL) {
        /* Delete broken cache file */
        unlink(c->filename);
        return -1;
    }
    if (c->len != -1)           /* add a content-length header */
        if (ap_table_get(c->hdrs, "Content-Length") == NULL) {
            ap_table_set(c->hdrs, "Content-Length",
                         ap_psprintf(r->pool, "%lu", (unsigned long)c->len));
        }


    return 1;
}

/*
 * Call this to check the possible conditional status of
 * the client request, and return the response from the cache
 *
 * Conditionals include If-Modified-Since, If-Match, If-Unmodified-Since
 * and If-None-Match.
 *
 * We don't yet understand If-Range, but we will...
 */
int ap_proxy_cache_conditional(request_rec *r, cache_req *c, BUFF *cachefp)
{
    const char *etag, *wetag = NULL;

    /* get etag */
    if ((etag = ap_table_get(c->hdrs, "Etag"))) {
        wetag = ap_pstrcat(r->pool, "W/", etag, NULL);
    }

    /* check for If-Match, If-Unmodified-Since */
    while (1) {

        /*
         * check If-Match and If-Unmodified-Since exist
         * 
         * If neither of these exist, the request is not conditional, and we
         * serve it normally
         */
        if (!c->im && BAD_DATE == c->ius) {
            break;
        }

        /*
         * check If-Match
         * 
         * we check if the Etag on the cached file is in the list of Etags in
         * the If-Match field. The comparison must be a strong comparison, so
         * the Etag cannot be marked as weak. If the comparision fails we
         * return 412 Precondition Failed.
         * 
         * if If-Match is specified AND If-Match is not a "*" AND Etag is
         * missing or weak or not in the list THEN return 412 Precondition
         * Failed
         */

        if (c->im) {
            if (strcmp(c->im, "*") &&
                (!etag || (strlen(etag) > 1 && 'W' == etag[0] && '/' == etag[1]) || !ap_proxy_liststr(c->im, etag, NULL))) {
                ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, r->server, "If-Match specified, and it didn't - return 412");
            }
            else {
                ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, r->server, "If-Match specified, and it matched");
                break;
            }
        }

        /*
         * check If-Unmodified-Since
         * 
         * if If-Unmodified-Since is specified AND Last-Modified is specified
         * somewhere AND If-Unmodified-Since is in the past compared to
         * Last-Modified THEN return 412 Precondition Failed
         */
        if (BAD_DATE != c->ius && BAD_DATE != c->lmod) {
            if (c->ius < c->lmod) {
                ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, r->server, "If-Unmodified-Since specified, but it wasn't - return 412");
            }
            else {
                ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, r->server, "If-Unmodified-Since specified, and it was unmodified");
                break;
            }
        }

        /* if cache file is being updated */
        if (c->origfp) {
            ap_proxy_write_headers(c, c->resp_line, c->hdrs);
            ap_proxy_send_fb(c->origfp, r, c, c->len, 1, 0, IOBUFSIZE);
            ap_proxy_cache_tidy(c);
        }
        else
            ap_pclosef(r->pool, ap_bfileno(cachefp, B_WR));

        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, r->server, "Use your cached copy, conditional precondition failed.");
        return HTTP_PRECONDITION_FAILED;
    }


    /* check for If-None-Match, If-Modified-Since */
    while (1) {

        /*
         * check for existance of If-None-Match and If-Modified-Since
         * 
         * if neither of these headers have been set, then the request is not
         * conditional, and we just send the cached response and be done with
         * it.
         */
        if (!c->inm && BAD_DATE == c->ims) {
            break;
        }

        /*
         * check If-None-Match
         * 
         * we check if the Etag on the cached file is in the list of Etags in
         * the If-None-Match field. The comparison must be a strong
         * comparison, so the Etag cannot be marked as weak. If the
         * comparision fails we return 412 Precondition Failed.
         * 
         * if If-None-Match is specified: if If-None-Match is a "*" THEN 304
         * else if Etag is specified AND we get a match THEN 304 else if Weak
         * Etag is specified AND we get a match THEN 304 else sent the
         * original object
         */
        if (c->inm) {
            if (!strcmp(c->inm, "*")) {
                ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, r->server, "If-None-Match: * specified, return 304");
            }
            else if (etag && ap_proxy_liststr(c->inm, etag, NULL)) {
                ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, r->server, "If-None-Match: specified and we got a strong match - return 304");
            }
            else if (wetag && ap_proxy_liststr(c->inm, wetag, NULL)) {
                ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, r->server, "If-None-Match specified, and we got a weak match - return 304");
            }
            else
                break;
        }

        /*
         * check If-Modified-Since
         * 
         * if If-Modified-Since is specified AND Last-Modified is specified
         * somewhere: if last modification date is earlier than
         * If-Modified-Since THEN 304 else send the original object
         */
        if (BAD_DATE != c->ims && BAD_DATE != c->lmod) {
            if (c->ims >= c->lmod) {
                ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, r->server, "If-Modified-Since specified and not modified, try return 304");
            }
            else
                break;
        }


        /* are we updating the cache file? */
        if (c->origfp) {
            ap_proxy_write_headers(c, c->resp_line, c->hdrs);
            ap_proxy_send_fb(c->origfp, r, c, c->len, 1, 0, IOBUFSIZE);
            ap_proxy_cache_tidy(c);
        }
        else
            ap_pclosef(r->pool, ap_bfileno(cachefp, B_WR));

        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, r->server, "Use local copy, cached file hasn't changed");
        return HTTP_NOT_MODIFIED;
    }


    /* No conditional - just send it cousin! */
    ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, r->server, "Local copy modified, send it");
    r->status_line = strchr(c->resp_line, ' ') + 1;
    r->status = c->status;

    /* Prepare and send headers to client */
    ap_proxy_table_replace(r->headers_out, c->hdrs);
    /* make sure our X-Cache header does not stomp on a previous header */
    ap_table_mergen(r->headers_out, "X-Cache", c->xcache);

    /* content type is already set in the headers */
    r->content_type = ap_table_get(r->headers_out, "Content-Type");

    ap_send_http_header(r);

    /* are we rewriting the cache file? */
    if (c->origfp) {
        ap_proxy_write_headers(c, c->resp_line, c->hdrs);
        ap_proxy_send_fb(c->origfp, r, c, c->len, r->header_only, 0, IOBUFSIZE);
        ap_proxy_cache_tidy(c);
        return OK;
    }

    /* no, we not */
    if (!r->header_only) {
        ap_proxy_send_fb(cachefp, r, NULL, c->len, 0, 0, IOBUFSIZE);
    }
    else {
        ap_pclosef(r->pool, ap_bfileno(cachefp, B_WR));
    }

    return OK;
}


/*
 * Call this to test for a resource in the cache
 * Returns DECLINED if we need to check the remote host
 * or an HTTP status code if successful
 *
 * Functions:
 *   if URL is cached then
 *      if cached file is not expired then
 *         if last modified after if-modified-since then send body
 *         else send 304 Not modified
 *      else if cached file is expired then
 *         if last modified after if-modified-since then add
 *            last modified date to request
 */
int ap_proxy_cache_check(request_rec *r, char *url, struct cache_conf * conf,
                             cache_req **cr)
{
    const char *datestr, *pragma_req = NULL, *pragma_cresp = NULL, *cc_req = NULL,
        *cc_cresp = NULL;
    cache_req *c;
    BUFF *cachefp;
    int i;
    void *sconf = r->server->module_config;
    proxy_server_conf *pconf =
    (proxy_server_conf *)ap_get_module_config(sconf, &proxy_module);
    const char *agestr = NULL;
    char *val;
    time_t age_c = 0;
    time_t age, maxage_req, maxage_cresp, maxage, smaxage, maxstale, minfresh;

    c = ap_pcalloc(r->pool, sizeof(cache_req));
    *cr = c;
    c->req = r;
    c->url = ap_pstrdup(r->pool, url);
    c->filename = NULL;
    c->tempfile = NULL;
    c->fp = NULL;
    c->origfp = NULL;
    c->version = 0;
    c->len = -1;
    c->req_hdrs = NULL;
    c->hdrs = NULL;
    c->xcache = NULL;

    /* get the If-Modified-Since date of the request, if it exists */
    c->ims = BAD_DATE;
    datestr = ap_table_get(r->headers_in, "If-Modified-Since");
    if (datestr != NULL) {
        /* this may modify the value in the original table */
        datestr = ap_proxy_date_canon(r->pool, datestr);
        c->ims = ap_parseHTTPdate(datestr);
        if (c->ims == BAD_DATE) /* bad or out of range date; remove it */
            ap_table_unset(r->headers_in, "If-Modified-Since");
    }

/* get the If-Unmodified-Since date of the request, if it exists */
    c->ius = BAD_DATE;
    datestr = ap_table_get(r->headers_in, "If-Unmodified-Since");
    if (datestr != NULL) {
        /* this may modify the value in the original table */
        datestr = ap_proxy_date_canon(r->pool, datestr);
        c->ius = ap_parseHTTPdate(datestr);
        if (c->ius == BAD_DATE) /* bad or out of range date; remove it */
            ap_table_unset(r->headers_in, "If-Unmodified-Since");
    }

/* get the If-Match of the request, if it exists */
    c->im = ap_table_get(r->headers_in, "If-Match");

/* get the If-None-Match of the request, if it exists */
    c->inm = ap_table_get(r->headers_in, "If-None-Match");

/* find the filename for this cache entry */
    if (conf->root != NULL) {
        char hashfile[66];
        ap_proxy_hash(url, hashfile, pconf->cache.dirlevels, pconf->cache.dirlength);
        c->filename = ap_pstrcat(r->pool, conf->root, "/", hashfile, NULL);
    }
    else {
        c->filename = NULL;
        c->fp = NULL;
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, r->server, "No CacheRoot, so no caching. Declining.");
        return DECLINED;
    }

/* find certain cache controlling headers */
    pragma_req = ap_table_get(r->headers_in, "Pragma");
    cc_req = ap_table_get(r->headers_in, "Cache-Control");

/* first things first - does the request allow us to return
 * cached information at all? If not, just decline the request.
 *
 * Note that there is a big difference between not being allowed
 * to cache a request (no-store) and not being allowed to return
 * a cached request without revalidation (max-age=0).
 *
 * Caching is forbidden under the following circumstances:
 *
 * - RFC2616 14.9.2 Cache-Control: no-store
 * we are not supposed to store this request at all. Behave as a tunnel.
 *
 */
    if (ap_proxy_liststr(cc_req, "no-store", NULL)) {

/* delete the previously cached file */
        if (c->filename)
            unlink(c->filename);
        c->fp = NULL;
        c->filename = NULL;
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, r->server, "no-store forbids caching. Declining.");
        return DECLINED;
    }

/* if the cache file exists, open it */
    cachefp = NULL;
    ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, r->server, "Request for %s, pragma_req=%s, ims=%ld", url,
                 (pragma_req == NULL) ? "(unset)" : pragma_req, c->ims);
/* find out about whether the request can access the cache */
    if (c->filename != NULL && r->method_number == M_GET &&
        strlen(url) < 1024) {
        cachefp = ap_proxy_open_cachefile(r, c->filename);
    }


    /*
     * if a cache file exists, try reading body and headers from cache file
     */
    if (cachefp != NULL) {
        i = rdcache(r, cachefp, c);
        if (i == -1)
            ap_log_rerror(APLOG_MARK, APLOG_ERR, r,
                          "proxy: error reading cache file %s",
                          c->filename);
        else if (i == 0)
            ap_log_rerror(APLOG_MARK, APLOG_ERR | APLOG_NOERRNO, r,
                          "proxy: bad (short?) cache file: %s", c->filename);
        if (i != 1) {
            ap_pclosef(r->pool, ap_bfileno(cachefp, B_WR));
            cachefp = NULL;
        }
        if (c->hdrs) {
            cc_cresp = ap_table_get(c->hdrs, "Cache-Control");
            pragma_cresp = ap_table_get(c->hdrs, "Pragma");
            if ((agestr = ap_table_get(c->hdrs, "Age"))) {
                age_c = atoi(agestr);
            }
        }
    }

    /* if a cache file does not exist, create empty header array */
/* fixed?  in this case, we want to get the headers from the remote server
   it will be handled later if we don't do this (I hope ;-)

    if (cachefp == NULL)
        c->hdrs = ap_make_table(r->pool, 20);
*/
    /* FIXME: Shouldn't we check the URL somewhere? */

    /*
     * Check Content-Negotiation - Vary
     * 
     * At this point we need to make sure that the object we found in the cache
     * is the same object that would be delivered to the client, when the
     * effects of content negotiation are taken into effect.
     * 
     * In plain english, we want to make sure that a language-negotiated
     * document in one language is not given to a client asking for a
     * language negotiated document in a different language by mistake.
     * 
     * RFC2616 13.6 and 14.44 describe the Vary mechanism.
     */
    if (c->hdrs && c->req_hdrs) {
        char *vary = ap_pstrdup(r->pool, ap_table_get(c->hdrs, "Vary"));

        while (vary && *vary) {
            char *name = vary;
            const char *h1, *h2;

            /* isolate header name */
            while (*vary && !ap_isspace(*vary) && (*vary != ','))
                ++vary;
            while (*vary && (ap_isspace(*vary) || (*vary == ','))) {
                *vary = '\0';
                ++vary;
            }

            /*
             * is this header in the request and the header in the cached
             * request identical? If not, we give up and do a straight get
             */
            h1 = ap_table_get(r->headers_in, name);
            h2 = ap_table_get(c->req_hdrs, name);
            if (h1 == h2) {
                /* both headers NULL, so a match - do nothing */
            }
            else if (h1 && h2 && !strcmp(h1, h2)) {
                /* both headers exist and are equal - do nothing */
            }
            else {

                /* headers do not match, so Vary failed */
                c->fp = cachefp;
                ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, r->server, "Vary header mismatch - object must be fetched from scratch. Declining.");
                return DECLINED;
            }
        }
    }


    /*
     * We now want to check if our cached data is still fresh. This depends
     * on a few things, in this order:
     * 
     * - RFC2616 14.9.4 End to end reload, Cache-Control: no-cache no-cache in
     * either the request or the cached response means that we must
     * revalidate the request unconditionally, overriding any expiration
     * mechanism. It's equivalent to max-age=0,must-revalidate.
     * 
     * - RFC2616 14.32 Pragma: no-cache This is treated the same as
     * Cache-Control: no-cache.
     * 
     * - RFC2616 14.9.3 Cache-Control: max-stale, must-revalidate,
     * proxy-revalidate if the max-stale request header exists, modify the
     * stale calculations below so that an object can be at most <max-stale>
     * seconds stale before we request a revalidation, _UNLESS_ a
     * must-revalidate or proxy-revalidate cached response header exists to
     * stop us doing this.
     * 
     * - RFC2616 14.9.3 Cache-Control: s-maxage the origin server specifies the
     * maximum age an object can be before it is considered stale. This
     * directive has the effect of proxy|must revalidate, which in turn means
     * simple ignore any max-stale setting.
     * 
     * - RFC2616 14.9.4 Cache-Control: max-age this header can appear in both
     * requests and responses. If both are specified, the smaller of the two
     * takes priority.
     * 
     * - RFC2616 14.21 Expires: if this request header exists in the cached
     * entity, and it's value is in the past, it has expired.
     * 
     */

    /* calculate age of object */
    age = ap_proxy_current_age(c, age_c);

    /* extract s-maxage */
    if (cc_cresp && ap_proxy_liststr(cc_cresp, "s-maxage", &val))
        smaxage = atoi(val);
    else
        smaxage = -1;

    /* extract max-age from request */
    if (cc_req && ap_proxy_liststr(cc_req, "max-age", &val))
        maxage_req = atoi(val);
    else
        maxage_req = -1;

    /* extract max-age from response */
    if (cc_cresp && ap_proxy_liststr(cc_cresp, "max-age", &val))
        maxage_cresp = atoi(val);
    else
        maxage_cresp = -1;

    /*
     * if both maxage request and response, the smaller one takes priority
     */
    if (-1 == maxage_req)
        maxage = maxage_cresp;
    else if (-1 == maxage_cresp)
        maxage = maxage_req;
    else
        maxage = MIN(maxage_req, maxage_cresp);

    /* extract max-stale */
    if (cc_req && ap_proxy_liststr(cc_req, "max-stale", &val))
        maxstale = atoi(val);
    else
        maxstale = 0;

    /* extract min-fresh */
    if (cc_req && ap_proxy_liststr(cc_req, "min-fresh", &val))
        minfresh = atoi(val);
    else
        minfresh = 0;

    /* override maxstale if must-revalidate or proxy-revalidate */
    if (maxstale && ((cc_cresp && ap_proxy_liststr(cc_cresp, "must-revalidate", NULL)) || (cc_cresp && ap_proxy_liststr(cc_cresp, "proxy-revalidate", NULL))))
        maxstale = 0;

    if (cachefp != NULL &&

    /* handle no-cache */
        !((cc_req && ap_proxy_liststr(cc_req, "no-cache", NULL)) ||
          (pragma_req && ap_proxy_liststr(pragma_req, "no-cache", NULL)) ||
          (cc_cresp && ap_proxy_liststr(cc_cresp, "no-cache", NULL)) ||
      (pragma_cresp && ap_proxy_liststr(pragma_cresp, "no-cache", NULL))) &&

    /* handle expiration */
        ((-1 < smaxage && age < (smaxage - minfresh)) ||
         (-1 < maxage && age < (maxage + maxstale - minfresh)) ||
         (c->expire != BAD_DATE && age < (c->expire - c->date + maxstale - minfresh)))
        ) {

        /* it's fresh darlings... */

        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, r->server, "Unexpired data available");

        /* set age header on response */
        ap_table_set(c->hdrs, "Age",
                     ap_psprintf(r->pool, "%lu", (unsigned long)age));

        /* add warning if maxstale overrode freshness calculation */
        if (!((-1 < smaxage && age < smaxage) ||
              (-1 < maxage && age < maxage) ||
              (c->expire != BAD_DATE && (c->expire - c->date) > age))) {
            /* make sure we don't stomp on a previous warning */
            ap_table_merge(c->hdrs, "Warning", "110 Response is stale");
        }

        /* check conditionals (If-Modified-Since, etc) */
        c->xcache = ap_pstrcat(r->pool, "HIT from ", ap_get_server_name(r), NULL);
        return ap_proxy_cache_conditional(r, c, cachefp);


    }

    /*
     * at this point we have determined our cached data needs revalidation
     * but first - we check 1 thing:
     * 
     * RFC2616 14.9.4 - if "only-if-cached" specified, send a 504 Gateway
     * Timeout - we're not allowed to revalidate the object
     */
    if (ap_proxy_liststr(cc_req, "only-if-cached", NULL)) {
        if (cachefp)
            ap_pclosef(r->pool, ap_bfileno(cachefp, B_WR));
        return HTTP_GATEWAY_TIME_OUT;
    }


    /*
     * If we already have cached data and a last-modified date, and it is not
     * a head request, then add an If-Modified-Since.
     * 
     * If we also have an Etag, then the object must have come from an HTTP/1.1
     * server. Add an If-None-Match as well.
     * 
     * See RFC2616 13.3.4
     */

    if (cachefp != NULL && !r->header_only) {

        const char *etag = ap_table_get(c->hdrs, "Etag");

        /* If-Modified-Since */
        if (c->lmod != BAD_DATE) {
            /*
             * use the later of the one from the request and the
             * last-modified date from the cache
             */
            if (c->ims == BAD_DATE || c->ims < c->lmod) {
                const char *q;

                if ((q = ap_table_get(c->hdrs, "Last-Modified")) != NULL)
                    ap_table_set(r->headers_in, "If-Modified-Since", (char *)q);
            }
        }

        /* If-None-Match */
        if (etag) {
            ap_table_set(r->headers_in, "If-None-Match", etag);
        }

    }


    c->fp = cachefp;

    ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, r->server, "Local copy not present or expired. Declining.");

    return DECLINED;
}

/*
 * Having read the response from the client, decide what to do
 * If the response is not cachable, then delete any previously cached
 * response, and copy data from remote server to client.
 * Functions:
 *  parse dates
 *  check for an uncachable response
 *  calculate an expiry date, if one is not provided
 *  if the remote file has not been modified, then return the document
 *  from the cache, maybe updating the header line
 *  otherwise, delete the old cached file and open a new temporary file
 */
int ap_proxy_cache_update(cache_req *c, table *resp_hdrs,
                              const int is_HTTP1, int nocache)
{
#if defined(ULTRIX_BRAIN_DEATH) || defined(SINIX_D_RESOLVER_BUG)
    extern char *mktemp(char *template);
#endif
    request_rec *r = c->req;
    char *p;
    const char *expire, *lmods, *dates, *clen;
    time_t expc, date, lmod, now;
    char buff[17 * 7 + 1];
    void *sconf = r->server->module_config;
    proxy_server_conf *conf =
    (proxy_server_conf *)ap_get_module_config(sconf, &proxy_module);
    const char *cc_resp;
    table *req_hdrs;

    cc_resp = ap_table_get(resp_hdrs, "Cache-Control");

    c->tempfile = NULL;

    /* we've received the response from the origin server */

    /*
     * read expiry date; if a bad date, then leave it so the client can read
     * it
     */
    expire = ap_table_get(resp_hdrs, "Expires");
    if (expire != NULL)
        expc = ap_parseHTTPdate(expire);
    else
        expc = BAD_DATE;

    /* read the last-modified date; if the date is bad, then delete it */
    lmods = ap_table_get(resp_hdrs, "Last-Modified");
    if (lmods != NULL) {
        lmod = ap_parseHTTPdate(lmods);
        if (lmod == BAD_DATE) {
            /* kill last modified date */
            lmods = NULL;
        }
    }
    else
        lmod = BAD_DATE;


    /*
     * what responses should we not cache?
     * 
     * At this point we decide based on the response headers whether it is
     * appropriate _NOT_ to cache the data from the server. There are a whole
     * lot of conditions that prevent us from caching this data. They are
     * tested here one by one to be clear and unambiguous.
     */

    /*
     * RFC2616 13.4 we are allowed to cache 200, 203, 206, 300, 301 or 410 We
     * don't cache 206, because we don't (yet) cache partial responses. We
     * include 304 Not Modified here too as this is the origin server telling
     * us to serve the cached copy.
     */
    if ((r->status != HTTP_OK && r->status != HTTP_NON_AUTHORITATIVE && r->status != HTTP_MULTIPLE_CHOICES && r->status != HTTP_MOVED_PERMANENTLY && r->status != HTTP_NOT_MODIFIED) ||

    /* if a broken Expires header is present, don't cache it */
        (expire != NULL && expc == BAD_DATE) ||

    /*
     * if the server said 304 Not Modified but we have no cache file - pass
     * this untouched to the user agent, it's not for us.
     */
        (r->status == HTTP_NOT_MODIFIED && (c == NULL || c->fp == NULL)) ||

    /*
     * 200 OK response from HTTP/1.0 and up without a Last-Modified header
     */
        (r->status == HTTP_OK && lmods == NULL && is_HTTP1) ||

    /* HEAD requests */
        r->header_only ||

    /*
     * RFC2616 14.9.2 Cache-Control: no-store response indicating do not
     * cache, or stop now if you are trying to cache it
     */
        ap_proxy_liststr(cc_resp, "no-store", NULL) ||

    /*
     * RFC2616 14.9.1 Cache-Control: private this object is marked for this
     * user's eyes only. Behave as a tunnel.
     */
        ap_proxy_liststr(cc_resp, "private", NULL) ||

    /*
     * RFC2616 14.8 Authorisation: if authorisation is included in the
     * request, we don't cache, but we can cache if the following exceptions
     * are true: 1) If Cache-Control: s-maxage is included 2) If
     * Cache-Control: must-revalidate is included 3) If Cache-Control: public
     * is included
     */
        (ap_table_get(r->headers_in, "Authorization") != NULL

         && !(ap_proxy_liststr(cc_resp, "s-maxage", NULL) || ap_proxy_liststr(cc_resp, "must-revalidate", NULL) || ap_proxy_liststr(cc_resp, "public", NULL))
         ) ||

    /* or we've been asked not to cache it above */
        nocache) {

        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, r->server, "Response is not cacheable, unlinking %s", c->filename);

        /* close the file */
        if (c->fp != NULL) {
            ap_pclosef(r->pool, ap_bfileno(c->fp, B_WR));
            c->fp = NULL;
        }

        /* delete the previously cached file */
        if (c->filename)
            unlink(c->filename);
        return DECLINED;        /* send data to client but not cache */
    }


    /*
     * It's safe to cache the response.
     * 
     * We now want to update the cache file header information with the new
     * date, last modified, expire and content length and write it away to
     * our cache file. First, we determine these values from the response,
     * using heuristics if appropriate.
     * 
     * In addition, we make HTTP/1.1 age calculations and write them away too.
     */

    /* Read the date. Generate one if one is not supplied */
    dates = ap_table_get(resp_hdrs, "Date");
    if (dates != NULL)
        date = ap_parseHTTPdate(dates);
    else
        date = BAD_DATE;

    now = time(NULL);

    if (date == BAD_DATE) {     /* No, or bad date */
/* no date header! */
/* add one; N.B. use the time _now_ rather than when we were checking the cache
 */
        date = now;
        dates = ap_gm_timestr_822(r->pool, now);
        ap_table_set(resp_hdrs, "Date", dates);
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, r->server, "Added date header");
    }

/* set response_time for HTTP/1.1 age calculations */
    c->resp_time = now;

/* check last-modified date */
    if (lmod != BAD_DATE && lmod > date)
/* if its in the future, then replace by date */
    {
        lmod = date;
        lmods = dates;
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, r->server, "Last modified is in the future, replacing with now");
    }
/* if the response did not contain the header, then use the cached version */
    if (lmod == BAD_DATE && c->fp != NULL) {
        lmod = c->lmod;
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, r->server, "Reusing cached last modified");
    }

/* we now need to calculate the expire data for the object. */
    if (expire == NULL && c->fp != NULL) {      /* no expiry data sent in
                                                 * response */
        expire = ap_table_get(c->hdrs, "Expires");
        if (expire != NULL)
            expc = ap_parseHTTPdate(expire);
    }
/* so we now have the expiry date */
/* if no expiry date then
 *   if lastmod
 *      expiry date = now + min((date - lastmod) * factor, maxexpire)
 *   else
 *      expire date = now + defaultexpire
 */
    ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, r->server, "Expiry date is %ld", (long)expc);
    if (expc == BAD_DATE) {
        if (lmod != BAD_DATE) {
            double x = (double)(date - lmod) * conf->cache.lmfactor;
            double maxex = conf->cache.maxexpire;
            if (x > maxex)
                x = maxex;
            expc = now + (int)x;
        }
        else
            expc = now + conf->cache.defaultexpire;
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, r->server, "Expiry date calculated %ld", (long)expc);
    }

/* get the content-length header */
    clen = ap_table_get(resp_hdrs, "Content-Length");
    if (clen == NULL)
        c->len = -1;
    else
        c->len = ap_strtol(clen, NULL, 10);

/* we have all the header information we need - write it to the cache file */
    c->version++;
    ap_proxy_sec2hex(date, buff + 17 * (0));
    buff[17 * (1) - 1] = ' ';
    ap_proxy_sec2hex(lmod, buff + 17 * (1));
    buff[17 * (2) - 1] = ' ';
    ap_proxy_sec2hex(expc, buff + 17 * (2));
    buff[17 * (3) - 1] = ' ';
    ap_proxy_sec2hex(c->version, buff + 17 * (3));
    buff[17 * (4) - 1] = ' ';
    ap_proxy_sec2hex(c->req_time, buff + 17 * (4));
    buff[17 * (5) - 1] = ' ';
    ap_proxy_sec2hex(c->resp_time, buff + 17 * (5));
    buff[17 * (6) - 1] = ' ';
    ap_proxy_sec2hex(c->len, buff + 17 * (6));
    buff[17 * (7) - 1] = '\n';
    buff[17 * (7)] = '\0';

/* Was the server response a 304 Not Modified?
 *
 * If it was, it means that we requested a revalidation, and that
 * the result of that revalidation was that the object was fresh.
 *
 */

/* if response from server 304 not modified */
    if (r->status == HTTP_NOT_MODIFIED) {

/* Have the headers changed?
 *
 * if not - we fulfil the request and return now.
 */

        if (c->hdrs) {
            /* recall at this point that c->len is already set from resp_hdrs.
               If Content-Length was NULL, then c->len is -1, otherwise it's
               set to whatever the value was. */
            if (c->len == 0 || c->len == -1) {
                const char *c_clen_str;
                off_t c_clen;
                if ( (c_clen_str = ap_table_get(c->hdrs, "Content-Length")) &&
                   ( (c_clen = ap_strtol(c_clen_str, NULL, 10)) > 0) ) {
                        ap_table_set(resp_hdrs, "Content-Length", c_clen_str);
                        c->len = c_clen;
                        ap_proxy_sec2hex(c->len, buff + 17 * (6));
                        buff[17 * (7) - 1] = '\n';
                        buff[17 * (7)] = '\0';
                }
            }
            if (!ap_proxy_table_replace(c->hdrs, resp_hdrs)) {
                c->xcache = ap_pstrcat(r->pool, "HIT from ", ap_get_server_name(r), " (with revalidation)", NULL);
                return ap_proxy_cache_conditional(r, c, c->fp);
            }
        }
        else
            c->hdrs = resp_hdrs;
/* if we get here - the headers have changed. Go through the motions
 * of creating a new temporary cache file below, we'll then serve
 * the request like we would have in ap_proxy_cache_conditional()
 * above, and at the same time we will also rewrite the contents
 * to the new temporary file.
 */
    }

/*
 * Ok - lets prepare and open the cached file
 *
 * If a cached file (in c->fp) is already open, then we want to
 * update that cached file. Copy the c->fp to c->origfp and open
 * up a new one.
 *
 * If the cached file (in c->fp) is NULL, we must open a new cached
 * file from scratch.
 *
 * The new cache file will be moved to it's final location in the
 * directory tree later, overwriting the old cache file should it exist.
 */

/* if a cache file was already open */
    if (c->fp != NULL) {
        c->origfp = c->fp;
    }

    while (1) {
/* create temporary filename */
#ifndef TPF
#define TMPFILESTR    "/tmpXXXXXX"
        if (conf->cache.root == NULL) {
            c = ap_proxy_cache_error(c);
            break;
        }
        c->tempfile = ap_palloc(r->pool, strlen(conf->cache.root) + sizeof(TMPFILESTR));
        strcpy(c->tempfile, conf->cache.root);
        strcat(c->tempfile, TMPFILESTR);
#undef TMPFILESTR
        p = mktemp(c->tempfile);
#else
        if (conf->cache.root == NULL) {
            c = ap_proxy_cache_error(c);
            break;
        }
        c->tempfile = ap_palloc(r->pool, strlen(conf->cache.root) + 1 + L_tmpnam);
        strcpy(c->tempfile, conf->cache.root);
        strcat(c->tempfile, "/");
        p = tmpnam(NULL);
        strcat(c->tempfile, p);
#endif
        if (p == NULL) {
            c = ap_proxy_cache_error(c);
            break;
        }

        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, r->server, "Create temporary file %s", c->tempfile);

/* create the new file */
        c->fp = ap_proxy_create_cachefile(r, c->tempfile);
        if (NULL == c->fp) {
            c = ap_proxy_cache_error(c);
            break;
        }

/* write away the cache header and the URL */
        if (ap_bvputs(c->fp, buff, "X-URL: ", c->url, "\n", NULL) == -1) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, r,
                        "proxy: error writing cache file(%s)", c->tempfile);
            c = ap_proxy_cache_error(c);
            break;
        }

/* get original request headers */
        if (c->req_hdrs)
            req_hdrs = ap_copy_table(r->pool, c->req_hdrs);
        else
            req_hdrs = ap_copy_table(r->pool, r->headers_in);

/* remove hop-by-hop headers */
        ap_proxy_clear_connection(r->pool, req_hdrs);

/* save original request headers */
        if (c->req_hdrs)
            ap_table_do(ap_proxy_send_hdr_line, c, c->req_hdrs, NULL);
        else
            ap_table_do(ap_proxy_send_hdr_line, c, r->headers_in, NULL);
        if (ap_bputs(CRLF, c->fp) == -1) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, c->req,
                          "proxy: error writing request headers terminating CRLF to %s", c->tempfile);
            c = ap_proxy_cache_error(c);
            break;
        }
        break;
    }

/* Was the server response a 304 Not Modified?
 *
 * If so, we have some work to do that we didn't do when we first
 * checked above. We need to fulfil the request, and we need to
 * copy the body from the old object to the new one.
 */

/* if response from server 304 not modified */
    if (r->status == HTTP_NOT_MODIFIED) {

/* fulfil the request */
        c->xcache = ap_pstrcat(r->pool, "HIT from ", ap_get_server_name(r), " (with revalidation)", NULL);
        return ap_proxy_cache_conditional(r, c, c->fp);

    }
    return DECLINED;
}

void ap_proxy_cache_tidy(cache_req *c)
{
    server_rec *s;
    long int bc;

    if (!c || !c->fp)
        return;

    s = c->req->server;

/* don't care how much was sent, but rather how much was written to cache
    ap_bgetopt(c->req->connection->client, BO_BYTECT, &bc);
 */
    bc = c->written;

    if (c->len != -1) {
/* file lengths don't match; don't cache it */
        if (bc != c->len) {
            ap_pclosef(c->req->pool, ap_bfileno(c->fp, B_WR));  /* no need to flush */
            unlink(c->tempfile);
            return;
        }
    }
/* don't care if aborted, cache it if fully retrieved from host!
    else if (c->req->connection->aborted) {
        ap_pclosef(c->req->pool, c->fp->fd);    / no need to flush /
        unlink(c->tempfile);
        return;
    }
*/
    else {
/* update content-length of file */
        char buff[17];
        off_t curpos;

        c->len = bc;
        ap_bflush(c->fp);
        ap_proxy_sec2hex(c->len, buff);
        curpos = lseek(ap_bfileno(c->fp, B_WR), 17 * 6, SEEK_SET);
        if (curpos == -1)
            ap_log_error(APLOG_MARK, APLOG_ERR, s,
                      "proxy: error seeking on cache file %s", c->tempfile);
        else if (write(ap_bfileno(c->fp, B_WR), buff, sizeof(buff) - 1) == -1)
            ap_log_error(APLOG_MARK, APLOG_ERR, s,
                         "proxy: error updating cache file %s", c->tempfile);
    }

    if (ap_bflush(c->fp) == -1) {
        ap_log_error(APLOG_MARK, APLOG_ERR, s,
                     "proxy: error writing to cache file %s",
                     c->tempfile);
        ap_pclosef(c->req->pool, ap_bfileno(c->fp, B_WR));
        unlink(c->tempfile);
        return;
    }

    if (ap_pclosef(c->req->pool, ap_bfileno(c->fp, B_WR))== -1) {
        ap_log_error(APLOG_MARK, APLOG_ERR, s,
                     "proxy: error closing cache file %s", c->tempfile);
        unlink(c->tempfile);
        return;
    }

    if (unlink(c->filename) == -1 && errno != ENOENT) {
        ap_log_error(APLOG_MARK, APLOG_ERR, s,
                     "proxy: error deleting old cache file %s",
                     c->filename);
        (void)unlink(c->tempfile);
    }
    else {
        char *p;
        proxy_server_conf *conf =
        (proxy_server_conf *)ap_get_module_config(s->module_config, &proxy_module);

        for (p = c->filename + strlen(conf->cache.root) + 1;;) {
            p = strchr(p, '/');
            if (!p)
                break;
            *p = '\0';
#if defined(WIN32) || defined(NETWARE)
            if (mkdir(c->filename) < 0 && errno != EEXIST)
#elif defined(__TANDEM)
                if (mkdir(c->filename, S_IRWXU | S_IRWXG | S_IRWXO) < 0 && errno != EEXIST)
#else
            if (mkdir(c->filename, S_IREAD | S_IWRITE | S_IEXEC) < 0 && errno != EEXIST)
#endif                          /* WIN32 */
                ap_log_error(APLOG_MARK, APLOG_ERR, s,
                             "proxy: error creating cache directory %s",
                             c->filename);
            *p = '/';
            ++p;
        }
#if defined(OS2) || defined(WIN32) || defined(NETWARE) || defined(MPE)
        /* Under OS/2 use rename. */
        if (rename(c->tempfile, c->filename) == -1) {
            ap_log_error(APLOG_MARK, APLOG_ERR, s,
                         "proxy: error renaming cache file %s to %s",
                         c->tempfile, c->filename);
            (void)unlink(c->tempfile);
        }
#else

        if (link(c->tempfile, c->filename) == -1)
            ap_log_error(APLOG_MARK, APLOG_INFO, s,
                         "proxy: error linking cache file %s to %s",
                         c->tempfile, c->filename);
        if (unlink(c->tempfile) == -1)
            ap_log_error(APLOG_MARK, APLOG_ERR, s,
                         "proxy: error deleting temp file %s", c->tempfile);
#endif
    }
}
