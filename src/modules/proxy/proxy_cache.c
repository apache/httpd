/* ====================================================================
 * Copyright (c) 1996-1999 The Apache Group.  All rights reserved.
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
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the Apache Group
 *    for use in the Apache HTTP server project (http://www.apache.org/)."
 *
 * 4. The names "Apache Server" and "Apache Group" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    apache@apache.org.
 *
 * 5. Products derived from this software may not be called "Apache"
 *    nor may "Apache" appear in their names without prior written
 *    permission of the Apache Group.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the Apache Group
 *    for use in the Apache HTTP server project (http://www.apache.org/)."
 *
 * THIS SOFTWARE IS PROVIDED BY THE APACHE GROUP ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE APACHE GROUP OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Group and was originally based
 * on public domain software written at the National Center for
 * Supercomputing Applications, University of Illinois, Urbana-Champaign.
 * For more information on the Apache Group and the Apache HTTP server
 * project, please see <http://www.apache.org/>.
 *
 */

/* Cache and garbage collection routines for Apache proxy */

#include "mod_proxy.h"
#include "http_conf_globals.h"
#include "http_log.h"
#include "http_main.h"
#include "util_date.h"
#ifdef WIN32
#include <sys/utime.h>
#else
#include <utime.h>
#endif /* WIN32 */
#include "multithread.h"
#include "ap_md5.h"

DEF_Explain

struct gc_ent {
    unsigned long int len;
    time_t expire;
    char file[HASH_LEN + 1];
};

/* Poor man's 61 bit arithmetic */
typedef struct {
    long lower;	/* lower 30 bits of result */
    long upper; /* upper 31 bits of result */
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
static long block_size = 512;	/* this must be a power of 2 */
static long61_t curbytes, cachesize;
static time_t every, garbage_now, garbage_expire;
static char *filename;
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
#if !defined(WIN32) && !defined(MPE) && !defined(OS2)
static void detached_proxy_garbage_coll(request_rec *r);
#endif


void ap_proxy_garbage_coll(request_rec *r)
{
    static int inside = 0;

    (void) ap_acquire_mutex(garbage_mutex);
    if (inside == 1) {
	(void) ap_release_mutex(garbage_mutex);
	return;
    }
    else
	inside = 1;
    (void) ap_release_mutex(garbage_mutex);

    ap_block_alarms();		/* avoid SIGALRM on big cache cleanup */
#if !defined(WIN32) && !defined(MPE) && !defined(OS2)
    detached_proxy_garbage_coll(r);
#else
    help_proxy_garbage_coll(r);
#endif
    ap_unblock_alarms();

    (void) ap_acquire_mutex(garbage_mutex);
    inside = 0;
    (void) ap_release_mutex(garbage_mutex);
}


static void
add_long61 (long61_t *accu, long val)
{
    /* Add in lower 30 bits */
    accu->lower += (val & 0x3FFFFFFFL);
    /* add in upper bits, and carry */
    accu->upper += (val >> 30) + ((accu->lower & ~0x3FFFFFFFL) != 0L);
    /* Clear carry */
    accu->lower &= 0x3FFFFFFFL;
}

static void
sub_long61 (long61_t *accu, long val)
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
static long
cmp_long61 (long61_t *left, long61_t *right)
{
    return (left->upper == right->upper) ? (left->lower - right->lower)
					 : (left->upper - right->upper);
}

/* Compare two gc_ent's, sort them by expiration date */
static int gcdiff(const void *ap, const void *bp)
{
    const struct gc_ent *a = (const struct gc_ent * const) ap;
    const struct gc_ent *b = (const struct gc_ent * const) bp;

    if (a->expire > b->expire)
	return 1;
    else if (a->expire < b->expire)
	return -1;
    else
	return 0;
}

#if !defined(WIN32) && !defined(MPE) && !defined(OS2)
static void detached_proxy_garbage_coll(request_rec *r)
{
    pid_t pid;
    int status;
    pid_t pgrp;

    switch (pid = fork()) {
	case -1:
	    ap_log_error(APLOG_MARK, APLOG_ERR, r->server,
			 "proxy: fork() for cache cleanup failed");
	    return;

	case 0:	/* Child */

	    /* close all sorts of things, including the socket fd */
	    ap_cleanup_for_exec();

	    /* Fork twice to disassociate from the child */
	    switch (pid = fork()) {
		case -1:
		    ap_log_error(APLOG_MARK, APLOG_ERR, r->server,
			 "proxy: fork(2nd) for cache cleanup failed");
		    exit(1);

		case 0:	/* Child */
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

		default:    /* Father */
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
#endif /* ndef WIN32 */

static void help_proxy_garbage_coll(request_rec *r)
{
    const char *cachedir;
    void *sconf = r->server->module_config;
    proxy_server_conf *pconf =
    (proxy_server_conf *) ap_get_module_config(sconf, &proxy_module);
    const struct cache_conf *conf = &pconf->cache;
    array_header *files;
    struct stat buf;
    struct gc_ent *fent;
    int i, timefd;
    static time_t lastcheck = BAD_DATE;		/* static (per-process) data!!! */

    cachedir = conf->root;
    /* configured size is given in kB. Make it bytes, convert to long61_t: */
    cachesize.lower = cachesize.upper = 0;
    add_long61(&cachesize, conf->space << 10);
    every = conf->gcinterval;

    if (cachedir == NULL || every == -1)
	return;
    garbage_now = time(NULL);
    /* Usually, the modification time of <cachedir>/.time can only increase.
     * Thus, even with several child processes having their own copy of
     * lastcheck, if time(NULL) still < lastcheck then it's not time
     * for GC yet.
     */
    if (garbage_now != -1 && lastcheck != BAD_DATE && garbage_now < lastcheck + every)
	return;

    ap_block_alarms();		/* avoid SIGALRM on big cache cleanup */

    filename = ap_palloc(r->pool, strlen(cachedir) + HASH_LEN + 2);
    strcpy(filename, cachedir);
    strcat(filename, "/.time");
    if (stat(filename, &buf) == -1) {	/* does not exist */
	if (errno != ENOENT) {
	    ap_log_error(APLOG_MARK, APLOG_ERR, r->server,
			 "proxy: stat(%s)", filename);
	    ap_unblock_alarms();
	    return;
	}
	if ((timefd = creat(filename, 0666)) == -1) {
	    if (errno != EEXIST)
		ap_log_error(APLOG_MARK, APLOG_ERR, r->server,
			     "proxy: creat(%s)", filename);
	    else
		lastcheck = garbage_now;	/* someone else got in there */
	    ap_unblock_alarms();
	    return;
	}
	close(timefd);
    }
    else {
	lastcheck = buf.st_mtime;	/* save the time */
	if (garbage_now < lastcheck + every) {
	    ap_unblock_alarms();
	    return;
	}
	if (utime(filename, NULL) == -1)
	    ap_log_error(APLOG_MARK, APLOG_ERR, r->server,
			 "proxy: utimes(%s)", filename);
    }
    files = ap_make_array(r->pool, 100, sizeof(struct gc_ent));
    curbytes.upper = curbytes.lower = 0L;

    sub_garbage_coll(r, files, cachedir, "/");

    if (cmp_long61(&curbytes, &cachesize) < 0L) {
	ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, r->server,
			 "proxy GC: Cache is %ld%% full (nothing deleted)",
			 (long)(((curbytes.upper<<20)|(curbytes.lower>>10))*100/conf->space));
	ap_unblock_alarms();
	return;
    }

    /* sort the files we found by expiration date */
    qsort(files->elts, files->nelts, sizeof(struct gc_ent), gcdiff);

    for (i = 0; i < files->nelts; i++) {
	fent = &((struct gc_ent *) files->elts)[i];
	sprintf(filename, "%s%s", cachedir, fent->file);
	Explain3("GC Unlinking %s (expiry %ld, garbage_now %ld)", filename, fent->expire, garbage_now);
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

    ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, r->server,
			 "proxy GC: Cache is %ld%% full (%d deleted)",
			 (long)(((curbytes.upper<<20)|(curbytes.lower>>10))*100/conf->space), i);
    ap_unblock_alarms();
}

static int sub_garbage_coll(request_rec *r, array_header *files,
			  const char *cachebasedir, const char *cachesubdir)
{
    char line[27];
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

    ap_snprintf(cachedir, sizeof(cachedir), "%s%s", cachebasedir, cachesubdir);
    Explain1("GC Examining directory %s", cachedir);
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
	Explain1("GC Examining file %s", filename);
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
		Explain1("GC unlink %s", filename);
		ap_log_error(APLOG_MARK, APLOG_INFO|APLOG_NOERRNO, r->server,
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
	/*      if (strlen(ent->d_name) != HASH_LEN) continue; */

/* under OS/2 use dirent's d_attr to identify a diretory */
#ifdef OS2
/* is it a directory? */
	if (ent->d_attr & A_DIR) {
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

/* In OS/2 this has already been done above */
#ifndef OS2
	if (S_ISDIR(buf.st_mode)) {
	    char newcachedir[HUGE_STRING_LEN];
	    close(fd);
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
	    } else {
		/* Directory is not empty. Account for its size: */
		add_long61(&curbytes, ROUNDUP2BLOCKS(buf.st_size));
	    }
	    continue;
	}
#endif

	i = read(fd, line, 26);
	close(fd);
	if (i == -1) {
	    ap_log_error(APLOG_MARK, APLOG_ERR, r->server,
			 "proxy gc: read(%s)", filename);
	    continue;
	}
	line[i] = '\0';
	garbage_expire = ap_proxy_hex2sec(line + 18);
	if (!ap_checkmask(line, "&&&&&&&& &&&&&&&& &&&&&&&&") ||
	    garbage_expire == BAD_DATE) {
	    /* bad file */
	    if (garbage_now != -1 && buf.st_atime > garbage_now + SEC_ONE_DAY &&
		buf.st_mtime > garbage_now + SEC_ONE_DAY) {
		ap_log_error(APLOG_MARK, APLOG_WARNING|APLOG_NOERRNO, r->server,
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
 * read a cache file;
 * returns 1 on success,
 *         0 on failure (bad file or wrong URL)
 *        -1 on UNIX error
 */
static int rdcache(request_rec *r, BUFF *cachefp, cache_req *c)
{
    char urlbuff[1034], *strp;
    int len;
/* read the data from the cache file */
/* format
 * date SP lastmod SP expire SP count SP content-length CRLF
 * dates are stored as hex seconds since 1970
 */
    len = ap_bgets(urlbuff, sizeof urlbuff, cachefp);
    if (len == -1)
	return -1;
    if (len == 0 || urlbuff[len - 1] != '\n')
	return 0;
    urlbuff[len - 1] = '\0';

    if (!ap_checkmask(urlbuff,
		   "&&&&&&&& &&&&&&&& &&&&&&&& &&&&&&&& &&&&&&&&"))
	return 0;

    c->date = ap_proxy_hex2sec(urlbuff);
    c->lmod = ap_proxy_hex2sec(urlbuff + 9);
    c->expire = ap_proxy_hex2sec(urlbuff + 18);
    c->version = ap_proxy_hex2sec(urlbuff + 27);
    c->len = ap_proxy_hex2sec(urlbuff + 36);

/* check that we have the same URL */
    len = ap_bgets(urlbuff, sizeof urlbuff, cachefp);
    if (len == -1)
	return -1;
    if (len == 0 || strncmp(urlbuff, "X-URL: ", 7) != 0 ||
	urlbuff[len - 1] != '\n')
	return 0;
    urlbuff[len - 1] = '\0';
    if (strcmp(urlbuff + 7, c->url) != 0)
	return 0;

/* What follows is the message */
    len = ap_bgets(urlbuff, sizeof urlbuff, cachefp);
    if (len == -1)
	return -1;
    if (len == 0 || urlbuff[len - 1] != '\n')
	return 0;
    urlbuff[--len] = '\0';

    c->resp_line = ap_pstrdup(r->pool, urlbuff);
    strp = strchr(urlbuff, ' ');
    if (strp == NULL)
	return 0;

    c->status = atoi(strp);
    c->hdrs = ap_proxy_read_headers(r, urlbuff, sizeof urlbuff, cachefp);
    if (c->hdrs == NULL)
	return -1;
    if (c->len != -1) {		/* add a content-length header */
	if (ap_table_get(c->hdrs, "Content-Length") == NULL) {
	    ap_table_set(c->hdrs, "Content-Length",
			 ap_psprintf(r->pool, "%lu", (unsigned long)c->len));
	}
    }
    return 1;
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
 *      else
 *         if last modified after if-modified-since then add
 *            last modified date to request
 */
int ap_proxy_cache_check(request_rec *r, char *url, struct cache_conf *conf,
		      cache_req **cr)
{
    char hashfile[66];
    const char *imstr, *pragma, *auth;
    cache_req *c;
    time_t now;
    BUFF *cachefp;
    int cfd, i;
    const long int zero = 0L;
    void *sconf = r->server->module_config;
    proxy_server_conf *pconf =
    (proxy_server_conf *) ap_get_module_config(sconf, &proxy_module);

    c = ap_pcalloc(r->pool, sizeof(cache_req));
    *cr = c;
    c->req = r;
    c->url = ap_pstrdup(r->pool, url);

/* get the If-Modified-Since date of the request */
    c->ims = BAD_DATE;
    imstr = ap_table_get(r->headers_in, "If-Modified-Since");
    if (imstr != NULL) {
/* this may modify the value in the original table */
	imstr = ap_proxy_date_canon(r->pool, imstr);
	c->ims = ap_parseHTTPdate(imstr);
	if (c->ims == BAD_DATE)	/* bad or out of range date; remove it */
	    ap_table_unset(r->headers_in, "If-Modified-Since");
    }

/* find the filename for this cache entry */
    ap_proxy_hash(url, hashfile, pconf->cache.dirlevels, pconf->cache.dirlength);
    if (conf->root != NULL)
	c->filename = ap_pstrcat(r->pool, conf->root, "/", hashfile, NULL);
    else
	c->filename = NULL;

    cachefp = NULL;
/* find out about whether the request can access the cache */
    pragma = ap_table_get(r->headers_in, "Pragma");
    auth = ap_table_get(r->headers_in, "Authorization");
    Explain5("Request for %s, pragma=%s, auth=%s, ims=%ld, imstr=%s", url,
	     pragma, auth, c->ims, imstr);
    if (c->filename != NULL && r->method_number == M_GET &&
	strlen(url) < 1024 && !ap_proxy_liststr(pragma, "no-cache") &&
	auth == NULL) {
	Explain1("Check file %s", c->filename);
	cfd = open(c->filename, O_RDWR | O_BINARY);
	if (cfd != -1) {
	    ap_note_cleanups_for_fd(r->pool, cfd);
	    cachefp = ap_bcreate(r->pool, B_RD | B_WR);
	    ap_bpushfd(cachefp, cfd, cfd);
	}
	else if (errno != ENOENT)
	    ap_log_rerror(APLOG_MARK, APLOG_ERR, r,
			 "proxy: error opening cache file %s",
			 c->filename);
#ifdef EXPLAIN
	else
	    Explain1("File %s not found", c->filename);
#endif
    }

    if (cachefp != NULL) {
	i = rdcache(r, cachefp, c);
	if (i == -1)
	    ap_log_rerror(APLOG_MARK, APLOG_ERR, r,
			 "proxy: error reading cache file %s", 
			 c->filename);
	else if (i == 0)
	    ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, r,
			 "proxy: bad (short?) cache file: %s", c->filename);
	if (i != 1) {
	    ap_pclosef(r->pool, cachefp->fd);
	    cachefp = NULL;
	}
    }
/* fixed?  in this case, we want to get the headers from the remote server
   it will be handled later if we don't do this (I hope ;-)
    if (cachefp == NULL)
	c->hdrs = ap_make_table(r->pool, 20);
*/
    /* FIXME: Shouldn't we check the URL somewhere? */
    now = time(NULL);
/* Ok, have we got some un-expired data? */
    if (cachefp != NULL && c->expire != BAD_DATE && now < c->expire) {
	Explain0("Unexpired data available");
/* check IMS */
	if (c->lmod != BAD_DATE && c->ims != BAD_DATE && c->ims >= c->lmod) {
/* has the cached file changed since this request? */
	    if (c->date == BAD_DATE || c->date > c->ims) {
/* No, but these header values may have changed, so we send them with the
 * 304 HTTP_NOT_MODIFIED response
 */
		const char *q;

		if ((q = ap_table_get(c->hdrs, "Expires")) != NULL)
		    ap_table_set(r->headers_out, "Expires", q);
	    }
	    ap_pclosef(r->pool, cachefp->fd);
	    Explain0("Use local copy, cached file hasn't changed");
	    return HTTP_NOT_MODIFIED;
	}

/* Ok, has been modified */
	Explain0("Local copy modified, send it");
	r->status_line = strchr(c->resp_line, ' ') + 1;
	r->status = c->status;
	if (!r->assbackwards) {
	    ap_soft_timeout("proxy send headers", r);
	    ap_proxy_send_headers(r, c->resp_line, c->hdrs);
	    ap_kill_timeout(r);
	}
	ap_bsetopt(r->connection->client, BO_BYTECT, &zero);
	r->sent_bodyct = 1;
	if (!r->header_only)
	    ap_proxy_send_fb(cachefp, r, NULL);
	ap_pclosef(r->pool, cachefp->fd);
	return OK;
    }

/* if we already have data and a last-modified date, and it is not a head
 * request, then add an If-Modified-Since
 */

    if (cachefp != NULL && c->lmod != BAD_DATE && !r->header_only) {
/*
 * use the later of the one from the request and the last-modified date
 * from the cache
 */
	if (c->ims == BAD_DATE || c->ims < c->lmod) {
	    const char *q;

	    if ((q = ap_table_get(c->hdrs, "Last-Modified")) != NULL)
		ap_table_set(r->headers_in, "If-Modified-Since",
			  (char *) q);
	}
    }
    c->fp = cachefp;

    Explain0("Local copy not present or expired. Declining.");

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
#ifdef ULTRIX_BRAIN_DEATH
  extern char *mktemp(char *template);
#endif 
    request_rec *r = c->req;
    char *p;
    int i;
    const char *expire, *lmods, *dates, *clen;
    time_t expc, date, lmod, now;
    char buff[46];
    void *sconf = r->server->module_config;
    proxy_server_conf *conf =
    (proxy_server_conf *) ap_get_module_config(sconf, &proxy_module);
    const long int zero = 0L;

    c->tempfile = NULL;

/* we've received the response */
/* read expiry date; if a bad date, then leave it so the client can
 * read it
 */
    expire = ap_table_get(resp_hdrs, "Expires");
    if (expire != NULL)
	expc = ap_parseHTTPdate(expire);
    else
	expc = BAD_DATE;

/*
 * read the last-modified date; if the date is bad, then delete it
 */
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
 * Unknown status responses and those known to be uncacheable
 * 304 HTTP_NOT_MODIFIED response when we have no valid cache file, or
 * 200 HTTP_OK response from HTTP/1.0 and up without a Last-Modified header, or
 * HEAD requests, or
 * requests with an Authorization header, or
 * protocol requests nocache (e.g. ftp with user/password)
 */
/* @@@ XXX FIXME: is the test "r->status != HTTP_MOVED_PERMANENTLY" corerct?
 * or shouldn't it be "ap_is_HTTP_REDIRECT(r->status)" ? -MnKr */
    if ((r->status != HTTP_OK && r->status != HTTP_MOVED_PERMANENTLY && r->status != HTTP_NOT_MODIFIED) ||
	(expire != NULL && expc == BAD_DATE) ||
	(r->status == HTTP_NOT_MODIFIED && (c == NULL || c->fp == NULL)) ||
	(r->status == HTTP_OK && lmods == NULL && is_HTTP1) ||
	r->header_only ||
	ap_table_get(r->headers_in, "Authorization") != NULL ||
	nocache) {
	Explain1("Response is not cacheable, unlinking %s", c->filename);
/* close the file */
	if (c->fp != NULL) {
	    ap_pclosef(r->pool, c->fp->fd);
	    c->fp = NULL;
	}
/* delete the previously cached file */
        if (c->filename)
            unlink(c->filename);
	return DECLINED;	/* send data to client but not cache */
    }

/* otherwise, we are going to cache the response */
/*
 * Read the date. Generate one if one is not supplied
 */
    dates = ap_table_get(resp_hdrs, "Date");
    if (dates != NULL)
	date = ap_parseHTTPdate(dates);
    else
	date = BAD_DATE;

    now = time(NULL);

    if (date == BAD_DATE) {	/* No, or bad date */
/* no date header! */
/* add one; N.B. use the time _now_ rather than when we were checking the cache
 */
	date = now;
	dates = ap_gm_timestr_822(r->pool, now);
	ap_table_set(resp_hdrs, "Date", dates);
	Explain0("Added date header");
    }

/* check last-modified date */
    if (lmod != BAD_DATE && lmod > date)
/* if its in the future, then replace by date */
    {
	lmod = date;
	lmods = dates;
	Explain0("Last modified is in the future, replacing with now");
    }
/* if the response did not contain the header, then use the cached version */
    if (lmod == BAD_DATE && c->fp != NULL) {
	lmod = c->lmod;
	Explain0("Reusing cached last modified");
    }

/* we now need to calculate the expire data for the object. */
    if (expire == NULL && c->fp != NULL) {	/* no expiry data sent in response */
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
    Explain1("Expiry date is %ld", expc);
    if (expc == BAD_DATE) {
	if (lmod != BAD_DATE) {
	    double x = (double) (date - lmod) * conf->cache.lmfactor;
	    double maxex = conf->cache.maxexpire;
	    if (x > maxex)
		x = maxex;
	    expc = now + (int) x;
	}
	else
	    expc = now + conf->cache.defaultexpire;
	Explain1("Expiry date calculated %ld", expc);
    }

/* get the content-length header */
    clen = ap_table_get(resp_hdrs, "Content-Length");
    if (clen == NULL)
	c->len = -1;
    else
	c->len = atoi(clen);

    ap_proxy_sec2hex(date, buff);
    buff[8] = ' ';
    ap_proxy_sec2hex(lmod, buff + 9);
    buff[17] = ' ';
    ap_proxy_sec2hex(expc, buff + 18);
    buff[26] = ' ';
    ap_proxy_sec2hex(c->version++, buff + 27);
    buff[35] = ' ';
    ap_proxy_sec2hex(c->len, buff + 36);
    buff[44] = '\n';
    buff[45] = '\0';

/* if file not modified */
    if (r->status == HTTP_NOT_MODIFIED) {
	if (c->ims != BAD_DATE && lmod != BAD_DATE && lmod <= c->ims) {
/* set any changed headers somehow */
/* update dates and version, but not content-length */
	    if (lmod != c->lmod || expc != c->expire || date != c->date) {
		off_t curpos = lseek(c->fp->fd, 0, SEEK_SET);
		if (curpos == -1)
		    ap_log_rerror(APLOG_MARK, APLOG_ERR, r,
				 "proxy: error seeking on cache file %s",
				 c->filename);
		else if (write(c->fp->fd, buff, 35) == -1)
		    ap_log_rerror(APLOG_MARK, APLOG_ERR, r,
				 "proxy: error updating cache file %s",
				 c->filename);
	    }
	    ap_pclosef(r->pool, c->fp->fd);
	    Explain0("Remote document not modified, use local copy");
	    /* CHECKME: Is this right? Shouldn't we check IMS again here? */
	    return HTTP_NOT_MODIFIED;
	}
	else {
/* return the whole document */
	    Explain0("Remote document updated, sending");
	    r->status_line = strchr(c->resp_line, ' ') + 1;
	    r->status = c->status;
	    if (!r->assbackwards) {
		ap_soft_timeout("proxy send headers", r);
		ap_proxy_send_headers(r, c->resp_line, c->hdrs);
		ap_kill_timeout(r);
	    }
	    ap_bsetopt(r->connection->client, BO_BYTECT, &zero);
	    r->sent_bodyct = 1;
	    if (!r->header_only)
		ap_proxy_send_fb(c->fp, r, NULL);
/* set any changed headers somehow */
/* update dates and version, but not content-length */
	    if (lmod != c->lmod || expc != c->expire || date != c->date) {
		off_t curpos = lseek(c->fp->fd, 0, SEEK_SET);

		if (curpos == -1)
		    ap_log_rerror(APLOG_MARK, APLOG_ERR, r,
				 "proxy: error seeking on cache file %s",
				 c->filename);
		else if (write(c->fp->fd, buff, 35) == -1)
		    ap_log_rerror(APLOG_MARK, APLOG_ERR, r,
				 "proxy: error updating cache file %s",
				 c->filename);
	    }
	    ap_pclosef(r->pool, c->fp->fd);
	    return OK;
	}
    }
/* new or modified file */
    if (c->fp != NULL) {
	ap_pclosef(r->pool, c->fp->fd);
	c->fp->fd = -1;
    }
    c->version = 0;
    ap_proxy_sec2hex(0, buff + 27);
    buff[35] = ' ';

/* open temporary file */
#define TMPFILESTR	"/tmpXXXXXX"
    if (conf->cache.root == NULL)
	return DECLINED;
    c->tempfile = ap_palloc(r->pool, strlen(conf->cache.root) + sizeof(TMPFILESTR));
    strcpy(c->tempfile, conf->cache.root);
    strcat(c->tempfile, TMPFILESTR);
#undef TMPFILESTR
    p = mktemp(c->tempfile);
    if (p == NULL)
	return DECLINED;

    Explain1("Create temporary file %s", c->tempfile);

    i = open(c->tempfile, O_WRONLY | O_CREAT | O_EXCL | O_BINARY, 0622);
    if (i == -1) {
	ap_log_rerror(APLOG_MARK, APLOG_ERR, r,
		     "proxy: error creating cache file %s",
		     c->tempfile);
	return DECLINED;
    }
    ap_note_cleanups_for_fd(r->pool, i);
    c->fp = ap_bcreate(r->pool, B_WR);
    ap_bpushfd(c->fp, -1, i);

    if (ap_bvputs(c->fp, buff, "X-URL: ", c->url, "\n", NULL) == -1) {
	ap_log_rerror(APLOG_MARK, APLOG_ERR, r,
		     "proxy: error writing cache file(%s)", c->tempfile);
	ap_pclosef(r->pool, c->fp->fd);
	unlink(c->tempfile);
	c->fp = NULL;
    }
    return DECLINED;
}

void ap_proxy_cache_tidy(cache_req *c)
{
    server_rec *s;
    long int bc;

    if (c == NULL || c->fp == NULL)
	return;

    s = c->req->server;

/* don't care how much was sent, but rather how much was written to cache
    ap_bgetopt(c->req->connection->client, BO_BYTECT, &bc);
 */
    bc = c->written;

    if (c->len != -1) {
/* file lengths don't match; don't cache it */
	if (bc != c->len) {
	    ap_pclosef(c->req->pool, c->fp->fd);	/* no need to flush */
	    unlink(c->tempfile);
	    return;
	}
    }
/* don't care if aborted, cache it if fully retrieved from host!
    else if (c->req->connection->aborted) {
	ap_pclosef(c->req->pool, c->fp->fd);	/ no need to flush /
	unlink(c->tempfile);
	return;
    }
*/
    else {
/* update content-length of file */
	char buff[9];
	off_t curpos;

	c->len = bc;
	ap_bflush(c->fp);
	ap_proxy_sec2hex(c->len, buff);
	curpos = lseek(c->fp->fd, 36, SEEK_SET);
	if (curpos == -1)
	    ap_log_error(APLOG_MARK, APLOG_ERR, s,
			 "proxy: error seeking on cache file %s", c->tempfile);
	else if (write(c->fp->fd, buff, 8) == -1)
	    ap_log_error(APLOG_MARK, APLOG_ERR, s,
			 "proxy: error updating cache file %s", c->tempfile);
    }

    if (ap_bflush(c->fp) == -1) {
	ap_log_error(APLOG_MARK, APLOG_ERR, s,
		     "proxy: error writing to cache file %s",
		     c->tempfile);
	ap_pclosef(c->req->pool, c->fp->fd);
	unlink(c->tempfile);
	return;
    }

    if (ap_pclosef(c->req->pool, c->fp->fd) == -1) {
	ap_log_error(APLOG_MARK, APLOG_ERR, s,
		     "proxy: error closing cache file %s", c->tempfile);
	unlink(c->tempfile);
	return;
    }

    if (unlink(c->filename) == -1 && errno != ENOENT) {
	ap_log_error(APLOG_MARK, APLOG_ERR, s,
		     "proxy: error deleting old cache file %s",
		     c->tempfile);
    }
    else {
	char *p;
	proxy_server_conf *conf =
	(proxy_server_conf *) ap_get_module_config(s->module_config, &proxy_module);

	for (p = c->filename + strlen(conf->cache.root) + 1;;) {
	    p = strchr(p, '/');
	    if (!p)
		break;
	    *p = '\0';
#ifdef WIN32
	    if (mkdir(c->filename) < 0 && errno != EEXIST)
#else
	    if (mkdir(c->filename, S_IREAD | S_IWRITE | S_IEXEC) < 0 && errno != EEXIST)
#endif /* WIN32 */
		ap_log_error(APLOG_MARK, APLOG_ERR, s,
			     "proxy: error creating cache directory %s",
			     c->filename);
	    *p = '/';
	    ++p;
	}
#if defined(OS2) || defined(WIN32)
	/* Under OS/2 use rename. */
	if (rename(c->tempfile, c->filename) == -1)
	    ap_log_error(APLOG_MARK, APLOG_ERR, s,
			 "proxy: error renaming cache file %s to %s",
			 c->tempfile, c->filename);
    }
#else

	if (link(c->tempfile, c->filename) == -1)
	    ap_log_error(APLOG_MARK, APLOG_ERR, s,
			 "proxy: error linking cache file %s to %s",
			 c->tempfile, c->filename);
    }

    if (unlink(c->tempfile) == -1)
	ap_log_error(APLOG_MARK, APLOG_ERR, s,
		     "proxy: error deleting temp file %s", c->tempfile);
#endif

}
