/* ====================================================================
 * Copyright (c) 1996-1998 The Apache Group.  All rights reserved.
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
#include "http_log.h"
#include "http_main.h"
#include "util_date.h"
#ifdef WIN32
#include <sys/utime.h>
#else
#include <utime.h>
#endif /* WIN32 */
#include "multithread.h"
#include "md5.h"

DEF_Explain

#ifndef abs
#define	abs(c)	((c) >= 0 ? (c) : -(c))
#endif

struct gc_ent {
    unsigned long int len;
    time_t expire;
    char file[HASH_LEN + 1];

};

static int gcdiff(const void *ap, const void *bp)
{
    const struct gc_ent *a = *(const struct gc_ent * const *) ap;
    const struct gc_ent *b = *(const struct gc_ent * const *) bp;

    if (a->expire > b->expire)
	return 1;
    else if (a->expire < b->expire)
	return -1;
    else
	return 0;
}

static int curbytes, cachesize, every;
static unsigned long int curblocks;
static time_t garbage_now, garbage_expire;
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

    help_proxy_garbage_coll(r);

    (void) ap_acquire_mutex(garbage_mutex);
    inside = 0;
    (void) ap_release_mutex(garbage_mutex);
}


static void help_proxy_garbage_coll(request_rec *r)
{
    const char *cachedir;
    void *sconf = r->server->module_config;
    proxy_server_conf *pconf =
    (proxy_server_conf *) ap_get_module_config(sconf, &proxy_module);
    const struct cache_conf *conf = &pconf->cache;
    array_header *files;
    struct stat buf;
    struct gc_ent *fent, **elts;
    int i, timefd;
    static time_t lastcheck = BAD_DATE;		/* static data!!! */

    cachedir = conf->root;
    cachesize = conf->space;
    every = conf->gcinterval;

    if (cachedir == NULL || every == -1)
	return;
    garbage_now = time(NULL);
    if (garbage_now != -1 && lastcheck != BAD_DATE && garbage_now < lastcheck + every)
	return;

    ap_block_alarms();		/* avoid SIGALRM on big cache cleanup */

    filename = ap_palloc(r->pool, strlen(cachedir) + HASH_LEN + 2);
    strcpy(filename, cachedir);
    strcat(filename, "/.time");
    if (stat(filename, &buf) == -1) {	/* does not exist */
	if (errno != ENOENT) {
	    ap_proxy_log_uerror("stat", filename, NULL, r->server);
	    ap_unblock_alarms();
	    return;
	}
	if ((timefd = creat(filename, 0666)) == -1) {
	    if (errno != EEXIST)
		ap_proxy_log_uerror("creat", filename, NULL, r->server);
	    else
		lastcheck = abs(garbage_now);	/* someone else got in there */
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
	    ap_proxy_log_uerror("utimes", filename, NULL, r->server);
    }
    files = ap_make_array(r->pool, 100, sizeof(struct gc_ent *));
    curblocks = 0;
    curbytes = 0;

    sub_garbage_coll(r, files, cachedir, "/");

    if (curblocks < cachesize || curblocks + curbytes <= cachesize) {
	ap_unblock_alarms();
	return;
    }

    qsort(files->elts, files->nelts, sizeof(struct gc_ent *), gcdiff);

    elts = (struct gc_ent **) files->elts;
    for (i = 0; i < files->nelts; i++) {
	fent = elts[i];
	sprintf(filename, "%s%s", cachedir, fent->file);
	Explain3("GC Unlinking %s (expiry %ld, garbage_now %ld)", filename, fent->expire, garbage_now);
#if TESTING
	fprintf(stderr, "Would unlink %s\n", filename);
#else
	if (unlink(filename) == -1) {
	    if (errno != ENOENT)
		ap_proxy_log_uerror("unlink", filename, NULL, r->server);
	}
	else
#endif
	{
	    curblocks -= fent->len >> 10;
	    curbytes -= fent->len & 0x3FF;
	    if (curbytes < 0) {
		curbytes += 1024;
		curblocks--;
	    }
	    if (curblocks < cachesize || curblocks + curbytes <= cachesize)
		break;
	}
    }
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
	ap_proxy_log_uerror("opendir", cachedir, NULL, r->server);
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
		    ap_proxy_log_uerror("stat", filename, NULL, r->server);
	    }
	    else if (garbage_now != -1 && buf.st_atime < garbage_now - SEC_ONE_DAY &&
		     buf.st_mtime < garbage_now - SEC_ONE_DAY) {
		Explain1("GC unlink %s", filename);
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
#ifdef __EMX__
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
		ap_proxy_log_uerror("open", filename, NULL,
				 r->server);
	    continue;
	}
	if (fstat(fd, &buf) == -1) {
	    ap_proxy_log_uerror("fstat", filename, NULL, r->server);
	    close(fd);
	    continue;
	}

/* In OS/2 this has already been done above */
#ifndef __EMX__
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
	    }
	    continue;
	}
#endif

	i = read(fd, line, 26);
	if (i == -1) {
	    ap_proxy_log_uerror("read", filename, NULL, r->server);
	    close(fd);
	    continue;
	}
	close(fd);
	line[i] = '\0';
	garbage_expire = ap_proxy_hex2sec(line + 18);
	if (!ap_checkmask(line, "&&&&&&&& &&&&&&&& &&&&&&&&") ||
	    garbage_expire == BAD_DATE) {
	    /* bad file */
	    if (garbage_now != -1 && buf.st_atime > garbage_now + SEC_ONE_DAY &&
		buf.st_mtime > garbage_now + SEC_ONE_DAY) {
		ap_log_error_old("proxy: deleting bad cache file", r->server);
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
	/* FIXME: We should make the array an array of gc_ents, not gc_ent *s
	 */
	fent = ap_palloc(r->pool, sizeof(struct gc_ent));
	fent->len = buf.st_size;
	fent->expire = garbage_expire;
	strcpy(fent->file, cachesubdir);
	strcat(fent->file, ent->d_name);
	*(struct gc_ent **) ap_push_array(files) = fent;

/* accumulate in blocks, to cope with directories > 4Gb */
	curblocks += buf.st_size >> 10;		/* Kbytes */
	curbytes += buf.st_size & 0x3FF;
	if (curbytes >= 1024) {
	    curbytes -= 1024;
	    curblocks++;
	}
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
static int rdcache(pool *p, BUFF *cachefp, struct cache_req *c)
{
    char urlbuff[1034], *strp;
    int len;
/* read the data from the cache file */
/* format
 * date SP lastmod SP expire SP count SP content-length CRLF
 * dates are stored as hex seconds since 1970
 */
    len = ap_bgets(urlbuff, 1034, cachefp);
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
    len = ap_bgets(urlbuff, 1034, cachefp);
    if (len == -1)
	return -1;
    if (len == 0 || strncmp(urlbuff, "X-URL: ", 7) != 0 ||
	urlbuff[len - 1] != '\n')
	return 0;
    urlbuff[len - 1] = '\0';
    if (strcmp(urlbuff + 7, c->url) != 0)
	return 0;

/* What follows is the message */
    len = ap_bgets(urlbuff, 1034, cachefp);
    if (len == -1)
	return -1;
    if (len == 0 || urlbuff[len - 1] != '\n')
	return 0;
    urlbuff[--len] = '\0';

    c->resp_line = ap_pstrdup(p, urlbuff);
    strp = strchr(urlbuff, ' ');
    if (strp == NULL)
	return 0;

    c->status = atoi(strp);
    c->hdrs = ap_proxy_read_headers(p, urlbuff, 1034, cachefp);
    if (c->hdrs == NULL)
	return -1;
    if (c->len != -1) {		/* add a content-length header */
	struct hdr_entry *q;
	q = ap_proxy_get_header(c->hdrs, "Content-Length");
	if (q == NULL) {
	    strp = ap_palloc(p, 15);
	    ap_snprintf(strp, 15, "%u", c->len);
	    ap_proxy_add_header(c->hdrs, "Content-Length", strp, HDR_REP);
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
		      struct cache_req **cr)
{
    char hashfile[66], *imstr, *pragma, *auth;
    struct cache_req *c;
    time_t now;
    BUFF *cachefp;
    int cfd, i;
    const long int zero = 0L;
    void *sconf = r->server->module_config;
    proxy_server_conf *pconf =
    (proxy_server_conf *) ap_get_module_config(sconf, &proxy_module);

    c = ap_pcalloc(r->pool, sizeof(struct cache_req));
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
	    ap_proxy_log_uerror("open", c->filename,
			     "proxy: error opening cache file", r->server);
#ifdef EXPLAIN
	else
	    Explain1("File %s not found", c->filename);
#endif
    }

    if (cachefp != NULL) {
	i = rdcache(r->pool, cachefp, c);
	if (i == -1)
	    ap_proxy_log_uerror("read", c->filename,
			     "proxy: error reading cache file", r->server);
	else if (i == 0)
	    ap_log_error_old("proxy: bad cache file", r->server);
	if (i != 1) {
	    ap_pclosef(r->pool, cachefp->fd);
	    cachefp = NULL;
	}
    }
    if (cachefp == NULL)
	c->hdrs = ap_make_array(r->pool, 2, sizeof(struct hdr_entry));
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
 * 304 response
 */
		/* CHECKME: surely this was wrong? (Ben)
		   p = table_get(r->headers_in, "Expires");
		 */
		struct hdr_entry *q;

		q = ap_proxy_get_header(c->hdrs, "Expires");
		if (q != NULL && q->value != NULL)
		    ap_table_set(r->headers_out, "Expires", q->value);
	    }
	    ap_pclosef(r->pool, cachefp->fd);
	    Explain0("Use local copy, cached file hasn't changed");
	    return USE_LOCAL_COPY;
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
	    ap_proxy_send_fb(cachefp, r, NULL, NULL);
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
	    struct hdr_entry *q;

	    q = ap_proxy_get_header(c->hdrs, "Last-Modified");

	    if (q != NULL && q->value != NULL)
		ap_table_set(r->headers_in, "If-Modified-Since",
			  (char *) q->value);
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
int ap_proxy_cache_update(struct cache_req *c, array_header *resp_hdrs,
		       const int is_HTTP1, int nocache)
{
#ifdef ULTRIX_BRAIN_DEATH
  extern char *mktemp(char *template);
#endif 
    request_rec *r = c->req;
    char *p;
    int i;
    struct hdr_entry *expire, *dates, *lmods, *clen;
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
    expire = ap_proxy_get_header(resp_hdrs, "Expires");
    if (expire != NULL)
	expc = ap_parseHTTPdate(expire->value);
    else
	expc = BAD_DATE;

/*
 * read the last-modified date; if the date is bad, then delete it
 */
    lmods = ap_proxy_get_header(resp_hdrs, "Last-Modified");
    if (lmods != NULL) {
	lmod = ap_parseHTTPdate(lmods->value);
	if (lmod == BAD_DATE) {
/* kill last modified date */
	    lmods->value = NULL;
	    lmods = NULL;
	}
    }
    else
	lmod = BAD_DATE;

/*
 * what responses should we not cache?
 * Unknown status responses and those known to be uncacheable
 * 304 response when we have no valid cache file, or
 * 200 response from HTTP/1.0 and up without a Last-Modified header, or
 * HEAD requests, or
 * requests with an Authorization header, or
 * protocol requests nocache (e.g. ftp with user/password)
 */
    if ((r->status != 200 && r->status != 301 && r->status != 304) ||
	(expire != NULL && expc == BAD_DATE) ||
	(r->status == 304 && c->fp == NULL) ||
	(r->status == 200 && lmods == NULL && is_HTTP1) ||
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
	unlink(c->filename);
	return DECLINED;	/* send data to client but not cache */
    }

/* otherwise, we are going to cache the response */
/*
 * Read the date. Generate one if one is not supplied
 */
    dates = ap_proxy_get_header(resp_hdrs, "Date");
    if (dates != NULL)
	date = ap_parseHTTPdate(dates->value);
    else
	date = BAD_DATE;

    now = time(NULL);

    if (date == BAD_DATE) {	/* No, or bad date */
/* no date header! */
/* add one; N.B. use the time _now_ rather than when we were checking the cache
 */
	date = abs(now);
	p = ap_gm_timestr_822(r->pool, now);
	dates = ap_proxy_add_header(resp_hdrs, "Date", p, HDR_REP);
	Explain0("Added date header");
    }

/* check last-modified date */
    if (lmod != BAD_DATE && lmod > date)
/* if its in the future, then replace by date */
    {
	lmod = date;
	lmods->value = dates->value;
	Explain0("Last modified is in the future, replacing with now");
    }
/* if the response did not contain the header, then use the cached version */
    if (lmod == BAD_DATE && c->fp != NULL) {
	lmod = c->lmod;
	Explain0("Reusing cached last modified");
    }

/* we now need to calculate the expire data for the object. */
    if (expire == NULL && c->fp != NULL) {	/* no expiry data sent in response */
	expire = ap_proxy_get_header(c->hdrs, "Expires");
	if (expire != NULL)
	    expc = ap_parseHTTPdate(expire->value);
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
	    expc = abs(now) + (int) x;
	}
	else
	    expc = abs(now) + conf->cache.defaultexpire;
	Explain1("Expiry date calculated %ld", expc);
    }

/* get the content-length header */
    clen = ap_proxy_get_header(c->hdrs, "Content-Length");
    if (clen == NULL)
	c->len = -1;
    else
	c->len = atoi(clen->value);

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
    if (r->status == 304) {
	if (c->ims != BAD_DATE && lmod != BAD_DATE && lmod <= c->ims) {
/* set any changed headers somehow */
/* update dates and version, but not content-length */
	    if (lmod != c->lmod || expc != c->expire || date != c->date) {
		off_t curpos = lseek(c->fp->fd, 0, SEEK_SET);
		if (curpos == -1)
		    ap_proxy_log_uerror("lseek", c->filename,
			   "proxy: error seeking on cache file", r->server);
		else if (write(c->fp->fd, buff, 35) == -1)
		    ap_proxy_log_uerror("write", c->filename,
			     "proxy: error updating cache file", r->server);
	    }
	    ap_pclosef(r->pool, c->fp->fd);
	    Explain0("Remote document not modified, use local copy");
	    /* CHECKME: Is this right? Shouldn't we check IMS again here? */
	    return USE_LOCAL_COPY;
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
		ap_proxy_send_fb(c->fp, r, NULL, NULL);
/* set any changed headers somehow */
/* update dates and version, but not content-length */
	    if (lmod != c->lmod || expc != c->expire || date != c->date) {
		off_t curpos = lseek(c->fp->fd, 0, SEEK_SET);

		if (curpos == -1)
		    ap_proxy_log_uerror("lseek", c->filename,
			   "proxy: error seeking on cache file", r->server);
		else if (write(c->fp->fd, buff, 35) == -1)
		    ap_proxy_log_uerror("write", c->filename,
			     "proxy: error updating cache file", r->server);
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
	ap_proxy_log_uerror("open", c->tempfile,
			 "proxy: error creating cache file", r->server);
	return DECLINED;
    }
    ap_note_cleanups_for_fd(r->pool, i);
    c->fp = ap_bcreate(r->pool, B_WR);
    ap_bpushfd(c->fp, -1, i);

    if (ap_bvputs(c->fp, buff, "X-URL: ", c->url, "\n", NULL) == -1) {
	ap_proxy_log_uerror("write", c->tempfile,
			 "proxy: error writing cache file", r->server);
	ap_pclosef(r->pool, c->fp->fd);
	unlink(c->tempfile);
	c->fp = NULL;
    }
    return DECLINED;
}

void ap_proxy_cache_tidy(struct cache_req *c)
{
    server_rec *s = c->req->server;
    long int bc;

    if (c->fp == NULL)
	return;

    ap_bgetopt(c->req->connection->client, BO_BYTECT, &bc);

    if (c->len != -1) {
/* file lengths don't match; don't cache it */
	if (bc != c->len) {
	    ap_pclosef(c->req->pool, c->fp->fd);	/* no need to flush */
	    unlink(c->tempfile);
	    return;
	}
    }
    else if (c->req->connection->aborted) {
	ap_pclosef(c->req->pool, c->fp->fd);	/* no need to flush */
	unlink(c->tempfile);
	return;
    }
    else {
/* update content-length of file */
	char buff[9];
	off_t curpos;

	c->len = bc;
	ap_bflush(c->fp);
	ap_proxy_sec2hex(c->len, buff);
	curpos = lseek(c->fp->fd, 36, SEEK_SET);
	if (curpos == -1)
	    ap_proxy_log_uerror("lseek", c->tempfile,
			     "proxy: error seeking on cache file", s);
	else if (write(c->fp->fd, buff, 8) == -1)
	    ap_proxy_log_uerror("write", c->tempfile,
			     "proxy: error updating cache file", s);
    }

    if (ap_bflush(c->fp) == -1) {
	ap_proxy_log_uerror("write", c->tempfile,
			 "proxy: error writing to cache file", s);
	ap_pclosef(c->req->pool, c->fp->fd);
	unlink(c->tempfile);
	return;
    }

    if (ap_pclosef(c->req->pool, c->fp->fd) == -1) {
	ap_proxy_log_uerror("close", c->tempfile,
			 "proxy: error closing cache file", s);
	unlink(c->tempfile);
	return;
    }

    if (unlink(c->filename) == -1 && errno != ENOENT) {
	ap_proxy_log_uerror("unlink", c->filename,
			 "proxy: error deleting old cache file", s);
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
		ap_proxy_log_uerror("mkdir", c->filename,
				 "proxy: error creating cache directory", s);
	    *p = '/';
	    ++p;
	}
#if defined(__EMX__) || defined(WIN32)
	/* Under OS/2 use rename. */
	if (rename(c->tempfile, c->filename) == -1)
	    ap_proxy_log_uerror("rename", c->filename,
			     "proxy: error renaming cache file", s);
    }
#else

	if (link(c->tempfile, c->filename) == -1)
	    ap_proxy_log_uerror("link", c->filename,
			     "proxy: error linking cache file", s);
    }

    if (unlink(c->tempfile) == -1)
	ap_proxy_log_uerror("unlink", c->tempfile,
			 "proxy: error deleting temp file", s);
#endif

}
