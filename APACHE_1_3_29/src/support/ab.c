/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000-2003 The Apache Software Foundation.  All rights
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

/*
   ** This program is based on ZeusBench V1.0 written by Adam Twiss
   ** which is Copyright (c) 1996 by Zeus Technology Ltd. http://www.zeustech.net/
   **
   ** This software is provided "as is" and any express or implied waranties,
   ** including but not limited to, the implied warranties of merchantability and
   ** fitness for a particular purpose are disclaimed.  In no event shall
   ** Zeus Technology Ltd. be liable for any direct, indirect, incidental, special,
   ** exemplary, or consequential damaged (including, but not limited to,
   ** procurement of substitute good or services; loss of use, data, or profits;
   ** or business interruption) however caused and on theory of liability.  Whether
   ** in contract, strict liability or tort (including negligence or otherwise)
   ** arising in any way out of the use of this software, even if advised of the
   ** possibility of such damage.
   **
 */

/*
   ** HISTORY:
   **    - Originally written by Adam Twiss <adam@zeus.co.uk>, March 1996
   **      with input from Mike Belshe <mbelshe@netscape.com> and
   **      Michael Campanella <campanella@stevms.enet.dec.com>
   **    - Enhanced by Dean Gaudet <dgaudet@apache.org>, November 1997
   **    - Cleaned up by Ralf S. Engelschall <rse@apache.org>, March 1998
   **    - POST and verbosity by Kurt Sussman <kls@merlot.com>, August 1998
   **    - HTML table output added by David N. Welton <davidw@prosa.it>, January 1999
   **    - Added Cookie, Arbitrary header and auth support. <dirkx@webweaving.org>, April 1999
   ** Version 1.3d
   **    - Increased version number - as some of the socket/error handling has
   **      fundamentally changed - and will give fundamentally different results
   **      in situations where a server is dropping requests. Therefore you can
   **      no longer compare results of AB as easily. Hence the inc of the version.
   **      They should be closer to the truth though. Sander & <dirkx@covalent.net>, End 2000.
   **    - Fixed proxy functionality, added median/mean statistics, added gnuplot
   **      output option, added _experimental/rudimentary_ SSL support. Added
   **      confidence guestimators and warnings. Sander & <dirkx@covalent.net>, End 2000
   **    - Fixed serious int overflow issues which would cause realistic (longer
   **      than a few minutes) run's to have wrong (but believable) results. Added
   **	   trapping of connection errors which influenced measurements.
   **	   Contributed by Sander Temme - Early 2001
   **
 */
 /*
  * BUGS:
  *
  * - uses strcpy/etc.
  * - has various other poor buffer attacks related to the lazy parsing of
  *   response headers from the server
  * - doesn't implement much of HTTP/1.x, only accepts certain forms of
  *   responses
  * - (performance problem) heavy use of strstr shows up top in profile
  *   only an issue for loopback usage
  * - SSL implementation is a joke. Compile with:
  *	CFLAGS="-DUSE_SSL -I/usr/local/include" \
  *		LIBS="-L/usr/local/lib -lssl -lcrypto" \
  *		configure --your-other-options
  */


#define VERSION "1.3d"

/* -------------------------------------------------------------------- */

/* affects include files on Solaris */
#define BSD_COMP

/* allow compilation outside an Apache build tree */
#ifdef NO_APACHE_INCLUDES
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <string.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/uio.h>

#define ap_select       select
#else				/* (!)NO_APACHE_INCLUDES */
#include "ap_config.h"
#include "ap.h"
#ifdef CHARSET_EBCDIC
#include "ebcdic.h"
#endif
#include <fcntl.h>
#ifndef MPE
#include <sys/time.h>
#endif

#ifndef NO_WRITEV
#include <sys/types.h>
#include <sys/uio.h>
#endif

#endif				/* NO_APACHE_INCLUDES */

#ifdef	USE_SSL
#if ((!defined(RSAREF)) && (!defined(SYSSSL)))
/* Libraries on most systems.. */
#include <openssl/rsa.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#else
/* Libraries for RSAref and SYSSSL */
#include <rsa.h>
#include <crypto.h>
#include <x509.h>
#include <pem.h>
#include <err.h>
#include <ssl.h>
#endif
#endif

#include <math.h>
/* ------------------- DEFINITIONS -------------------------- */

/* maximum number of requests on a time limited test */
#define MAX_REQUESTS 50000

/* good old state hostname */
#define STATE_UNCONNECTED 0
#define STATE_CONNECTING  1
#define STATE_READ        2

#define CBUFFSIZE       512

struct connection {
    int fd;
    int state;
    int read;			/* amount of bytes read */
    int bread;			/* amount of body read */
    int length;			/* Content-Length value used for keep-alive */
    char cbuff[CBUFFSIZE];	/* a buffer to store server response header */
    int cbx;			/* offset in cbuffer */
    int keepalive;		/* non-zero if a keep-alive request */
    int gotheader;		/* non-zero if we have the entire header in
				 * cbuff */
    struct timeval start,	/* Start of connection */
            connect,		/* Connected, start writing */
            endwrite,		/* Request written */
            beginread,		/* First byte of input */
            done;		/* Connection closed */

#ifdef USE_SSL
    SSL *ssl;
#endif
};

struct data {
#ifdef USE_SSL
    /* XXX insert timings for ssl */
#endif
    int read;			/* number of bytes read */
    long starttime;		/* start time of connection in seconds since
				 * Jan. 1, 1970 */
    long waittime;		/* Between writing request and reading
				 * response */
    long ctime;			/* time in ms to connect */
    long time;			/* time in ms for connection */
};

#define ap_min(a,b) ((a)<(b))?(a):(b)
#define ap_max(a,b) ((a)>(b))?(a):(b)
#define _rnd(x) ((long)(x+0.5))

/* --------------------- GLOBALS ---------------------------- */

int verbosity = 0;		/* no verbosity by default */
int percentile = 1;		/* Show percentile served */
int confidence = 1;		/* Show confidence estimator and warnings */
int posting = 0;		/* GET by default */
long requests = 1;		/* Number of requests to make */
int heartbeatres = 100;		/* How often do we say we're alive */
int concurrency = 1;		/* Number of multiple requests to make */
int tlimit = 0;			/* time limit in cs */
int keepalive = 0;		/* try and do keepalive connections */
char servername[1024];		/* name that server reports */
char hostname[1024];		/* host name */
char proxyhost[1024];		/* proxy host name */
int proxyport = 0;		/* proxy port */
int isproxy = 0;
char path[1024];		/* path name */
char postfile[1024];		/* name of file containing post data */
char *postdata;			/* *buffer containing data from postfile */
char *gnuplot;			/* GNUplot file */
char *csvperc;			/* CSV Percentile file */
char url[1024];
char fullurl[1024];
char colonport[1024];
int postlen = 0;		/* length of data to be POSTed */
char content_type[1024];	/* content type to put in POST header */
char cookie[1024],		/* optional cookie line */
     auth[1024],		/* optional (basic/uuencoded)
				 * authentification */
     hdrs[4096];		/* optional arbitrary headers */
int port = 80;			/* port number */

int use_html = 0;		/* use html in the report */
char *tablestring;
char *trstring;
char *tdstring;

int doclen = 0;			/* the length the document should be */
long totalread = 0;		/* total number of bytes read */
long totalbread = 0;		/* totoal amount of entity body read */
long totalposted = 0;		/* total number of bytes posted, inc. headers */
long done = 0;			/* number of requests we have done */
long doneka = 0;		/* number of keep alive connections done */
long good = 0, bad = 0;		/* number of good and bad requests */
long epipe = 0;			/* number of broken pipe writes */

#ifdef USE_SSL
int ssl = 0;
SSL_CTX *ctx;
#endif
/* store error cases */
int err_length = 0, err_conn = 0, err_except = 0;
int err_response = 0;

struct timeval start, endtime;

/* global request (and its length) */
char request[1024];
int reqlen;

/* one global throw-away buffer to read stuff into */
char buffer[8192];

struct connection *con;		/* connection array */
struct data *stats;		/* date for each request */

fd_set readbits, writebits;	/* bits for select */
struct sockaddr_in server;	/* server addr structure */

#ifndef BEOS
#define ab_close(s) close(s)
#define ab_read(a,b,c) read(a,b,c)
#define ab_write(a,b,c) write(a,b,c)
#else
#define ab_close(s) closesocket(s)
#define ab_read(a,b,c) recv(a,b,c,0)
#define ab_write(a,b,c) send(a,b,c,0)
#endif

static void close_connection(struct connection * c);
#if (defined(NO_WRITEV) || defined(USE_SSL))
#define USE_S_WRITE
static int s_write(struct connection * c, char *buff, int len);
#endif

/* --------------------------------------------------------- */

/* simple little function to perror and exit */

static void err(char *s)
{
    if (errno) {
	perror(s);
    }
    else {
	fprintf(stderr,"%s", s);
    }
    exit(errno ? errno : 1);
}

/* --------------------------------------------------------- */

/*
 * write out request to a connection - assumes we can write (small) request
 * out in one go into our new socket buffer
 */

static void write_request(struct connection * c)
{
/* XXX this sucks - SSL mode and writev() do not mix
 *     another artificial difference.
 */
#ifndef USE_S_WRITE
    struct iovec out[2];
    int outcnt = 1;
#endif
    int snd = 0;
    gettimeofday(&c->connect, 0);
#ifndef USE_S_WRITE
    out[0].iov_base = request;
    out[0].iov_len = reqlen;

    if (posting > 0) {
	out[1].iov_base = postdata;
	out[1].iov_len = postlen;
	outcnt = 2;
	totalposted += (reqlen + postlen);
    }
    snd = writev(c->fd, out, outcnt);
#else
    snd = s_write(c, request, reqlen);
    if (posting > 0) {
        snd += s_write(c, postdata, postlen);
        totalposted += (reqlen + postlen);
    }
#endif
    if (snd < 0) {
	bad++; 
	err_conn++;
        close_connection(c);
	return;
    } else
    if (snd != (reqlen + postlen)) {
	/* We cannot cope with this. */
	fprintf(stderr,"The entire post RQ could not be transmitted to the socket.\n");
	exit(1);
    }
    FD_SET(c->fd, &readbits);
    FD_CLR(c->fd, &writebits);
    c->state = STATE_READ;
    gettimeofday(&c->endwrite, 0);
}

/* --------------------------------------------------------- */

/*  Do actual data writing */

#ifdef USE_S_WRITE
static int s_write(struct connection * c, char *buff, int len)
{
	int left = len;
    do {
	int n;
#ifdef USE_SSL
	if (ssl) {
	    n = SSL_write(c->ssl, buff, left);
	    if (n < 0) {
		int e = SSL_get_error(c->ssl, n);
		/* XXXX probably wrong !!! */
		if ((e != SSL_ERROR_WANT_READ) && (e != SSL_ERROR_WANT_WRITE))
		    n = -1;
		else
		    n = 0;
	    };
	}
	else
#endif
    n = ab_write(c->fd, buff, left);

	if (n < 0) {
	    switch (errno) {
	    case EAGAIN:
		break;
	    case EPIPE:
		/* We've tried to write to a broken pipe. */
		epipe++;
		close_connection(c);
		return len-left;
	    default:
#ifdef USE_SSL
		if (ssl) {
			fprintf(stderr,"Error writing: ");
	    		ERR_print_errors_fp(stderr);
		} else
#endif
			perror("write");
		exit(1);
	    }
	}
	else if (n) {
	    if (verbosity >= 3)
		printf(" --> write(%x) %d (%d)\n", (unsigned char) buff[0], n, left);
	    buff += n;
	    left -= n;
	};
    } while (left > 0);
    
	return len - left;
}
#endif

/* --------------------------------------------------------- */

/* make an fd non blocking */

static void nonblock(int fd)
{
    int i = 1;
#ifdef BEOS
    setsockopt(fd, SOL_SOCKET, SO_NONBLOCK, &i, sizeof(i));
#else
    ioctl(fd, FIONBIO, &i);
#endif
}

/* --------------------------------------------------------- */

/* returns the time in ms between two timevals */

static int timedif(struct timeval a, struct timeval b)
{
    register int us, s;

    us = a.tv_usec - b.tv_usec;
    us /= 1000;
    s = a.tv_sec - b.tv_sec;
    s *= 1000;
    return s + us;
}

/* --------------------------------------------------------- */

/* calculate and output results */

static int compradre(struct data * a, struct data * b)
{
    if ((a->ctime) < (b->ctime))
	return -1;
    if ((a->ctime) > (b->ctime))
	return +1;
    return 0;
}

static int comprando(struct data * a, struct data * b)
{
    if ((a->time) < (b->time))
	return -1;
    if ((a->time) > (b->time))
	return +1;
    return 0;
}

static int compri(struct data * a, struct data * b)
{
    int p = a->time - a->ctime;
    int q = b->time - b->ctime;
    if (p < q)
	return -1;
    if (p > q)
	return +1;
    return 0;
}

static int compwait(struct data * a, struct data * b)
{
    if ((a->waittime) < (b->waittime))
	return -1;
    if ((a->waittime) > (b->waittime))
	return 1;
    return 0;
}

static void output_results(void)
{
    long timetaken;
    long i;

    gettimeofday(&endtime, 0);
    timetaken = timedif(endtime, start);

    printf("\r                                                                           \r");
    printf("Server Software:        %s\n", servername);
    printf("Server Hostname:        %s\n", hostname);
    printf("Server Port:            %d\n", port);
    printf("\n");
    printf("Document Path:          %s\n", path);
    printf("Document Length:        %d bytes\n", doclen);
    printf("\n");
    printf("Concurrency Level:      %d\n", concurrency);
    printf("Time taken for tests:   %ld.%03ld seconds\n",
	   timetaken / 1000, timetaken % 1000);
    printf("Complete requests:      %ld\n", done);
    printf("Failed requests:        %ld\n", bad);
    if (bad)
	printf("   (Connect: %d, Length: %d, Exceptions: %d)\n",
	       err_conn, err_length, err_except);
    printf("Broken pipe errors:     %ld\n", epipe);
    if (err_response)
	printf("Non-2xx responses:      %d\n", err_response);
    if (keepalive)
	printf("Keep-Alive requests:    %ld\n", doneka);
    printf("Total transferred:      %ld bytes\n", totalread);
    if (posting > 0)
	printf("Total POSTed:           %ld\n", totalposted);
    printf("HTML transferred:       %ld bytes\n", totalbread);

    /* avoid divide by zero */
    if (timetaken) {
	printf("Requests per second:    %.2f [#/sec] (mean)\n", 1000 * (float) (done) / timetaken);
	printf("Time per request:       %.2f [ms] (mean)\n", concurrency * timetaken / (float) done);
	printf("Time per request:       %.2f [ms] (mean, across all concurrent requests)\n", timetaken / (float) done);
	printf("Transfer rate:          %.2f [Kbytes/sec] received\n",
	       (float) (totalread) / timetaken);
	if (posting > 0) {
	    printf("                        %.2f kb/s sent\n",
		   (float) (totalposted) / timetaken);
	    printf("                        %.2f kb/s total\n",
		   (float) (totalread + totalposted) / timetaken);
	}
    }
    if (requests>1) {
	/* work out connection times */
	double totalcon = 0, total = 0, totald = 0, totalwait = 0;
	long mincon = 9999999, mintot = 999999, mind = 99999, minwait = 99999;
	long maxcon = 0, maxtot = 0, maxd = 0, maxwait = 0;
	long meancon = 0, meantot = 0, meand = 0, meanwait = 0;
	double sdtot = 0, sdcon = 0, sdd = 0, sdwait = 0;

	for (i = 0; i < requests; i++) {
	    struct data s = stats[i];
	    mincon = ap_min(mincon, s.ctime);
	    mintot = ap_min(mintot, s.time);
	    mind = ap_min(mintot, s.time - s.ctime);
	    minwait = ap_min(minwait, s.waittime);

	    maxcon = ap_max(maxcon, s.ctime);
	    maxtot = ap_max(maxtot, s.time);
	    maxd = ap_max(maxd, s.time - s.ctime);
	    maxwait = ap_max(maxwait, s.waittime);

	    totalcon += s.ctime;
	    total += s.time;
	    totald += s.time - s.ctime;
	    totalwait += s.waittime;
	};
	totalcon /= requests;
	total /= requests;
	totald /= requests;
	totalwait /= requests;

	for (i = 0; i < requests; i++) {
	    struct data s = stats[i];
	    int a;
	    a = (s.time - total);
	    sdtot += a * a;
	    a = (s.ctime - totalcon);
	    sdcon += a * a;
	    a = (s.time - s.ctime - totald);
	    sdd += a * a;
	    a = (s.waittime - totalwait);
	    sdwait += a * a;
	};

	sdtot = (requests > 1) ? sqrt(sdtot / (requests - 1)) : 0;
	sdcon = (requests > 1) ? sqrt(sdcon / (requests - 1)) : 0;
	sdd = (requests > 1) ? sqrt(sdd / (requests - 1)) : 0;
	sdwait = (requests > 1) ? sqrt(sdwait / (requests - 1)) : 0;

	if (gnuplot) {
	    FILE *out = fopen(gnuplot, "w");
	    if (!out) {
		perror("Cannot open gnuplot output file");
		exit(1);
	    };
	    fprintf(out, "starttime\tseconds\tctime\tdtime\tttime\twait\n");
	    for (i = 0; i < requests; i++) {
		time_t sttime;
		char *tmstring;
		sttime = stats[i].starttime;
		tmstring = ctime(&sttime);
		tmstring[strlen(tmstring) - 1] = '\0';	/* ctime returns a
							 * string with a
							 * trailing newline */
		fprintf(out, "%s\t%ld\t%ld\t%ld\t%ld\t%ld\n",
			tmstring,
			sttime,
			stats[i].ctime,
			stats[i].time - stats[i].ctime,
			stats[i].time,
			stats[i].waittime);
	    }
	    fclose(out);
	};

	/*
	 * XXX: what is better; this hideous cast of the copare function; or
	 * the four warnings during compile ? dirkx just does not know and
	 * hates both
	 */
	qsort(stats, requests, sizeof(struct data),
	      (int (*) (const void *, const void *)) compradre);
	if ((requests > 1) && (requests % 2))
	    meancon = (stats[requests / 2].ctime + stats[requests / 2 + 1].ctime) / 2;
	else
	    meancon = stats[requests / 2].ctime;

	qsort(stats, requests, sizeof(struct data),
	      (int (*) (const void *, const void *)) compri);
	if ((requests > 1) && (requests % 2))
	    meand = (stats[requests / 2].time + stats[requests / 2 + 1].time \
	    -stats[requests / 2].ctime - stats[requests / 2 + 1].ctime) / 2;
	else
	    meand = stats[requests / 2].time - stats[requests / 2].ctime;

	qsort(stats, requests, sizeof(struct data),
	      (int (*) (const void *, const void *)) compwait);
	if ((requests > 1) && (requests % 2))
	    meanwait = (stats[requests / 2].waittime + stats[requests / 2 + 1].waittime) / 2;
	else
	    meanwait = stats[requests / 2].waittime;

	qsort(stats, requests, sizeof(struct data),
	      (int (*) (const void *, const void *)) comprando);
	if ((requests > 1) && (requests % 2))
	    meantot = (stats[requests / 2].time + stats[requests / 2 + 1].time) / 2;
	else
	    meantot = stats[requests / 2].time;


	printf("\nConnnection Times (ms)\n");

	if (confidence) {
	    printf("              min  mean[+/-sd] median   max\n");
	    printf("Connect:    %5ld %5ld %6.1f  %5ld %5ld\n",
		   mincon, _rnd(totalcon), sdcon, meancon, maxcon);
	    printf("Processing: %5ld %5ld %6.1f  %5ld %5ld\n",
		   mind, _rnd(totald), sdd, meand, maxd);
	    printf("Waiting:    %5ld %5ld %6.1f  %5ld %5ld\n",
		   minwait, _rnd(totalwait), sdwait, meanwait, maxwait);
	    printf("Total:      %5ld %5ld %6.1f  %5ld %5ld\n", mintot, _rnd(total), sdtot, meantot, maxtot);

#define     SANE(what,avg,mean,sd) \
            { \
		double d = avg - mean; \
		if (d < 0) d = -d; \
		if (d > 2 * sd ) \
			printf("ERROR: The median and mean for " what " are more than twice the standard\n" \
			    "       deviation apart. These results are NOT reliable.\n"); \
		else if (d > sd ) \
			printf("WARING: The median and mean for " what " are not within a normal deviation\n" \
			    "        These results are propably not that reliable.\n"); \
	    }
	    SANE("the initial connection time", totalcon, meancon, sdcon);
	    SANE("the processing time", totald, meand, sdd);
	    SANE("the waiting time", totalwait, meanwait, sdwait);
	    SANE("the total time", total, meantot, sdtot);
	}
	else {
	    printf("              min   avg   max\n");
	    printf("Connect:    %5ld %5ld %5ld\n", mincon, _rnd(totalcon), maxcon);
	    printf("Processing: %5ld %5ld %5ld\n", mind, _rnd(totald), maxd);
	    printf("Total:      %5ld %5ld %5ld\n", mintot, _rnd(total), maxtot);
	};

	/* Sorted on total connect times */
	if (percentile && (requests > 1)) {
	    printf("\nPercentage of the requests served within a certain time (ms)\n");
	    printf("  50%%  %5ld\n", stats[(int) (requests * 0.50)].time);
	    printf("  66%%  %5ld\n", stats[(int) (requests * 0.66)].time);
	    printf("  75%%  %5ld\n", stats[(int) (requests * 0.75)].time);
	    printf("  80%%  %5ld\n", stats[(int) (requests * 0.80)].time);
	    printf("  90%%  %5ld\n", stats[(int) (requests * 0.90)].time);
	    printf("  95%%  %5ld\n", stats[(int) (requests * 0.95)].time);
	    printf("  98%%  %5ld\n", stats[(int) (requests * 0.98)].time);
	    printf("  99%%  %5ld\n", stats[(int) (requests * 0.99)].time);
	    printf(" 100%%  %5ld (last request)\n", stats[(int) (requests - 1)].time);
	    \
	};
	if (csvperc) {
	    FILE *out = fopen(csvperc, "w");
	    if (!out) {
		perror("Cannot open CSV output file");
		exit(1);
	    };
	    fprintf(out, "" "Percentage served" "," "Time in ms" "\n");
	    for (i = 0; i < 100; i++) {
		double d;
		if (i == 0)
		    d = stats[0].time;
		else if (i == 100)
		    d = stats[requests - 1].time;
		else
		    d = stats[(int) (0.5 + requests * i / 100.0)].time;
		fprintf(out, "%ld,%f\n", i, d);
	    }
	    fclose(out);
	};
    }
}

/* --------------------------------------------------------- */

/* calculate and output results in HTML  */

static void output_html_results(void)
{
    long timetaken;
    long i;

    gettimeofday(&endtime, 0);
    timetaken = timedif(endtime, start);

    printf("\n\n<table %s>\n", tablestring);
    printf("<tr %s><th colspan=2 %s>Server Software:</th>"
	   "<td colspan=2 %s>%s</td></tr>\n",
	   trstring, tdstring, tdstring, servername);
    printf("<tr %s><th colspan=2 %s>Server Hostname:</th>"
	   "<td colspan=2 %s>%s</td></tr>\n",
	   trstring, tdstring, tdstring, hostname);
    printf("<tr %s><th colspan=2 %s>Server Port:</th>"
	   "<td colspan=2 %s>%d</td></tr>\n",
	   trstring, tdstring, tdstring, port);
    printf("<tr %s><th colspan=2 %s>Document Path:</th>"
	   "<td colspan=2 %s>%s</td></tr>\n",
	   trstring, tdstring, tdstring, path);
    printf("<tr %s><th colspan=2 %s>Document Length:</th>"
	   "<td colspan=2 %s>%d bytes</td></tr>\n",
	   trstring, tdstring, tdstring, doclen);
    printf("<tr %s><th colspan=2 %s>Concurrency Level:</th>"
	   "<td colspan=2 %s>%d</td></tr>\n",
	   trstring, tdstring, tdstring, concurrency);
    printf("<tr %s><th colspan=2 %s>Time taken for tests:</th>"
	   "<td colspan=2 %s>%ld.%03ld seconds</td></tr>\n",
	   trstring, tdstring, tdstring, timetaken / 1000, timetaken % 1000);
    printf("<tr %s><th colspan=2 %s>Complete requests:</th>"
	   "<td colspan=2 %s>%ld</td></tr>\n",
	   trstring, tdstring, tdstring, done);
    printf("<tr %s><th colspan=2 %s>Failed requests:</th>"
	   "<td colspan=2 %s>%ld</td></tr>\n",
	   trstring, tdstring, tdstring, bad);
    if (bad)
	printf("<tr %s><td colspan=4 %s >   (Connect: %d, Length: %d, Exceptions: %d)</td></tr>\n",
	       trstring, tdstring, err_conn, err_length, err_except);
    if (err_response)
	printf("<tr %s><th colspan=2 %s>Non-2xx responses:</th>"
	       "<td colspan=2 %s>%d</td></tr>\n",
	       trstring, tdstring, tdstring, err_response);
    if (keepalive)
	printf("<tr %s><th colspan=2 %s>Keep-Alive requests:</th>"
	       "<td colspan=2 %s>%ld</td></tr>\n",
	       trstring, tdstring, tdstring, doneka);
    printf("<tr %s><th colspan=2 %s>Total transferred:</th>"
	   "<td colspan=2 %s>%ld bytes</td></tr>\n",
	   trstring, tdstring, tdstring, totalread);
    if (posting > 0)
	printf("<tr %s><th colspan=2 %s>Total POSTed:</th>"
	       "<td colspan=2 %s>%ld</td></tr>\n",
	       trstring, tdstring, tdstring, totalposted);
    printf("<tr %s><th colspan=2 %s>HTML transferred:</th>"
	   "<td colspan=2 %s>%ld bytes</td></tr>\n",
	   trstring, tdstring, tdstring, totalbread);

    /* avoid divide by zero */
    if (timetaken) {
	printf("<tr %s><th colspan=2 %s>Requests per second:</th>"
	       "<td colspan=2 %s>%.2f</td></tr>\n",
	   trstring, tdstring, tdstring, 1000 * (float) (done) / timetaken);
	printf("<tr %s><th colspan=2 %s>Transfer rate:</th>"
	       "<td colspan=2 %s>%.2f kb/s received</td></tr>\n",
	     trstring, tdstring, tdstring, (float) (totalread) / timetaken);
	if (posting > 0) {
	    printf("<tr %s><td colspan=2 %s>&nbsp;</td>"
		   "<td colspan=2 %s>%.2f kb/s sent</td></tr>\n",
		   trstring, tdstring, tdstring,
		   (float) (totalposted) / timetaken);
	    printf("<tr %s><td colspan=2 %s>&nbsp;</td>"
		   "<td colspan=2 %s>%.2f kb/s total</td></tr>\n",
		   trstring, tdstring, tdstring,
		   (float) (totalread + totalposted) / timetaken);
	}
    } {
	/* work out connection times */
	long totalcon = 0, total = 0;
	long mincon = 9999999, mintot = 999999;
	long maxcon = 0, maxtot = 0;

	for (i = 0; i < requests; i++) {
	    struct data s = stats[i];
	    mincon = ap_min(mincon, s.ctime);
	    mintot = ap_min(mintot, s.time);
	    maxcon = ap_max(maxcon, s.ctime);
	    maxtot = ap_max(maxtot, s.time);
	    totalcon += s.ctime;
	    total += s.time;
	}

	if (requests > 0) {	/* avoid division by zero (if 0 requests) */
	    printf("<tr %s><th %s colspan=4>Connnection Times (ms)</th></tr>\n",
		   trstring, tdstring);
	    printf("<tr %s><th %s>&nbsp;</th> <th %s>min</th>   <th %s>avg</th>   <th %s>max</th></tr>\n",
		   trstring, tdstring, tdstring, tdstring, tdstring);
	    printf("<tr %s><th %s>Connect:</th>"
		   "<td %s>%5ld</td>"
		   "<td %s>%5ld</td>"
		   "<td %s>%5ld</td></tr>\n",
		   trstring, tdstring, tdstring, mincon, tdstring, totalcon / requests, tdstring, maxcon);
	    printf("<tr %s><th %s>Processing:</th>"
		   "<td %s>%5ld</td>"
		   "<td %s>%5ld</td>"
		   "<td %s>%5ld</td></tr>\n",
		   trstring, tdstring, tdstring, mintot - mincon, tdstring,
		   (total / requests) - (totalcon / requests), tdstring, maxtot - maxcon);
	    printf("<tr %s><th %s>Total:</th>"
		   "<td %s>%5ld</td>"
		   "<td %s>%5ld</td>"
		   "<td %s>%5ld</td></tr>\n",
		   trstring, tdstring, tdstring, mintot, tdstring, total / requests, tdstring, maxtot);
	}
	printf("</table>\n");
    }
}

/* --------------------------------------------------------- */

/* start asnchronous non-blocking connection */

static void start_connect(struct connection * c)
{
    const char *what = "none";

    c->read = 0;
    c->bread = 0;
    c->keepalive = 0;
    c->cbx = 0;
    c->gotheader = 0;

    c->fd = socket(AF_INET, SOCK_STREAM, 0);
    if (c->fd < 0) {
	what = "SOCKET";
	goto _bad;
    };

#ifdef USE_SSL
    /*
     * XXX move nonblocker - so that measnurement needs to have its OWN
     * state engine OR cannot be compared to http.
     */
    if (!ssl)
#endif
	nonblock(c->fd);

again:
    gettimeofday(&c->start, 0);
    if (connect(c->fd, (struct sockaddr *) & server, sizeof(server)) < 0) {
	if (errno != EINPROGRESS) {
	    what = "CONNECT";
	    goto _bad;
	};
    }
    c->state = STATE_CONNECTING;

#ifdef USE_SSL
    /* XXX no proper freeing in error's */
    /*
     * XXX no proper choise of completely new connection or one which reuses
     * (older) session keys. Fundamentally unrealistic.
     */
    if (ssl) {
	int e;
	if (!(c->ssl = SSL_new(ctx))) {
	    fprintf(stderr, "Failed to set up new SSL context ");
	    ERR_print_errors_fp(stderr);
	    goto _bad;
	};
	SSL_set_connect_state(c->ssl);
	if ((e = SSL_set_fd(c->ssl, c->fd)) == -1) {
	    fprintf(stderr, "SSL fd init failed ");
	    ERR_print_errors_fp(stderr);
	    goto _bad;
	};
	if ((e = SSL_connect(c->ssl)) == -1) {
	    fprintf(stderr, "SSL connect failed ");
	    ERR_print_errors_fp(stderr);
	    goto _bad;
	};
	if (verbosity >= 1)
	    fprintf(stderr, "SSL connection OK: %s\n", SSL_get_cipher(c->ssl));
    }
#endif
#ifdef USE_SSL
    if (ssl)
	nonblock(c->fd);
#endif
    FD_SET(c->fd, &writebits);
    return;

_bad:
    ab_close(c->fd);
    err_conn++;
    bad++;
    if (bad > 10) {
	err("\nTest aborted after 10 failures\n\n");
    }
    goto again;
}

/* --------------------------------------------------------- */

/* close down connection and save stats */

static void close_connection(struct connection * c)
{
    if (c->read == 0 && c->keepalive) {
	/*
	 * server has legitimately shut down an idle keep alive request
	 */
	good--;			/* connection never happend */
    }
    else {
	if (good == 1) {
	    /* first time here */
	    doclen = c->bread;
	}
	else if (c->bread != doclen) {
	    bad++;
	    err_length++;
	}
	/* save out time */
	if (done < requests) {
	    struct data s;
	    if ((done) && (heartbeatres) && (!(done % heartbeatres))) {
		fprintf(stderr, "Completed %ld requests\n", done);
		fflush(stderr);
	    }
	    gettimeofday(&c->done, 0);
	    s.read = c->read;
	    s.starttime = c->start.tv_sec;
	    s.ctime = timedif(c->connect, c->start);
	    s.waittime = timedif(c->beginread, c->endwrite);
	    s.time = timedif(c->done, c->start);
	    stats[done++] = s;
	}
    }

    ab_close(c->fd);
    FD_CLR(c->fd, &readbits);
    FD_CLR(c->fd, &writebits);

    /* connect again */
    start_connect(c);
    return;
}

/* --------------------------------------------------------- */

/* read data from connection */

static void read_connection(struct connection * c)
{
    int r;
    char *part;
    char respcode[4];		/* 3 digits and null */

    gettimeofday(&c->beginread, 0);
#ifdef USE_SSL
    if (ssl) {
	r = SSL_read(c->ssl, buffer, sizeof(buffer));
	/* XXX fundamentally worng .. */
	if (r < 0 && SSL_get_error(c->ssl, r) == SSL_ERROR_WANT_READ) {
	    r = -1;
	    errno = EAGAIN;
	}
    }
    else
#endif
	r = ab_read(c->fd, buffer, sizeof(buffer));

    if (r == 0 || (r < 0 && errno != EAGAIN)) {
	good++;
	close_connection(c);
	return;
    }
    if (r < 0 && errno == EAGAIN)
	return;

    c->read += r;
    totalread += r;

    if (!c->gotheader) {
	char *s;
	int l = 4;
	int space = CBUFFSIZE - c->cbx - 1;	/* -1 to allow for 0
						 * terminator */
	int tocopy = (space < r) ? space : r;
#ifndef CHARSET_EBCDIC
	memcpy(c->cbuff + c->cbx, buffer, tocopy);
#else				/* CHARSET_EBCDIC */
	ascii2ebcdic(c->cbuff + c->cbx, buffer, tocopy);
#endif				/* CHARSET_EBCDIC */
	c->cbx += tocopy;
	space -= tocopy;
	c->cbuff[c->cbx] = 0;	/* terminate for benefit of strstr */
	if (verbosity >= 4) {
	    printf("LOG: header received:\n%s\n", c->cbuff);
	}
	s = strstr(c->cbuff, "\r\n\r\n");
	/*
	 * this next line is so that we talk to NCSA 1.5 which blatantly
	 * breaks the http specification
	 */
	if (!s) {
	    s = strstr(c->cbuff, "\n\n");
	    l = 2;
	}
	if (!s) {
	    /* read rest next time */
	    if (space)
		return;
	    else {
		/*
		 * header is in invalid or too big - close connection
		 */
		ab_close(c->fd);
		if (bad++ > 10) {
		    err("\nTest aborted after 10 failures\n\n");
		}
		FD_CLR(c->fd, &writebits);
		start_connect(c);
	    }
	}
	else {
	    /* have full header */
	    if (!good) {
		/*
		 * this is first time, extract some interesting info
		 */
		char *p, *q;
		int qlen;
		p = strstr(c->cbuff, "Server:");
		q = servername; qlen = sizeof(servername);
		if (p) {
		    p += 8;
		    while (*p > 32 && qlen-- > 1) 
			*q++ = *p++;
		}
		*q = 0;
	    }
	    /*
	     * XXX: this parsing isn't even remotely HTTP compliant... but in
	     * the interest of speed it doesn't totally have to be, it just
	     * needs to be extended to handle whatever servers folks want to
	     * test against. -djg
	     */

	    /* check response code */
	    part = strstr(c->cbuff, "HTTP");	/* really HTTP/1.x_ */
            if (part && strlen(part) > strlen("HTTP/1.x_")) {
                strncpy(respcode, (part + strlen("HTTP/1.x_")), 3);
                respcode[3] = '\0';
            }
            else {
                strcpy(respcode, "500");
            }

	    if (respcode[0] != '2') {
		err_response++;
		if (verbosity >= 2)
		    printf("WARNING: Response code not 2xx (%s)\n", respcode);
	    }
	    else if (verbosity >= 3) {
		printf("LOG: Response code = %s\n", respcode);
	    }
	    c->gotheader = 1;
	    *s = 0;		/* terminate at end of header */
	    if (keepalive &&
		(strstr(c->cbuff, "Keep-Alive")
		 || strstr(c->cbuff, "keep-alive"))) {	/* for benefit of MSIIS */
		char *cl;
		cl = strstr(c->cbuff, "Content-Length:");
		/* handle NCSA, which sends Content-length: */
		if (!cl)
		    cl = strstr(c->cbuff, "Content-length:");
		if (cl) {
		    c->keepalive = 1;
		    c->length = atoi(cl + 16);
		}
	    }
	    c->bread += c->cbx - (s + l - c->cbuff) + r - tocopy;
	    totalbread += c->bread;
	}
    }
    else {
	/* outside header, everything we have read is entity body */
	c->bread += r;
	totalbread += r;
    }

    /*
     * cater for the case where we're using keepalives and doing HEAD
     * requests
     */
    if (c->keepalive && ((c->bread >= c->length) || (posting < 0))) {
	/* finished a keep-alive connection */
	good++;
	doneka++;
	/* save out time */
	if (good == 1) {
	    /* first time here */
	    doclen = c->bread;
	}
	else if (c->bread != doclen) {
	    bad++;
	    err_length++;
	}
	if (done < requests) {
	    struct data s;
	    if ((done) && (heartbeatres) && (!(done % heartbeatres))) {
		fprintf(stderr, "Completed %ld requests\n", done);
		fflush(stderr);
	    }
	    gettimeofday(&c->done, 0);
	    s.read = c->read;
	    s.starttime = c->start.tv_sec;
	    s.ctime = timedif(c->connect, c->start);
	    s.waittime = timedif(c->beginread, c->endwrite);
	    s.time = timedif(c->done, c->start);
	    stats[done++] = s;
	}
	c->keepalive = 0;
	c->length = 0;
	c->gotheader = 0;
	c->cbx = 0;
	c->read = c->bread = 0;
	write_request(c);
	c->start = c->connect;	/* zero connect time with keep-alive */
    }
}

/* --------------------------------------------------------- */

/* run the tests */

static void test(void)
{
    struct timeval timeout, now;
    fd_set sel_read, sel_except, sel_write;
    long i;
    int connectport;
    char * connecthost;
    char * url_on_request;

    /* There are four hostname's involved:
     * The 'hostname' from the URL, the
     * hostname of the proxy, the value which
     * is to go into the Host: header and
     * the hostname we connect to over TCP.
     */
    if (isproxy) {
	/* Connect to proxyhost:proxyport
         * And set Host: to the hostname and
	 * if not default :port of the URL.
	 * See RFC2616 - $14.23. But then in
	 * $5.2.1 it says that the Host: field
	 * when passed on MUST be ignored. So	
	 * perhaps we should NOT send any
	 * when we are proxying.
	 */
	connecthost  = proxyhost;
	connectport = proxyport;
    	url_on_request = fullurl;
    }
    else {
	/* When there is no proxy: 
	 * use the hostname to connect to,
	 * use the hostname in the Host:
	 * header; and do not quote a full
	 * URL in the GET/POST line.
	 */
	connecthost  = hostname;
	connectport = port;
    	url_on_request = path;
    }
    
    if (!use_html) {
	printf("Benchmarking %s (be patient)%s",
	       hostname, (heartbeatres ? "\n" : "..."));
	fflush(stdout);
    }
    {
	/* get server information */
	struct hostent *he;
	he = gethostbyname(connecthost);
	if (!he) {
	    char theerror[1024];
	    ap_snprintf(theerror, sizeof(theerror),
                        "Bad hostname: %s\n", connecthost);
	    err(theerror);
	}
	server.sin_family = he->h_addrtype;
	server.sin_port = htons(connectport);
	server.sin_addr.s_addr = ((unsigned long *) (he->h_addr_list[0]))[0];
    }

    con = malloc(concurrency * sizeof(struct connection));
    memset(con, 0, concurrency * sizeof(struct connection));

    stats = malloc(requests * sizeof(struct data));

    FD_ZERO(&readbits);
    FD_ZERO(&writebits);

    /* setup request */
    if (posting <= 0) {
	ap_snprintf(request, sizeof(request), 
                    "%s %s HTTP/1.0\r\n"
                    "User-Agent: ApacheBench/%s\r\n"
                    "%s" "%s" "%s"
                    "Host: %s%s\r\n"
                    "Accept: */*\r\n"
                    "%s" "\r\n",
                    (posting == 0) ? "GET" : "HEAD",
                    url_on_request,
                    VERSION,
                    keepalive ? "Connection: Keep-Alive\r\n" : "",
                    cookie, auth, 
                    hostname,colonport, hdrs);
    }
    else {
        ap_snprintf(request, sizeof(request),
                    "POST %s HTTP/1.0\r\n"
                    "User-Agent: ApacheBench/%s\r\n"
                    "%s" "%s" "%s"
                    "Host: %s%s\r\n"
                    "Accept: */*\r\n"
                    "Content-length: %d\r\n"
                    "Content-type: %s\r\n"
                    "%s"
                    "\r\n",
                    url_on_request,
                    VERSION,
                    keepalive ? "Connection: Keep-Alive\r\n" : "",
                    cookie, auth,
                    hostname, colonport, postlen,
                    (content_type[0]) ? content_type : "text/plain", hdrs);
    }

    if (verbosity >= 2)
	printf("INFO: POST header == \n---\n%s\n---\n", request);

    reqlen = strlen(request);

#ifdef CHARSET_EBCDIC
    ebcdic2ascii(request, request, reqlen);
#endif				/* CHARSET_EBCDIC */

    /* ok - lets start */
    gettimeofday(&start, 0);

    /* initialise lots of requests */
    for (i = 0; i < concurrency; i++)
	start_connect(&con[i]);

    while (done < requests) {
	int n;
	/* setup bit arrays */
	memcpy(&sel_except, &readbits, sizeof(readbits));
	memcpy(&sel_read, &readbits, sizeof(readbits));
	memcpy(&sel_write, &writebits, sizeof(readbits));

	/* check for time limit expiry */
	gettimeofday(&now, 0);
	if (tlimit && timedif(now, start) >= (tlimit * 1000)) {
	    requests = done;	/* so stats are correct */
	}
	/* Timeout of 30 seconds. */
	timeout.tv_sec = 120;
	timeout.tv_usec = 0;
	n = ap_select(FD_SETSIZE, &sel_read, &sel_write, &sel_except, &timeout);
	if (!n) {
	    err("\nServer timed out\n\n");
	}
	if (n < 1)
	    err("select");

	for (i = 0; i < concurrency; i++) {
	    int s = con[i].fd;
	    if (FD_ISSET(s, &sel_except)) {
		bad++;
		err_except++;
		start_connect(&con[i]);
		continue;
	    }
	    if (FD_ISSET(s, &sel_read))
		read_connection(&con[i]);
	    if (FD_ISSET(s, &sel_write))
		write_request(&con[i]);
	}
    }

    if (heartbeatres)
	fprintf(stderr, "Finished %ld requests\n", done);
    else
	printf("..done\n");

    if (use_html)
	output_html_results();
    else
	output_results();
}

/* ------------------------------------------------------- */

/* display copyright information */
static void copyright(void)
{
    if (!use_html) {
	printf("This is ApacheBench, Version %s\n", VERSION " <$Revision: 1.70 $> apache-1.3");
	printf("Copyright (c) 1996 Adam Twiss, Zeus Technology Ltd, http://www.zeustech.net/\n");
	printf("Copyright (c) 1998-2002 The Apache Software Foundation, http://www.apache.org/\n");
	printf("\n");
    }
    else {
	printf("<p>\n");
	printf(" This is ApacheBench, Version %s <i>&lt;%s&gt;</i> apache-1.3<br>\n", VERSION, "$Revision: 1.70 $");
	printf(" Copyright (c) 1996 Adam Twiss, Zeus Technology Ltd, http://www.zeustech.net/<br>\n");
	printf(" Copyright (c) 1998-2002 The Apache Software Foundation, http://www.apache.org/<br>\n");
	printf("</p>\n<p>\n");
    }
}

/* display usage information */
static void usage(char *progname)
{
    fprintf(stderr, "Usage: %s [options] [http"
#ifdef USE_SSL
	    "[s]"
#endif
	    "://]hostname[:port]/path\n", progname);
    fprintf(stderr, "Options are:\n");
    fprintf(stderr, "    -n requests     Number of requests to perform\n");
    fprintf(stderr, "    -c concurrency  Number of multiple requests to make\n");
    fprintf(stderr, "    -t timelimit    Seconds to max. wait for responses\n");
    fprintf(stderr, "    -p postfile     File containg data to POST\n");
    fprintf(stderr, "    -T content-type Content-type header for POSTing\n");
    fprintf(stderr, "    -v verbosity    How much troubleshooting info to print\n");
    fprintf(stderr, "    -w              Print out results in HTML tables\n");
    fprintf(stderr, "    -i              Use HEAD instead of GET\n");
    fprintf(stderr, "    -x attributes   String to insert as table attributes\n");
    fprintf(stderr, "    -y attributes   String to insert as tr attributes\n");
    fprintf(stderr, "    -z attributes   String to insert as td or th attributes\n");
    fprintf(stderr, "    -C attribute    Add cookie, eg. 'Apache=1234' (repeatable)\n");
    fprintf(stderr, "    -H attribute    Add Arbitrary header line, eg. 'Accept-Encoding: zop'\n");
    fprintf(stderr, "                    Inserted after all normal header lines. (repeatable)\n");
    fprintf(stderr, "    -A attribute    Add Basic WWW Authentication, the attributes\n");
    fprintf(stderr, "                    are a colon separated username and password.\n");
    fprintf(stderr, "    -P attribute    Add Basic Proxy Authentication, the attributes\n");
    fprintf(stderr, "                    are a colon separated username and password.\n");
    fprintf(stderr, "    -X proxy:port   Proxyserver and port number to use\n");
    fprintf(stderr, "    -V              Print version number and exit\n");
    fprintf(stderr, "    -k              Use HTTP KeepAlive feature\n");
    fprintf(stderr, "    -d              Do not show percentiles served table.\n");
    fprintf(stderr, "    -S              Do not show confidence estimators and warnings.\n");
    fprintf(stderr, "    -g filename     Output collected data to gnuplot format file.\n");
    fprintf(stderr, "    -e filename     Output CSV file with percentages served\n");
#ifdef USE_SSL
    fprintf(stderr, "    -s              Use httpS instead of HTTP (SSL)\n");
#endif
    fprintf(stderr, "    -h              Display usage information (this message)\n");
    exit(EINVAL);
}

/* ------------------------------------------------------- */

/* split URL into parts */

static int parse_url(char * purl)
{
    char *cp;
    char *h;
    char *p = NULL;

    if (strlen(purl) > 7 && strncmp(purl, "http://", 7) == 0)
	purl += 7;
    else
#ifdef USE_SSL
    if (strlen(purl) > 8 && strncmp(purl, "https://", 8) == 0) {
	purl += 8;
	ssl = 1;
	port = 443;
    }
#else
    if (strlen(purl) > 8 && strncmp(purl, "https://", 8) == 0) {
	fprintf(stderr, "SSL not compiled in; no https support\n");
	exit(1);
    }
#endif

    h = purl;
    if ((cp = strchr(purl, ':')) != NULL) {
	*cp++ = '\0';
	p = cp;
	purl = cp;
    }
    if ((cp = strchr(purl, '/')) == NULL)
	return 1;
    strcpy(path, cp);
    *cp = '\0';
    strcpy(hostname, h);
    if (p != NULL)
	port = atoi(p);

    if ((
#ifdef USE_SSL
	(ssl != 0) && (port != 443)) || ((ssl == 0) && 
#endif
	(port != 80))) 
   {
	ap_snprintf(colonport,sizeof(colonport),":%d",port);
   } else {
	colonport[0] = '\0';
   }
   return 0;
}

/* ------------------------------------------------------- */

/* read data to POST from file, save contents and length */

static int open_postfile(char *pfile)
{
    int postfd, status;
    struct stat postfilestat;

    if ((postfd = open(pfile, O_RDONLY)) == -1) {
	printf("Invalid postfile name (%s)\n", pfile);
	return errno;
    }
    if ((status = fstat(postfd, &postfilestat)) == -1) {
	perror("Can\'t stat postfile\n");
	return status;
    }
    postdata = malloc(postfilestat.st_size);
    if (!postdata) {
	printf("Can\'t alloc postfile buffer\n");
	return ENOMEM;
    }
    if (read(postfd, postdata, postfilestat.st_size) != postfilestat.st_size) {
	printf("error reading postfilen");
	return EIO;
    }
    postlen = postfilestat.st_size;
    return 0;
}

/* ------------------------------------------------------- */

extern char *optarg;
extern int optind, opterr, optopt;

/* sort out command-line args and call test */
int main(int argc, char **argv)
{
    int c, r, l;
    char tmp[1024];
    /* table defaults  */
    tablestring = "";
    trstring = "";
    tdstring = "bgcolor=white";
    cookie[0] = '\0';
    auth[0] = '\0';
    hdrs[0] = '\0';
    proxyhost[0] = '\0';
    optind = 1;
    while ((c = getopt(argc, argv, "n:c:t:T:p:v:kVhwix:y:z:C:H:P:A:g:X:de:Sq"
#ifdef USE_SSL
		       "s"
#endif
		       )) > 0) {
	switch (c) {
#ifdef USE_SSL
	case 's':
	    ssl = 1;
	    break;
#endif
	case 'n':
	    requests = atoi(optarg);
	    if (!requests) {
		err("Invalid number of requests\n");
	    }
	    break;
	case 'q':
	    heartbeatres = 0;
	    break;
	case 'k':
	    keepalive = 1;
	    break;
	case 'c':
	    concurrency = atoi(optarg);
	    break;
	case 'g':
	    gnuplot = strdup(optarg);
	    break;
	case 'd':
	    percentile = 0;
	    break;
	case 'e':
	    csvperc = strdup(optarg);
	    break;
	case 'S':
	    confidence = 0;
	    break;
	case 'i':
	    if (posting == 1)
		err("Cannot mix POST and HEAD");

	    posting = -1;
	    break;
	case 'p':
	    if (posting != 0)
		err("Cannot mix POST and HEAD");

	    if (0 == (r = open_postfile(optarg))) {
		posting = 1;
	    }
	    else if (postdata) {
		exit(r);
	    }
	    break;
	case 'v':
	    verbosity = atoi(optarg);
	    break;
	case 't':
	    tlimit = atoi(optarg);
	    requests = MAX_REQUESTS;	/* need to size data array on
					 * something */
	    break;
	case 'T':
	    strcpy(content_type, optarg);
	    break;
	case 'C':
	    strncat(cookie, "Cookie: ", sizeof(cookie)-strlen(cookie)-1);
	    strncat(cookie, optarg, sizeof(cookie)-strlen(cookie)-1);
	    strncat(cookie, "\r\n", sizeof(cookie)-strlen(cookie)-1);
	    break;
	case 'A':
	    /*
	     * assume username passwd already to be in colon separated form.
	     * Ready to be uu-encoded.
	     */
	    while (isspace((int)*optarg))
		optarg++;
            if (ap_base64encode_len(strlen(optarg)) > sizeof(tmp)) {
                fprintf(stderr, "%s: Authentication credentials too long\n",
                        argv[0]);
                exit(1);
            }
            l = ap_base64encode(tmp, optarg, strlen(optarg));
	    tmp[l] = '\0';

	    strncat(auth, "Authorization: Basic ", sizeof(auth)-strlen(auth)-1);
	    strncat(auth, tmp, sizeof(auth)-strlen(auth)-1);
	    strncat(auth, "\r\n", sizeof(auth)-strlen(auth)-1);
	    break;
	case 'P':
	    /*
	     * assume username passwd already to be in colon separated form.
	     */
	    while (isspace((int)*optarg))
		optarg++;
            if (ap_base64encode_len(strlen(optarg)) > sizeof(tmp)) {
                fprintf(stderr, "%s: Proxy credentials too long\n", argv[0]);
                exit(1);
            }
	    l = ap_base64encode(tmp, optarg, strlen(optarg));
	    tmp[l] = '\0';

	    strncat(auth, "Proxy-Authorization: Basic ", sizeof(auth)-strlen(auth)-1);
	    strncat(auth, tmp, sizeof(auth)-strlen(auth)-1);
	    strncat(auth, "\r\n", sizeof(auth)-strlen(auth)-1);
	    break;
	case 'X':
	    {
		char *p;
		/*
		 * assume proxy-name[:port]
		 */
		if ((p = strchr(optarg, ':'))) {
		    *p = '\0';
		    p++;
		    proxyport = atoi(p);
		};
		strcpy(proxyhost, optarg);
		isproxy = 1;
	    }
	    break;
	case 'H':
	    strncat(hdrs, optarg, sizeof(hdrs)-strlen(hdrs)-1);
	    strncat(hdrs, "\r\n", sizeof(hdrs)-strlen(hdrs)-1);
	    break;
	case 'V':
	    copyright();
	    exit(0);
	    break;
	case 'w':
	    use_html = 1;
	    break;
	    /*
	     * if any of the following three are used, turn on html output
	     * automatically
	     */
	case 'x':
	    use_html = 1;
	    tablestring = optarg;
	    break;
	case 'y':
	    use_html = 1;
	    trstring = optarg;
	    break;
	case 'z':
	    use_html = 1;
	    tdstring = optarg;
	    break;
	case 'h':
	    usage(argv[0]);
	    break;
	default:
	    fprintf(stderr, "%s: invalid option `%c'\n", argv[0], c);
	    usage(argv[0]);
	    break;
	}
    }
    if (optind != argc - 1) {
	fprintf(stderr, "%s: wrong number of arguments\n", argv[0]);
	usage(argv[0]);
    }
    strcpy(url, argv[optind++]);
    strcpy(fullurl, url);
    if (parse_url(url)) {
	fprintf(stderr, "%s: invalid URL\n", argv[0]);
	usage(argv[0]);
    }

    if ((heartbeatres) && (requests > 150)) {
	heartbeatres = requests / 10;	/* Print a line every 10% of requests */
	if (heartbeatres < 100)
	    heartbeatres = 100;	/* but never more often than once every 100
				 * connections. */
    }
    else
	/* if there are less than 150 requests; do not show
	 * the little tick/tock dots.
	 */
	heartbeatres = 0;

#ifdef USE_SSL
    SSL_library_init();
    if (!(ctx = SSL_CTX_new(SSLv2_client_method()))) {
	fprintf(stderr, "Could not init SSL CTX: ");
	ERR_print_errors_fp(stderr);
	exit(1);
    }
#endif
    signal(SIGPIPE, SIG_IGN);           /* Ignore writes to connections that
					 * have been closed at the other end.
					 * These writes are dealt with in the
					 * s_write() function. */

    copyright();
    test();

    exit(0);
}
