/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000-2001 The Apache Software Foundation.  All rights
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
   **      trapping of connection errors which influenced measurements.
   **      Contributed by Sander Temme - <sctemme@covalent.net>, Early 2001
   ** Version 1.3e
   **    - Changed timeout behavour during write to work whilst the sockets
   **      are filling up and apr_write() does writes a few - but not all.
   **      This will potentially change results. <dirkx@webweaving.org>, April 2001
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
 */

/*  -------------------------------------------------------------------- */

#if 'A' != 0x41
/* Hmmm... This source code isn't being compiled in ASCII.
 * In order for data that flows over the network to make
 * sense, we need to translate to/from ASCII.
 */
#define NOT_ASCII
#endif

/* affects include files on Solaris */
#define BSD_COMP

#include "apr.h"
#include "apr_strings.h"
#include "apr_network_io.h"
#include "apr_file_io.h"
#include "apr_time.h"
#include "apr_getopt.h"
#include "apr_general.h"
#include <signal.h>
#include "apr_lib.h"
#include "ap_release.h"

#define APR_WANT_STRFUNC
#include "apr_want.h"
#if APR_HAVE_STDIO_H
#include <stdio.h>		/* for EOF */
#endif
#if APR_HAVE_STDLIB_H
#include <stdlib.h>
#endif

#include "apr_base64.h"
#ifdef NOT_ASCII
#include "apr_xlate.h"
#endif
#if APR_HAVE_STDIO_H
#include <stdio.h>
#endif
#if APR_HAVE_STDLIB_H
#include <stdlib.h>

#ifdef	USE_SSL
#if ((!(RSAREF)) && (!(SYSSSL)))
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
#endif
#if APR_HAVE_CTYPE_H
#include <ctype.h>
#endif

/* ------------------- DEFINITIONS -------------------------- */

#ifndef LLONG_MAX
#define AB_MAX APR_INT64_C(0x7fffffffffffffff)
#else
#define AB_MAX LLONG_MAX
#endif

/* maximum number of requests on a time limited test */
#define MAX_REQUESTS 50000

/* good old state hostname */
#define STATE_UNCONNECTED 0
#define STATE_CONNECTING  1
#define STATE_READ        2

#define CBUFFSIZE (2048)

struct connection {
    apr_pool_t *ctx;
    apr_socket_t *aprsock;
    int state;
    apr_size_t read;		/* amount of bytes read */
    apr_size_t bread;		/* amount of body read */
    apr_size_t rwrite, rwrote;	/* keep pointers in what we write - across
				 * EAGAINs */
    apr_size_t length;	        /* Content-Length value used for keep-alive */
    char cbuff[CBUFFSIZE];	/* a buffer to store server response header */
    int cbx;			/* offset in cbuffer */
    int keepalive;		/* non-zero if a keep-alive request */
    int gotheader;		/* non-zero if we have the entire header in
				 * cbuff */
    apr_time_t start,		/* Start of connection */
               connect,		/* Connected, start writing */
               endwrite,	/* Request written */
               beginread,	/* First byte of input */
               done;		/* Connection closed */

    int socknum;
#ifdef USE_SSL
    SSL *ssl;
#endif
};

struct data {
#ifdef USE_SSL
    /* XXXX insert SSL timings */
#endif
    int read;              /* number of bytes read */
    apr_time_t starttime;  /* start time of connection in seconds since
                            * Jan. 1, 1970 */
    apr_interval_time_t waittime;   /* Between writing request and reading
                                     * response */
    apr_interval_time_t ctime;      /* time in ms to connect */
    apr_interval_time_t time;       /* time in ms for connection */
};

#define ap_min(a,b) ((a)<(b))?(a):(b)
#define ap_max(a,b) ((a)>(b))?(a):(b)

/* --------------------- GLOBALS ---------------------------- */

int verbosity = 0;		/* no verbosity by default */
int posting = 0;		/* GET by default */
int requests = 1;		/* Number of requests to make */
int heartbeatres = 100;		/* How often do we say we're alive */
int concurrency = 1;		/* Number of multiple requests to make */
int percentile = 1;		/* Show percentile served */
int confidence = 1;		/* Show confidence estimator and warnings */
int tlimit = 0;			/* time limit in cs */
int keepalive = 0;		/* try and do keepalive connections */
char servername[1024];		/* name that server reports */
char *hostname;			/* host name from URL */
char *host_field;		/* value of "Host:" header field */
char path[1024];		/* path name */
char postfile[1024];		/* name of file containing post data */
char *postdata;			/* *buffer containing data from postfile */
apr_size_t postlen = 0;		/* length of data to be POSTed */
char content_type[1024];	/* content type to put in POST header */
char cookie[1024],		/* optional cookie line */
     auth[1024],		/* optional (basic/uuencoded)
				 * authentification */
     hdrs[4096];		/* optional arbitrary headers */
apr_port_t port;		/* port number */
char proxyhost[1024];		/* proxy host name */
int proxyport = 0;		/* proxy port */
char connecthost[1024];
apr_port_t connectport;
char *gnuplot;			/* GNUplot file */
char *csvperc;			/* CSV Percentile file */
char url[1024];
char fullurl[1024];
int isproxy = 0;
apr_short_interval_time_t aprtimeout = 30 * APR_USEC_PER_SEC;	/* timeout value */
 /*
  * XXX - this is now a per read/write transact type of value
  */

int use_html = 0;		/* use html in the report */
const char *tablestring;
const char *trstring;
const char *tdstring;

apr_size_t doclen = 0;		/* the length the document should be */
long started = 0;		/* number of requests started, so no excess */
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

apr_time_t start, endtime;

/* global request (and its length) */
char _request[512];
char *request = _request;
apr_size_t reqlen;

/* one global throw-away buffer to read stuff into */
char buffer[8192];

/* interesting percentiles */
int percs[] = {50, 66, 75, 80, 90, 95, 98, 99, 100};

struct connection *con;		/* connection array */
struct data *stats;		/* date for each request */
apr_pool_t *cntxt;

apr_pollfd_t *readbits;

apr_sockaddr_t *destsa;

#ifdef NOT_ASCII
apr_xlate_t *from_ascii, *to_ascii;
#endif

static void close_connection(struct connection * c);
/* --------------------------------------------------------- */

/* simple little function to write an error string and exit */

static void err(char *s)
{
    fprintf(stderr, "%s\n", s);
    if (done)
        printf("Total of %ld requests completed\n" , done);
    exit(1);
}

/* simple little function to write an APR error string and exit */

static void apr_err(char *s, apr_status_t rv)
{
    char buf[120];

    fprintf(stderr,
	    "%s: %s (%d)\n",
	    s, apr_strerror(rv, buf, sizeof buf), rv);
    if (done)
        printf("Total of %ld requests completed\n" , done);
    exit(rv);
}

/* --------------------------------------------------------- */
/* write out request to a connection - assumes we can write
 * (small) request out in one go into our new socket buffer
 *
 */
static void write_request(struct connection * c)
{
    do {
	apr_time_t tnow = apr_time_now();
	apr_size_t l = c->rwrite;
	apr_status_t e;

	/*
	 * First time round ?
	 */
	if (c->rwrite == 0) {
	    apr_setsocketopt(c->aprsock, APR_SO_TIMEOUT, 0);
	    c->connect = tnow;
	    c->rwrite = reqlen;
	    c->rwrote = 0;
	    if (posting)
		c->rwrite += postlen;
	}
	else if (tnow > c->connect + aprtimeout) {
	    printf("Send request timed out!\n");
	    close_connection(c);
	    return;
	}

	e = apr_send(c->aprsock, request + c->rwrote, &l);

	/*
	 * Bail early on the most common case
	 */
	if (l == c->rwrite)
	    break;

	if (e != APR_SUCCESS) {
	    /*
	     * Let's hope this traps EWOULDBLOCK too !
	     */
	    if (!APR_STATUS_IS_EAGAIN(e)) {
		epipe++;
		printf("Send request failed!\n");
		close_connection(c);
	    }
	    return;
	}
	c->rwrote += l;
	c->rwrite -= l;
    } while (1);

    totalposted += c->rwrite;
    c->state = STATE_READ;
    c->endwrite = apr_time_now();
    apr_poll_socket_add(readbits, c->aprsock, APR_POLLIN);
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
    apr_interval_time_t p = a->time - a->ctime;
    apr_interval_time_t q = b->time - b->ctime;
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
    apr_interval_time_t timetakenusec;
    float timetaken;

    endtime = apr_time_now();
    timetakenusec = endtime - start;
    timetaken = (float) timetakenusec / APR_USEC_PER_SEC;
    
    printf("\r                                                                           \r");
    printf("Server Software:        %s\n", servername);
    printf("Server Hostname:        %s\n", hostname);
    printf("Server Port:            %hd\n", port);
    printf("\n");
    printf("Document Path:          %s\n", path);
    printf("Document Length:        %" APR_SIZE_T_FMT " bytes\n", doclen);
    printf("\n");
    printf("Concurrency Level:      %d\n", concurrency);
    printf("Time taken for tests:   %ld.%03ld seconds\n",
           (long) (timetakenusec / APR_USEC_PER_SEC),
           (long) (timetakenusec % APR_USEC_PER_SEC));
    printf("Complete requests:      %ld\n", done);
    printf("Failed requests:        %ld\n", bad);
    if (bad)
	printf("   (Connect: %d, Length: %d, Exceptions: %d)\n",
	       err_conn, err_length, err_except);
    printf("Write errors:           %ld\n", epipe);
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
	printf("Requests per second:    %.2f [#/sec] (mean)\n", 
               (float) (done / timetaken));
	printf("Time per request:       %.3f [ms] (mean)\n", 
               (float) (concurrency * timetaken / done));
	printf("Time per request:       %.3f [ms] (mean, across all concurrent requests)\n",
	       (float) (timetaken / done));
	printf("Transfer rate:          %.2f [Kbytes/sec] received\n",
	       (float) (totalread / 1024 / timetaken));
	if (posting > 0) {
	    printf("                        %.2f kb/s sent\n",
		   (float) (totalposted / timetaken / 1024));
	    printf("                        %.2f kb/s total\n",
		   (float) ((totalread + totalposted) / timetaken / 1024));
	}
    }

    if (requests) {
	/* work out connection times */
	long i;
	apr_time_t totalcon = 0, total = 0, totald = 0, totalwait = 0;
        apr_interval_time_t mincon = AB_MAX, mintot = AB_MAX, mind = AB_MAX, 
                            minwait = AB_MAX;
        apr_interval_time_t maxcon = 0, maxtot = 0, maxd = 0, maxwait = 0;
        apr_interval_time_t meancon = 0, meantot = 0, meand = 0, meanwait = 0;
        double sdtot = 0, sdcon = 0, sdd = 0, sdwait = 0;

	for (i = 0; i < requests; i++) {
	    struct data s = stats[i];
	    mincon = ap_min(mincon, s.ctime);
	    mintot = ap_min(mintot, s.time);
	    mind = ap_min(mind, s.time - s.ctime);
	    minwait = ap_min(minwait, s.waittime);

	    maxcon = ap_max(maxcon, s.ctime);
	    maxtot = ap_max(maxtot, s.time);
	    maxd = ap_max(maxd, s.time - s.ctime);
	    maxwait = ap_max(maxwait, s.waittime);

	    totalcon += s.ctime;
	    total += s.time;
	    totald += s.time - s.ctime;
	    totalwait += s.waittime;
	}
	totalcon /= requests;
	total /= requests;
	totald /= requests;
	totalwait /= requests;

	for (i = 0; i < requests; i++) {
	    struct data s = stats[i];
            double a;
            a = ((double)s.time - total);
            sdtot += a * a;
	    a = ((double)s.ctime - totalcon);
	    sdcon += a * a;
	    a = ((double)s.time - (double)s.ctime - totald);
	    sdd += a * a;
	    a = ((double)s.waittime - totalwait);
	    sdwait += a * a;
	}

	sdtot = (requests > 1) ? sqrt(sdtot / (requests - 1)) : 0;
	sdcon = (requests > 1) ? sqrt(sdcon / (requests - 1)) : 0;
	sdd = (requests > 1) ? sqrt(sdd / (requests - 1)) : 0;
	sdwait = (requests > 1) ? sqrt(sdwait / (requests - 1)) : 0;

	if (gnuplot) {
	    FILE *out = fopen(gnuplot, "w");
	    long i;
	    apr_time_t sttime;
	    char tmstring[1024];/* XXXX */
	    if (!out) {
		perror("Cannot open gnuplot output file");
		exit(1);
	    }
	    fprintf(out, "starttime\tseconds\tctime\tdtime\tttime\twait\n");
	    for (i = 0; i < requests; i++) {
                apr_time_t diff = stats[i].time - stats[i].ctime;

		sttime = stats[i].starttime;
		(void) apr_ctime(tmstring, sttime);
		tmstring[strlen(tmstring) - 1] = '\0';	/* ctime returns a
							 * string with a
							 * trailing newline */
		fprintf(out, "%s\t%" APR_TIME_T_FMT "\t%" APR_TIME_T_FMT "\t%" APR_TIME_T_FMT "\t%" APR_TIME_T_FMT "\t%" APR_TIME_T_FMT "\n",
			tmstring,
			sttime,
			stats[i].ctime,
			diff,
			stats[i].time,
			stats[i].waittime);
	    }
	    fclose(out);
	}
    /*
     * XXX: what is better; this hideous cast of the compradre function; or
     * the four warnings during compile ? dirkx just does not know and
     * hates both/
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

	printf("\nConnection Times (ms)\n");

	if (confidence) {
#define CONF_FMT_STRING "%" APR_TIME_T_FMT " %5d %6.1f %" APR_TIME_T_FMT " %" APR_TIME_T_FMT "\n"
	    printf("            min  mean[+/-sd] median   max\n");
	    printf("Connect:    " CONF_FMT_STRING, 
                   mincon, (int) (totalcon + 0.5), sdcon, meancon, maxcon);
	    printf("Processing: " CONF_FMT_STRING,
		   mind, (int) (totald + 0.5), sdd, meand, maxd);
	    printf("Waiting:    " CONF_FMT_STRING,
	           minwait, (int) (totalwait + 0.5), sdwait, meanwait, maxwait);
	    printf("Total:      " CONF_FMT_STRING,
		   mintot, (int) (total + 0.5), sdtot, meantot, maxtot);
#undef CONF_FMT_STRING

#define     SANE(what,avg,mean,sd) \
              { \
                double d = (double)avg - mean; \
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
#define CONF_FMT_STRING "%5" APR_TIME_T_FMT " %5" APR_TIME_T_FMT "%5" APR_TIME_T_FMT "\n"
	    printf("Connect:    " CONF_FMT_STRING, 
                   mincon, totalcon / requests, maxcon);
	    printf("Processing: " CONF_FMT_STRING, mintot - mincon, 
                   (total / requests) - (totalcon / requests), 
                   maxtot - maxcon);
	    printf("Total:      " CONF_FMT_STRING, 
                   mintot, total / requests, maxtot);
#undef CONF_FMT_STRING
	}


	/* Sorted on total connect times */
	if (percentile && (requests > 1)) {
	    printf("\nPercentage of the requests served within a certain time (ms)\n");
	    for (i = 0; i < sizeof(percs) / sizeof(int); i++)
		if (percs[i] <= 0)
		    printf(" 0%%  <0> (never)\n");
                else if (percs[i] >= 100)
		    printf(" 100%%  %5" APR_TIME_T_FMT " (longest request)\n",
                           stats[requests - 1].time);
                else
		    printf("  %d%%  %5" APR_TIME_T_FMT "\n", percs[i], 
                           stats[(int) (requests * percs[i] / 100)].time);
	}
	if (csvperc) {
	    FILE *out = fopen(csvperc, "w");
	    int i;
	    if (!out) {
		perror("Cannot open CSV output file");
		exit(1);
	    }
	    fprintf(out, "" "Percentage served" "," "Time in ms" "\n");
	    for (i = 0; i < 100; i++) {
		apr_time_t t;
		if (i == 0)
		    t = stats[0].time;
		else if (i == 100)
		    t = stats[requests - 1].time;
		else
		    t = stats[(int) (0.5 + requests * i / 100.0)].time;
		fprintf(out, "%d,%e\n", i, (double)t);
	    }
	    fclose(out);
        }

    }
}

/* --------------------------------------------------------- */

/* calculate and output results in HTML  */

static void output_html_results(void)
{
    long timetaken;

    endtime = apr_time_now();
    timetaken = (long)((endtime - start) / 1000);

    printf("\n\n<table %s>\n", tablestring);
    printf("<tr %s><th colspan=2 %s>Server Software:</th>"
	   "<td colspan=2 %s>%s</td></tr>\n",
	   trstring, tdstring, tdstring, servername);
    printf("<tr %s><th colspan=2 %s>Server Hostname:</th>"
	   "<td colspan=2 %s>%s</td></tr>\n",
	   trstring, tdstring, tdstring, hostname);
    printf("<tr %s><th colspan=2 %s>Server Port:</th>"
	   "<td colspan=2 %s>%hd</td></tr>\n",
	   trstring, tdstring, tdstring, port);
    printf("<tr %s><th colspan=2 %s>Document Path:</th>"
	   "<td colspan=2 %s>%s</td></tr>\n",
	   trstring, tdstring, tdstring, path);
    printf("<tr %s><th colspan=2 %s>Document Length:</th>"
	   "<td colspan=2 %s>%" APR_SIZE_T_FMT " bytes</td></tr>\n",
	   trstring, tdstring, tdstring, doclen);
    printf("<tr %s><th colspan=2 %s>Concurrency Level:</th>"
	   "<td colspan=2 %s>%d</td></tr>\n",
	   trstring, tdstring, tdstring, concurrency);
    printf("<tr %s><th colspan=2 %s>Time taken for tests:</th>"
	   "<td colspan=2 %s>%qd.%03qd seconds</td></tr>\n",
	   trstring, tdstring, tdstring, timetaken / APR_USEC_PER_SEC, timetaken % APR_USEC_PER_SEC);
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
	long i;
	apr_interval_time_t totalcon = 0, total = 0;
	apr_interval_time_t mincon = AB_MAX, mintot = AB_MAX;
	apr_interval_time_t maxcon = 0, maxtot = 0;

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
		   "<td %s>%5" APR_TIME_T_FMT "</td>"
		   "<td %s>%5" APR_TIME_T_FMT "</td>"
		   "<td %s>%5" APR_TIME_T_FMT "</td></tr>\n",
		   trstring, tdstring, tdstring, mincon, tdstring, totalcon / requests, tdstring, maxcon);
	    printf("<tr %s><th %s>Processing:</th>"
		   "<td %s>%5" APR_TIME_T_FMT "</td>"
		   "<td %s>%5" APR_TIME_T_FMT "</td>"
		   "<td %s>%5" APR_TIME_T_FMT "</td></tr>\n",
		   trstring, tdstring, tdstring, mintot - mincon, tdstring,
		   (total / requests) - (totalcon / requests), tdstring, maxtot - maxcon);
	    printf("<tr %s><th %s>Total:</th>"
		   "<td %s>%5" APR_TIME_T_FMT "</td>"
		   "<td %s>%5" APR_TIME_T_FMT "</td>"
		   "<td %s>%5" APR_TIME_T_FMT "</td></tr>\n",
		   trstring, tdstring, tdstring, mintot, tdstring, total / requests, tdstring, maxtot);
	}
	printf("</table>\n");
    }
}

/* --------------------------------------------------------- */

/* start asnchronous non-blocking connection */

static void start_connect(struct connection * c)
{
    apr_status_t rv;
    
    if (!(started < requests))
	return;

    c->read = 0;
    c->bread = 0;
    c->keepalive = 0;
    c->cbx = 0;
    c->gotheader = 0;
    c->rwrite = 0;
    if (c->ctx)
        apr_pool_destroy(c->ctx);
    apr_pool_create(&c->ctx, cntxt);

    if ((rv = apr_socket_create(&c->aprsock, destsa->sa.sin.sin_family,
				SOCK_STREAM, c->ctx)) != APR_SUCCESS) {
	apr_err("socket", rv);
    }
    c->start = apr_time_now();
    if ((rv = apr_connect(c->aprsock, destsa)) != APR_SUCCESS) {
	if (APR_STATUS_IS_EINPROGRESS(rv)) {
	    c->state = STATE_CONNECTING;
	    c->rwrite = 0;
	    apr_poll_socket_add(readbits, c->aprsock, APR_POLLOUT);
	    return;
	}
	else {
	    apr_poll_socket_remove(readbits, c->aprsock);
	    apr_socket_close(c->aprsock);
	    err_conn++;
	    if (bad++ > 10) {
		fprintf(stderr,
			"\nTest aborted after 10 failures\n\n");
		apr_err("apr_connect()", rv);
	    }
	    c->state = STATE_UNCONNECTED;
	    start_connect(c);
	    return;
	}
    }

    /* connected first time */
    started++;
    write_request(c);
}

/* --------------------------------------------------------- */

/* close down connection and save stats */

static void close_connection(struct connection * c)
{
    if (c->read == 0 && c->keepalive) {
	/*
	 * server has legitimately shut down an idle keep alive request
	 */
	if (good)
	    good--;		/* connection never happened */
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
	    if ((done) && heartbeatres && !(done % heartbeatres)) {
		fprintf(stderr, "Completed %ld requests\n", done);
		fflush(stderr);
	    }
	    c->done = apr_time_now();
	    s.read = c->read;
	    s.starttime = c->start;
	    s.ctime = (c->connect - c->start) / 1000;
	    s.time = (c->done - c->start) / 1000;
	    s.waittime = (c->beginread - c->endwrite) / 1000;
	    stats[done++] = s;
	}
    }

    apr_poll_socket_remove(readbits, c->aprsock);
    apr_socket_close(c->aprsock);
    c->state = STATE_UNCONNECTED;

    /* connect again */
    start_connect(c);
    return;
}

/* --------------------------------------------------------- */

/* read data from connection */

static void read_connection(struct connection * c)
{
    apr_size_t r;
    apr_status_t status;
    char *part;
    char respcode[4];		/* 3 digits and null */

    r = sizeof(buffer);
    apr_setsocketopt(c->aprsock, APR_SO_TIMEOUT, aprtimeout);
    status = apr_recv(c->aprsock, buffer, &r);
    if (r == 0 || (status != APR_SUCCESS && !APR_STATUS_IS_EAGAIN(status))) {
	good++;
	close_connection(c);
	return;
    }

    if (APR_STATUS_IS_EAGAIN(status))
	return;

    totalread += r;
    if (c->read == 0) {
	c->beginread = apr_time_now();
    }
    c->read += r;


    if (!c->gotheader) {
	char *s;
	int l = 4;
	apr_size_t space = CBUFFSIZE - c->cbx - 1; /* -1 allows for \0 term */
	int tocopy = (space < r) ? space : r;
#ifdef NOT_ASCII
	apr_size_t inbytes_left = space, outbytes_left = space;

	status = apr_xlate_conv_buffer(from_ascii, buffer, &inbytes_left,
				       c->cbuff + c->cbx, &outbytes_left);
	if (status || inbytes_left || outbytes_left) {
	    fprintf(stderr, "only simple translation is supported (%d/%u/%u)\n",
		    status, inbytes_left, outbytes_left);
	    exit(1);
	}
#else
	memcpy(c->cbuff + c->cbx, buffer, space);
#endif				/* NOT_ASCII */
	c->cbx += tocopy;
	space -= tocopy;
	c->cbuff[c->cbx] = 0;	/* terminate for benefit of strstr */
	if (verbosity >= 4) {
	    printf("LOG: header received:\n%s\n", c->cbuff);
	}
	s = strstr(c->cbuff, "\r\n\r\n");
	/*
	 * this next line is so that we talk to NCSA 1.5 which blatantly
	 * breaks the http specifaction
	 */
	if (!s) {
	    s = strstr(c->cbuff, "\n\n");
	    l = 2;
	}

	if (!s) {
	    /* read rest next time */
	    if (space) {
		return;
	    }
	    else {
		/* header is in invalid or too big - close connection */
		apr_poll_socket_remove(readbits, c->aprsock);
		apr_socket_close(c->aprsock);
		err_response++;
		if (bad++ > 10) {
		    err("\nTest aborted after 10 failures\n\n");
		}
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
		p = strstr(c->cbuff, "Server:");
		q = servername;
		if (p) {
		    p += 8;
		    while (*p > 32)
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
	    strncpy(respcode, (part + strlen("HTTP/1.x_")), 3);
	    respcode[3] = '\0';
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

    if (c->keepalive && (c->bread >= c->length)) {
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
	    if (done && heartbeatres && !(done % heartbeatres)) {
		fprintf(stderr, "Completed %ld requests\n", done);
		fflush(stderr);
	    }
	    c->done = apr_time_now();
	    s.read = c->read;
	    s.starttime = c->start;
	    s.ctime = (c->connect - c->start) / 1000;
	    s.waittime = (c->beginread - c->endwrite) / 1000;
	    s.time = (c->done - c->start) / 1000;
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
    apr_time_t now;
    apr_int16_t rv;
    long i;
    apr_status_t status;
#ifdef NOT_ASCII
    apr_size_t inbytes_left, outbytes_left;
#endif

    if (isproxy) {
	strcpy(connecthost, proxyhost);
	connectport = proxyport;
    }
    else {
	strcpy(connecthost, hostname);
	connectport = port;
    }

    if (!use_html) {
	printf("Benchmarking %s ", hostname);
	if (isproxy)
	    printf("[through %s:%d] ", proxyhost, proxyport);
	printf("(be patient)%s",
	       (heartbeatres ? "\n" : "..."));
	fflush(stdout);
    }

    now = apr_time_now();

    con = calloc(concurrency * sizeof(struct connection), 1);
    
    stats = calloc(requests * sizeof(struct data), 1);
    apr_poll_setup(&readbits, concurrency, cntxt);

    /* setup request */
    if (posting <= 0) {
	sprintf(request, "%s %s HTTP/1.0\r\n"
		"User-Agent: ApacheBench/%s\r\n"
		"%s" "%s" "%s"
		"Host: %s\r\n"
		"Accept: */*\r\n"
		"%s" "\r\n",
		(posting == 0) ? "GET" : "HEAD",
		(isproxy) ? fullurl : path,
		AP_SERVER_BASEREVISION,
		keepalive ? "Connection: Keep-Alive\r\n" : "",
		cookie, auth, host_field, hdrs);
    }
    else {
	sprintf(request, "POST %s HTTP/1.0\r\n"
		"User-Agent: ApacheBench/%s\r\n"
		"%s" "%s" "%s"
		"Host: %s\r\n"
		"Accept: */*\r\n"
		"Content-length: %" APR_SIZE_T_FMT "\r\n"
		"Content-type: %s\r\n"
		"%s"
		"\r\n",
		(isproxy) ? fullurl : path,
		AP_SERVER_BASEREVISION,
		keepalive ? "Connection: Keep-Alive\r\n" : "",
		cookie, auth,
		host_field, postlen,
		(content_type[0]) ? content_type : "text/plain", hdrs);
    }

    if (verbosity >= 2)
	printf("INFO: POST header == \n---\n%s\n---\n", request);

    reqlen = strlen(request);

    /*
     * Combine headers and (optional) post file into one contineous buffer
     */
    if (posting == 1) {
	char *buff = (char *) malloc(postlen + reqlen + 1);
	strcpy(buff, request);
	strcpy(buff + reqlen, postdata);
	request = buff;
    }

#ifdef NOT_ASCII
    inbytes_left = outbytes_left = reqlen;
    status = apr_xlate_conv_buffer(to_ascii, request, &inbytes_left,
				   request, &outbytes_left);
    if (status || inbytes_left || outbytes_left) {
	fprintf(stderr, "only simple translation is supported (%d/%u/%u)\n",
		status, inbytes_left, outbytes_left);
	exit(1);
    }
#endif				/* NOT_ASCII */

    /* This only needs to be done once */
    if ((rv = apr_sockaddr_info_get(&destsa, connecthost, APR_UNSPEC, connectport, 0, cntxt))
	!= APR_SUCCESS) {
	char buf[120];
	apr_snprintf(buf, sizeof(buf),
		     "apr_sockaddr_info_get() for %s", connecthost);
	apr_err(buf, rv);
    }

    /* ok - lets start */
    start = apr_time_now();

    /* initialise lots of requests */
    for (i = 0; i < concurrency; i++) {
	con[i].socknum = i;
	start_connect(&con[i]);
    }

    while (done < requests) {
	apr_int32_t n;
	apr_int32_t timed;

	/* check for time limit expiry */
	now = apr_time_now();
	timed = (apr_int32_t)((now - start) / APR_USEC_PER_SEC);
	if (tlimit && timed > (tlimit * 1000)) {
	    requests = done;	/* so stats are correct */
	}

	n = concurrency;
	status = apr_poll(readbits, &n, aprtimeout);
	if (status != APR_SUCCESS)
	    apr_err("apr_poll", status);

	if (!n) {
	    err("\nServer timed out\n\n");
	}

	for (i = 0; i < concurrency; i++) {
	    /*
	     * If the connection isn't connected how can we check it?
	     */
	    if (con[i].state == STATE_UNCONNECTED)
		continue;

	    apr_poll_revents_get(&rv, con[i].aprsock, readbits);
	    /*
	     * Notes: APR_POLLHUP is set after FIN is received on some
	     * systems, so treat that like APR_POLLIN so that we try to read
	     * again.
	     *
	     * Some systems return APR_POLLERR with APR_POLLHUP.  We need to
	     * call read_connection() for APR_POLLHUP, so check for
	     * APR_POLLHUP first so that a closed connection isn't treated
	     * like an I/O error.  If it is, we never figure out that the
	     * connection is done and we loop here endlessly calling
	     * apr_poll().
	     */
	    if ((rv & APR_POLLIN) || (rv & APR_POLLPRI) || (rv & APR_POLLHUP))
		read_connection(&con[i]);
	    if ((rv & APR_POLLERR) || (rv & APR_POLLNVAL)) {
		bad++;
		err_except++;
		start_connect(&con[i]);
		continue;
	    }
	    if (rv & APR_POLLOUT)
		write_request(&con[i]);

	    /*
	     * When using a select based poll every time we check the bits
	     * are reset. In 1.3's ab we copied the FD_SET's each time
	     * through, but here we're going to check the state and if the
	     * connection is in STATE_READ or STATE_CONNECTING we'll add the
	     * socket back in as APR_POLLIN.
	     */
	    if (con[i].state == STATE_READ || con[i].state == STATE_CONNECTING)
		apr_poll_socket_add(readbits, con[i].aprsock, APR_POLLIN);

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
	printf("This is ApacheBench, Version %s\n", AP_SERVER_BASEREVISION " <$Revision: 1.87 $> apache-2.0");
	printf("Copyright (c) 1996 Adam Twiss, Zeus Technology Ltd, http://www.zeustech.net/\n");
	printf("Copyright (c) 1998-2001 The Apache Software Foundation, http://www.apache.org/\n");
	printf("\n");
    }
    else {
	printf("<p>\n");
	printf(" This is ApacheBench, Version %s <i>&lt;%s&gt;</i> apache-2.0<br>\n", AP_SERVER_BASEREVISION, "$Revision: 1.87 $");
	printf(" Copyright (c) 1996 Adam Twiss, Zeus Technology Ltd, http://www.zeustech.net/<br>\n");
	printf(" Copyright (c) 1998-2001 The Apache Software Foundation, http://www.apache.org/<br>\n");
	printf("</p>\n<p>\n");
    }
}

/* display usage information */
static void usage(const char *progname)
{
    fprintf(stderr, "Usage: %s [options] [http"
#if USE_SSL
	    "[s]"
#endif
	    "://]hostname[:port]/path\n", progname);
    fprintf(stderr, "Options are:\n");
    fprintf(stderr, "    -n requests     Number of requests to perform\n");
    fprintf(stderr, "    -c concurrency  Number of multiple requests to make\n");
    fprintf(stderr, "    -t timelimit    Seconds to max. wait for responses\n");
    fprintf(stderr, "    -p postfile     File containing data to POST\n");
    fprintf(stderr, "    -T content-type Content-type header for POSTing\n");
    fprintf(stderr, "    -v verbosity    How much troubleshooting info to print\n");
    fprintf(stderr, "    -w              Print out results in HTML tables\n");
    fprintf(stderr, "    -i              Use HEAD instead of GET\n");
    fprintf(stderr, "    -x attributes   String to insert as table attributes\n");
    fprintf(stderr, "    -y attributes   String to insert as tr attributes\n");
    fprintf(stderr, "    -z attributes   String to insert as td or th attributes\n");
    fprintf(stderr, "    -C attribute    Add cookie, eg. 'Apache=1234. (repeatable)\n");
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
#if USE_SSL
    fprintf(stderr, "    -s              Use httpS instead of HTTP (SSL)\n");
#endif
    fprintf(stderr, "    -h              Display usage information (this message)\n");
    exit(EINVAL);
}

/* ------------------------------------------------------- */

/* split URL into parts */

static int parse_url(char *url)
{
    char *cp;
    char *h;
    char *scope_id;
    apr_status_t rv;

    if (strlen(url) > 7 && strncmp(url, "http://", 7) == 0)
	url += 7;
    else
#if USE_SSL
    if (strlen(url) > 8 && strncmp(url, "https://", 8) == 0) {
	url += 8;
	ssl = 1;
	port = 443;
    }
#else
    if (strlen(url) > 8 && strncmp(url, "https://", 8) == 0) {
	fprintf(stderr, "SSL not compiled in; no https support\n");
	exit(1);
    }
#endif

    if ((cp = strchr(url, '/')) == NULL)
	return 1;
    h = apr_palloc(cntxt, cp - url + 1);
    memcpy(h, url, cp - url);
    h[cp - url] = '\0';
    rv = apr_parse_addr_port(&hostname, &scope_id, &port, h, cntxt);
    if (rv != APR_SUCCESS || !hostname || scope_id) {
	return 1;
    }
    strcpy(path, cp);
    *cp = '\0';
    if (*url == '[') {		/* IPv6 numeric address string */
	host_field = apr_psprintf(cntxt, "[%s]", hostname);
    }
    else {
	host_field = hostname;
    }
    if (port == 0) {		/* no port specified */
	port = 80;
    }
    return 0;
}

/* ------------------------------------------------------- */

/* read data to POST from file, save contents and length */

static int open_postfile(const char *pfile)
{
    apr_file_t *postfd = NULL;
    apr_finfo_t finfo;
    apr_fileperms_t mode = APR_OS_DEFAULT;
    apr_size_t length;
    apr_status_t rv;
    char errmsg[120];

    rv = apr_file_open(&postfd, pfile, APR_READ, mode, cntxt);
    if (rv != APR_SUCCESS) {
	printf("Invalid postfile name (%s): %s\n", pfile,
	       apr_strerror(rv, errmsg, sizeof errmsg));
	return rv;
    }

    apr_file_info_get(&finfo, APR_FINFO_NORM, postfd);
    postlen = (apr_size_t)finfo.size;
    postdata = (char *) malloc(postlen);
    if (!postdata) {
	printf("Can\'t alloc postfile buffer\n");
	return APR_ENOMEM;
    }
    length = postlen;
    rv = apr_file_read(postfd, postdata, &length);
    if (rv != APR_SUCCESS) {
	printf("error reading postfile: %s\n",
	       apr_strerror(rv, errmsg, sizeof errmsg));
	return rv;
    }
    if (length != postlen) {
	printf("error reading postfile: read only %"
	       APR_SIZE_T_FMT " bytes",
	       length);
	return APR_EINVAL;
    }
    apr_file_close(postfd);
    return 0;
}

/* ------------------------------------------------------- */

/* sort out command-line args and call test */
int main(int argc, const char *const argv[])
{
    int r, l;
    char tmp[1024];
    apr_status_t status;
    apr_getopt_t *opt;
    const char *optarg;
    char c;

    /* table defaults  */
    tablestring = "";
    trstring = "";
    tdstring = "bgcolor=white";
    cookie[0] = '\0';
    auth[0] = '\0';
    proxyhost[0] = '\0';
    hdrs[0] = '\0';

    apr_initialize();
    atexit(apr_terminate);
    apr_pool_create(&cntxt, NULL);

#ifdef NOT_ASCII
    status = apr_xlate_open(&to_ascii, "ISO8859-1", APR_DEFAULT_CHARSET, cntxt);
    if (status) {
	fprintf(stderr, "apr_xlate_open(to ASCII)->%d\n", status);
	exit(1);
    }
    status = apr_xlate_open(&from_ascii, APR_DEFAULT_CHARSET, "ISO8859-1", cntxt);
    if (status) {
	fprintf(stderr, "apr_xlate_open(from ASCII)->%d\n", status);
	exit(1);
    }
    status = apr_base64init_ebcdic(to_ascii, from_ascii);
    if (status) {
	fprintf(stderr, "apr_base64init_ebcdic()->%d\n", status);
	exit(1);
    }
#endif

    apr_getopt_init(&opt, cntxt, argc, argv);
    while ((status = apr_getopt(opt, "n:c:t:T:p:v:kVhwix:y:z:C:H:P:A:g:X:de:Sq"
#if USE_SSL
				"s"
#endif
				,&c, &optarg)) == APR_SUCCESS) {
	switch (c) {
	case 's':
#if USE_SSL
        ssl = 1;
        break;
#else
        fprintf(stderr, "SSL not compiled in; no https support\n");
        exit(1);
#endif
	case 'n':
	    requests = atoi(optarg);
	    if (!requests) {
		err("Invalid number of requests\n");
	    }
	    break;
	case 'k':
	    keepalive = 1;
	    break;
	case 'q':
	    heartbeatres = 0;
	    break;
	case 'c':
	    concurrency = atoi(optarg);
	    break;
	case 'i':
	    if (posting == 1)
		err("Cannot mix POST and HEAD\n");
	    posting = -1;
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
	case 'p':
	    if (posting != 0)
		err("Cannot mix POST and HEAD\n");

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
	    strncat(cookie, "Cookie: ", sizeof(cookie));
	    strncat(cookie, optarg, sizeof(cookie));
	    strncat(cookie, "\r\n", sizeof(cookie));
	    break;
	case 'A':
	    /*
	     * assume username passwd already to be in colon separated form.
	     * Ready to be uu-encoded.
	     */
	    while (apr_isspace(*optarg))
		optarg++;
	    l = apr_base64_encode(tmp, optarg, strlen(optarg));
	    tmp[l] = '\0';

	    strncat(auth, "Authorization: Basic ", sizeof(auth));
	    strncat(auth, tmp, sizeof(auth));
	    strncat(auth, "\r\n", sizeof(auth));
	    break;
	case 'P':
	    /*
             * assume username passwd already to be in colon separated form.
             */
	    while (apr_isspace(*optarg))
		optarg++;
	    l = apr_base64_encode(tmp, optarg, strlen(optarg));
	    tmp[l] = '\0';

	    strncat(auth, "Proxy-Authorization: Basic ", sizeof(auth));
	    strncat(auth, tmp, sizeof(auth));
	    strncat(auth, "\r\n", sizeof(auth));
	    break;
	case 'H':
	    strncat(hdrs, optarg, sizeof(hdrs));
	    strncat(hdrs, "\r\n", sizeof(hdrs));
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
		}
		strcpy(proxyhost, optarg);
		isproxy = 1;
	    }
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
	case 'V':
	    copyright();
	    return 0;
	}
    }

    if (opt->ind != argc - 1) {
	fprintf(stderr, "%s: wrong number of arguments\n", argv[0]);
	usage(argv[0]);
    }

    if (parse_url(apr_pstrdup(cntxt, opt->argv[opt->ind++]))) {
	fprintf(stderr, "%s: invalid URL\n", argv[0]);
	usage(argv[0]);
    }


    if ((heartbeatres) && (requests > 150)) {
	heartbeatres = requests / 10;	/* Print line every 10% of requests */
	if (heartbeatres < 100)
	    heartbeatres = 100;	/* but never more often than once every 100
				 * connections. */
    }
    else
	heartbeatres = 0;

#ifdef USE_SSL
    SSL_library_init();
    if (!(ctx = SSL_CTX_new(SSLv2_client_method()))) {
	fprintf(stderr, "Could not init SSL CTX");
	ERR_print_errors_fp(stderr);
	exit(1);
    }
#endif
#if SIGPIPE
    signal(SIGPIPE, SIG_IGN);	        /* Ignore writes to connections that
					 * have been closed at the other end. */
#endif
    copyright();
    test();
    apr_pool_destroy(cntxt);

    return 0;
}
