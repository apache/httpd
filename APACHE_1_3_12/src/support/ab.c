/* ====================================================================
 * Copyright (c) 1998-1999 The Apache Group.  All rights reserved.
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

#define VERSION "1.3c"

/*  -------------------------------------------------------------------- */

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
    struct timeval start, connect, done;
};

struct data {
    int read;			/* number of bytes read */
    int ctime;			/* time in ms to connect */
    int time;			/* time in ms for connection */
};

#define ap_min(a,b) ((a)<(b))?(a):(b)
#define ap_max(a,b) ((a)>(b))?(a):(b)

/* --------------------- GLOBALS ---------------------------- */

int verbosity = 0;		/* no verbosity by default */
int posting = 0;		/* GET by default */
int requests = 1;		/* Number of requests to make */
int concurrency = 1;		/* Number of multiple requests to make */
int tlimit = 0;			/* time limit in cs */
int keepalive = 0;		/* try and do keepalive connections */
char servername[1024];		/* name that server reports */
char hostname[1024];		/* host name */
char path[1024];		/* path name */
char postfile[1024];		/* name of file containing post data */
char *postdata;			/* *buffer containing data from postfile */
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
int totalread = 0;		/* total number of bytes read */
int totalbread = 0;		/* totoal amount of entity body read */
int totalposted = 0;		/* total number of bytes posted, inc. headers */
int done = 0;			/* number of requests we have done */
int doneka = 0;			/* number of keep alive connections done */
int good = 0, bad = 0;		/* number of good and bad requests */

/* store error cases */
int err_length = 0, err_conn = 0, err_except = 0;
int err_response = 0;

struct timeval start, endtime;

/* global request (and its length) */
char request[512];
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

/* --------------------------------------------------------- */

/* simple little function to perror and exit */

static void err(char *s)
{
    if (errno) {
	perror(s);
    }
    else {
	printf("%s", s);
    }
    exit(errno);
}

/* --------------------------------------------------------- */

/* write out request to a connection - assumes we can write
   (small) request out in one go into our new socket buffer  */

static void write_request(struct connection * c)
{
#ifndef NO_WRITEV
    struct iovec out[2]; int outcnt = 1;
#endif
    gettimeofday(&c->connect, 0);
#ifndef NO_WRITEV
    out[0].iov_base = request;
    out[0].iov_len = reqlen;

    if (posting>0) {
	out[1].iov_base = postdata;
	out[1].iov_len = postlen;
	outcnt = 2;
	totalposted += (reqlen + postlen);
    }
    writev(c->fd,out, outcnt);
#else
    ab_write(c->fd,request,reqlen);
    if (posting>0) {
        ab_write(c->fd,postdata,postlen);
        totalposted += (reqlen + postlen);
    }
#endif

    c->state = STATE_READ;
    FD_SET(c->fd, &readbits);
    FD_CLR(c->fd, &writebits);
}

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

static void output_results(void)
{
    int timetaken;

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
    printf("Time taken for tests:   %d.%03d seconds\n",
	   timetaken / 1000, timetaken % 1000);
    printf("Complete requests:      %d\n", done);
    printf("Failed requests:        %d\n", bad);
    if (bad)
	printf("   (Connect: %d, Length: %d, Exceptions: %d)\n",
	       err_conn, err_length, err_except);
    if (err_response)
	printf("Non-2xx responses:      %d\n", err_response);
    if (keepalive)
	printf("Keep-Alive requests:    %d\n", doneka);
    printf("Total transferred:      %d bytes\n", totalread);
    if (posting>0)
	printf("Total POSTed:           %d\n", totalposted);
    printf("HTML transferred:       %d bytes\n", totalbread);

    /* avoid divide by zero */
    if (timetaken) {
	printf("Requests per second:    %.2f\n", 1000 * (float) (done) / timetaken);
	printf("Transfer rate:          %.2f kb/s received\n",
	       (float) (totalread) / timetaken);
	if (posting>0) {
	    printf("                        %.2f kb/s sent\n",
		   (float) (totalposted) / timetaken);
	    printf("                        %.2f kb/s total\n",
		   (float) (totalread + totalposted) / timetaken);
	}
    }

    {
	/* work out connection times */
	int i;
	int totalcon = 0, total = 0;
	int mincon = 9999999, mintot = 999999;
	int maxcon = 0, maxtot = 0;

	for (i = 0; i < requests; i++) {
	    struct data s = stats[i];
	    mincon = ap_min(mincon, s.ctime);
	    mintot = ap_min(mintot, s.time);
	    maxcon = ap_max(maxcon, s.ctime);
	    maxtot = ap_max(maxtot, s.time);
	    totalcon += s.ctime;
	    total += s.time;
	}
	if (requests > 0) { /* avoid division by zero (if 0 requests) */
	    printf("\nConnnection Times (ms)\n");
	    printf("              min   avg   max\n");
	    printf("Connect:    %5d %5d %5d\n", mincon, totalcon / requests, maxcon);
	    printf("Processing: %5d %5d %5d\n",
		   mintot - mincon, (total / requests) - (totalcon / requests),
		   maxtot - maxcon);
	    printf("Total:      %5d %5d %5d\n", mintot, total / requests, maxtot);
	}
    }
}

/* --------------------------------------------------------- */

/* calculate and output results in HTML  */

static void output_html_results(void)
{
    int timetaken;

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
	   "<td colspan=2 %s>%d.%03d seconds</td></tr>\n",
	   trstring, tdstring, tdstring, timetaken / 1000, timetaken % 1000);
    printf("<tr %s><th colspan=2 %s>Complete requests:</th>"
	   "<td colspan=2 %s>%d</td></tr>\n",
	   trstring, tdstring, tdstring, done);
    printf("<tr %s><th colspan=2 %s>Failed requests:</th>"
	   "<td colspan=2 %s>%d</td></tr>\n",
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
	       "<td colspan=2 %s>%d</td></tr>\n",
	       trstring, tdstring, tdstring, doneka);
    printf("<tr %s><th colspan=2 %s>Total transferred:</th>"
	   "<td colspan=2 %s>%d bytes</td></tr>\n",
	   trstring, tdstring, tdstring, totalread);
    if (posting>0)
	printf("<tr %s><th colspan=2 %s>Total POSTed:</th>"
	       "<td colspan=2 %s>%d</td></tr>\n",
	       trstring, tdstring, tdstring, totalposted);
    printf("<tr %s><th colspan=2 %s>HTML transferred:</th>"
	   "<td colspan=2 %s>%d bytes</td></tr>\n",
	   trstring, tdstring, tdstring, totalbread);

    /* avoid divide by zero */
    if (timetaken) {
	printf("<tr %s><th colspan=2 %s>Requests per second:</th>"
	       "<td colspan=2 %s>%.2f</td></tr>\n",
	   trstring, tdstring, tdstring, 1000 * (float) (done) / timetaken);
	printf("<tr %s><th colspan=2 %s>Transfer rate:</th>"
	       "<td colspan=2 %s>%.2f kb/s received</td></tr>\n",
	     trstring, tdstring, tdstring, (float) (totalread) / timetaken);
	if (posting>0) {
	    printf("<tr %s><td colspan=2 %s>&nbsp;</td>"
		   "<td colspan=2 %s>%.2f kb/s sent</td></tr>\n",
		   trstring, tdstring, tdstring,
		   (float) (totalposted) / timetaken);
	    printf("<tr %s><td colspan=2 %s>&nbsp;</td>"
		   "<td colspan=2 %s>%.2f kb/s total</td></tr>\n",
		   trstring, tdstring, tdstring,
		   (float) (totalread + totalposted) / timetaken);
	}
    }

    {
	/* work out connection times */
	int i;
	int totalcon = 0, total = 0;
	int mincon = 9999999, mintot = 999999;
	int maxcon = 0, maxtot = 0;

	for (i = 0; i < requests; i++) {
	    struct data s = stats[i];
	    mincon = ap_min(mincon, s.ctime);
	    mintot = ap_min(mintot, s.time);
	    maxcon = ap_max(maxcon, s.ctime);
	    maxtot = ap_max(maxtot, s.time);
	    totalcon += s.ctime;
	    total += s.time;
	}

	if (requests > 0) { /* avoid division by zero (if 0 requests) */
	    printf("<tr %s><th %s colspan=4>Connnection Times (ms)</th></tr>\n",
		   trstring, tdstring);
	    printf("<tr %s><th %s>&nbsp;</th> <th %s>min</th>   <th %s>avg</th>   <th %s>max</th></tr>\n",
		   trstring, tdstring, tdstring, tdstring, tdstring);
	    printf("<tr %s><th %s>Connect:</th>"
		   "<td %s>%5d</td>"
		   "<td %s>%5d</td>"
		   "<td %s>%5d</td></tr>\n",
		   trstring, tdstring, tdstring, mincon, tdstring, totalcon / requests, tdstring, maxcon);
	    printf("<tr %s><th %s>Processing:</th>"
		   "<td %s>%5d</td>"
		   "<td %s>%5d</td>"
		   "<td %s>%5d</td></tr>\n",
		   trstring, tdstring, tdstring, mintot - mincon, tdstring,
		   (total / requests) - (totalcon / requests), tdstring, maxtot - maxcon);
	    printf("<tr %s><th %s>Total:</th>"
		   "<td %s>%5d</td>"
		   "<td %s>%5d</td>"
		   "<td %s>%5d</td></tr>\n",
		   trstring, tdstring, tdstring, mintot, tdstring, total / requests, tdstring, maxtot);
	}
	printf("</table>\n");
    }
}

/* --------------------------------------------------------- */

/* start asnchronous non-blocking connection */

static void start_connect(struct connection * c)
{
    c->read = 0;
    c->bread = 0;
    c->keepalive = 0;
    c->cbx = 0;
    c->gotheader = 0;

    c->fd = socket(AF_INET, SOCK_STREAM, 0);
    if (c->fd < 0)
	err("socket");

    nonblock(c->fd);
    gettimeofday(&c->start, 0);

    if (connect(c->fd, (struct sockaddr *) & server, sizeof(server)) < 0) {
	if (errno == EINPROGRESS) {
	    c->state = STATE_CONNECTING;
	    FD_SET(c->fd, &writebits);
	    return;
	}
	else {
	    ab_close(c->fd);
	    err_conn++;
	    if (bad++ > 10) {
		err("\nTest aborted after 10 failures\n\n");
	    }
	    start_connect(c);
	}
    }

    /* connected first time */
    c->state = STATE_CONNECTING;
    FD_SET(c->fd, &writebits);
}

/* --------------------------------------------------------- */

/* close down connection and save stats */

static void close_connection(struct connection * c)
{
    if (c->read == 0 && c->keepalive) {
	/* server has legitimately shut down an idle keep alive request */
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
	    gettimeofday(&c->done, 0);
	    s.read = c->read;
	    s.ctime = timedif(c->connect, c->start);
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
		/* header is in invalid or too big - close connection */
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
		/* this is first time, extract some interesting info */
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

    /* cater for the case where we're using keepalives and doing HEAD requests */
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
	    gettimeofday(&c->done, 0);
	    s.read = c->read;
	    s.ctime = timedif(c->connect, c->start);
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
    int i;

    if (!use_html) {
	printf("Benchmarking %s (be patient)...", hostname);
	fflush(stdout);
    }

    {
	/* get server information */
	struct hostent *he;
	he = gethostbyname(hostname);
	if (!he)
	    err("bad hostname");
	server.sin_family = he->h_addrtype;
	server.sin_port = htons(port);
	server.sin_addr.s_addr = ((unsigned long *) (he->h_addr_list[0]))[0];
    }

    con = malloc(concurrency * sizeof(struct connection));
    memset(con, 0, concurrency * sizeof(struct connection));

    stats = malloc(requests * sizeof(struct data));

    FD_ZERO(&readbits);
    FD_ZERO(&writebits);

    /* setup request */
    if (posting <= 0) {
	sprintf(request, "%s %s HTTP/1.0\r\n"
		"User-Agent: ApacheBench/%s\r\n"
		"%s" "%s" "%s"
		"Host: %s\r\n"
		"Accept: */*\r\n"
		"%s" "\r\n",
		(posting == 0) ? "GET" : "HEAD",
		path,
		VERSION,
		keepalive ? "Connection: Keep-Alive\r\n" : "",
		cookie, auth, hostname, hdrs);
    }
    else {
	sprintf(request, "POST %s HTTP/1.0\r\n"
		"User-Agent: ApacheBench/%s\r\n"
		"%s" "%s" "%s"
		"Host: %s\r\n"
		"Accept: */*\r\n"
		"Content-length: %d\r\n"
		"Content-type: %s\r\n"
		"%s"
		"\r\n",
		path,
		VERSION,
		keepalive ? "Connection: Keep-Alive\r\n" : "",
		cookie, auth,
		hostname, postlen,
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
	if (tlimit && timedif(now, start) > (tlimit * 1000)) {
	    requests = done;	/* so stats are correct */
	}

	/* Timeout of 30 seconds. */
	timeout.tv_sec = 30;
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
	printf("This is ApacheBench, Version %s\n", VERSION " <$Revision: 1.38 $> apache-1.3");
	printf("Copyright (c) 1996 Adam Twiss, Zeus Technology Ltd, http://www.zeustech.net/\n");
	printf("Copyright (c) 1998-1999 The Apache Group, http://www.apache.org/\n");
	printf("\n");
    }
    else {
	printf("<p>\n");
	printf(" This is ApacheBench, Version %s <i>&lt;%s&gt;</i> apache-1.3<br>\n", VERSION, "$Revision: 1.38 $");
	printf(" Copyright (c) 1996 Adam Twiss, Zeus Technology Ltd, http://www.zeustech.net/<br>\n");
	printf(" Copyright (c) 1998-1999 The Apache Group, http://www.apache.org/<br>\n");
	printf("</p>\n<p>\n");
    }
}

/* display usage information */
static void usage(char *progname)
{
    fprintf(stderr, "Usage: %s [options] [http://]hostname[:port]/path\n", progname);
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
    fprintf(stderr, "    -C attribute    Add cookie, eg. 'Apache=1234. (repeatable)\n");
    fprintf(stderr, "    -H attribute    Add Arbitrary header line, eg. 'Accept-Encoding: zop'\n");
    fprintf(stderr, "                    Inserted after all normal header lines. (repeatable)\n");
    fprintf(stderr, "    -A attribute    Add Basic WWW Authentication, the attributes\n");
    fprintf(stderr, "                    are a colon separated username and password.\n");
    fprintf(stderr, "    -p attribute    Add Basic Proxy Authentication, the attributes\n");
    fprintf(stderr, "                    are a colon separated username and password.\n");
    fprintf(stderr, "    -V              Print version number and exit\n");
    fprintf(stderr, "    -k              Use HTTP KeepAlive feature\n");
    fprintf(stderr, "    -h              Display usage information (this message)\n");
    exit(EINVAL);
}

/* ------------------------------------------------------- */

/* split URL into parts */

static int parse_url(char *url)
{
    char *cp;
    char *h;
    char *p = NULL;

    if (strlen(url) > 7 && strncmp(url, "http://", 7) == 0)
	url += 7;
    h = url;
    if ((cp = strchr(url, ':')) != NULL) {
	*cp++ = '\0';
	p = cp;
	url = cp;
    }
    if ((cp = strchr(url, '/')) == NULL)
	return 1;
    strcpy(path, cp);
    *cp = '\0';
    strcpy(hostname, h);
    if (p != NULL)
	port = atoi(p);
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
    int c, r,l;
    char tmp[1024];

    /* table defaults  */
    tablestring = "";
    trstring = "";
    tdstring = "bgcolor=white";
    cookie[0] = '\0';
    auth[0] = '\0';
    hdrs[0] = '\0';
    optind = 1;
    while ((c = getopt(argc, argv, "n:c:t:T:p:v:kVhwix:y:z:C:H:P:A:")) > 0) {
	switch (c) {
	case 'n':
	    requests = atoi(optarg);
	    if (!requests) {
		err("Invalid number of requests\n");
	    }
	    break;
	case 'k':
	    keepalive = 1;
	    break;
	case 'c':
	    concurrency = atoi(optarg);
	    break;
	case 'i':
	    if (posting==1) 
		err("Cannot mix POST and HEAD");

	    posting = -1;
	    break;
	case 'p':
	    if (posting!=0) 
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
	    strncat(cookie, "Cookie: ", sizeof(cookie));
	    strncat(cookie, optarg, sizeof(cookie));
	    strncat(cookie, "\r\n", sizeof(cookie));
	    break;
	case 'A': 
	    /* assume username passwd already to be in colon separated form. Ready
	     * to be uu-encoded.
	     */
	    while(isspace(*optarg))
		optarg++;
	    l=ap_base64encode(tmp,optarg,strlen(optarg));
	    tmp[l]='\0';

	    strncat(auth, "Authorization: basic ", sizeof(auth));
	    strncat(auth, tmp, sizeof(auth));
	    strncat(auth, "\r\n", sizeof(auth));
	    break;
	case 'P':
	    /*
	     * assume username passwd already to be in colon separated form.
	     */
	    while(isspace(*optarg))
		optarg++;
	    l=ap_base64encode(tmp,optarg,strlen(optarg));
	    tmp[l]='\0';

	    strncat(auth, "Proxy-Authorization: basic ", sizeof(auth));
	    strncat(auth, tmp, sizeof(auth));
	    strncat(auth, "\r\n", sizeof(auth));
	    break;
	case 'H':
	    strncat(hdrs, optarg, sizeof(hdrs));
	    strncat(hdrs, "\r\n", sizeof(hdrs));
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

    if (parse_url(argv[optind++])) {
	fprintf(stderr, "%s: invalid URL\n", argv[0]);
	usage(argv[0]);
    }

    copyright();
    test();

    exit(0);
}
