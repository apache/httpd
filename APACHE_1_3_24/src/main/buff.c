/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000-2002 The Apache Software Foundation.  All rights
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

#include "httpd.h"
#include "http_main.h"
#include "http_log.h"
#include "buff.h"

#include <errno.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#ifndef NO_WRITEV
#include <sys/types.h>
#include <sys/uio.h>
#endif

#ifdef HAVE_BSTRING_H
#include <bstring.h>		/* for IRIX, FD_SET calls bzero() */
#endif

#ifndef DEFAULT_BUFSIZE
#define DEFAULT_BUFSIZE (4096)
#endif
/* This must be enough to represent (DEFAULT_BUFSIZE - 3) in hex,
 * plus two extra characters.
 */
#ifndef CHUNK_HEADER_SIZE
#define CHUNK_HEADER_SIZE (5)
#endif

#define ascii_CRLF "\015\012" /* A CRLF which won't pass the conversion machinery */

/* bwrite()s of greater than this size can result in a large_write() call,
 * which can result in a writev().  It's a little more work to set up the
 * writev() rather than copy bytes into the buffer, so we don't do it for small
 * writes.  This is especially important when chunking (which is a very likely
 * source of small writes if it's a module using ap_bputc/ap_bputs)...because we
 * have the expense of actually building two chunks for each writev().
 */
#ifndef LARGE_WRITE_THRESHOLD
#define LARGE_WRITE_THRESHOLD 31
#endif


/*
 * Buffered I/O routines.
 * These are a replacement for the stdio routines.
 * Advantages:
 *  Known semantics for handling of file-descriptors (on close etc.)
 *  No problems reading and writing simultanously to the same descriptor
 *  No limits on the number of open file handles.
 *  Only uses memory resources; no need to ensure the close routine
 *  is called.
 *  Extra code could be inserted between the buffered and un-buffered routines.
 *  Timeouts could be handled by using select or poll before read or write.
 *  Extra error handling could be introduced; e.g.
 *   keep an address to which we should longjump(), or
 *   keep a stack of routines to call on error.
 */

/* Notes:
 *  On reading EOF, EOF will set in the flags and no further Input will
 * be done.
 *
 * On an error except for EAGAIN, ERROR will be set in the flags and no
 * futher I/O will be done
 */

#if defined(WIN32) || defined(NETWARE) || defined(CYGWIN_WINSOCK) 

/*
  select() sometimes returns 1 even though the write will block. We must work around this.
*/

API_EXPORT(int) ap_sendwithtimeout(int sock, const char *buf, int len, int flags)
{
    int iostate = 1;
    fd_set fdset;
    struct timeval tv;
    int err = WSAEWOULDBLOCK;
    int rv;
    int retry;

    tv.tv_sec = ap_check_alarm();

    /* If ap_sendwithtimeout is called with an invalid timeout
     * set a default timeout of 300 seconds. This hack is needed
     * to emulate the non-blocking send() that was removed in 
     * the previous patch to this function. Network servers
     * should never make network i/o calls w/o setting a timeout.
     * (doing otherwise opens a DoS attack exposure)
     */
    if (tv.tv_sec <= 0) {
        tv.tv_sec = 300;
    }

    rv = ioctlsocket(sock, FIONBIO, (u_long*)&iostate);
    iostate = 0;
    if (rv) {
	err = WSAGetLastError();
	ap_assert(0);
    }

    rv = send(sock, buf, len, flags);
    if (rv == SOCKET_ERROR) {
	err = WSAGetLastError();
	if (err == WSAEWOULDBLOCK)
	    do {
		retry=0;

		FD_ZERO(&fdset);
		FD_SET(sock, &fdset);
		tv.tv_usec = 0;
		rv = select(FD_SETSIZE, NULL, &fdset, NULL, &tv);
		if (rv == SOCKET_ERROR)
		    err = WSAGetLastError();
		else if (rv == 0) {
 		    ioctlsocket(sock, FIONBIO, (u_long*)&iostate);
		    if(ap_check_alarm() < 0) {
			WSASetLastError(EINTR);	/* Simulate an alarm() */
			return (SOCKET_ERROR);
		    }
 		}
		else {
		    rv = send(sock, buf, len, flags);
		    if (rv == SOCKET_ERROR) {
		        err = WSAGetLastError();
			if(err == WSAEWOULDBLOCK) {
			    
			    retry=1;
                            ap_log_error(APLOG_MARK,APLOG_DEBUG,NULL,
                                         "select claimed we could write, but in fact we couldn't.");
#ifdef NETWARE
                            ThreadSwitchWithDelay();
#else
			    Sleep(100);
#endif
			}
		    }
		}
	    } while(retry);
    }

    ioctlsocket(sock, FIONBIO, (u_long*)&iostate);

    if (rv == SOCKET_ERROR)
	WSASetLastError(err);
    return (rv);
}


API_EXPORT(int) ap_recvwithtimeout(int sock, char *buf, int len, int flags)
{
    int iostate = 1;
    fd_set fdset;
    struct timeval tv;
    int err = WSAEWOULDBLOCK;
    int rv;
    int retry;

    tv.tv_sec = ap_check_alarm();

    /* If ap_recvwithtimeout is called with an invalid timeout
     * set a default timeout of 300 seconds. This hack is needed
     * to emulate the non-blocking recv() that was removed in 
     * the previous patch to this function. Network servers
     * should never make network i/o calls w/o setting a timeout.
     * (doing otherwise opens a DoS attack exposure)
     */
    if (tv.tv_sec <= 0) {
        tv.tv_sec = 300;
    }

    rv = ioctlsocket(sock, FIONBIO, (u_long*)&iostate);
    iostate = 0;
    ap_assert(!rv);

    rv = recv(sock, buf, len, flags);
    if (rv == SOCKET_ERROR) {
	err = WSAGetLastError();
	if (err == WSAEWOULDBLOCK) {
            do {
                retry = 0;
                FD_ZERO(&fdset);
                FD_SET(sock, &fdset);
                tv.tv_usec = 0;
                rv = select(FD_SETSIZE, &fdset, NULL, NULL, &tv);
                if (rv == SOCKET_ERROR)
                    err = WSAGetLastError();
                else if (rv == 0) {
                    ioctlsocket(sock, FIONBIO, (u_long*)&iostate);
                    ap_check_alarm();
                    WSASetLastError(WSAEWOULDBLOCK);
                    return (SOCKET_ERROR);
                }
                else {
                    rv = recv(sock, buf, len, flags);
                    if (rv == SOCKET_ERROR) {
                        err = WSAGetLastError();
                        if (err == WSAEWOULDBLOCK) {
                            ap_log_error(APLOG_MARK, APLOG_DEBUG, NULL,
                                         "select claimed we could read, but in fact we couldn't.");
                            retry = 1;
#ifdef NETWARE
                            ThreadSwitchWithDelay();
#else
                            Sleep(100);
#endif
                        }
                    }
                }
            } while (retry);
        }
    }

    ioctlsocket(sock, FIONBIO, (u_long*)&iostate);

    if (rv == SOCKET_ERROR)
	WSASetLastError(err);
    return (rv);
}

#endif /* WIN32 */


/* the lowest level reading primitive */
static int ap_read(BUFF *fb, void *buf, int nbyte)
{
    int rv;
    
#ifdef WIN32
    if (fb->hFH != INVALID_HANDLE_VALUE) {
        if (!ReadFile(fb->hFH,buf,nbyte,&rv,NULL)) {
            errno = GetLastError();
            rv = -1;
        }
    }
    else
#endif
	rv = read(fb->fd_in, buf, nbyte);
    
    return rv;
}

static ap_inline int buff_read(BUFF *fb, void *buf, int nbyte)
{
    int rv;

#if defined (WIN32) || defined(NETWARE) || defined(CYGWIN_WINSOCK) 
    if (fb->flags & B_SOCKET) {
	rv = ap_recvwithtimeout(fb->fd_in, buf, nbyte, 0);
	if (rv == SOCKET_ERROR)
	    errno = WSAGetLastError();
    }
    else
	rv = ap_read(fb, buf, nbyte);
#elif defined (BEOS)
    if (fb->flags & B_SOCKET) {
        rv = recv(fb->fd_in, buf, nbyte, 0);
    } else
        rv = ap_read(fb,buf,nbyte);
#elif defined(TPF)
    fd_set fds;
    struct timeval tv;

    ap_check_signals();
    if (fb->flags & B_SOCKET) {
        FD_ZERO(&fds);
        FD_SET(fb->fd_in, &fds);
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        rv = ap_select(fb->fd_in + 1, &fds, NULL, NULL, &tv);
        if (rv > 0)
            rv = ap_read(fb, buf, nbyte);
    }
    else
        rv = ap_read(fb, buf, nbyte);
#else
    rv = ap_read(fb, buf, nbyte);
#endif /* WIN32 */
    return rv;
}

/* the lowest level writing primitive */
static int ap_write(BUFF *fb, const void *buf, int nbyte)
{
    int rv;
    
#ifdef WIN32
    if (fb->hFH != INVALID_HANDLE_VALUE) {
        if (!WriteFile(fb->hFH,buf,nbyte,&rv,NULL)) {
            errno = GetLastError();
            rv = -1;
        }
    }
    else
#endif
#if defined (B_SFIO)
	rv = sfwrite(fb->sf_out, buf, nbyte);
#else
#ifdef _OSD_POSIX
        /* Sorry, but this is a hack: On BS2000, currently the send() call
         * has slightly better performance, and it doesn't have a maximum
	 * transfer size of 16kB per write. Both write() and writev()
	 * currently have such a limit and therefore don't work
	 * too well with MMAP files.
	 */
	if (fb->flags & B_SOCKET)
	    rv = send(fb->fd, buf, nbyte, 0);
	else
#endif
	rv = write(fb->fd, buf, nbyte);
#endif
    
    return rv;
}

static ap_inline int buff_write(BUFF *fb, const void *buf, int nbyte)
{
    int rv;

    if (fb->filter_callback != NULL) {
        fb->filter_callback(fb, buf, nbyte);
    }
   
#if defined(WIN32) || defined(NETWARE)
    if (fb->flags & B_SOCKET) {
	rv = ap_sendwithtimeout(fb->fd, buf, nbyte, 0);
	if (rv == SOCKET_ERROR)
	    errno = WSAGetLastError();
    }
    else
	rv = ap_write(fb, buf, nbyte);
#elif defined(BEOS)
    if(fb->flags & B_SOCKET) {
        rv = send(fb->fd, buf, nbyte, 0);
    } else 
        rv = ap_write(fb, buf,nbyte);
#else
    rv = ap_write(fb, buf, nbyte);
#endif /* WIN32 */
    return rv;
}

static void doerror(BUFF *fb, int direction)
{
    int errsave = errno;	/* Save errno to prevent overwriting it below */

    fb->flags |= (direction == B_RD ? B_RDERR : B_WRERR);
    if (fb->error != NULL)
	(*fb->error) (fb, direction, fb->error_data);

    errno = errsave;
}

/* Buffering routines */
/*
 * Create a new buffered stream
 */
API_EXPORT(BUFF *) ap_bcreate(pool *p, int flags)
{
    BUFF *fb;

    fb = ap_palloc(p, sizeof(BUFF));
    fb->pool = p;
    fb->bufsiz = DEFAULT_BUFSIZE;
    fb->flags = flags & (B_RDWR | B_SOCKET);

    if (flags & B_RD)
	fb->inbase = ap_palloc(p, fb->bufsiz);
    else
	fb->inbase = NULL;

    /* overallocate so that we can put a chunk trailer of CRLF into this
     * buffer */
    if (flags & B_WR)
	fb->outbase = ap_palloc(p, fb->bufsiz + 2);
    else
	fb->outbase = NULL;

#ifdef CHARSET_EBCDIC
    fb->flags |= (flags & B_SOCKET) ? (B_EBCDIC2ASCII | B_ASCII2EBCDIC) : 0;
#endif /*CHARSET_EBCDIC*/

    fb->inptr = fb->inbase;

    fb->incnt = 0;
    fb->outcnt = 0;
    fb->outchunk = -1;
    fb->error = NULL;
    fb->bytes_sent = 0L;

    fb->fd = -1;
    fb->fd_in = -1;
#ifdef WIN32
    fb->hFH = INVALID_HANDLE_VALUE;
#endif

#ifdef B_SFIO
    fb->sf_in = NULL;
    fb->sf_out = NULL;
    fb->sf_in = sfnew(fb->sf_in, NIL(Void_t *),
		      (size_t) SF_UNBOUND, 0, SF_READ);
    fb->sf_out = sfnew(fb->sf_out, NIL(Void_t *),
		       (size_t) SF_UNBOUND, 1, SF_WRITE);
#endif

    fb->callback_data = NULL;
    fb->filter_callback = NULL;

    return fb;
}

/*
 * Push some I/O file descriptors onto the stream
 */
API_EXPORT(void) ap_bpushfd(BUFF *fb, int fd_in, int fd_out)
{
    fb->fd = fd_out;
    fb->fd_in = fd_in;
}

#ifdef WIN32
/*
 * Push some Win32 handles onto the stream.
 */
API_EXPORT(void) ap_bpushh(BUFF *fb, HANDLE hFH)
{
    fb->hFH = hFH;
}
#endif

API_EXPORT(int) ap_bsetopt(BUFF *fb, int optname, const void *optval)
{
    if (optname == BO_BYTECT) {
	fb->bytes_sent = *(const long int *) optval - (long int) fb->outcnt;;
	return 0;
    }
    else {
	errno = EINVAL;
	return -1;
    }
}

API_EXPORT(int) ap_bgetopt(BUFF *fb, int optname, void *optval)
{
    if (optname == BO_BYTECT) {
	long int bs = fb->bytes_sent + fb->outcnt;
	if (bs < 0L)
	    bs = 0L;
	*(long int *) optval = bs;
	return 0;
    }
    else {
	errno = EINVAL;
	return -1;
    }
}

static int bflush_core(BUFF *fb);

/*
 * Start chunked encoding.
 *
 * Note that in order for ap_bputc() to be an efficient macro we have to guarantee
 * that start_chunk() has always been called on the buffer before we leave any
 * routine in this file.  Said another way, if a routine here uses end_chunk()
 * and writes something on the wire, then it has to call start_chunk() or set
 * an error condition before returning.
 */
static void start_chunk(BUFF *fb)
{
    if (fb->outchunk != -1) {
	/* already chunking */
	return;
    }
    if ((fb->flags & (B_WRERR | B_EOUT | B_WR)) != B_WR) {
	/* unbuffered writes */
	return;
    }

    /* we need at least the header_len + at least 1 data byte
     * remember that we've overallocated fb->outbase so that we can always
     * fit the two byte CRLF trailer
     */
    if (fb->bufsiz - fb->outcnt < CHUNK_HEADER_SIZE + 1) {
	bflush_core(fb);
    }
    fb->outchunk = fb->outcnt;
    fb->outcnt += CHUNK_HEADER_SIZE;
}


/*
 * end a chunk -- tweak the chunk_header from start_chunk, and add a trailer
 */
static void end_chunk(BUFF *fb)
{
    int i;
    unsigned char *strp;

    if (fb->outchunk == -1) {
	/* not chunking */
	return;
    }

    if (fb->outchunk + CHUNK_HEADER_SIZE == fb->outcnt) {
	/* nothing was written into this chunk, and we can't write a 0 size
	 * chunk because that signifies EOF, so just erase it
	 */
	fb->outcnt = fb->outchunk;
	fb->outchunk = -1;
	return;
    }

    /* we know this will fit because of how we wrote it in start_chunk() */
    i = ap_snprintf((char *) &fb->outbase[fb->outchunk], CHUNK_HEADER_SIZE,
		"%x", fb->outcnt - fb->outchunk - CHUNK_HEADER_SIZE);

    /* we may have to tack some trailing spaces onto the number we just wrote
     * in case it was smaller than our estimated size.  We've also written
     * a \0 into the buffer with ap_snprintf so we might have to put a
     * \r back in.
     */
    strp = &fb->outbase[fb->outchunk + i];
    while (i < CHUNK_HEADER_SIZE - 2) {
	*strp++ = ' ';
	++i;
    }
    *strp++ = CR;
    *strp = LF;

    /* tack on the trailing CRLF, we've reserved room for this */
    fb->outbase[fb->outcnt++] = CR;
    fb->outbase[fb->outcnt++] = LF;

#ifdef CHARSET_EBCDIC
    /* Chunks are an HTTP/1.1 Protocol feature. They must ALWAYS be in ASCII */
    ebcdic2ascii(&fb->outbase[fb->outchunk], &fb->outbase[fb->outchunk], CHUNK_HEADER_SIZE);
    ebcdic2ascii(&fb->outbase[fb->outcnt-2], &fb->outbase[fb->outcnt-2], 2);
#endif /*CHARSET_EBCDIC*/

    fb->outchunk = -1;
}


/*
 * Set a flag on (1) or off (0).
 */
API_EXPORT(int) ap_bsetflag(BUFF *fb, int flag, int value)
{
    if (value) {
	fb->flags |= flag;
	if (flag & B_CHUNK) {
	    start_chunk(fb);
	}
    }
    else {
	fb->flags &= ~flag;
	if (flag & B_CHUNK) {
	    end_chunk(fb);
	}
    }
    return value;
}


API_EXPORT(int) ap_bnonblock(BUFF *fb, int direction)
{
    int fd;

    fd = (direction == B_RD) ? fb->fd_in : fb->fd;
#if defined(O_NONBLOCK)
    return fcntl(fd, F_SETFL, O_NONBLOCK);
#elif defined(O_NDELAY)
    return fcntl(fd, F_SETFL, O_NDELAY);
#elif defined(FNDELAY)
    return fcntl(fd, F_SETFL, FNDELAY);
#else
    /* XXXX: this breaks things, but an alternative isn't obvious...*/
    return 0;
#endif
}

API_EXPORT(int) ap_bfileno(BUFF *fb, int direction)
{
    return (direction == B_RD) ? fb->fd_in : fb->fd;
}

/*
 * This is called instead of read() everywhere in here.  It implements
 * the B_SAFEREAD functionality -- which is to force a flush() if a read()
 * would block.  It also deals with the EINTR errno result from read().
 * return code is like read() except EINTR is eliminated.
 */


#if !defined (B_SFIO) || defined (WIN32)
#define saferead saferead_guts
#else
static int saferead(BUFF *fb, char *buf, int nbyte)
{
    return sfread(fb->sf_in, buf, nbyte);
}
#endif


/* Test the descriptor and flush the output buffer if it looks like
 * we will block on the next read.
 *
 * Note we assume the caller has ensured that fb->fd_in <= FD_SETSIZE
 */
API_EXPORT(void) ap_bhalfduplex(BUFF *fb)
{
    int rv;
    fd_set fds;
    struct timeval tv;

    /* We don't need to do anything if the connection has been closed
     * or there is something readable in the incoming buffer
     * or there is nothing flushable in the output buffer.
     */
    if (fb == NULL || fb->fd_in < 0 || fb->incnt > 0 || fb->outcnt == 0) {
	return;
    }
    /* test for a block */
    do {
	FD_ZERO(&fds);
	FD_SET(fb->fd_in, &fds);
	tv.tv_sec = 0;
	tv.tv_usec = 0;
	rv = ap_select(fb->fd_in + 1, &fds, NULL, NULL, &tv);
    } while (rv < 0 && errno == EINTR && !(fb->flags & B_EOUT));

    /* treat any error as if it would block as well */
    if (rv != 1) {
	ap_bflush(fb);
    }
}

static ap_inline int saferead_guts(BUFF *fb, void *buf, int nbyte)
{
    int rv;

    if (fb->flags & B_SAFEREAD) {
	ap_bhalfduplex(fb);
    }
    do {
	rv = buff_read(fb, buf, nbyte);
    } while (rv == -1 && errno == EINTR && !(fb->flags & B_EOUT));
    return (rv);
}

#ifdef B_SFIO
int bsfio_read(Sfio_t * f, char *buf, int nbyte, apache_sfio *disc)
{
    int rv;
    BUFF *fb = disc->buff;

    rv = saferead_guts(fb, buf, nbyte);

    buf[rv] = '\0';
    f->next = 0;

    return (rv);
}

int bsfio_write(Sfio_t * f, char *buf, int nbyte, apache_sfio *disc)
{
    return ap_write(disc->buff, buf, nbyte);
}

Sfdisc_t *bsfio_new(pool *p, BUFF *b)
{
    apache_sfio *disc;

    if (!(disc = (apache_sfio *) ap_palloc(p, sizeof(apache_sfio))))
	            return (Sfdisc_t *) disc;

    disc->disc.readf = (Sfread_f) bsfio_read;
    disc->disc.writef = (Sfwrite_f) bsfio_write;
    disc->disc.seekf = (Sfseek_f) NULL;
    disc->disc.exceptf = (Sfexcept_f) NULL;
    disc->buff = b;

    return (Sfdisc_t *) disc;
}
#endif


/* A wrapper around saferead which does error checking and EOF checking
 * yeah, it's confusing, this calls saferead, which calls buff_read...
 * and then there's the SFIO case.  Note that saferead takes care
 * of EINTR.
 */
static int read_with_errors(BUFF *fb, void *buf, int nbyte)
{
    int rv;

    rv = saferead(fb, buf, nbyte);
    if (rv == 0) {
	fb->flags |= B_EOF;
    }
    else if (rv == -1 && errno != EAGAIN) {
	doerror(fb, B_RD);
    }
    return rv;
}


/*
 * Read up to nbyte bytes into buf.
 * If fewer than byte bytes are currently available, then return those.
 * Returns 0 for EOF, -1 for error.
 * NOTE EBCDIC: The readahead buffer _always_ contains *unconverted* data.
 * Only when the caller retrieves data from the buffer (calls bread)
 * is a conversion done, if the conversion flag is set at that time.
 */
API_EXPORT(int) ap_bread(BUFF *fb, void *buf, int nbyte)
{
    int i, nrd;

    if (fb->flags & B_RDERR)
	return -1;
    if (nbyte == 0)
	return 0;

    if (!(fb->flags & B_RD)) {
	/* Unbuffered reading.  First check if there was something in the
	 * buffer from before we went unbuffered. */
	if (fb->incnt) {
	    i = (fb->incnt > nbyte) ? nbyte : fb->incnt;
#ifdef CHARSET_EBCDIC
	    if (fb->flags & B_ASCII2EBCDIC)
		ascii2ebcdic(buf, fb->inptr, i);
	    else
#endif /*CHARSET_EBCDIC*/
	    memcpy(buf, fb->inptr, i);
	    fb->incnt -= i;
	    fb->inptr += i;
	    return i;
	}
	i = read_with_errors(fb, buf, nbyte);
#ifdef CHARSET_EBCDIC
	if (i > 0 && ap_bgetflag(fb, B_ASCII2EBCDIC))
	    ascii2ebcdic(buf, buf, i);
#endif /*CHARSET_EBCDIC*/
	return i;
    }

    nrd = fb->incnt;
/* can we fill the buffer */
    if (nrd >= nbyte) {
#ifdef CHARSET_EBCDIC
	if (fb->flags & B_ASCII2EBCDIC)
	    ascii2ebcdic(buf, fb->inptr, nbyte);
	else
#endif /*CHARSET_EBCDIC*/
	memcpy(buf, fb->inptr, nbyte);
	fb->incnt = nrd - nbyte;
	fb->inptr += nbyte;
	return nbyte;
    }

    if (nrd > 0) {
#ifdef CHARSET_EBCDIC
	if (fb->flags & B_ASCII2EBCDIC)
	    ascii2ebcdic(buf, fb->inptr, nrd);
	else
#endif /*CHARSET_EBCDIC*/
	memcpy(buf, fb->inptr, nrd);
	nbyte -= nrd;
	buf = nrd + (char *) buf;
	fb->incnt = 0;
    }
    if (fb->flags & B_EOF)
	return nrd;

/* do a single read */
    if (nbyte >= fb->bufsiz) {
/* read directly into caller's buffer */
	i = read_with_errors(fb, buf, nbyte);
#ifdef CHARSET_EBCDIC
	if (i > 0 && ap_bgetflag(fb, B_ASCII2EBCDIC))
	    ascii2ebcdic(buf, buf, i);
#endif /*CHARSET_EBCDIC*/
	if (i == -1) {
	    return nrd ? nrd : -1;
	}
    }
    else {
/* read into hold buffer, then memcpy */
	fb->inptr = fb->inbase;
	i = read_with_errors(fb, fb->inptr, fb->bufsiz);
	if (i == -1) {
	    return nrd ? nrd : -1;
	}
	fb->incnt = i;
	if (i > nbyte)
	    i = nbyte;
#ifdef CHARSET_EBCDIC
	if (fb->flags & B_ASCII2EBCDIC)
	    ascii2ebcdic(buf, fb->inptr, i);
	else
#endif /*CHARSET_EBCDIC*/
	memcpy(buf, fb->inptr, i);
	fb->incnt -= i;
	fb->inptr += i;
    }
    return nrd + i;
}


/*
 * Reads from the stream into the array pointed to by buff, until
 * a (CR)LF sequence is read, or end-of-file condition is encountered
 * or until n-1 bytes have been stored in buff. If a CRLF sequence is
 * read, it is replaced by a newline character.  The string is then
 * terminated with a null character.
 *
 * Returns the number of bytes stored in buff, or zero on end of
 * transmission, or -1 on an error.
 *
 * Notes:
 *  If null characters are expected in the data stream, then
 * buff should not be treated as a null terminated C string; instead
 * the returned count should be used to determine the length of the
 * string.
 *  CR characters in the byte stream not immediately followed by a LF
 * will be preserved.
 */
API_EXPORT(int) ap_bgets(char *buff, int n, BUFF *fb)
{
    int i, ch, ct;

/* Can't do bgets on an unbuffered stream */
    if (!(fb->flags & B_RD)) {
	errno = EINVAL;
	return -1;
    }
    if (fb->flags & B_RDERR)
	return -1;

    ct = 0;
    i = 0;
    for (;;) {
	if (i == fb->incnt) {
/* no characters left */
	    fb->inptr = fb->inbase;
	    fb->incnt = 0;
	    if (fb->flags & B_EOF)
		break;
	    i = read_with_errors(fb, fb->inptr, fb->bufsiz);
	    if (i == -1) {
		buff[ct] = '\0';
		return ct ? ct : -1;
	    }
	    fb->incnt = i;
	    if (i == 0)
		break;		/* EOF */
	    i = 0;
	    continue;		/* restart with the new data */
	}

	ch = fb->inptr[i++];
#ifdef CHARSET_EBCDIC
	if (fb->flags & B_ASCII2EBCDIC)
	    ch = os_toebcdic[(unsigned char)ch];
#endif
	if (ch == LF) {  /* got LF */
	    if (ct == 0)
		buff[ct++] = '\n';
/* if just preceeded by CR, replace CR with LF */
	    else if (buff[ct - 1] == CR)
		buff[ct - 1] = '\n';
	    else if (ct < n - 1)
		buff[ct++] = '\n';
	    else
		i--;		/* no room for LF */
	    break;
	}
	if (ct == n - 1) {
	    i--;		/* push back ch */
	    break;
	}

	buff[ct++] = ch;
    }
    fb->incnt -= i;
    fb->inptr += i;

    buff[ct] = '\0';
    return ct;
}

/*
 * Looks at the stream fb and places the first character into buff
 * without removing it from the stream buffer.
 *
 * Returns 1 on success, zero on end of transmission, or -1 on an error.
 *
 */
API_EXPORT(int) ap_blookc(char *buff, BUFF *fb)
{
    int i;

    *buff = '\0';

    if (!(fb->flags & B_RD)) {	/* Can't do blookc on an unbuffered stream */
	errno = EINVAL;
	return -1;
    }
    if (fb->flags & B_RDERR)
	return -1;

    if (fb->incnt == 0) {	/* no characters left in stream buffer */
	fb->inptr = fb->inbase;
	if (fb->flags & B_EOF)
	    return 0;

	i = read_with_errors(fb, fb->inptr, fb->bufsiz);
	if (i <= 0) {
	    return i;
	}
	fb->incnt = i;
    }

#ifndef CHARSET_EBCDIC
    *buff = fb->inptr[0];
#else /*CHARSET_EBCDIC*/
    *buff = (fb->flags & B_ASCII2EBCDIC)
	     ? os_toebcdic[(unsigned char)fb->inptr[0]]
	     : fb->inptr[0];
#endif /*CHARSET_EBCDIC*/
    return 1;
}

/*
 * Skip data until a linefeed character is read
 * Returns 1 on success, 0 if no LF found, or -1 on error
 */
API_EXPORT(int) ap_bskiplf(BUFF *fb)
{
    unsigned char *x;
    int i;

/* Can't do bskiplf on an unbuffered stream */
    if (!(fb->flags & B_RD)) {
	errno = EINVAL;
	return -1;
    }
    if (fb->flags & B_RDERR)
	return -1;

    for (;;) {
	x = (unsigned char *) memchr(fb->inptr, '\012', fb->incnt);
	if (x != NULL) {
	    x++;
	    fb->incnt -= x - fb->inptr;
	    fb->inptr = x;
	    return 1;
	}

	fb->inptr = fb->inbase;
	fb->incnt = 0;
	if (fb->flags & B_EOF)
	    return 0;
	i = read_with_errors(fb, fb->inptr, fb->bufsiz);
	if (i <= 0)
	    return i;
	fb->incnt = i;
    }
}

/*
 * output a single character.  Used by ap_bputs when the buffer
 * is full... and so it'll cause the buffer to be flushed first.
 */
API_EXPORT(int) ap_bflsbuf(int c, BUFF *fb)
{
    char ss[1];

    ss[0] = c;
    return ap_bwrite(fb, ss, 1);
}

/*
 * Fill the buffer and read a character from it
 */
API_EXPORT(int) ap_bfilbuf(BUFF *fb)
{
    int i;
    char buf[1];

    i = ap_bread(fb, buf, 1);
    if (i == 0)
	errno = 0;		/* no error; EOF */
    if (i != 1)
	return EOF;
    else
	return buf[0];
}


/*
 * When doing chunked encodings we really have to write everything in the
 * chunk before proceeding onto anything else.  This routine either writes
 * nbytes and returns 0 or returns -1 indicating a failure.
 *
 * This is *seriously broken* if used on a non-blocking fd.  It will poll.
 *
 * Deals with calling doerror and setting bytes_sent.
 */
static int write_it_all(BUFF *fb, const void *buf, int nbyte)
{
    int i;

    if (fb->flags & (B_WRERR | B_EOUT))
	return -1;

    while (nbyte > 0) {
	i = buff_write(fb, buf, nbyte);
	if (i < 0) {
	    if (errno != EAGAIN && errno != EINTR) {
		doerror(fb, B_WR);
		return -1;
	    }
	}
	else {
	    nbyte -= i;
	    buf = i + (const char *) buf;
	    fb->bytes_sent += i;
	}
	if (fb->flags & B_EOUT)
	    return -1;
    }
    return 0;
}


#ifndef NO_WRITEV
/* Similar to previous, but uses writev.  Note that it modifies vec.
 * return 0 if successful, -1 otherwise.
 *
 * Deals with doerror() and bytes_sent.
 */
static int writev_it_all(BUFF *fb, struct iovec *vec, int nvec)
{
    int i, rv;
    
    if (fb->filter_callback != NULL) {
        for (i = 0; i < nvec; i++) {
            fb->filter_callback(fb, vec[i].iov_base, vec[i].iov_len);
        }
    }

    /* while it's nice an easy to build the vector and crud, it's painful
     * to deal with a partial writev()
     */
    i = 0;
    while (i < nvec) {
	do
	    rv = writev(fb->fd, &vec[i], nvec - i);
	while (rv == -1 && (errno == EINTR || errno == EAGAIN)
	       && !(fb->flags & B_EOUT));
	if (rv == -1) {
	    if (errno != EINTR && errno != EAGAIN) {
		doerror(fb, B_WR);
	    }
	    return -1;
	}
	fb->bytes_sent += rv;
	/* recalculate vec to deal with partial writes */
	while (rv > 0) {
	    if (rv < vec[i].iov_len) {
		vec[i].iov_base = (char *) vec[i].iov_base + rv;
		vec[i].iov_len -= rv;
		rv = 0;
	    }
	    else {
		rv -= vec[i].iov_len;
		++i;
	    }
	}
	if (fb->flags & B_EOUT)
	    return -1;
    }
    /* if we got here, we wrote it all */
    return 0;
}
#endif

/* A wrapper for buff_write which deals with error conditions and
 * bytes_sent.  Also handles non-blocking writes.
 */
static int write_with_errors(BUFF *fb, const void *buf, int nbyte)
{
    int rv;

    do
	rv = buff_write(fb, buf, nbyte);
    while (rv == -1 && errno == EINTR && !(fb->flags & B_EOUT));
    if (rv == -1) {
	if (errno != EAGAIN) {
	    doerror(fb, B_WR);
	}
	return -1;
    }
    else if (rv == 0) {
	errno = EAGAIN;
	return -1;
    }
    fb->bytes_sent += rv;
    return rv;
}


/*
 * A hook to write() that deals with chunking. This is really a protocol-
 * level issue, but we deal with it here because it's simpler; this is
 * an interim solution pending a complete rewrite of all this stuff in
 * 2.0, using something like sfio stacked disciplines or BSD's funopen().
 *
 * Can be used on non-blocking descriptors, but only if they're not chunked.
 * Deals with doerror() and bytes_sent.
 */
static int bcwrite(BUFF *fb, const void *buf, int nbyte)
{
    char chunksize[16];		/* Big enough for practically anything */
#ifndef NO_WRITEV
    struct iovec vec[3];
#endif

    if (fb->flags & (B_WRERR | B_EOUT))
	return -1;

    if (!(fb->flags & B_CHUNK)) {
	return write_with_errors(fb, buf, nbyte);
    }

#ifdef NO_WRITEV
    /* without writev() this has poor performance, too bad */

    ap_snprintf(chunksize, sizeof(chunksize), "%x" CRLF, nbyte);
#ifdef CHARSET_EBCDIC
    /* Chunks are an HTTP/1.1 Protocol feature. They must ALWAYS be in ASCII */
    ebcdic2ascii(chunksize, chunksize, strlen(chunksize));
#endif /*CHARSET_EBCDIC*/
    if (write_it_all(fb, chunksize, strlen(chunksize)) == -1)
	return -1;
    if (write_it_all(fb, buf, nbyte) == -1)
	return -1;
    if (write_it_all(fb, ascii_CRLF, 2) == -1)
	return -1;
    return nbyte;
#else
    vec[0].iov_base = chunksize;
    vec[0].iov_len = ap_snprintf(chunksize, sizeof(chunksize), "%x" CRLF,
				 nbyte);
#ifdef CHARSET_EBCDIC
    /* Chunks are an HTTP/1.1 Protocol feature. They must ALWAYS be in ASCII */
    ebcdic2ascii(chunksize, chunksize, strlen(chunksize));
#endif /*CHARSET_EBCDIC*/
    vec[1].iov_base = (void *) buf;	/* cast is to avoid const warning */
    vec[1].iov_len = nbyte;
    vec[2].iov_base = ascii_CRLF;
    vec[2].iov_len = 2;

    return writev_it_all(fb, vec, (sizeof(vec) / sizeof(vec[0]))) ? -1 : nbyte;
#endif
}


#ifndef NO_WRITEV
/*
 * Used to combine the contents of the fb buffer, and a large buffer
 * passed in.
 */
static int large_write(BUFF *fb, const void *buf, int nbyte)
{
    struct iovec vec[4];
    int nvec;
    char chunksize[16];

    /* it's easiest to end the current chunk */
    if (fb->flags & B_CHUNK) {
	end_chunk(fb);
    }
    nvec = 0;
    if (fb->outcnt > 0) {
	vec[nvec].iov_base = (void *) fb->outbase;
	vec[nvec].iov_len = fb->outcnt;
	++nvec;
    }
    if (fb->flags & B_CHUNK) {
	vec[nvec].iov_base = chunksize;
	vec[nvec].iov_len = ap_snprintf(chunksize, sizeof(chunksize),
					"%x" CRLF, nbyte);
#ifdef CHARSET_EBCDIC
    /* Chunks are an HTTP/1.1 Protocol feature. They must ALWAYS be in ASCII */
	ebcdic2ascii(chunksize, chunksize, strlen(chunksize));
#endif /*CHARSET_EBCDIC*/
	++nvec;
	vec[nvec].iov_base = (void *) buf;
	vec[nvec].iov_len = nbyte;
	++nvec;
	vec[nvec].iov_base = ascii_CRLF;
	vec[nvec].iov_len = 2;
	++nvec;
    }
    else {
	vec[nvec].iov_base = (void *) buf;
	vec[nvec].iov_len = nbyte;
	++nvec;
    }

    fb->outcnt = 0;
    if (writev_it_all(fb, vec, nvec)) {
	return -1;
    }
    else if (fb->flags & B_CHUNK) {
	start_chunk(fb);
    }
    return nbyte;
}
#endif


/*
 * Write nbyte bytes.
 * Only returns fewer than nbyte if an error ocurred.
 * Returns -1 if no bytes were written before the error ocurred.
 * It is worth noting that if an error occurs, the buffer is in an unknown
 * state.
 */
API_EXPORT(int) ap_bwrite(BUFF *fb, const void *buf, int nbyte)
{
    int i, nwr, useable_bufsiz;
#ifdef CHARSET_EBCDIC
    static char *cbuf = NULL;
    static int csize = 0;
#endif /*CHARSET_EBCDIC*/

    if (fb->flags & (B_WRERR | B_EOUT))
	return -1;
    if (nbyte == 0)
	return 0;

#ifdef CHARSET_EBCDIC
    if (ap_bgetflag(fb, B_EBCDIC2ASCII)) {
        if (nbyte > csize) {
            if (cbuf != NULL)
                free(cbuf);
            cbuf = malloc(csize = nbyte+HUGE_STRING_LEN);
            if (cbuf == NULL) {
                fprintf(stderr, "Ouch!  Out of memory in ap_bwrite()!\n");
                csize = 0;
            }
        }
        ebcdic2ascii((cbuf) ? cbuf : (void*)buf, buf, nbyte);
        buf = (cbuf) ? cbuf : buf;
    }
#endif /*CHARSET_EBCDIC*/

    if (!(fb->flags & B_WR)) {
/* unbuffered write -- have to use bcwrite since we aren't taking care
 * of chunking any other way */
	return bcwrite(fb, buf, nbyte);
    }

#ifndef NO_WRITEV
/*
 * Detect case where we're asked to write a large buffer, and combine our
 * current buffer with it in a single writev().  Note we don't consider
 * the case nbyte == 1 because modules which use rputc() loops will cause
 * us to use writev() too frequently.  In those cases we really should just
 * start a new buffer.
 */
    if (fb->outcnt > 0 && nbyte > LARGE_WRITE_THRESHOLD
	&& nbyte + fb->outcnt >= fb->bufsiz) {
	return large_write(fb, buf, nbyte);
    }
#endif

/*
 * Whilst there is data in the buffer, keep on adding to it and writing it
 * out
 */
    nwr = 0;
    while (fb->outcnt > 0) {
/* can we accept some data? */
	i = fb->bufsiz - fb->outcnt;
	if (i > 0) {
	    if (i > nbyte)
		i = nbyte;
	    memcpy(fb->outbase + fb->outcnt, buf, i);
	    fb->outcnt += i;
	    nbyte -= i;
	    buf = i + (const char *) buf;
	    nwr += i;
	    if (nbyte == 0)
		return nwr;	/* return if none left */
	}

/* the buffer must be full */
	if (fb->flags & B_CHUNK) {
	    end_chunk(fb);
	    /* it is just too painful to try to re-cram the buffer while
	     * chunking
	     */
	    if (write_it_all(fb, fb->outbase, fb->outcnt) == -1) {
		/* we cannot continue after a chunked error */
		return -1;
	    }
	    fb->outcnt = 0;
	    break;
	}
	i = write_with_errors(fb, fb->outbase, fb->outcnt);
	if (i <= 0) {
	    return nwr ? nwr : -1;
	}

	/* deal with a partial write */
	if (i < fb->outcnt) {
	    int j, n = fb->outcnt;
	    unsigned char *x = fb->outbase;
	    for (j = i; j < n; j++)
		x[j - i] = x[j];
	    fb->outcnt -= i;
	}
	else
	    fb->outcnt = 0;

	if (fb->flags & B_EOUT)
	    return -1;
    }
/* we have emptied the file buffer. Now try to write the data from the
 * original buffer until there is less than bufsiz left.  Note that we
 * use bcwrite() to do this for us, it will do the chunking so that
 * we don't have to dink around building a chunk in our own buffer.
 *
 * Note also that bcwrite never does a partial write if we're chunking,
 * so we're guaranteed to either end in an error state, or make it
 * out of this loop and call start_chunk() below.
 *
 * Remember we may not be able to use the entire buffer if we're
 * chunking.
 */
    useable_bufsiz = fb->bufsiz;
    if (fb->flags & B_CHUNK) useable_bufsiz -= CHUNK_HEADER_SIZE;
    while (nbyte >= useable_bufsiz) {
	i = bcwrite(fb, buf, nbyte);
	if (i <= 0) {
	    return nwr ? nwr : -1;
	}

	buf = i + (const char *) buf;
	nwr += i;
	nbyte -= i;

	if (fb->flags & B_EOUT)
	    return -1;
    }
/* copy what's left to the file buffer */
    fb->outcnt = 0;
    if (fb->flags & B_CHUNK)
	start_chunk(fb);
    if (nbyte > 0)
	memcpy(fb->outbase + fb->outcnt, buf, nbyte);
    fb->outcnt += nbyte;
    nwr += nbyte;
    return nwr;
}


static int bflush_core(BUFF *fb)
{
    int i;

    while (fb->outcnt > 0) {
	i = write_with_errors(fb, fb->outbase, fb->outcnt);
	if (i <= 0)
	    return -1;

	/*
	 * We should have written all the data, but if the fd was in a
	 * strange (non-blocking) mode, then we might not have done so.
	 */
	if (i < fb->outcnt) {
	    int j, n = fb->outcnt;
	    unsigned char *x = fb->outbase;
	    for (j = i; j < n; j++)
		x[j - i] = x[j];
	}
	fb->outcnt -= i;

	/* If a soft timeout occurs while flushing, the handler should
	 * have set the buffer flag B_EOUT.
	 */
	if (fb->flags & B_EOUT)
	    return -1;
    }

    return 0;
}

/*
 * Flushes the buffered stream.
 * Returns 0 on success or -1 on error
 */
API_EXPORT(int) ap_bflush(BUFF *fb)
{
    int ret;

    if ((fb->flags & (B_WRERR | B_EOUT | B_WR)) != B_WR)
	return -1;

    if (fb->flags & B_CHUNK)
	end_chunk(fb);

    ret = bflush_core(fb);

    if (ret == 0 && (fb->flags & B_CHUNK)) {
	start_chunk(fb);
    }

    return ret;
}

/*
 * Flushes and closes the file, even if an error occurred.
 * Discards an data that was not read, or not written by bflush()
 * Sets the EOF flag to indicate no futher data can be read,
 * and the EOUT flag to indicate no further data can be written.
 */
API_EXPORT(int) ap_bclose(BUFF *fb)
{
    int rc1, rc2, rc3;

    if (fb->flags & B_WR)
	rc1 = ap_bflush(fb);
    else
	rc1 = 0;
#if defined(WIN32) || defined(NETWARE) || defined(CYGWIN_WINSOCK) 
    if (fb->flags & B_SOCKET) {
	rc2 = ap_pclosesocket(fb->pool, fb->fd);
	if (fb->fd_in != fb->fd) {
	    rc3 = ap_pclosesocket(fb->pool, fb->fd_in);
	}
	else {
	    rc3 = 0;
	}
    }
#if !defined(NETWARE) && !defined(CYGWIN_WINSOCK) 
    else if (fb->hFH != INVALID_HANDLE_VALUE) {
        rc2 = ap_pcloseh(fb->pool, fb->hFH);
        rc3 = 0;
    }
#endif
    else {
#elif defined(BEOS)
    if (fb->flags & B_SOCKET) {
	rc2 = ap_pclosesocket(fb->pool, fb->fd);
	if (fb->fd_in != fb->fd) {
	    rc3 = ap_pclosesocket(fb->pool, fb->fd_in);
	}
	else {
	    rc3 = 0;
	}
    } else {
#endif
	rc2 = ap_pclosef(fb->pool, fb->fd);
	if (fb->fd_in != fb->fd) {
	    rc3 = ap_pclosef(fb->pool, fb->fd_in);
	}
	else {
	    rc3 = 0;
	}
#if defined(WIN32) || defined (BEOS) || defined(NETWARE) || defined(CYGWIN_WINSOCK) 
    }
#endif

    fb->inptr = fb->inbase;
    fb->incnt = 0;
    fb->outcnt = 0;

    fb->flags |= B_EOF | B_EOUT;
    fb->fd = -1;
    fb->fd_in = -1;

#ifdef B_SFIO
    sfclose(fb->sf_in);
    sfclose(fb->sf_out);
#endif

    if (rc1 != 0)
	return rc1;
    else if (rc2 != 0)
	return rc2;
    else
	return rc3;
}

/*
 * returns the number of bytes written or -1 on error
 */
API_EXPORT(int) ap_bputs(const char *x, BUFF *fb)
{
    int i, j = strlen(x);
    i = ap_bwrite(fb, x, j);
    if (i != j)
	return -1;
    else
	return j;
}

/*
 * returns the number of bytes written or -1 on error
 */
API_EXPORT_NONSTD(int) ap_bvputs(BUFF *fb,...)
{
    int i, j, k;
    va_list v;
    const char *x;

    va_start(v, fb);
    for (k = 0;;) {
	x = va_arg(v, const char *);
	if (x == NULL)
	    break;
	j = strlen(x);
	i = ap_bwrite(fb, x, j);
	if (i != j) {
	    va_end(v);
	    return -1;
	}
	k += i;
    }

    va_end(v);

    return k;
}

API_EXPORT(void) ap_bonerror(BUFF *fb, void (*error) (BUFF *, int, void *),
			  void *data)
{
    fb->error = error;
    fb->error_data = data;
}

struct bprintf_data {
    ap_vformatter_buff vbuff;
    BUFF *fb;
};

static int bprintf_flush(ap_vformatter_buff *vbuff)
{
    struct bprintf_data *b = (struct bprintf_data *)vbuff;
    BUFF *fb = b->fb;

#ifdef CHARSET_EBCDIC
    /* Characters were pushed into the buffer without conversion. Do it now */
    if (fb->flags & B_EBCDIC2ASCII)
        ebcdic2ascii(&fb->outbase[fb->outcnt],
		     &fb->outbase[fb->outcnt],
		     b->vbuff.curpos - (char *)&fb->outbase[fb->outcnt]);
#endif /*CHARSET_EBCDIC*/
    fb->outcnt += b->vbuff.curpos - (char *)&fb->outbase[fb->outcnt];
    if (fb->outcnt == fb->bufsiz) {
	if (ap_bflush(fb)) {
	    return -1;
	}
    }
    vbuff->curpos = (char *)&fb->outbase[fb->outcnt];
    vbuff->endpos = (char *)&fb->outbase[fb->bufsiz];
    return 0;
}

API_EXPORT_NONSTD(int) ap_bprintf(BUFF *fb, const char *fmt, ...)
{
    va_list ap;
    int res;
    struct bprintf_data b;

    /* XXX: only works with buffered writes */
    if ((fb->flags & (B_WRERR | B_EOUT | B_WR)) != B_WR)
	return -1;
    b.vbuff.curpos = (char *)&fb->outbase[fb->outcnt];
    b.vbuff.endpos = (char *)&fb->outbase[fb->bufsiz];
    b.fb = fb;
    va_start(ap, fmt);
    res = ap_vformatter(bprintf_flush, &b.vbuff, fmt, ap);
    va_end(ap);
    if (res != -1) {
#ifdef CHARSET_EBCDIC
	/* Characters were pushed into the buffer without conversion. Do it now */
	if (fb->flags & B_EBCDIC2ASCII)
	    ebcdic2ascii(&fb->outbase[fb->outcnt],
			 &fb->outbase[fb->outcnt],
			 b.vbuff.curpos - (char *)&fb->outbase[fb->outcnt]);
#endif /*CHARSET_EBCDIC*/
	fb->outcnt += b.vbuff.curpos - (char *)&fb->outbase[fb->outcnt];
    }
    return res;
}

API_EXPORT(int) ap_vbprintf(BUFF *fb, const char *fmt, va_list ap)
{
    struct bprintf_data b;
    int res;

    /* XXX: only works with buffered writes */
    if ((fb->flags & (B_WRERR | B_EOUT | B_WR)) != B_WR)
	return -1;
    b.vbuff.curpos = (char *)&fb->outbase[fb->outcnt];
    b.vbuff.endpos = (char *)&fb->outbase[fb->bufsiz];
    b.fb = fb;
    res = ap_vformatter(bprintf_flush, &b.vbuff, fmt, ap);
    if (res != -1) {
#ifdef CHARSET_EBCDIC
	/* Characters were pushed into the buffer without conversion. Do it now */
	if (fb->flags & B_EBCDIC2ASCII)
	    ebcdic2ascii(&fb->outbase[fb->outcnt],
			 &fb->outbase[fb->outcnt],
			 b.vbuff.curpos - (char *)&fb->outbase[fb->outcnt]);
#endif /*CHARSET_EBCDIC*/
	fb->outcnt += b.vbuff.curpos - (char *)&fb->outbase[fb->outcnt];
    }
    return res;
}
 
