/* ====================================================================
 * Copyright (c) 1996 The Apache Group.  All rights reserved.
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
 *    prior written permission.
 *
 * 5. Redistributions of any form whatsoever must retain the following
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

#include <errno.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>

#include "alloc.h"
#include "buff.h"

#define DEFAULT_BUFSIZE (4096)

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

static void
doerror(BUFF *fb, int err)
{
    if (err == B_RD)
	fb->flags |= B_RDERR;
    else
	fb->flags |= B_WRERR;
    if (fb->error != NULL) (*fb->error)(fb, err, fb->error_data);
}

/* Buffering routines */
/*
 * Create a new buffered stream
 */
BUFF *
bcreate(pool *p, int flags)
{
    BUFF *fb;

    fb = palloc(p, sizeof(BUFF));
    fb->pool=p;
    fb->bufsiz = DEFAULT_BUFSIZE;
    fb->flags = flags & B_RDWR;

    if (flags & B_RD) fb->inbase = palloc(p, fb->bufsiz);
    else fb->inbase = NULL;

    if (flags & B_WR) fb->outbase = palloc(p, fb->bufsiz);
    else fb->inbase = NULL;

    fb->inptr = fb->inbase;

    fb->incnt = 0;
    fb->outcnt = 0;
    fb->error = NULL;
    fb->bytes_sent = 0L;

    fb->fd = -1;
    fb->fd_in = -1;

    return fb;
}

/*
 * Push some I/O file descriptors onto the stream
 */
void
bpushfd(BUFF *fb, int fd_in, int fd_out)
{
    fb->fd = fd_out;
    fb->fd_in = fd_in;
    note_cleanups_for_fd(fb->pool,fb->fd);
    if(fb->fd != fb->fd_in)
	note_cleanups_for_fd(fb->pool,fb->fd_in);
}

int
bsetopt(BUFF *fb, int optname, const void *optval)
{
    if (optname == BO_BYTECT)
    {
	fb->bytes_sent = *(const long int *)optval - (long int)fb->outcnt;;
	return 0;
    } else
    {
	errno = EINVAL;
	return -1;
    }
}

int
bgetopt(BUFF *fb, int optname, void *optval)
{
    if (optname == BO_BYTECT)
    {
	long int bs=fb->bytes_sent + fb->outcnt;
	if (bs < 0L) bs = 0L;
	*(long int *)optval = bs;
	return 0;
    } else
    {
	errno = EINVAL;
	return -1;
    }
}

/*
 * Read up to nbyte bytes into buf.
 * If fewer than byte bytes are currently available, then return those.
 * Returns 0 for EOF, -1 for error.
 */
int
bread(BUFF *fb, void *buf, int nbyte)
{
    int i, nrd;

    if (fb->flags & B_RDERR) return -1;
    if (nbyte == 0) return 0;

    if (!(fb->flags & B_RD))
    {
/* Unbuffered reading */
	do i = read(fb->fd_in, buf, nbyte);
	while (i == -1 && errno == EINTR);
	if (i == -1 && errno != EAGAIN) doerror(fb, B_RD);
	return i;
    }

    nrd = fb->incnt;
/* can we fill the buffer */
    if (nrd >= nbyte)
    {
	memcpy(buf, fb->inptr, nbyte);
	fb->incnt = nrd - nbyte;
	fb->inptr += nbyte;
	return nbyte;
    }
	
    if (nrd > 0)
    {
	memcpy(buf, fb->inptr, nrd);
	nbyte -= nrd;
	buf = nrd + (char *)buf;
	fb->incnt = 0;
    }
    if (fb->flags & B_EOF) return nrd;

/* do a single read */
    if (nbyte >= fb->bufsiz)
    {
/* read directly into buffer */
	do i = read(fb->fd_in, buf, nbyte);
	while (i == -1 && errno == EINTR);
	if (i == -1)
	{
	    if (nrd == 0)
	    {
		if (errno != EAGAIN) doerror(fb, B_RD);
		return -1;
	    }
	    else return nrd;
	} else if (i == 0) fb->flags |= B_EOF;
    } else
    {
/* read into hold buffer, then memcpy */
	fb->inptr = fb->inbase;
	do i = read(fb->fd_in, fb->inptr, fb->bufsiz);
	while (i == -1 && errno == EINTR);
	if (i == -1)
	{
	    if (nrd == 0)
	    {
		if (errno != EAGAIN) doerror(fb, B_RD);
		return -1;
	    }
	    else return nrd;
	} else if (i == 0) fb->flags |= B_EOF;
	fb->incnt = i;
	if (i > nbyte) i = nbyte;
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
 *  If null characters are exepected in the data stream, then
 * buff should not be treated as a null terminated C string; instead
 * the returned count should be used to determine the length of the
 * string.
 *  CR characters in the byte stream not immediately followed by a LF
 * will be preserved.
 */
int
bgets(char *buff, int n, BUFF *fb)
{
    int i, ch, ct;

/* Can't do bgets on an unbuffered stream */
    if (!(fb->flags & B_RD))
    {
	errno = EINVAL;
	return -1;
    }
    if (fb->flags & B_RDERR) return -1;

    ct = 0;
    i = 0;
    for (;;)
    {
	if (i == fb->incnt)
	{
/* no characters left */
	    fb->inptr = fb->inbase;
	    fb->incnt = 0;
	    if (fb->flags & B_EOF) break;
	    do i = read(fb->fd_in, fb->inptr, fb->bufsiz);
	    while (i == -1 && errno == EINTR);
	    if (i == -1)
	    {
		buff[ct] = '\0';
		if (ct == 0)
		{
		    if (errno != EAGAIN) doerror(fb, B_RD);
		    return -1;
		}
		else return ct;
	    }
	    fb->incnt = i;
	    if (i == 0)
	    {
		fb->flags |= B_EOF;
		break; /* EOF */
	    }
	    i = 0;
	    continue;  /* restart with the new data */
	}

	ch = fb->inptr[i++];
	if (ch == '\012')  /* got LF */
	{
	    if (ct == 0) buff[ct++] = '\n';
/* if just preceeded by CR, replace CR with LF */
	    else if (buff[ct-1] == '\015') buff[ct-1] = '\n';
	    else if (ct < n-1) buff[ct++] = '\n';
	    else i--; /* no room for LF */
	    break;
	}
	if (ct == n-1)
	{
	    i--;  /* push back ch */
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
 * Skip data until a linefeed character is read
 * Returns 1 on success, 0 if no LF found, or -1 on error
 */
int
bskiplf(BUFF *fb)
{
    unsigned char *x;
    int i;

/* Can't do bskiplf on an unbuffered stream */
    if (!(fb->flags & B_RD))
    {
	errno = EINVAL;
	return -1;
    }
    if (fb->flags & B_RDERR) return -1;

    for (;;)
    {
	x = memchr(fb->inptr, '\012', fb->incnt);
	if (x != NULL)
	{
	    x++;
	    fb->incnt -= x - fb->inptr;
	    fb->inptr = x;
	    return 1;
	}

	fb->inptr = fb->inbase;
	fb->incnt = 0;
	if (fb->flags & B_EOF) return 0;
	do i = read(fb->fd_in, fb->inptr, fb->bufsiz);
	while (i == -1 && errno == EINTR);
	if (i == 0) fb->flags |= B_EOF;
	if (i == -1 && errno != EAGAIN) doerror(fb, B_RD);
	if (i == 0 || i == -1) return i;
	fb->incnt = i;
    }
}

/*
 * Emtpy the buffer after putting a single character in it
 */
int
bflsbuf(int c, BUFF *fb)
{
    char ss[1];

    ss[0] = c;
    return bwrite(fb, ss, 1);
}

/*
 * Fill the buffer and read a character from it
 */
int
bfilbuf(BUFF *fb)
{
    int i;
    char buf[1];

    i = bread(fb, buf, 1);
    if (i == 0) errno = 0;  /* no error; EOF */
    if (i != 1) return EOF;
    else return buf[0];
}

/*
 * Write nbyte bytes.
 * Only returns fewer than nbyte if an error ocurred.
 * Returns -1 if no bytes were written before the error ocurred.
 */
int
bwrite(BUFF *fb, const void *buf, int nbyte)
{
    int i, nwr;

    if (fb->flags & (B_WRERR|B_EOUT)) return -1;
    if (nbyte == 0) return 0;

    if (!(fb->flags & B_WR))
    {
/* unbuffered write */
	do i = write(fb->fd, buf, nbyte);
	while (i == -1 && errno == EINTR);
	if (i > 0) fb->bytes_sent += i;
	if (i == 0)
	{
	    i = -1;  /* return of 0 means non-blocking */
	    errno = EAGAIN;
	}
	if (i == -1 && errno != EAGAIN) doerror(fb, B_WR);
	return i;
    }

/*
 * Whilst there is data in the buffer, keep on adding to it and writing it
 * out
 */
    nwr = 0;
    while (fb->outcnt > 0)
    {
/* can we accept some data? */
	i = fb->bufsiz - fb->outcnt;
	if (i > 0)
	{
	    if (i > nbyte) i = nbyte;
	    memcpy(fb->outbase + fb->outcnt, buf, i);
	    fb->outcnt += i;
	    nbyte -= i;
	    buf = i + (const char *)buf;
	    nwr += i;
	    if (nbyte == 0) return nwr; /* return if none left */
	}

/* the buffer must be full */
	do i = write(fb->fd, fb->outbase, fb->bufsiz);
	while (i == -1 && errno == EINTR);
	if (i > 0) fb->bytes_sent += i;
	if (i == 0)
	{
	    i = -1;  /* return of 0 means non-blocking */
	    errno = EAGAIN;
	}
	if (i == -1)
	{
	    if (nwr == 0)
	    {
		if (errno != EAGAIN) doerror(fb, B_WR);
		return -1;
	    }
	    else return nwr;
	}

/*
 * we should have written all the data, however if the fd was in a
 * strange (non-blocking) mode, then we might not have done so.
 */
	if (i < fb->bufsiz)
	{
	    int j, n=fb->bufsiz;
	    unsigned char *x=fb->outbase;
	    for (j=i; j < n; j++) x[j-i] = x[j];
	    fb->outcnt = fb->bufsiz - i;
	} else
	    fb->outcnt = 0;
    }
/* we have emptied the file buffer. Now try to write the data from the
 * original buffer until there is less than bufsiz left
 */
    while (nbyte > fb->bufsiz)
    {
	do i = write(fb->fd, buf, nbyte);
	while (i == -1 && errno == EINTR);
	if (i > 0) fb->bytes_sent += i;
	if (i == 0)
	{
	    i = -1;  /* return of 0 means non-blocking */
	    errno = EAGAIN;
	}
	if (i == -1)
	{
	    if (nwr == 0)
	    {
		if (errno != EAGAIN) doerror(fb, B_WR);
		return -1;
	    }
	    else return nwr;
	}

	buf = i + (const char *)buf;
	nwr += i;
	nbyte -= i;
    }
/* copy what's left to the file buffer */
    if (nbyte > 0) memcpy(fb->outbase, buf, nbyte);
    fb->outcnt = nbyte;
    nwr += nbyte;
    return nwr;
}

/*
 * Flushes the buffered stream.
 * Returns 0 on success or -1 on error
 */
int
bflush(BUFF *fb)
{
    int i, j;

    if (!(fb->flags & B_WR) || (fb->flags & B_EOUT)) return 0;

    if (fb->flags & B_WRERR) return -1;
    
    while (fb->outcnt > 0)
    {
/* the buffer must be full */
	j = fb->outcnt;
	do i = write(fb->fd, fb->outbase, fb->outcnt);
	while (i == -1 && errno == EINTR);
	if (i > 0) fb->bytes_sent += i;
	if (i == 0)
	{
	    errno = EAGAIN;
	    return -1;  /* return of 0 means non-blocking */
	}
	if (i == -1)
	{
	    if (errno != EAGAIN) doerror(fb, B_WR);
	    return -1;
	}

/*
 * we should have written all the data, however if the fd was in a
 * strange (non-blocking) mode, then we might not have done so.
 */
	if (i < fb->outcnt)
	{
	    int j, n=fb->outcnt;
	    unsigned char *x=fb->outbase;
	    for (j=i; j < n; j++) x[j-i] = x[j];
	}
	fb->outcnt -= i;
    }
    return 0;
}

/*
 * Flushes and closes the file, even if an error occurred.
 * Discards an data that was not read, or not written by bflush()
 * Sets the EOF flag to indicate no futher data can be read,
 * and the EOUT flag to indicate no further data can be written.
 */
int
bclose(BUFF *fb)
{
    int rc1, rc2, rc3;

    if (fb->flags & B_WR) rc1 = bflush(fb);
    else rc1 = 0;
    rc2 = close(fb->fd);
    if (fb->fd_in != fb->fd) rc3 = close(fb->fd_in);
    else rc3 = 0;

    fb->inptr = fb->inbase;
    fb->incnt = 0;
    fb->outcnt = 0;

    fb->flags |= B_EOF | B_EOUT;
    fb->fd = -1;
    fb->fd_in = -1;

    if (rc1 != 0) return rc1;
    else if (rc2 != 0) return rc2;
    else return rc3;
}

/*
 * returns the number of bytes written or -1 on error
 */
int
bputs(const char *x, BUFF *fb)
{
    int i, j=strlen(x);
    i = bwrite(fb, x, j);
    if (i != j) return -1;
    else return j;
}

/*
 * returns the number of bytes written or -1 on error
 */
int
bvputs(BUFF *fb, ...)
{
    int i, j, k;
    va_list v;
    const char *x;

    va_start(v, fb);
    for (k=0;;)
    {
	x = va_arg(v, const char *);
	if (x == NULL) break;
	j = strlen(x);
	i = bwrite(fb, x, j);
	if (i != j)
	{
	    va_end(v);
	    return -1;
	}
	k += i;
    }

    va_end(v);

    return k;
}

void
bonerror(BUFF *fb, void (*error)(BUFF *, int, void *), void *data)
{
    fb->error = error;
    fb->error_data = data;
}
