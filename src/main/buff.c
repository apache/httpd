/* ====================================================================
 * Copyright (c) 1996,1997 The Apache Group.  All rights reserved.
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

#include "conf.h"
#include "alloc.h"
#include "buff.h"

#include <errno.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#ifndef NO_UNISTD_H
#include <unistd.h>
#endif
#ifndef NO_WRITEV
#include <sys/types.h>
#include <sys/uio.h>
#endif

#ifdef HAVE_BSTRING_H
#include <bstring.h>		/* for IRIX, FD_SET calls bzero() */
#endif

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
    int errsave = errno;  /* Save errno to prevent overwriting it below */

    if (err == B_RD)
	fb->flags |= B_RDERR;
    else
	fb->flags |= B_WRERR;
    if (fb->error != NULL) (*fb->error)(fb, err, fb->error_data);

    errno = errsave;
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

    /* overallocate so that we can put a chunk trailer of CRLF into this
     * buffer */
    if (flags & B_WR) fb->outbase = palloc(p, fb->bufsiz + 2);
    else fb->outbase = NULL;

    fb->inptr = fb->inbase;

    fb->incnt = 0;
    fb->outcnt = 0;
    fb->outchunk = -1;
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
 * start chunked encoding
 */
static void
start_chunk( BUFF *fb )
{
    char chunksize[16];	/* Big enough for practically anything */
    int chunk_header_size;

    if (fb->outchunk != -1) {
	/* already chunking */
	return;
    }
    if (!(fb->flags & B_WR) || (fb->flags & (B_WRERR|B_EOUT))) {
	/* unbuffered writes */
	return;
    }

    /* we know that the chunk header is going to take at least 3 bytes... */
    chunk_header_size = ap_snprintf( chunksize, sizeof(chunksize),
	"%x\015\012", fb->bufsiz - fb->outcnt - 3 );
    /* we need at least the header_len + at least 1 data byte
     * remember that we've overallocated fb->outbase so that we can always
     * fit the two byte CRLF trailer
     */
    if( fb->bufsiz - fb->outcnt < chunk_header_size + 1 ) {
	bflush(fb);
    }
    /* assume there's enough space now */
    memcpy( &fb->outbase[fb->outcnt], chunksize, chunk_header_size );
    fb->outchunk = fb->outcnt;
    fb->outcnt += chunk_header_size;
    fb->outchunk_header_size = chunk_header_size;
}


/*
 * end a chunk -- tweak the chunk_header from start_chunk, and add a trailer
 */
static void
end_chunk( BUFF *fb )
{
    int i;

    if( fb->outchunk == -1 ) {
	/* not chunking */
	return;
    }

    if( fb->outchunk + fb->outchunk_header_size == fb->outcnt ) {
	/* nothing was written into this chunk, and we can't write a 0 size
	 * chunk because that signifies EOF, so just erase it
	 */
	fb->outcnt = fb->outchunk;
	fb->outchunk = -1;
	return;
    }

    /* we know this will fit because of how we wrote it in start_chunk() */
    i = ap_snprintf( (char *)&fb->outbase[fb->outchunk],
	fb->outchunk_header_size,
	"%x", fb->outcnt - fb->outchunk - fb->outchunk_header_size );

    /* we may have to tack some trailing spaces onto the number we just wrote
     * in case it was smaller than our estimated size.  We've also written
     * a \0 into the buffer with ap_snprintf so we might have to put a
     * \r back in.
     */
    i += fb->outchunk;
    while( fb->outbase[i] != '\015' && fb->outbase[i] != '\012' ) {
	fb->outbase[i++] = ' ';
    }
    if( fb->outbase[i] == '\012' ) {
	/* we overwrote the \r, so put it back */
	fb->outbase[i-1] = '\015';
    }

    /* tack on the trailing CRLF, we've reserved room for this */
    fb->outbase[fb->outcnt++] = '\015';
    fb->outbase[fb->outcnt++] = '\012';

    fb->outchunk = -1;
}


/*
 * Set a flag on (1) or off (0).
 */
int bsetflag(BUFF *fb, int flag, int value)
{
    if (value) {
	fb->flags |= flag;
	if( flag & B_CHUNK ) {
	    start_chunk(fb);
	}
    } else {
	fb->flags &= ~flag;
	if( flag & B_CHUNK ) {
	    end_chunk(fb);
	}
    }
    return value;
}


/*
 * This is called instead of read() everywhere in here.  It implements
 * the B_SAFEREAD functionality -- which is to force a flush() if a read()
 * would block.  It also deals with the EINTR errno result from read().
 * return code is like read() except EINTR is eliminated.
 */
static int
saferead( BUFF *fb, void *buf, int nbyte )
{
    int rv;

    if( fb->flags & B_SAFEREAD ) {
	fd_set fds;
	struct timeval tv;

	/* test for a block */
	do {
	    FD_ZERO( &fds );
	    FD_SET( fb->fd_in, &fds );
	    tv.tv_sec = 0;
	    tv.tv_usec = 0;
#ifdef SELECT_NEEDS_CAST
	    rv = select( fb->fd_in + 1, (int *)&fds, NULL, NULL, &tv );
#else
	    rv = select( fb->fd_in + 1, &fds, NULL, NULL, &tv );
#endif
	} while( rv < 0 && errno == EINTR );
	/* treat any error as if it would block as well */
	if( rv != 1 ) {
	    bflush(fb);
	}
    }
    do {
	rv = read( fb->fd_in, buf, nbyte );
    } while ( rv == -1 && errno == EINTR );
    return( rv );
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
	i = saferead( fb, buf, nbyte );
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
	i = saferead( fb, buf, nbyte );
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
	i = saferead( fb, fb->inptr, fb->bufsiz );
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
	    i = saferead( fb, fb->inptr, fb->bufsiz );
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
 * Looks at the stream fb and places the first character into buff
 * without removing it from the stream buffer.
 *
 * Returns 1 on success, zero on end of transmission, or -1 on an error.
 *
 */
int blookc(char *buff, BUFF *fb)
{
    int i;

    *buff = '\0';
    
    if (!(fb->flags & B_RD)) {   /* Can't do blookc on an unbuffered stream */
        errno = EINVAL;
        return -1;
    }
    if (fb->flags & B_RDERR) return -1;

    if (fb->incnt == 0) {        /* no characters left in stream buffer */
        fb->inptr = fb->inbase;
        if (fb->flags & B_EOF)
            return 0;

	i = saferead( fb, fb->inptr, fb->bufsiz );

        if (i == -1) {
            if (errno != EAGAIN)
                doerror(fb, B_RD);
            return -1;
        }
        if (i == 0) {
            fb->flags |= B_EOF;
            return 0; /* EOF */
        }
        else fb->incnt = i;
    }

    *buff = fb->inptr[0];
    return 1;
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
	x = (unsigned char *)memchr(fb->inptr, '\012', fb->incnt);
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
	i = saferead( fb, fb->inptr, fb->bufsiz );
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
 * When doing chunked encodings we really have to write everything in the
 * chunk before proceeding onto anything else.  This routine either writes
 * nbytes and returns 0 or returns -1 indicating a failure.
 *
 * This is *seriously broken* if used on a non-blocking fd.  It will poll.
 */
static int
write_it_all(BUFF *fb, const void *buf, int nbyte)
{
    int i;

    if (fb->flags & (B_WRERR|B_EOUT))
	return -1;

    while (nbyte > 0) {
	i = write(fb->fd, buf, nbyte);
	if (i < 0) {
	    if (errno != EAGAIN && errno != EINTR) {
		return -1;
	    }
	}
	else {
	    nbyte -= i;
	    buf = i + (const char *)buf;
	}
	if (fb->flags & B_EOUT)
	    return -1;
    }
    return 0;
}


/*
 * A hook to write() that deals with chunking. This is really a protocol-
 * level issue, but we deal with it here because it's simpler; this is
 * an interim solution pending a complete rewrite of all this stuff in
 * 2.0, using something like sfio stacked disciplines or BSD's funopen().
 */
static int
bcwrite(BUFF *fb, const void *buf, int nbyte)
{
    char chunksize[16];	/* Big enough for practically anything */
#ifndef NO_WRITEV
    struct iovec vec[3];
    int i, rv;
#endif

    if (fb->flags & (B_WRERR|B_EOUT))
	return -1;

    if (!(fb->flags & B_CHUNK))
	return write(fb->fd, buf, nbyte);

#ifdef NO_WRITEV
    /* without writev() this has poor performance, too bad */

    ap_snprintf(chunksize, sizeof(chunksize), "%x\015\012", nbyte);
    if (write_it_all(fb, chunksize, strlen(chunksize)) == -1)
	return -1;
    if (write_it_all(fb, buf, nbyte) == -1)
	return -1;
    if (write_it_all(fb, "\015\012", 2) == -1)
	return -1;
    return nbyte;
#else

#define NVEC	(sizeof(vec)/sizeof(vec[0]))

    vec[0].iov_base = chunksize;
    vec[0].iov_len = ap_snprintf(chunksize, sizeof(chunksize), "%x\015\012",
	nbyte);
    vec[1].iov_base = (void *)buf;	/* cast is to avoid const warning */
    vec[1].iov_len = nbyte;
    vec[2].iov_base = "\r\n";
    vec[2].iov_len = 2;
    /* while it's nice an easy to build the vector and crud, it's painful
     * to deal with a partial writev()
     */
    for( i = 0; i < NVEC; ) {
	do rv = writev( fb->fd, &vec[i], NVEC - i );
	while (rv == -1 && errno == EINTR && !(fb->flags & B_EOUT));
	if (rv == -1)
	    return -1;
	/* recalculate vec to deal with partial writes */
	while (rv > 0) {
	    if( rv <= vec[i].iov_len ) {
		vec[i].iov_base = (char *)vec[i].iov_base + rv;
		vec[i].iov_len -= rv;
		rv = 0;
		if( vec[i].iov_len == 0 ) {
		    ++i;
		}
	    } else {
		rv -= vec[i].iov_len;
		++i;
	    }
	}
	if (fb->flags & B_EOUT)
	    return -1;
    }
    /* if we got here, we wrote it all */
    return nbyte;
#undef NVEC
#endif
}


/*
 * Write nbyte bytes.
 * Only returns fewer than nbyte if an error ocurred.
 * Returns -1 if no bytes were written before the error ocurred.
 * It is worth noting that if an error occurs, the buffer is in an unknown
 * state.
 */
int
bwrite(BUFF *fb, const void *buf, int nbyte)
{
    int i, nwr;

    if (fb->flags & (B_WRERR|B_EOUT)) return -1;
    if (nbyte == 0) return 0;

    if (!(fb->flags & B_WR))
    {
/* unbuffered write -- have to use bcwrite since we aren't taking care
 * of chunking any other way */
	do i = bcwrite(fb, buf, nbyte);
	while (i == -1 && errno == EINTR && !(fb->flags & B_EOUT));
	if (i == 0) {  /* return of 0 means non-blocking */
	    errno = EAGAIN;
	    return -1;
	}
	else if (i < 0) {
	    if (errno != EAGAIN)
	        doerror(fb, B_WR);
	    return -1;
	}
	fb->bytes_sent += i;
	if (fb->flags & B_EOUT)
	    return -1;
	else
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
	if (fb->flags & B_CHUNK) {
	    end_chunk(fb);
	    /* it is just too painful to try to re-cram the buffer while
	     * chunking
	     */
	    i = (write_it_all(fb, fb->outbase, fb->outcnt) == -1) ?
	            -1 : fb->outcnt;
	}
	else {
	    do i = write(fb->fd, fb->outbase, fb->outcnt);
	    while (i == -1 && errno == EINTR && !(fb->flags & B_EOUT));
	}
	if (i <= 0) {
	    if (i == 0) /* return of 0 means non-blocking */
	        errno = EAGAIN;
	    if (nwr == 0) {
		if (errno != EAGAIN) doerror(fb, B_WR);
		return -1;
	    }
	    else return nwr;
	}
	fb->bytes_sent += i;

	/* deal with a partial write */
	if (i < fb->outcnt)
	{
	    int j, n=fb->outcnt;
	    unsigned char *x=fb->outbase;
	    for (j=i; j < n; j++) x[j-i] = x[j];
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
 */
    while (nbyte >= fb->bufsiz)
    {
	do i = bcwrite(fb, buf, nbyte);
	while (i == -1 && errno == EINTR && !(fb->flags & B_EOUT));
	if (i <= 0) {
	    if (i == 0) /* return of 0 means non-blocking */
	        errno = EAGAIN;
	    if (nwr == 0) {
		if (errno != EAGAIN) doerror(fb, B_WR);
		return -1;
	    }
	    else return nwr;
	}
	fb->bytes_sent += i;

	buf = i + (const char *)buf;
	nwr += i;
	nbyte -= i;

	if (fb->flags & B_EOUT)
	    return -1;
    }
/* copy what's left to the file buffer */
    fb->outcnt = 0;
    if( fb->flags & B_CHUNK ) start_chunk( fb );
    if (nbyte > 0) memcpy(fb->outbase + fb->outcnt, buf, nbyte);
    fb->outcnt += nbyte;
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
    int i;

    if (!(fb->flags & B_WR) || (fb->flags & B_EOUT)) return 0;

    if (fb->flags & B_WRERR) return -1;
    
    if (fb->flags & B_CHUNK) end_chunk(fb);

    while (fb->outcnt > 0)
    {
	/* the buffer must be full */
	do i = write(fb->fd, fb->outbase, fb->outcnt);
	while (i == -1 && errno == EINTR && !(fb->flags & B_EOUT));
	if (i == 0) {
	    errno = EAGAIN;
	    return -1;  /* return of 0 means non-blocking */
	}
	else if (i < 0) {
	    if (errno != EAGAIN) doerror(fb, B_WR);
	    return -1;
	}
	fb->bytes_sent += i;

	/*
 	 * We should have written all the data, but if the fd was in a
 	 * strange (non-blocking) mode, then we might not have done so.
 	 */
	if (i < fb->outcnt)
	{
	    int j, n=fb->outcnt;
	    unsigned char *x=fb->outbase;
	    for (j=i; j < n; j++) x[j-i] = x[j];
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
