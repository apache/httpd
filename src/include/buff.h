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

#include <stdarg.h>

/* Reading is buffered */
#define B_RD     (1)
/* Writing is buffered */
#define B_WR     (2)
#define B_RDWR   (3)
/* At end of file, or closed stream; no further input allowed */
#define B_EOF    (4)
/* No further output possible */
#define B_EOUT   (8)
/* A read error has occurred */
#define B_RDERR (16)
/* A write error has occurred */
#define B_WRERR (32)
#define B_ERROR (48)

typedef struct buff_struct BUFF;

struct buff_struct
{
    int flags;             /* flags */
    unsigned char *inptr;  /* pointer to next location to read */
    int incnt;             /* number of bytes left to read from input buffer;
			    * always 0 if had a read error  */
    int outcnt;            /* number of byte put in output buffer */
    unsigned char *inbase;
    unsigned char *outbase;
    int bufsiz;
    void (*error)(BUFF *fb, int op, void *data);
    void *error_data;
    long int bytes_sent;   /* number of bytes actually written */

    pool *pool;

/* could also put pointers to the basic I/O routines here */
    int fd;                /* the file descriptor */
    int fd_in;             /* input file descriptor, if different */
};

/* Options to bset/getopt */
#define BO_BYTECT (1)

/* Stream creation and modification */
extern BUFF *bcreate(pool *p, int flags);
extern void bpushfd(BUFF *fb, int fd_in, int fd_out);
extern int bsetopt(BUFF *fb, int optname, const void *optval);
extern int bgetopt(BUFF *fb, int optname, void *optval);
extern int bclose(BUFF *fb);

/* Error handling */
extern void bonerror(BUFF *fb, void (*error)(BUFF *, int, void *),
		     void *data);

/* I/O */
extern int bread(BUFF *fb, void *buf, int nbyte);
extern int bgets(char *s, int n, BUFF *fb);
extern int bskiplf(BUFF *fb);
extern int bwrite(BUFF *fb, const void *buf, int nbyte);
extern int bflush(BUFF *fb);
extern int bputs(const char *x, BUFF *fb);
extern int bvputs(BUFF *fb, ...);
extern int bprintf(BUFF *fb,const char *fmt,...);
extern int vbprintf(BUFF *fb,const char *fmt,va_list vlist);

/* Internal routines */
extern int bflsbuf(int c, BUFF *fb);
extern int bfilbuf(BUFF *fb);

#define bgetc(fb)   ( ((fb)->incnt == 0) ? bfilbuf(fb) : \
		    ((fb)->incnt--, *((fb)->inptr++)) )

#define bputc(c, fb) ((((fb)->flags & (B_EOUT|B_WRERR|B_WR)) != B_WR || \
		     (fb)->outcnt == (fb)->bufsiz) ? bflsbuf(c, (fb)) : \
		     ((fb)->outbase[(fb)->outcnt++] = (c), 0))
