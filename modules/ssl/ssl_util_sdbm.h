/*                      _             _
**  _ __ ___   ___   __| |    ___ ___| |  mod_ssl
** | '_ ` _ \ / _ \ / _` |   / __/ __| |  Apache Interface to OpenSSL
** | | | | | | (_) | (_| |   \__ \__ \ |  www.modssl.org
** |_| |_| |_|\___/ \__,_|___|___/___/_|  ftp.modssl.org
**                      |_____|
**  ssl_util_sdbm.c
**  Built-in Simple DBM (Header)
*/

/* ====================================================================
 * Copyright (c) 1998-2001 Ralf S. Engelschall. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following
 *    disclaimer in the documentation and/or other materials
 *    provided with the distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by
 *     Ralf S. Engelschall <rse@engelschall.com> for use in the
 *     mod_ssl project (http://www.modssl.org/)."
 *
 * 4. The names "mod_ssl" must not be used to endorse or promote
 *    products derived from this software without prior written
 *    permission. For written permission, please contact
 *    rse@engelschall.com.
 *
 * 5. Products derived from this software may not be called "mod_ssl"
 *    nor may "mod_ssl" appear in their names without prior
 *    written permission of Ralf S. Engelschall.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by
 *     Ralf S. Engelschall <rse@engelschall.com> for use in the
 *     mod_ssl project (http://www.modssl.org/)."
 *
 * THIS SOFTWARE IS PROVIDED BY RALF S. ENGELSCHALL ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL RALF S. ENGELSCHALL OR
 * HIS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 */

/*
 * sdbm - ndbm work-alike hashed database library
 * based on Per-Ake Larson's Dynamic Hashing algorithms. BIT 18 (1978).
 * author: oz@nexus.yorku.ca
 * status: public domain.
 */

#ifndef SSL_UTIL_SDBM_H
#define SSL_UTIL_SDBM_H

#define DUFF    /* go ahead and use the loop-unrolled version */

#include <stdio.h>

#ifdef MOD_SSL
#define DBLKSIZ 16384                   /* SSL cert chains require more */
#define PBLKSIZ 8192                    /* SSL cert chains require more */
#define PAIRMAX 8008                    /* arbitrary on PBLKSIZ-N */
#else
#define DBLKSIZ 4096
#define PBLKSIZ 1024
#define PAIRMAX 1008                    /* arbitrary on PBLKSIZ-N */
#endif
#define SPLTMAX 10                      /* maximum allowed splits */
                                        /* for a single insertion */
#define DIRFEXT ".dir"
#define PAGFEXT ".pag"

typedef struct {
        int dirf;                      /* directory file descriptor */
        int pagf;                      /* page file descriptor */
        int flags;                     /* status/error flags, see below */
        long maxbno;                   /* size of dirfile in bits */
        long curbit;                   /* current bit number */
        long hmask;                    /* current hash mask */
        long blkptr;                   /* current block for nextkey */
        int keyptr;                    /* current key for nextkey */
        long blkno;                    /* current page to read/write */
        long pagbno;                   /* current page in pagbuf */
        char pagbuf[PBLKSIZ];          /* page file block buffer */
        long dirbno;                   /* current block in dirbuf */
        char dirbuf[DBLKSIZ];          /* directory file block buffer */
} DBM;

#define DBM_RDONLY      0x1            /* data base open read-only */
#define DBM_IOERR       0x2            /* data base I/O error */

/*
 * utility macros
 */
#define sdbm_rdonly(db)         ((db)->flags & DBM_RDONLY)
#define sdbm_error(db)          ((db)->flags & DBM_IOERR)

#define sdbm_clearerr(db)       ((db)->flags &= ~DBM_IOERR)  /* ouch */

#define sdbm_dirfno(db) ((db)->dirf)
#define sdbm_pagfno(db) ((db)->pagf)

typedef struct {
        char *dptr;
        int dsize;
} datum;

extern datum nullitem;

#ifdef __STDC__
#define proto(p) p
#else
#define proto(p) ()
#endif

/*
 * flags to sdbm_store
 */
#define DBM_INSERT      0
#define DBM_REPLACE     1

/*
 * ndbm interface
 */
extern DBM *sdbm_open proto((char *, int, int));
extern void sdbm_close proto((DBM *));
extern datum sdbm_fetch proto((DBM *, datum));
extern int sdbm_delete proto((DBM *, datum));
extern int sdbm_store proto((DBM *, datum, datum, int));
extern datum sdbm_firstkey proto((DBM *));
extern datum sdbm_nextkey proto((DBM *));

/*
 * other
 */
extern DBM *sdbm_prep proto((char *, char *, int, int));
extern long sdbm_hash proto((char *, int));

/* pair.h */
extern int fitpair proto((char *, int));
extern void  putpair proto((char *, datum, datum));
extern datum    getpair proto((char *, datum));
extern int  delpair proto((char *, datum));
extern int  chkpage proto((char *));
extern datum getnkey proto((char *, int));
extern void splpage proto((char *, char *, long));
extern int duppair proto((char *, datum));

/* tune.h */
/*
 * sdbm - ndbm work-alike hashed database library
 * tuning and portability constructs [not nearly enough]
 * author: oz@nexus.yorku.ca
 */

#define BYTESIZ         8

/*
 * important tuning parms (hah)
 */

#define SEEDUPS                 /* always detect duplicates */
#define BADMESS                 /* generate a message for worst case:
                                   cannot make room after SPLTMAX splits */
/*
 * misc
 */
#ifdef DEBUG
#define debug(x)        printf x
#else
#define debug(x)
#endif

#endif /* SSL_UTIL_SDBM_H */
