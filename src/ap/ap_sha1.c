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
 * The only exported function:
 *
 * 	 ap_sha1_base64(char *clear, int len, char *out);
 *
 * provides a means to SHA1 crypt/encode a plaintext password in
 * a way which makes password files compatible with those commonly
 * used in netscape web and ldap installations. It was put together
 * by Clinton Wong <clintdw@netcom.com>, who also notes that:
 *
 * Note: SHA1 support is useful for migration purposes, but is less
 *     secure than Apache's password format, since Apache's (MD5)
 *     password format uses a random eight character salt to generate
 *     one of many possible hashes for the same password.  Netscape
 *     uses plain SHA1 without a salt, so the same password
 *     will always generate the same hash, making it easier
 *     to break since the search space is smaller.
 *
 * See also the documentation in support/SHA1 as to hints on how to 
 * migrate an existing netscape installation and other supplied utitlites.
 *
 * This software also makes use of the following components: 
 *
 * NIST Secure Hash Algorithm
 *  	heavily modified by Uwe Hollerbach uh@alumni.caltech edu
 *	from Peter C. Gutmann's implementation as found in
 *	Applied Cryptography by Bruce Schneier
 *	This code is hereby placed in the public domain
 *
 * MIME Base 64 encoding based on src/metamail/codes.c in metamail,
 *	available at: ftp://thumper.bellcore.com/pub/nsb/
 *
 * Metamail's copyright is:
 * 	Copyright (c) 1991 Bell Communications Research, Inc. (Bellcore)
 * 	Permission to use, copy, modify, and distribute this material 
 *	for any purpose and without fee is hereby granted, provided 
 *	that the above copyright notice and this permission notice 
 *	appear in all copies, and that the name of Bellcore not be 
 *	used in advertising or publicity pertaining to this 
 *	material without the specific, prior written permission 
 *	of an authorized representative of Bellcore.  BELLCORE 
 *	MAKES NO REPRESENTATIONS ABOUT THE ACCURACY OR SUITABILITY 
 *	OF THIS MATERIAL FOR ANY PURPOSE.  IT IS PROVIDED "AS IS", 
 *	WITHOUT ANY EXPRESS OR IMPLIED WARRANTIES.
 */

#include <string.h>

#include "ap_config.h"
#include "ap_sha1.h"
#include "ap.h"
#ifdef CHARSET_EBCDIC
#include "ebcdic.h"
#endif /*CHARSET_EBCDIC*/

/* a bit faster & bigger, if defined */
#define UNROLL_LOOPS

/* NIST's proposed modification to SHA, 7/11/94 */
#define USE_MODIFIED_SHA

/* SHA f()-functions */
#define f1(x,y,z)	((x & y) | (~x & z))
#define f2(x,y,z)	(x ^ y ^ z)
#define f3(x,y,z)	((x & y) | (x & z) | (y & z))
#define f4(x,y,z)	(x ^ y ^ z)

/* SHA constants */
#define CONST1		0x5a827999L
#define CONST2		0x6ed9eba1L
#define CONST3		0x8f1bbcdcL
#define CONST4		0xca62c1d6L

/* 32-bit rotate */

#define ROT32(x,n)	((x << n) | (x >> (32 - n)))

#define FUNC(n,i)						\
    temp = ROT32(A,5) + f##n(B,C,D) + E + W[i] + CONST##n;	\
    E = D; D = C; C = ROT32(B,30); B = A; A = temp

typedef unsigned char BYTE;     /* an 8-bit quantity */
typedef unsigned long LONG;     /* a 32-bit quantity */
 
#define SHA_BLOCKSIZE           64
#define SHA_DIGESTSIZE          20
 
typedef struct {
   LONG digest[5];             /* message digest */
   LONG count_lo, count_hi;    /* 64-bit bit count */
   LONG data[16];              /* SHA data buffer */
   int local;                  /* unprocessed amount in data */
   } SHA_INFO;

void sha_init(SHA_INFO *);
void sha_update(SHA_INFO *, BYTE *, int);
void sha_final(SHA_INFO *);
void sha_raw_swap(SHA_INFO *);
void output64chunk(unsigned char, unsigned char, unsigned char,
                   int, unsigned char **);
void encode_mime64(unsigned char *, unsigned char *, int);
void sha1_base64(char *, int, char *);

/* do SHA transformation */
static void sha_transform(SHA_INFO *sha_info)
{
    int i;
    LONG temp, A, B, C, D, E, W[80];

    for (i = 0; i < 16; ++i) {
	W[i] = sha_info->data[i];
    }
    for (i = 16; i < 80; ++i) {
	W[i] = W[i-3] ^ W[i-8] ^ W[i-14] ^ W[i-16];
#ifdef USE_MODIFIED_SHA
	W[i] = ROT32(W[i], 1);
#endif /* USE_MODIFIED_SHA */
    }
    A = sha_info->digest[0];
    B = sha_info->digest[1];
    C = sha_info->digest[2];
    D = sha_info->digest[3];
    E = sha_info->digest[4];
#ifdef UNROLL_LOOPS
    FUNC(1, 0);  FUNC(1, 1);  FUNC(1, 2);  FUNC(1, 3);  FUNC(1, 4);
    FUNC(1, 5);  FUNC(1, 6);  FUNC(1, 7);  FUNC(1, 8);  FUNC(1, 9);
    FUNC(1,10);  FUNC(1,11);  FUNC(1,12);  FUNC(1,13);  FUNC(1,14);
    FUNC(1,15);  FUNC(1,16);  FUNC(1,17);  FUNC(1,18);  FUNC(1,19);

    FUNC(2,20);  FUNC(2,21);  FUNC(2,22);  FUNC(2,23);  FUNC(2,24);
    FUNC(2,25);  FUNC(2,26);  FUNC(2,27);  FUNC(2,28);  FUNC(2,29);
    FUNC(2,30);  FUNC(2,31);  FUNC(2,32);  FUNC(2,33);  FUNC(2,34);
    FUNC(2,35);  FUNC(2,36);  FUNC(2,37);  FUNC(2,38);  FUNC(2,39);

    FUNC(3,40);  FUNC(3,41);  FUNC(3,42);  FUNC(3,43);  FUNC(3,44);
    FUNC(3,45);  FUNC(3,46);  FUNC(3,47);  FUNC(3,48);  FUNC(3,49);
    FUNC(3,50);  FUNC(3,51);  FUNC(3,52);  FUNC(3,53);  FUNC(3,54);
    FUNC(3,55);  FUNC(3,56);  FUNC(3,57);  FUNC(3,58);  FUNC(3,59);

    FUNC(4,60);  FUNC(4,61);  FUNC(4,62);  FUNC(4,63);  FUNC(4,64);
    FUNC(4,65);  FUNC(4,66);  FUNC(4,67);  FUNC(4,68);  FUNC(4,69);
    FUNC(4,70);  FUNC(4,71);  FUNC(4,72);  FUNC(4,73);  FUNC(4,74);
    FUNC(4,75);  FUNC(4,76);  FUNC(4,77);  FUNC(4,78);  FUNC(4,79);
#else /* !UNROLL_LOOPS */
    for (i = 0; i < 20; ++i) {
	FUNC(1,i);
    }
    for (i = 20; i < 40; ++i) {
	FUNC(2,i);
    }
    for (i = 40; i < 60; ++i) {
	FUNC(3,i);
    }
    for (i = 60; i < 80; ++i) {
	FUNC(4,i);
    }
#endif /* !UNROLL_LOOPS */
    sha_info->digest[0] += A;
    sha_info->digest[1] += B;
    sha_info->digest[2] += C;
    sha_info->digest[3] += D;
    sha_info->digest[4] += E;
}

union endianTest {
  long Long;
  char Char[sizeof(long)];
};

char isLittleEndian() {
  static union endianTest u;
  u.Long = 1;
  return(u.Char[0]==1);
}

/* change endianness of data */

/* count is the number of bytes to do an endian flip */
static void maybe_byte_reverse(LONG *buffer, int count)
{
    int i;
    BYTE ct[4], *cp;

    if (isLittleEndian()) {    /* do the swap only if it is little endian */
      count /= sizeof(LONG);
      cp = (BYTE *) buffer;
      for (i = 0; i < count; ++i) {
	  ct[0] = cp[0];
	  ct[1] = cp[1];
	  ct[2] = cp[2];
	  ct[3] = cp[3];
	  cp[0] = ct[3];
	  cp[1] = ct[2];
	  cp[2] = ct[1];
	  cp[3] = ct[0];
	  cp += sizeof(LONG);
      }
    }
}

/* initialize the SHA digest */

void sha_init(SHA_INFO *sha_info)
{
    sha_info->digest[0] = 0x67452301L;
    sha_info->digest[1] = 0xefcdab89L;
    sha_info->digest[2] = 0x98badcfeL;
    sha_info->digest[3] = 0x10325476L;
    sha_info->digest[4] = 0xc3d2e1f0L;
    sha_info->count_lo = 0L;
    sha_info->count_hi = 0L;
    sha_info->local = 0;
}

/* update the SHA digest */

void sha_update(SHA_INFO *sha_info, BYTE *buffer, int count)
{
    int i;

    if ((sha_info->count_lo + ((LONG) count << 3)) < sha_info->count_lo) {
	++sha_info->count_hi;
    }
    sha_info->count_lo += (LONG) count << 3;
    sha_info->count_hi += (LONG) count >> 29;
    if (sha_info->local) {
	i = SHA_BLOCKSIZE - sha_info->local;
	if (i > count) {
	    i = count;
	}
	memcpy(((BYTE *) sha_info->data) + sha_info->local, buffer, i);
	count -= i;
	buffer += i;
	sha_info->local += i;
	if (sha_info->local == SHA_BLOCKSIZE) {
	    maybe_byte_reverse(sha_info->data, SHA_BLOCKSIZE);
	    sha_transform(sha_info);
	} else {
	    return;
	}
    }
    while (count >= SHA_BLOCKSIZE) {
	memcpy(sha_info->data, buffer, SHA_BLOCKSIZE);
	buffer += SHA_BLOCKSIZE;
	count -= SHA_BLOCKSIZE;
	maybe_byte_reverse(sha_info->data, SHA_BLOCKSIZE);
	sha_transform(sha_info);
    }
    memcpy(sha_info->data, buffer, count);
    sha_info->local = count;
}

/* finish computing the SHA digest */

void sha_final(SHA_INFO *sha_info)
{
    int count;
    LONG lo_bit_count, hi_bit_count;

    lo_bit_count = sha_info->count_lo;
    hi_bit_count = sha_info->count_hi;
    count = (int) ((lo_bit_count >> 3) & 0x3f);
    ((BYTE *) sha_info->data)[count++] = 0x80;
    if (count > SHA_BLOCKSIZE - 8) {
	memset(((BYTE *) sha_info->data) + count, 0, SHA_BLOCKSIZE - count);
	maybe_byte_reverse(sha_info->data, SHA_BLOCKSIZE);
	sha_transform(sha_info);
	memset((BYTE *) sha_info->data, 0, SHA_BLOCKSIZE - 8);
    } else {
	memset(((BYTE *) sha_info->data) + count, 0,
	    SHA_BLOCKSIZE - 8 - count);
    }
    maybe_byte_reverse(sha_info->data, SHA_BLOCKSIZE);
    sha_info->data[14] = hi_bit_count;
    sha_info->data[15] = lo_bit_count;
    sha_transform(sha_info);

}

/*
   internally implemented as an array of longs, need to swap if 
   you're going to access the memory in the raw, instead of looping
   through with arrays of longs.
*/

void sha_raw_swap(SHA_INFO *sha_info) {
  int i;

  for (i=0; i<5; ++i)
     maybe_byte_reverse((LONG *) &sha_info->digest[i], 4);
}

static char basis_64[] =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

void output64chunk(unsigned char c1, unsigned char c2, unsigned char c3,
                   int pads, unsigned char **outfile) {

  *(*outfile)++ = basis_64[c1>>2];

  *(*outfile)++ = basis_64[((c1 & 0x3)<< 4) | ((c2 & 0xF0) >> 4)];
  if (pads == 2) {
    *(*outfile)++ = '=';
    *(*outfile)++ = '=';
  } else if (pads) {
    *(*outfile)++ =  basis_64[((c2 & 0xF) << 2) | ((c3 & 0xC0) >>6)];
    *(*outfile)++ = '=';
  } else {
    *(*outfile)++ = basis_64[((c2 & 0xF) << 2) | ((c3 & 0xC0) >>6)];
    *(*outfile)++ = basis_64[c3 & 0x3F];
  }
}

void encode_mime64(unsigned char *in, unsigned char *out, int length) {
  int diff, ct=0;

  while ( (diff= length - ct) ) {
    if ( diff >= 3 ) {
      diff = 3;
      output64chunk(in[ct], in[ct+1], in[ct+2], 0, &out);
    }
    else if ( diff == 2 ) {
      output64chunk(in[ct], in[ct+1], 0, 1, &out);
    }
    else if ( diff == 1 ) {
      output64chunk(in[ct], 0, 0, 2, &out);
    }
    ct += diff;
  }

  *out++ = 0;
}

/* {SHA} is the prefix used for base64 encoded sha1 in
 * ldap data interchange format.
 */
const char *sha1_id = "{SHA}";

API_EXPORT(void) ap_sha1_base64(char *clear, int len, char *out)  {
  SHA_INFO context;

  if (!strncmp(clear,sha1_id,strlen(sha1_id)))
	clear+=strlen(sha1_id);

  sha_init(&context);
  sha_update(&context, clear, len);
  sha_final(&context);
  
  sha_raw_swap(&context);

  /* private marker. */
  strcpy(out,sha1_id);

  /* SHA1 hash is always 20 chars */
  encode_mime64((char *)context.digest, out+strlen(sha1_id), 20);
  /* output of MIME Base 64 encoded SHA1 is always 28 characters + strlen(sha1_id) */
}
