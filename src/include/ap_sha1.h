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
 * NIST Secure Hash Algorithm
 * 	heavily modified by Uwe Hollerbach uh@alumni.caltech edu
 * 	from Peter C. Gutmann's implementation as found in
 * 	Applied Cryptography by Bruce Schneier
 * 	This code is hereby placed in the public domain
 */

#ifndef APACHE_SHA1_H
#define APACHE_SHA1_H

#ifdef __cplusplus
extern "C" {
#endif

#define SHA_DIGESTSIZE 20

/*
 * Define the Magic String prefix that identifies a password as being
 * hashed using our algorithm.
 */
#define AP_SHA1PW_ID "{SHA}"
#define AP_SHA1PW_IDLEN 5

typedef unsigned long AP_LONG;     /* a 32-bit quantity */

typedef struct {
    AP_LONG digest[5];             /* message digest */
    AP_LONG count_lo, count_hi;    /* 64-bit bit count */
    AP_LONG data[16];              /* SHA data buffer */
    int local;                     /* unprocessed amount in data */
} AP_SHA1_CTX;

API_EXPORT(void) ap_sha1_base64(const char *clear, int len, char *out);
API_EXPORT(void) ap_SHA1Init(AP_SHA1_CTX *context);
API_EXPORT(void) ap_SHA1Update(AP_SHA1_CTX *context, const char *input,
			       unsigned int inputLen);
API_EXPORT(void) ap_SHA1Update_binary(AP_SHA1_CTX *context,
				      const unsigned char *input,
				      unsigned int inputLen);
API_EXPORT(void) ap_SHA1Final(unsigned char digest[SHA_DIGESTSIZE],
                              AP_SHA1_CTX *context);

#ifdef __cplusplus
}
#endif

#endif	/* !APACHE_SHA1_H */
