/*
 * This is work is derived from material Copyright RSA Data Security, Inc.
 *
 * The RSA copyright statement and Licence for that original material is
 * included below. This is followed by the Apache copyright statement and
 * licence for the modifications made to that material.
 */

/* Copyright (C) 1991-2, RSA Data Security, Inc. Created 1991. All
   rights reserved.

   License to copy and use this software is granted provided that it
   is identified as the "RSA Data Security, Inc. MD5 Message-Digest
   Algorithm" in all material mentioning or referencing this software
   or this function.

   License is also granted to make and use derivative works provided
   that such works are identified as "derived from the RSA Data
   Security, Inc. MD5 Message-Digest Algorithm" in all material
   mentioning or referencing the derived work.

   RSA Data Security, Inc. makes no representations concerning either
   the merchantability of this software or the suitability of this
   software for any particular purpose. It is provided "as is"
   without express or implied warranty of any kind.

   These notices must be retained in any copies of any part of this
   documentation and/or software.
 */

/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef APACHE_MD5_H
#define APACHE_MD5_H

#ifdef __cplusplus
extern "C" {
#endif

/* MD5.H - header file for MD5C.C */

#define MD5_DIGESTSIZE 16

/* UINT4 defines a four byte word */
typedef unsigned int UINT4;

/* MD5 context. */
typedef struct {
    UINT4 state[4];		/* state (ABCD) */
    UINT4 count[2];		/* number of bits, modulo 2^64 (lsb first) */
    unsigned char buffer[64];	/* input buffer */
} AP_MD5_CTX;

/*
 * Define the Magic String prefix that identifies a password as being
 * hashed using our algorithm.
 */
#define AP_MD5PW_ID "$apr1$"
#define AP_MD5PW_IDLEN 6

API_EXPORT(void) ap_MD5Init(AP_MD5_CTX *context);
API_EXPORT(void) ap_MD5Update(AP_MD5_CTX *context, const unsigned char *input,
			      unsigned int inputLen);
API_EXPORT(void) ap_MD5Final(unsigned char digest[MD5_DIGESTSIZE],
			     AP_MD5_CTX *context);
API_EXPORT(void) ap_MD5Encode(const unsigned char *password,
			      const unsigned char *salt,
			      char *result, size_t nbytes);
API_EXPORT(void) ap_to64(char *s, unsigned long v, int n);

#ifdef __cplusplus
}
#endif

#endif	/* !APACHE_MD5_H */
