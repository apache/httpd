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

/*
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
