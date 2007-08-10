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

/* base64 encoder/decoder. Originally part of main/util.c
 * but moved here so that support/ab and ap_sha1.c could
 * use it. This meant removing the ap_palloc()s and adding
 * ugly 'len' functions, which is quite a nasty cost.
 */

#include <string.h>

#include "ap_config.h"
#include "ap.h"

#ifdef CHARSET_EBCDIC
#include "ap_ebcdic.h"
#endif				/* CHARSET_EBCDIC */

/* aaaack but it's fast and const should make it shared text page. */
static const unsigned char pr2six[256] =
{
#ifndef CHARSET_EBCDIC
    /* ASCII table */
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 62, 64, 64, 64, 63,
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 64, 64, 64, 64, 64, 64,
    64,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 64, 64, 64, 64, 64,
    64, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64
#else /*CHARSET_EBCDIC*/
    /* EBCDIC table */
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 62, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 63, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 26, 27, 28, 29, 30, 31, 32, 33, 34, 64, 64, 64, 64, 64, 64,
    64, 35, 36, 37, 38, 39, 40, 41, 42, 43, 64, 64, 64, 64, 64, 64,
    64, 64, 44, 45, 46, 47, 48, 49, 50, 51, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64,  0,  1,  2,  3,  4,  5,  6,  7,  8, 64, 64, 64, 64, 64, 64,
    64,  9, 10, 11, 12, 13, 14, 15, 16, 17, 64, 64, 64, 64, 64, 64,
    64, 64, 18, 19, 20, 21, 22, 23, 24, 25, 64, 64, 64, 64, 64, 64,
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 64, 64, 64, 64, 64, 64
#endif /*CHARSET_EBCDIC*/
};

API_EXPORT(int) ap_base64decode_len(const char *bufcoded)
{
    int nbytesdecoded;
    register const unsigned char *bufin;
    register int nprbytes;

    bufin = (const unsigned char *) bufcoded;
    while (pr2six[*(bufin++)] <= 63);

    nprbytes = (bufin - (const unsigned char *) bufcoded) - 1;
    nbytesdecoded = ((nprbytes + 3) / 4) * 3;

    return nbytesdecoded + 1;
}

API_EXPORT(int) ap_base64decode(char *bufplain, const char *bufcoded)
{
#ifdef CHARSET_EBCDIC
    int i;
#endif				/* CHARSET_EBCDIC */
    int len;
    
    len = ap_base64decode_binary((unsigned char *) bufplain, bufcoded);
#ifdef CHARSET_EBCDIC
    for (i = 0; i < len; i++)
	bufplain[i] = os_toebcdic[bufplain[i]];
#endif				/* CHARSET_EBCDIC */
    bufplain[len] = '\0';
    return len;
}

/* This is the same as ap_base64udecode() except on EBCDIC machines, where
 * the conversion of the output to ebcdic is left out.
 */
API_EXPORT(int) ap_base64decode_binary(unsigned char *bufplain,
				   const char *bufcoded)
{
    int nbytesdecoded;
    register const unsigned char *bufin;
    register unsigned char *bufout;
    register int nprbytes;

    bufin = (const unsigned char *) bufcoded;
    while (pr2six[*(bufin++)] <= 63);
    nprbytes = (bufin - (const unsigned char *) bufcoded) - 1;
    nbytesdecoded = ((nprbytes + 3) / 4) * 3;

    bufout = (unsigned char *) bufplain;
    bufin = (const unsigned char *) bufcoded;

    while (nprbytes > 4) {
	*(bufout++) =
	    (unsigned char) (pr2six[*bufin] << 2 | pr2six[bufin[1]] >> 4);
	*(bufout++) =
	    (unsigned char) (pr2six[bufin[1]] << 4 | pr2six[bufin[2]] >> 2);
	*(bufout++) =
	    (unsigned char) (pr2six[bufin[2]] << 6 | pr2six[bufin[3]]);
	bufin += 4;
	nprbytes -= 4;
    }

    /* Note: (nprbytes == 1) would be an error, so just ingore that case */
    if (nprbytes > 1) {
	*(bufout++) =
	    (unsigned char) (pr2six[*bufin] << 2 | pr2six[bufin[1]] >> 4);
    }
    if (nprbytes > 2) {
	*(bufout++) =
	    (unsigned char) (pr2six[bufin[1]] << 4 | pr2six[bufin[2]] >> 2);
    }
    if (nprbytes > 3) {
	*(bufout++) =
	    (unsigned char) (pr2six[bufin[2]] << 6 | pr2six[bufin[3]]);
    }

    nbytesdecoded -= (4 - nprbytes) & 3;
    return nbytesdecoded;
}

static const char basis_64[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

API_EXPORT(int) ap_base64encode_len(int len)
{
    return ((len + 2) / 3 * 4) + 1;
}

API_EXPORT(int) ap_base64encode(char *encoded, const char *string, int len)
{
#ifndef CHARSET_EBCDIC
    return ap_base64encode_binary(encoded, (const unsigned char *) string, len);
#else				/* CHARSET_EBCDIC */
    int i;
    char *p;

    p = encoded;
    for (i = 0; i < len - 2; i += 3) {
	*p++ = basis_64[(os_toascii[string[i]] >> 2) & 0x3F];
	*p++ = basis_64[((os_toascii[string[i]] & 0x3) << 4) |
	                ((int) (os_toascii[string[i + 1]] & 0xF0) >> 4)];
	*p++ = basis_64[((os_toascii[string[i + 1]] & 0xF) << 2) |
	                ((int) (os_toascii[string[i + 2]] & 0xC0) >> 6)];
	*p++ = basis_64[os_toascii[string[i + 2]] & 0x3F];
    }
    if (i < len) {
	*p++ = basis_64[(os_toascii[string[i]] >> 2) & 0x3F];
	if (i == (len - 1)) {
	    *p++ = basis_64[((os_toascii[string[i]] & 0x3) << 4)];
	    *p++ = '=';
	}
	else {
	    *p++ = basis_64[((os_toascii[string[i]] & 0x3) << 4) |
	                    ((int) (os_toascii[string[i + 1]] & 0xF0) >> 4)];
	    *p++ = basis_64[((os_toascii[string[i + 1]] & 0xF) << 2)];
	}
	*p++ = '=';
    }

    *p++ = '\0';
    return p - encoded;
#endif				/* CHARSET_EBCDIC */
}

/* This is the same as ap_base64encode() except on EBCDIC machines, where
 * the conversion of the input to ascii is left out.
 */
API_EXPORT(int) ap_base64encode_binary(char *encoded,
                                       const unsigned char *string, int len)
{
    int i;
    char *p;

    p = encoded;
    for (i = 0; i < len - 2; i += 3) {
	*p++ = basis_64[(string[i] >> 2) & 0x3F];
	*p++ = basis_64[((string[i] & 0x3) << 4) |
	                ((int) (string[i + 1] & 0xF0) >> 4)];
	*p++ = basis_64[((string[i + 1] & 0xF) << 2) |
	                ((int) (string[i + 2] & 0xC0) >> 6)];
	*p++ = basis_64[string[i + 2] & 0x3F];
    }
    if (i < len) {
	*p++ = basis_64[(string[i] >> 2) & 0x3F];
	if (i == (len - 1)) {
	    *p++ = basis_64[((string[i] & 0x3) << 4)];
	    *p++ = '=';
	}
	else {
	    *p++ = basis_64[((string[i] & 0x3) << 4) |
	                    ((int) (string[i + 1] & 0xF0) >> 4)];
	    *p++ = basis_64[((string[i + 1] & 0xF) << 2)];
	}
	*p++ = '=';
    }

    *p++ = '\0';
    return p - encoded;
}
