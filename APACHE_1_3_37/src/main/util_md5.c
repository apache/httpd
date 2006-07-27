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

/************************************************************************
 * NCSA HTTPd Server
 * Software Development Group
 * National Center for Supercomputing Applications
 * University of Illinois at Urbana-Champaign
 * 605 E. Springfield, Champaign, IL 61820
 * httpd@ncsa.uiuc.edu
 *
 * Copyright  (C)  1995, Board of Trustees of the University of Illinois
 *
 ************************************************************************
 *
 * md5.c: NCSA HTTPd code which uses the md5c.c RSA Code
 *
 *  Original Code Copyright (C) 1994, Jeff Hostetler, Spyglass, Inc.
 *  Portions of Content-MD5 code Copyright (C) 1993, 1994 by Carnegie Mellon
 *     University (see Copyright below).
 *  Portions of Content-MD5 code Copyright (C) 1991 Bell Communications 
 *     Research, Inc. (Bellcore) (see Copyright below).
 *  Portions extracted from mpack, John G. Myers - jgm+@cmu.edu
 *  Content-MD5 Code contributed by Martin Hamilton (martin@net.lut.ac.uk)
 *
 */



/* md5.c --Module Interface to MD5. */
/* Jeff Hostetler, Spyglass, Inc., 1994. */

#include "httpd.h"
#include "util_md5.h"

API_EXPORT(char *) ap_md5_binary(pool *p, const unsigned char *buf, int length)
{
    const char *hex = "0123456789abcdef";
    AP_MD5_CTX my_md5;
    unsigned char hash[16];
    char *r, result[33];
    int i;

    /*
     * Take the MD5 hash of the string argument.
     */

    ap_MD5Init(&my_md5);
    ap_MD5Update(&my_md5, buf, (unsigned int)length);
    ap_MD5Final(hash, &my_md5);

    for (i = 0, r = result; i < 16; i++) {
	*r++ = hex[hash[i] >> 4];
	*r++ = hex[hash[i] & 0xF];
    }
    *r = '\0';

    return ap_pstrdup(p, result);
}

API_EXPORT(char *) ap_md5(pool *p, const unsigned char *string)
{
    return ap_md5_binary(p, string, (int) strlen((char *)string));
}

/* these portions extracted from mpack, John G. Myers - jgm+@cmu.edu */

/* (C) Copyright 1993,1994 by Carnegie Mellon University
 * All Rights Reserved.
 *
 * Permission to use, copy, modify, distribute, and sell this software
 * and its documentation for any purpose is hereby granted without
 * fee, provided that the above copyright notice appear in all copies
 * and that both that copyright notice and this permission notice
 * appear in supporting documentation, and that the name of Carnegie
 * Mellon University not be used in advertising or publicity
 * pertaining to distribution of the software without specific,
 * written prior permission.  Carnegie Mellon University makes no
 * representations about the suitability of this software for any
 * purpose.  It is provided "as is" without express or implied
 * warranty.
 *
 * CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
 * FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 */

/*
 * Copyright (c) 1991 Bell Communications Research, Inc. (Bellcore)
 *
 * Permission to use, copy, modify, and distribute this material
 * for any purpose and without fee is hereby granted, provided
 * that the above copyright notice and this permission notice
 * appear in all copies, and that the name of Bellcore not be
 * used in advertising or publicity pertaining to this
 * material without the specific, prior written permission
 * of an authorized representative of Bellcore.  BELLCORE
 * MAKES NO REPRESENTATIONS ABOUT THE ACCURACY OR SUITABILITY
 * OF THIS MATERIAL FOR ANY PURPOSE.  IT IS PROVIDED "AS IS",
 * WITHOUT ANY EXPRESS OR IMPLIED WARRANTIES.  
 */

static char basis_64[] =
"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

API_EXPORT(char *) ap_md5contextTo64(pool *a, AP_MD5_CTX * context)
{
    unsigned char digest[18];
    char *encodedDigest;
    int i;
    char *p;

    encodedDigest = (char *) ap_pcalloc(a, 25 * sizeof(char));

    ap_MD5Final(digest, context);
    digest[sizeof(digest) - 1] = digest[sizeof(digest) - 2] = 0;

    p = encodedDigest;
    for (i = 0; i < sizeof(digest); i += 3) {
	*p++ = basis_64[digest[i] >> 2];
	*p++ = basis_64[((digest[i] & 0x3) << 4) | ((int) (digest[i + 1] & 0xF0) >> 4)];
	*p++ = basis_64[((digest[i + 1] & 0xF) << 2) | ((int) (digest[i + 2] & 0xC0) >> 6)];
	*p++ = basis_64[digest[i + 2] & 0x3F];
    }
    *p-- = '\0';
    *p-- = '=';
    *p-- = '=';
    return encodedDigest;
}

#ifdef CHARSET_EBCDIC

API_EXPORT(char *) ap_md5digest(pool *p, FILE *infile, int convert)
{
    AP_MD5_CTX context;
    unsigned char buf[1000];
    int nbytes;

    ap_MD5Init(&context);
    while ((nbytes = fread(buf, 1, sizeof(buf), infile))) {
        if (!convert) {
            ascii2ebcdic(buf, buf, nbytes);
        }
      ap_MD5Update(&context, buf, nbytes);
    }
    rewind(infile);
    return ap_md5contextTo64(p, &context);
}

#else

API_EXPORT(char *) ap_md5digest(pool *p, FILE *infile)
{
    AP_MD5_CTX context;
    unsigned char buf[1000];
    unsigned int nbytes;

    ap_MD5Init(&context);
    while ((nbytes = fread(buf, 1, sizeof(buf), infile))) {
	ap_MD5Update(&context, buf, nbytes);
    }
    rewind(infile);
    return ap_md5contextTo64(p, &context);
}

#endif /* CHARSET_EBCDIC */
