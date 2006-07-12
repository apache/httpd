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

#include "ap_config.h"
#include "apr_portable.h"
#include "apr_strings.h"
#include "httpd.h"
#include "util_md5.h"
#include "util_ebcdic.h"

AP_DECLARE(char *) ap_md5_binary(apr_pool_t *p, const unsigned char *buf, int length)
{
    const char *hex = "0123456789abcdef";
    apr_md5_ctx_t my_md5;
    unsigned char hash[APR_MD5_DIGESTSIZE];
    char *r, result[33]; /* (MD5_DIGESTSIZE * 2) + 1 */
    int i;

    /*
     * Take the MD5 hash of the string argument.
     */

    apr_md5_init(&my_md5);
#if APR_CHARSET_EBCDIC
    apr_md5_set_xlate(&my_md5, ap_hdrs_to_ascii);
#endif
    apr_md5_update(&my_md5, buf, (unsigned int)length);
    apr_md5_final(hash, &my_md5);

    for (i = 0, r = result; i < APR_MD5_DIGESTSIZE; i++) {
        *r++ = hex[hash[i] >> 4];
        *r++ = hex[hash[i] & 0xF];
    }
    *r = '\0';

    return apr_pstrndup(p, result, APR_MD5_DIGESTSIZE*2);
}

AP_DECLARE(char *) ap_md5(apr_pool_t *p, const unsigned char *string)
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

AP_DECLARE(char *) ap_md5contextTo64(apr_pool_t *a, apr_md5_ctx_t *context)
{
    unsigned char digest[18];
    char *encodedDigest;
    int i;
    char *p;

    encodedDigest = (char *) apr_pcalloc(a, 25 * sizeof(char));

    apr_md5_final(digest, context);
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

AP_DECLARE(char *) ap_md5digest(apr_pool_t *p, apr_file_t *infile)
{
    apr_md5_ctx_t context;
    unsigned char buf[4096]; /* keep this a multiple of 64 */
    apr_size_t nbytes;
    apr_off_t offset = 0L;

    apr_md5_init(&context);
    nbytes = sizeof(buf);
    while (apr_file_read(infile, buf, &nbytes) == APR_SUCCESS) {
        apr_md5_update(&context, buf, nbytes);
        nbytes = sizeof(buf);
    }
    apr_file_seek(infile, APR_SET, &offset);
    return ap_md5contextTo64(p, &context);
}

