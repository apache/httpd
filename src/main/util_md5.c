/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000-2004 The Apache Software Foundation.  All rights
 * reserved.
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
 * 3. The end-user documentation included with the redistribution,
 *    if any, must include the following acknowledgment:
 *       "This product includes software developed by the
 *        Apache Software Foundation (http://www.apache.org/)."
 *    Alternately, this acknowledgment may appear in the software itself,
 *    if and wherever such third-party acknowledgments normally appear.
 *
 * 4. The names "Apache" and "Apache Software Foundation" must
 *    not be used to endorse or promote products derived from this
 *    software without prior written permission. For written
 *    permission, please contact apache@apache.org.
 *
 * 5. Products derived from this software may not be called "Apache",
 *    nor may "Apache" appear in their name, without prior written
 *    permission of the Apache Software Foundation.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE APACHE SOFTWARE FOUNDATION OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Software Foundation.  For more
 * information on the Apache Software Foundation, please see
 * <http://www.apache.org/>.
 *
 * Portions of this software are based upon public domain software
 * originally written at the National Center for Supercomputing Applications,
 * University of Illinois, Urbana-Champaign.
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
