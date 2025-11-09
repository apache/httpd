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
    apr_md5_ctx_t my_md5;
    unsigned char hash[APR_MD5_DIGESTSIZE];
    char *result;

    /*
     * Take the MD5 hash of the string argument.
     */

    apr_md5_init(&my_md5);
#if APR_CHARSET_EBCDIC
    apr_md5_set_xlate(&my_md5, ap_hdrs_to_ascii);
#endif
    apr_md5_update(&my_md5, buf, (unsigned int)length);
    apr_md5_final(hash, &my_md5);

    result = apr_palloc(p, 2 * APR_MD5_DIGESTSIZE + 1);
    ap_bin2hex(hash, APR_MD5_DIGESTSIZE, result); /* sets final '\0' */
    return result;
}

AP_DECLARE(char *) ap_md5(apr_pool_t *p, const unsigned char *string)
{
    return ap_md5_binary(p, string, (int) strlen((char *)string));
}
