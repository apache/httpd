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

#ifndef APACHE_UTIL_EBCDIC_H
#define APACHE_UTIL_EBCDIC_H


#ifdef __cplusplus
extern "C" {
#endif

#include "apr_xlate.h"
#include "httpd.h"
#include "util_charset.h"

/**
 * @package Utilities for EBCDIC conversion
 */

#if APR_CHARSET_EBCDIC

/**
 * Setup all of the global translation handlers
 * @param pool pool to allocate out of
 */
apr_status_t ap_init_ebcdic(apr_pool_t *pool);

/**
 * Convert protocol data from the implementation character
 * set to ASCII.
 * @param buffer buffer to translate
 * @param len number of bytes to translate
 */
void ap_xlate_proto_to_ascii(char *buffer, apr_size_t len);

/**
 * Convert protocol data to the implementation character
 * set from ASCII.
 * @param buffer buffer to translate
 * @param len number of bytes to translate
 */
void ap_xlate_proto_from_ascii(char *buffer, apr_size_t len);

/**
 * Convert protocol data from the implementation charater
 * set to ASCII, then send it.
 * @param r   the current request
 * @param ... the strings to write, followed by a NULL pointer
 */
int ap_rvputs_proto_in_ascii(request_rec *r, ...);

#else   /* APR_CHARSET_EBCDIC */

#define ap_xlate_proto_to_ascii(x,y)          /* NOOP */
#define ap_xlate_proto_from_ascii(x,y)        /* NOOP */

#define ap_rvputs_proto_in_ascii  ap_rvputs

#endif  /* APR_CHARSET_EBCDIC */

#ifdef __cplusplus
}
#endif

#endif  /* !APACHE_UTIL_EBCDIC_H */
