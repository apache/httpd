/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000-2003 The Apache Software Foundation.  All rights
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
 */

#ifndef MOD_CORE_H
#define MOD_CORE_H

#include "apr.h"
#include "apr_buckets.h"

#include "httpd.h"
#include "util_filter.h"


#ifdef __cplusplus
extern "C" {
#endif

/**
 * @package mod_core private header file
 */

/* Handles for core filters */
extern AP_DECLARE_DATA ap_filter_rec_t *ap_http_input_filter_handle;
extern AP_DECLARE_DATA ap_filter_rec_t *ap_http_header_filter_handle;
extern AP_DECLARE_DATA ap_filter_rec_t *ap_chunk_filter_handle;
extern AP_DECLARE_DATA ap_filter_rec_t *ap_byterange_filter_handle;

/*
 * These (input) filters are internal to the mod_core operation.
 */
apr_status_t ap_http_filter(ap_filter_t *f, apr_bucket_brigade *b,
                            ap_input_mode_t mode, apr_read_type_e block,
                            apr_off_t readbytes);

char *ap_response_code_string(request_rec *r, int error_index);

/**
 * Send the minimal part of an HTTP response header.
 * @param r The current request
 * @param bb The brigade to add the header to.
 * @warning Modules should be very careful about using this, and should
 *          the default behavior.  Much of the HTTP/1.1 implementation
 *          correctness depends on the full headers.
 * @deffunc void ap_basic_http_header(request_rec *r, apr_bucket_brigade *bb)
 */
AP_DECLARE(void) ap_basic_http_header(request_rec *r, apr_bucket_brigade *bb);
 
/**
 * Send an appropriate response to an http TRACE request.
 * @param r The current request
 * @tip returns DONE or the HTTP status error if it handles the TRACE,
 * or DECLINED if the request was not for TRACE.
 * request method was not TRACE.
 */
AP_DECLARE_NONSTD(int) ap_send_http_trace(request_rec *r);

/**
 * Send an appropriate response to an http OPTIONS request.
 * @param r The current request
 */
AP_DECLARE(int) ap_send_http_options(request_rec *r);

#ifdef __cplusplus
}
#endif

#endif	/* !MOD_CORE_H */
