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
 *
 * Portions of this software are based upon public domain software
 * originally written at the National Center for Supercomputing Applications,
 * University of Illinois, Urbana-Champaign.
 */

#ifndef APACHE_UTIL_SCRIPT_H
#define APACHE_UTIL_SCRIPT_H

#include "apr_buckets.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @package Apache script tools
 */

#ifndef APACHE_ARG_MAX
#ifdef _POSIX_ARG_MAX
#define APACHE_ARG_MAX _POSIX_ARG_MAX
#else
#define APACHE_ARG_MAX 512
#endif
#endif

/**
 * Create an environment variable out of an Apache table of key-value pairs
 * @param p pool to allocate out of
 * @param t Apache table of key-value pairs
 * @return An array containing the same key-value pairs suitable for
 *         use with an exec call.
 * @deffunc char **ap_create_environment(apr_pool_t *p, apr_table_t *t)
 */
AP_DECLARE(char **) ap_create_environment(apr_pool_t *p, apr_table_t *t);

/**
 * This "cute" little function comes about because the path info on
 * filenames and URLs aren't always the same. So we take the two,
 * and find as much of the two that match as possible.
 * @param uri The uri we are currently parsing
 * @param path_info The current path info
 * @return The length of the path info
 * @deffunc int ap_fine_path_info(const char *uri, const char *path_info)
 */
AP_DECLARE(int) ap_find_path_info(const char *uri, const char *path_info);

/**
 * Add CGI environment variables required by HTTP/1.1 to the request's 
 * environment table
 * @param r the current request
 * @deffunc void ap_add_cgi_vars(request_rec *r)
 */
AP_DECLARE(void) ap_add_cgi_vars(request_rec *r);

/**
 * Add common CGI environment variables to the requests environment table
 * @param r The current request
 * @deffunc void ap_add_common_vars(request_rec *r)
 */
AP_DECLARE(void) ap_add_common_vars(request_rec *r);

/**
 * Read headers output from a script, ensuring that the output is valid.  If
 * the output is valid, then the headers are added to the headers out of the
 * current request
 * @param r The current request
 * @param f The file to read from
 * @param buffer Empty when calling the function.  On output, if there was an
 *               error, the string that cause the error is stored here. 
 * @return HTTP_OK on success, HTTP_INTERNAL_SERVER_ERROR otherwise
 * @deffunc int ap_scan_script_header_err(request_rec *r, apr_file_t *f, char *buffer)
 */ 
AP_DECLARE(int) ap_scan_script_header_err(request_rec *r, apr_file_t *f, char *buffer);

/**
 * Read headers output from a script, ensuring that the output is valid.  If
 * the output is valid, then the headers are added to the headers out of the
 * current request
 * @param r The current request
 * @param bb The brigade from which to read
 * @param buffer Empty when calling the function.  On output, if there was an
 *               error, the string that cause the error is stored here. 
 * @return HTTP_OK on success, HTTP_INTERNAL_SERVER_ERROR otherwise
 * @deffunc int ap_scan_script_header_err_brigade(request_rec *r, apr_bucket_brigade *bb, char *buffer)
 */ 
AP_DECLARE(int) ap_scan_script_header_err_brigade(request_rec *r,
                                                  apr_bucket_brigade *bb,
                                                  char *buffer);

/**
 * Read headers strings from a script, ensuring that the output is valid.  If
 * the output is valid, then the headers are added to the headers out of the
 * current request
 * @param r The current request
 * @param buffer Empty when calling the function.  On output, if there was an
 *               error, the string that cause the error is stored here. 
 * @param termch Pointer to the last character parsed.
 * @param termarg Pointer to an int to capture the last argument parsed.
 * @param args   String arguments to parse consecutively for headers, 
 *               a NULL argument terminates the list.
 * @return HTTP_OK on success, HTTP_INTERNAL_SERVER_ERROR otherwise
 * @deffunc int ap_scan_script_header_err_core(request_rec *r, char *buffer, int (*getsfunc)(char *, int, void *), void *getsfunc_data)
 */ 
AP_DECLARE_NONSTD(int) ap_scan_script_header_err_strs(request_rec *r, 
                                                      char *buffer, 
                                                      const char **termch,
                                                      int *termarg, ...);

/**
 * Read headers output from a script, ensuring that the output is valid.  If
 * the output is valid, then the headers are added to the headers out of the
 * current request
 * @param r The current request
 * @param buffer Empty when calling the function.  On output, if there was an
 *               error, the string that cause the error is stored here. 
 * @param getsfunc Function to read the headers from.  This function should
                   act like gets()
 * @param getsfunc_data The place to read from
 * @return HTTP_OK on success, HTTP_INTERNAL_SERVER_ERROR otherwise
 * @deffunc int ap_scan_script_header_err_core(request_rec *r, char *buffer, int (*getsfunc)(char *, int, void *), void *getsfunc_data)
 */ 
AP_DECLARE(int) ap_scan_script_header_err_core(request_rec *r, char *buffer,
				       int (*getsfunc) (char *, int, void *),
				       void *getsfunc_data);

#ifdef __cplusplus
}
#endif

#endif	/* !APACHE_UTIL_SCRIPT_H */
