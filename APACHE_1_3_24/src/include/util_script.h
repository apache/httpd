/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000-2002 The Apache Software Foundation.  All rights
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

#ifdef __cplusplus
extern "C" {
#endif

#ifndef APACHE_ARG_MAX
#ifdef _POSIX_ARG_MAX
#define APACHE_ARG_MAX _POSIX_ARG_MAX
#else
#define APACHE_ARG_MAX 512
#endif
#endif

API_EXPORT(char **) ap_create_environment(pool *p, table *t);
API_EXPORT(int) ap_find_path_info(const char *uri, const char *path_info);
API_EXPORT(void) ap_add_cgi_vars(request_rec *r);
API_EXPORT(void) ap_add_common_vars(request_rec *r);
API_EXPORT(int) ap_scan_script_header_err(request_rec *r, FILE *f, char *buffer);
API_EXPORT(int) ap_scan_script_header_err_buff(request_rec *r, BUFF *f,
                                               char *buffer);
API_EXPORT(int) ap_scan_script_header_err_core(request_rec *r, char *buffer,
				       int (*getsfunc) (char *, int, void *),
				       void *getsfunc_data);
API_EXPORT_NONSTD(int) ap_scan_script_header_err_strs(request_rec *r, 
                                                      char *buffer, 
                                                      const char **termch,
                                                      int *termarg, ...);
API_EXPORT(void) ap_send_size(size_t size, request_rec *r);
API_EXPORT(int) ap_call_exec(request_rec *r, child_info *pinfo, char *argv0, char **env,
                          int shellcmd);

#ifdef __cplusplus
}
#endif

#endif	/* !APACHE_UTIL_SCRIPT_H */
