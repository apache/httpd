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

#ifndef APACHE_HTTP_MAIN_H
#define APACHE_HTTP_MAIN_H

#include "apr_optional.h"

/* AP_SERVER_BASEARGS is the command argument list parsed by http_main.c
 * in apr_getopt() format.  Use this for default'ing args that the MPM
 * can safely ignore and pass on from its rewrite_args() handler.
 */
#define AP_SERVER_BASEARGS "C:c:D:d:E:e:f:vVlLtSh?X"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @package Command line options
 */

/** The name of the Apache executable */
AP_DECLARE_DATA extern const char *ap_server_argv0;
/** The global server's ServerRoot */
AP_DECLARE_DATA extern const char *ap_server_root;

/* for -C, -c and -D switches */
/** An array of all -C directives.  These are processed before the server's
 *  config file */
AP_DECLARE_DATA extern apr_array_header_t *ap_server_pre_read_config;
/** An array of all -c directives.  These are processed after the server's
 *  config file */
AP_DECLARE_DATA extern apr_array_header_t *ap_server_post_read_config;
/** An array of all -D defines on the command line.  This allows people to
 *  effect the server based on command line options */
AP_DECLARE_DATA extern apr_array_header_t *ap_server_config_defines;

APR_DECLARE_OPTIONAL_FN(int, ap_signal_server, (int *, apr_pool_t *));

#ifdef __cplusplus
}
#endif

#endif	/* !APACHE_HTTP_MAIN_H */
