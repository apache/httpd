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

#ifndef _MOD_CGI_H
#define _MOD_CGI_H 1

#include "mod_include.h"

typedef enum {RUN_AS_SSI, RUN_AS_CGI} prog_types;

typedef struct {
    apr_int32_t          in_pipe;
    apr_int32_t          out_pipe;
    apr_int32_t          err_pipe;
    int                  process_cgi;
    apr_cmdtype_e        cmd_type;
    apr_int32_t          detached;
    prog_types           prog_type;
    apr_bucket_brigade **bb;
    include_ctx_t       *ctx;
    ap_filter_t         *next;
} cgi_exec_info_t;

/**
 * Registerable optional function to override CGI behavior;
 * Reprocess the command and arguments to execute the given CGI script.
 * @param cmd Pointer to the command to execute (may be overridden)
 * @param argv Pointer to the arguments to pass (may be overridden)
 * @param r The current request
 * @param p The pool to allocate correct cmd/argv elements within.
 * @param process_cgi Set true if processing r->filename and r->args
 *                    as a CGI invocation, otherwise false
 * @param type Set to APR_SHELLCMD or APR_PROGRAM on entry, may be
 *             changed to invoke the program with alternate semantics.
 * @param detach Should the child start in detached state?  Default is no. 
 * @remark This callback may be registered by the os-specific module 
 * to correct the command and arguments for apr_proc_create invocation
 * on a given os.  mod_cgi will call the function if registered.
 */
APR_DECLARE_OPTIONAL_FN(apr_status_t, ap_cgi_build_command, 
                        (const char **cmd, const char ***argv,
                         request_rec *r, apr_pool_t *p, 
                         cgi_exec_info_t *e_info));

#endif /* _MOD_CGI_H */
