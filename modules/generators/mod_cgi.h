/* Copyright 2001-2006 The Apache Software Foundation or its licensors, as
 * applicable.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef _MOD_CGI_H
#define _MOD_CGI_H 1

#include "mod_include.h"

#define AP_PROC_DETACHED       1
#define AP_PROC_NEWADDRSPACE   2

typedef enum {RUN_AS_SSI, RUN_AS_CGI} prog_types;

typedef struct {
    apr_int32_t          in_pipe;
    apr_int32_t          out_pipe;
    apr_int32_t          err_pipe;
    int                  process_cgi;
    apr_cmdtype_e        cmd_type;
    apr_int32_t          detached; /* used as a bitfield for detached_ & addrspace_set, */
                                   /* when initializing apr_proc_attr structure */
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
