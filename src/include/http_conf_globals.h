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

#ifndef APACHE_HTTP_CONF_GLOBALS_H
#define APACHE_HTTP_CONF_GLOBALS_H

#ifdef __cplusplus
extern "C" {
#endif

/* 
 * Process config --- what the process ITSELF is doing
 */

extern API_VAR_EXPORT int ap_standalone;
extern API_VAR_EXPORT int ap_configtestonly;
extern int ap_docrootcheck;
extern API_VAR_EXPORT uid_t ap_user_id;
extern API_VAR_EXPORT char *ap_user_name;
extern API_VAR_EXPORT gid_t ap_group_id;
#ifdef NETWARE
extern unsigned int ap_thread_stack_size;
#endif
#ifdef MULTIPLE_GROUPS
extern gid_t group_id_list[NGROUPS_MAX];
#endif
extern API_VAR_EXPORT int ap_max_requests_per_child;
extern API_VAR_EXPORT int ap_threads_per_child;
extern API_VAR_EXPORT int ap_excess_requests_per_child;
extern API_VAR_EXPORT struct in_addr ap_bind_address;
extern listen_rec *ap_listeners;
extern API_VAR_EXPORT int ap_daemons_to_start;
extern API_VAR_EXPORT int ap_daemons_min_free;
extern API_VAR_EXPORT int ap_daemons_max_free;
extern API_VAR_EXPORT int ap_daemons_limit;
extern API_VAR_EXPORT int ap_suexec_enabled;
extern API_VAR_EXPORT int ap_listenbacklog;
#ifdef SO_ACCEPTFILTER
extern int ap_acceptfilter;
#endif
extern int ap_dump_settings;
extern API_VAR_EXPORT int ap_extended_status;

extern API_VAR_EXPORT char *ap_pid_fname;
extern API_VAR_EXPORT char *ap_scoreboard_fname;
extern API_VAR_EXPORT char *ap_lock_fname;
extern API_VAR_EXPORT char *ap_server_argv0;

extern enum server_token_type ap_server_tokens;

extern API_VAR_EXPORT int ap_protocol_req_check;
extern API_VAR_EXPORT int ap_change_shmem_uid;

/* Trying to allocate these in the config pool gets us into some *nasty*
 * chicken-and-egg problems in http_main.c --- where do you stick them
 * when pconf gets cleared?  Better to just allocate a little space
 * statically...
 */

extern API_VAR_EXPORT char ap_server_root[MAX_STRING_LEN];
extern API_VAR_EXPORT char ap_server_confname[MAX_STRING_LEN];

/* for -C, -c and -D switches */
extern API_VAR_EXPORT array_header *ap_server_pre_read_config;
extern API_VAR_EXPORT array_header *ap_server_post_read_config;
extern API_VAR_EXPORT array_header *ap_server_config_defines;

/* We want this to have the least chance of being corrupted if there
 * is some memory corruption, so we allocate it statically.
 */
extern API_VAR_EXPORT char ap_coredump_dir[MAX_STRING_LEN];

#ifdef __cplusplus
}
#endif

#endif	/* !APACHE_HTTP_CONF_GLOBALS_H */
