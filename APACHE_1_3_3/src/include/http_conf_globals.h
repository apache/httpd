/* ====================================================================
 * Copyright (c) 1995-1998 The Apache Group.  All rights reserved.
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
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the Apache Group
 *    for use in the Apache HTTP server project (http://www.apache.org/)."
 *
 * 4. The names "Apache Server" and "Apache Group" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    apache@apache.org.
 *
 * 5. Products derived from this software may not be called "Apache"
 *    nor may "Apache" appear in their names without prior written
 *    permission of the Apache Group.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the Apache Group
 *    for use in the Apache HTTP server project (http://www.apache.org/)."
 *
 * THIS SOFTWARE IS PROVIDED BY THE APACHE GROUP ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE APACHE GROUP OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Group and was originally based
 * on public domain software written at the National Center for
 * Supercomputing Applications, University of Illinois, Urbana-Champaign.
 * For more information on the Apache Group and the Apache HTTP server
 * project, please see <http://www.apache.org/>.
 *
 */

#ifndef APACHE_HTTP_CONF_GLOBALS_H
#define APACHE_HTTP_CONF_GLOBALS_H

#ifdef __cplusplus
extern "C" {
#endif

/* 
 * Process config --- what the process ITSELF is doing
 */

extern int ap_standalone;
extern uid_t ap_user_id;
extern char *ap_user_name;
extern gid_t ap_group_id;
#ifdef MULTIPLE_GROUPS
extern gid_t group_id_list[NGROUPS_MAX];
#endif
extern int ap_max_requests_per_child;
extern int ap_threads_per_child;
extern int ap_excess_requests_per_child;
extern struct in_addr ap_bind_address;
extern listen_rec *ap_listeners;
extern int ap_daemons_to_start;
extern int ap_daemons_min_free;
extern int ap_daemons_max_free;
extern int ap_daemons_limit;
extern MODULE_VAR_EXPORT int ap_suexec_enabled;
extern int ap_listenbacklog;
extern int ap_dump_settings;
extern API_VAR_EXPORT int ap_extended_status;

extern char *ap_pid_fname;
extern char *ap_scoreboard_fname;
extern char *ap_lock_fname;
extern MODULE_VAR_EXPORT char *ap_server_argv0;

extern enum server_token_type ap_server_tokens;

/* Trying to allocate these in the config pool gets us into some *nasty*
 * chicken-and-egg problems in http_main.c --- where do you stick them
 * when pconf gets cleared?  Better to just allocate a little space
 * statically...
 */

extern API_VAR_EXPORT char ap_server_root[MAX_STRING_LEN];
extern char ap_server_confname[MAX_STRING_LEN];

/* for -C, -c and -D switches */
extern array_header *ap_server_pre_read_config;
extern array_header *ap_server_post_read_config;
extern array_header *ap_server_config_defines;

/* We want this to have the least chance of being corrupted if there
 * is some memory corruption, so we allocate it statically.
 */
extern char ap_coredump_dir[MAX_STRING_LEN];

#ifdef __cplusplus
}
#endif

#endif	/* !APACHE_HTTP_CONF_GLOBALS_H */
