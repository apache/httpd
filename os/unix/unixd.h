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

#ifndef UNIXD_H
#define UNIXD_H

#include "httpd.h"
#include "http_config.h"
#include "ap_listen.h"
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif
#include "apr_hooks.h"
#include "apr_thread_proc.h"
#include "apr_proc_mutex.h"
#include "apr_global_mutex.h"

#include <pwd.h>
#include <grp.h>
#ifdef APR_HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_IPC_H
#include <sys/ipc.h>
#endif

typedef struct {
    uid_t uid;
    gid_t gid;
    int userdir;
} ap_unix_identity_t;

AP_DECLARE_HOOK(ap_unix_identity_t *, get_suexec_identity,(const request_rec *r))

/* common stuff that unix MPMs will want */

/* Default user name and group name. These may be specified as numbers by
 * placing a # before a number */

#ifndef DEFAULT_USER
#define DEFAULT_USER "#-1"
#endif
#ifndef DEFAULT_GROUP
#define DEFAULT_GROUP "#-1"
#endif

typedef struct {
    const char *user_name;
    uid_t user_id;
    gid_t group_id;
    int suexec_enabled;
} unixd_config_rec;
AP_DECLARE_DATA extern unixd_config_rec unixd_config;

AP_DECLARE(int) unixd_setup_child(void);
AP_DECLARE(void) unixd_pre_config(apr_pool_t *ptemp);
AP_DECLARE(const char *) unixd_set_user(cmd_parms *cmd, void *dummy, 
                                        const char *arg);
AP_DECLARE(const char *) unixd_set_group(cmd_parms *cmd, void *dummy, 
                                         const char *arg);
#if defined(RLIMIT_CPU) || defined(RLIMIT_DATA) || defined(RLIMIT_VMEM) || defined(RLIMIT_NPROC) || defined(RLIMIT_AS)
AP_DECLARE(void) unixd_set_rlimit(cmd_parms *cmd, struct rlimit **plimit,
                           const char *arg, const char * arg2, int type);
#endif
AP_DECLARE(apr_status_t) unixd_set_proc_mutex_perms(apr_proc_mutex_t *pmutex);
AP_DECLARE(apr_status_t) unixd_set_global_mutex_perms(apr_global_mutex_t *gmutex);
AP_DECLARE(apr_status_t) unixd_accept(void **accepted, ap_listen_rec *lr, apr_pool_t *ptrans);

#ifdef HAVE_KILLPG
#define unixd_killpg(x, y)	(killpg ((x), (y)))
#define ap_os_killpg(x, y)      (killpg ((x), (y)))
#else /* HAVE_KILLPG */
#define unixd_killpg(x, y)	(kill (-(x), (y)))
#define ap_os_killpg(x, y)      (kill (-(x), (y)))
#endif /* HAVE_KILLPG */

#define UNIX_DAEMON_COMMANDS	\
AP_INIT_TAKE1("User", unixd_set_user, NULL, RSRC_CONF, \
  "Effective user id for this server"), \
AP_INIT_TAKE1("Group", unixd_set_group, NULL, RSRC_CONF, \
  "Effective group id for this server")

#endif
