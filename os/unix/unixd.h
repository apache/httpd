/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000 The Apache Software Foundation.  All rights
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
    char *user_name;
    uid_t user_id;
    gid_t group_id;
} unixd_config_rec;
extern unixd_config_rec unixd_config;

void unixd_detach(void);
int unixd_setup_child(void);
void unixd_pre_config(void);
const char *unixd_set_user(cmd_parms *cmd, void *dummy, char *arg);
const char *unixd_set_group(cmd_parms *cmd, void *dummy, char *arg);

/* Information on signals for the various platforms */

#if defined(NSIG)
#define NumSIG NSIG
#elif defined(_NSIG)
#define NumSIG _NSIG
#elif defined(__NSIG)
#define NumSIG __NSIG
#else
#define NumSIG 33   /* breaks on OS/390 with < 33; 32 is o.k. for most */
#endif

#ifdef SYS_SIGLIST /* platform has sys_siglist[] */
#define INIT_SIGLIST()  /* nothing */
#elif defined(SYS_SIGLIST_DECLARED) /* from autoconf */
#define INIT_SIGLIST()  /* nothing */
#define SYS_SIGLIST sys_siglist
#else
#define NEED_AP_SYS_SIGLIST
extern const char *ap_sys_siglist[NumSIG];
#define SYS_SIGLIST ap_sys_siglist
void unixd_siglist_init(void);
#define INIT_SIGLIST() unixd_siglist_init();
#endif /* platform has sys_siglist[] */

#ifdef HAVE_KILLPG
#define unixd_killpg(x, y)	(killpg ((x), (y)))
#else /* HAVE_KILLPG */
#define unixd_killpg(x, y)	(kill (-(x), (y)))
#endif /* HAVE_KILLPG */

#define UNIX_DAEMON_COMMANDS	\
{ "User", unixd_set_user, NULL, RSRC_CONF, TAKE1, \
  "Effective user id for this server"}, \
{ "Group", unixd_set_group, NULL, RSRC_CONF, TAKE1, \
  "Effective group id for this server"}, \

#endif
