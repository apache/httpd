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

#ifndef BEOSD_H
#define BEOSD_H

#include "httpd.h"
#include "ap_listen.h"
/* common stuff that beos MPMs will want */

/* Default user name and group name. These may be specified as numbers by
 * placing a # before a number */

#ifndef DEFAULT_USER
#define DEFAULT_USER "#-1"
#endif
#ifndef DEFAULT_GROUP
#define DEFAULT_GROUP "#"
#endif

typedef struct {
    char *user_name;
    uid_t user_id;
    gid_t group_id;
} beosd_config_rec;
extern beosd_config_rec beosd_config;

void beosd_detach(void);
int beosd_setup_child(void);
void beosd_pre_config(void);
AP_DECLARE(const char *) beosd_set_user (cmd_parms *cmd, void *dummy, 
                                         const char *arg);
AP_DECLARE(const char *) beosd_set_group(cmd_parms *cmd, void *dummy, 
                                         const char *arg);
AP_DECLARE(apr_status_t) beosd_accept(void **accepted, ap_listen_rec *lr,
                                      apr_pool_t *ptrans);

#define beosd_killpg(x, y)	(kill (-(x), (y)))
#define ap_os_killpg(x, y)      (kill (-(x), (y)))

#define BEOS_DAEMON_COMMANDS	\
AP_INIT_TAKE1("User", beosd_set_user, NULL, RSRC_CONF, \
  "Effective user id for this server (NO-OP)"), \
AP_INIT_TAKE1("Group", beosd_set_group, NULL, RSRC_CONF, \
  "Effective group id for this server (NO-OP)")

#endif /* BEOSD_H */
