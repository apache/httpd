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

/*
 * http_auth: authentication
 * 
 * Rob McCool & Brian Behlendorf.
 * 
 * Adapted to Apache by rst.
 *
 * Version 0.5 May 1996
 *
 * Modified by Dirk.vanGulik@jrc.it to
 * 
 * Adapted to allow anonymous logins, just like with Anon-FTP, when
 * one gives the magic user name 'anonymous' and ones email address
 * as the password.
 *
 * Just add the following tokes to your <directory> setup:
 * 
 * Anonymous                    magic-userid [magic-userid]...
 *
 * Anonymous_MustGiveEmail      [ on | off ] default = on
 * Anonymous_LogEmail           [ on | off ] default = on
 * Anonymous_VerifyEmail        [ on | off ] default = off
 * Anonymous_NoUserId           [ on | off ] default = off
 *
 * The magic user id is something like 'anonymous', it is NOT case sensitive. 
 * 
 * The MustGiveEmail flag can be used to force users to enter something
 * in the password field (like an email address). Default is on.
 *
 * Furthermore the 'NoUserID' flag can be set to allow completely empty
 * usernames in as well; this can be is convenient as a single return
 * in broken GUIs like W95 is often given by the user. The Default is off.
 *
 * Dirk.vanGulik@jrc.it; http://ewse.ceo.org; http://me-www.jrc.it/~dirkx
 * 
 */

#include "apr_strings.h"

#define APR_WANT_STRFUNC
#include "apr_want.h"

#include "ap_provider.h"
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_request.h"
#include "http_protocol.h"

#include "mod_auth.h"

typedef struct anon_auth_pw {
    char *password;
    struct anon_auth_pw *next;
} anon_auth_pw;

typedef struct {
    anon_auth_pw *passwords;
    int nouserid;
    int logemail;
    int verifyemail;
    int mustemail;
} authn_anon_config_rec;

static void *create_authn_anon_dir_config(apr_pool_t *p, char *d)
{
    authn_anon_config_rec *conf = apr_palloc(p, sizeof(*conf));

    /* just to illustrate the defaults really. */
    conf->passwords = NULL;

    conf->nouserid = 0;
    conf->logemail = 1;
    conf->verifyemail = 0;
    conf->mustemail = 1;
    return conf;
}

static const char *anon_set_string_slots(cmd_parms *cmd,
                                         void *my_config, const char *arg)
{
    authn_anon_config_rec *conf = my_config;
    anon_auth_pw *first;

    if (!(*arg)) {
        return "Anonymous string cannot be empty, use Anonymous_NoUserId";
    }

    /* squeeze in a record */
    first = conf->passwords;

    if (!(conf->passwords = apr_palloc(cmd->pool, sizeof(anon_auth_pw))) ||
        !(conf->passwords->password = apr_pstrdup(cmd->pool, arg))) {
        return "Failed to claim memory for an anonymous password...";
    }

    /* and repair the next */
    conf->passwords->next = first;

    return NULL;
}

static const command_rec authn_anon_cmds[] =
{
    AP_INIT_ITERATE("Anonymous", anon_set_string_slots, NULL, OR_AUTHCFG, 
     "a space-separated list of user IDs"),
    AP_INIT_FLAG("Anonymous_MustGiveEmail", ap_set_flag_slot,
     (void *)APR_OFFSETOF(authn_anon_config_rec, mustemail),
     OR_AUTHCFG, "Limited to 'on' or 'off'"),
    AP_INIT_FLAG("Anonymous_NoUserId", ap_set_flag_slot,
     (void *)APR_OFFSETOF(authn_anon_config_rec, nouserid),
     OR_AUTHCFG, "Limited to 'on' or 'off'"),
    AP_INIT_FLAG("Anonymous_VerifyEmail", ap_set_flag_slot,
     (void *)APR_OFFSETOF(authn_anon_config_rec, verifyemail),
     OR_AUTHCFG, "Limited to 'on' or 'off'"),
    AP_INIT_FLAG("Anonymous_LogEmail", ap_set_flag_slot,
     (void *)APR_OFFSETOF(authn_anon_config_rec, logemail),
     OR_AUTHCFG, "Limited to 'on' or 'off'"),
    {NULL}
};

module AP_MODULE_DECLARE_DATA authn_anon_module;

static authn_status check_anonymous(request_rec *r, const char *user,
                                    const char *sent_pw)
{
    authn_anon_config_rec *conf = ap_get_module_config(r->per_dir_config,
                                                      &authn_anon_module);
    authn_status res = AUTH_USER_NOT_FOUND;

    /* Ignore if we are not configured */
    if (!conf->passwords) {
        return AUTH_USER_NOT_FOUND;
    }

    /* Do we allow an empty userID and/or is it the magic one
     */

    if ((!user[0]) && (conf->nouserid)) {
        res = AUTH_USER_FOUND;
    }
    else {
        anon_auth_pw *p = conf->passwords;
        res = AUTH_USER_NOT_FOUND;
        while ((res == AUTH_USER_NOT_FOUND) && (p != NULL)) {
            if (!strcasecmp(user, p->password)) {
                res = AUTH_USER_FOUND;
            }
            p = p->next;
        }
    }

    /* Is username is OK and password been filled out (if required) */
    if ((res == AUTH_USER_FOUND) && ((!conf->mustemail) || strlen(sent_pw)) &&
        /* does the password look like an email address ? */
        ((!conf->verifyemail) ||
          ((strpbrk("@", sent_pw) != NULL) && 
           (strpbrk(".", sent_pw) != NULL)))) {
        if (conf->logemail && ap_is_initial_req(r)) {
            ap_log_rerror(APLOG_MARK, APLOG_INFO, APR_SUCCESS, r,
                        "Anonymous: Passwd <%s> Accepted",
                        sent_pw ? sent_pw : "\'none\'");
        }
        return AUTH_GRANTED;
    }

    return (res == AUTH_USER_NOT_FOUND ? res : AUTH_DENIED);
}

static const authn_provider authn_anon_provider =
{
    &check_anonymous,
    NULL
};

static void register_hooks(apr_pool_t *p)
{
    ap_register_provider(p, AUTHN_PROVIDER_GROUP, "anon", "0",
                         &authn_anon_provider);
}

module AP_MODULE_DECLARE_DATA authn_anon_module =
{
    STANDARD20_MODULE_STUFF,
    create_authn_anon_dir_config, /* dir config creater */
    NULL,                         /* dir merger ensure strictness */
    NULL,                         /* server config */
    NULL,                         /* merge server config */
    authn_anon_cmds,              /* command apr_table_t */
    register_hooks                /* register hooks */
};
