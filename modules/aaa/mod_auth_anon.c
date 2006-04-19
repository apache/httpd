/* Copyright 1999-2006 The Apache Software Foundation or its licensors, as
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
 * Anonymous_Authoritative      [ on | off ] default = off
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

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_request.h"
#include "http_protocol.h"

typedef struct anon_auth {
    char *password;
    struct anon_auth *next;
} anon_auth;

typedef struct {
    anon_auth *anon_auth_passwords;
    int anon_auth_nouserid;
    int anon_auth_logemail;
    int anon_auth_verifyemail;
    int anon_auth_mustemail;
    int anon_auth_authoritative;
} anon_auth_config_rec;

static void *create_anon_auth_dir_config(apr_pool_t *p, char *d)
{
    anon_auth_config_rec *conf = apr_palloc(p, sizeof(*conf));

    /* just to illustrate the defaults really. */
    conf->anon_auth_passwords = NULL;

    conf->anon_auth_nouserid = 0;
    conf->anon_auth_logemail = 1;
    conf->anon_auth_verifyemail = 0;
    conf->anon_auth_mustemail = 1;
    conf->anon_auth_authoritative = 0;
    return conf;
}

static const char *anon_set_string_slots(cmd_parms *cmd,
                                         void *my_config, const char *arg)
{
    anon_auth_config_rec *conf = my_config;
    anon_auth *first;

    if (!(*arg))
        return "Anonymous string cannot be empty, use Anonymous_NoUserId instead";

    /* squeeze in a record */
    first = conf->anon_auth_passwords;

    if (!(conf->anon_auth_passwords = apr_palloc(cmd->pool, sizeof(anon_auth))) ||
       !(conf->anon_auth_passwords->password = apr_pstrdup(cmd->pool, arg)))
             return "Failed to claim memory for an anonymous password...";

    /* and repair the next */
    conf->anon_auth_passwords->next = first;

    return NULL;
}

static const command_rec anon_auth_cmds[] =
{
    AP_INIT_ITERATE("Anonymous", anon_set_string_slots, NULL, OR_AUTHCFG, 
     "a space-separated list of user IDs"),
    AP_INIT_FLAG("Anonymous_MustGiveEmail", ap_set_flag_slot,
     (void *)APR_OFFSETOF(anon_auth_config_rec, anon_auth_mustemail),
     OR_AUTHCFG, "Limited to 'on' or 'off'"),
    AP_INIT_FLAG("Anonymous_NoUserId", ap_set_flag_slot,
     (void *)APR_OFFSETOF(anon_auth_config_rec, anon_auth_nouserid),
     OR_AUTHCFG, "Limited to 'on' or 'off'"),
    AP_INIT_FLAG("Anonymous_VerifyEmail", ap_set_flag_slot,
     (void *)APR_OFFSETOF(anon_auth_config_rec, anon_auth_verifyemail),
     OR_AUTHCFG, "Limited to 'on' or 'off'"),
    AP_INIT_FLAG("Anonymous_LogEmail", ap_set_flag_slot,
     (void *)APR_OFFSETOF(anon_auth_config_rec, anon_auth_logemail),
     OR_AUTHCFG, "Limited to 'on' or 'off'"),
    AP_INIT_FLAG("Anonymous_Authoritative", ap_set_flag_slot,
     (void *)APR_OFFSETOF(anon_auth_config_rec, anon_auth_authoritative),
     OR_AUTHCFG, "Limited to 'on' or 'off'"),
    {NULL}
};

module AP_MODULE_DECLARE_DATA auth_anon_module;

static int anon_authenticate_basic_user(request_rec *r)
{
    anon_auth_config_rec *conf = ap_get_module_config(r->per_dir_config,
                                                      &auth_anon_module);
    const char *sent_pw;
    int res = DECLINED;

    if ((res = ap_get_basic_auth_pw(r, &sent_pw))) {
        return res;
    }

    /* Ignore if we are not configured */
    if (!conf->anon_auth_passwords) {
        return DECLINED;
    }

    /* Do we allow an empty userID and/or is it the magic one
     */

    if ((!(r->user[0])) && (conf->anon_auth_nouserid)) {
        res = OK;
    }
    else {
        anon_auth *p = conf->anon_auth_passwords;
        res = DECLINED;
        while ((res == DECLINED) && (p != NULL)) {
            if (!(strcasecmp(r->user, p->password))) {
                res = OK;
            }
            p = p->next;
        }
    }
    if (
        /* username is OK */
        (res == OK)
        /* password been filled out ? */
           && ((!conf->anon_auth_mustemail) || strlen(sent_pw))
        /* does the password look like an email address ? */
           && ((!conf->anon_auth_verifyemail)
               || ((strpbrk("@", sent_pw) != NULL)
                   && (strpbrk(".", sent_pw) != NULL)))) {
        if (conf->anon_auth_logemail && ap_is_initial_req(r)) {
            ap_log_rerror(APLOG_MARK, APLOG_INFO, APR_SUCCESS, r,
                        "Anonymous: Passwd <%s> Accepted",
                        sent_pw ? sent_pw : "\'none\'");
        }
        return OK;
    }
    else {
        if (conf->anon_auth_authoritative) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r,
                        "Anonymous: Authoritative, Passwd <%s> not accepted",
                        sent_pw ? sent_pw : "\'none\'");
            return HTTP_UNAUTHORIZED;
        }
        /* Drop out the bottom to return DECLINED */
    }

    return DECLINED;
}

static int check_anon_access(request_rec *r)
{
#ifdef NOTYET
    conn_rec *c = r->connection;
    anon_auth_config_rec *conf = ap_get_module_config(r->per_dir_config,
                                                      &auth_anon_module);

    if (!conf->anon_auth) {
        return DECLINED;
    }

    if (strcasecmp(r->connection->user, conf->anon_auth)) {
        return DECLINED;
    }

    return OK;
#endif
    return DECLINED;
}

static void register_hooks(apr_pool_t *p)
{
    ap_hook_check_user_id(anon_authenticate_basic_user,NULL,NULL,APR_HOOK_MIDDLE);
    ap_hook_auth_checker(check_anon_access,NULL,NULL,APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA auth_anon_module =
{
    STANDARD20_MODULE_STUFF,
    create_anon_auth_dir_config,    /* dir config creater */
    NULL,                           /* dir merger ensure strictness */
    NULL,                           /* server config */
    NULL,                           /* merge server config */
    anon_auth_cmds,                 /* command apr_table_t */
    register_hooks                  /* register hooks */
};
