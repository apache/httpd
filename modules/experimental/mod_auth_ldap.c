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
 */

/*
 * mod_auth_ldap.c: LDAP authentication module
 * 
 * Original code from auth_ldap module for Apache v1.3:
 * Copyright 1998, 1999 Enbridge Pipelines Inc. 
 * Copyright 1999-2001 Dave Carrigan
 */

#include <apr_ldap.h>
#include <apr_strings.h>

#include "ap_config.h"
#if APR_HAVE_UNISTD_H
/* for getpid() */
#include <unistd.h>
#endif
#include <ctype.h>

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"
#include "util_ldap.h"

#ifndef APU_HAS_LDAP
#error mod_auth_ldap requires APR-util to have LDAP support built in
#endif

/* per directory configuration */
typedef struct {
    apr_pool_t *pool;			/* Pool that this config is allocated from */
#if APR_HAS_THREADS
    apr_thread_mutex_t *lock;           /* Lock for this config */
#endif
    int auth_authoritative;		/* Is this auth method the one and only? */
    int enabled;			/* Is auth_ldap enabled in this directory? */

    /* These parameters are all derived from the AuthLDAPURL directive */
    char *url;				/* String representation of the URL */

    char *host;				/* Name of the LDAP server (or space separated list) */
    int port;				/* Port of the LDAP server */
    char *basedn;			/* Base DN to do all searches from */
    char *attribute;			/* Attribute to search for */
    char **attributes;			/* Array of all the attributes to return */
    int scope;				/* Scope of the search */
    char *filter;			/* Filter to further limit the search  */
    deref_options deref;		/* how to handle alias dereferening */
    char *binddn;			/* DN to bind to server (can be NULL) */
    char *bindpw;			/* Password to bind to server (can be NULL) */

    int frontpage_hack;			/* Hack for frontpage support */
    int user_is_dn;			/* If true, connection->user is DN instead of userid */
    int compare_dn_on_server;		/* If true, will use server to do DN compare */

    int have_ldap_url;			/* Set if we have found an LDAP url */
 
    apr_array_header_t *groupattr;	/* List of Group attributes */
    int group_attrib_is_dn;		/* If true, the group attribute is the DN, otherwise, 
					   it's the exact string passed by the HTTP client */

    int netscapessl;			/* True if Netscape SSL is enabled */
    int starttls;                       /* True if StartTLS is enabled */
} mod_auth_ldap_config_t;

typedef struct mod_auth_ldap_request_t {
    char *dn;				/* The saved dn from a successful search */
    char *user;				/* The username provided by the client */
} mod_auth_ldap_request_t;

/* maximum group elements supported */
#define GROUPATTR_MAX_ELTS 10

struct mod_auth_ldap_groupattr_entry_t {
    char *name;
};

module AP_MODULE_DECLARE_DATA auth_ldap_module;

/* function prototypes */
void mod_auth_ldap_build_filter(char *filtbuf, 
                                request_rec *r, 
                                mod_auth_ldap_config_t *sec);
int mod_auth_ldap_check_user_id(request_rec *r);
int mod_auth_ldap_auth_checker(request_rec *r);
void *mod_auth_ldap_create_dir_config(apr_pool_t *p, char *d);

/* ---------------------------------------- */


/*
 * Build the search filter, or at least as much of the search filter that
 * will fit in the buffer. We don't worry about the buffer not being able
 * to hold the entire filter. If the buffer wasn't big enough to hold the
 * filter, ldap_search_s will complain, but the only situation where this
 * is likely to happen is if the client sent a really, really long
 * username, most likely as part of an attack.
 *
 * The search filter consists of the filter provided with the URL,
 * combined with a filter made up of the attribute provided with the URL,
 * and the actual username passed by the HTTP client. For example, assume
 * that the LDAP URL is
 * 
 *   ldap://ldap.airius.com/ou=People, o=Airius?uid??(posixid=*)
 *
 * Further, assume that the userid passed by the client was `userj'.  The
 * search filter will be (&(posixid=*)(uid=userj)).
 */
#define FILTER_LENGTH MAX_STRING_LEN
void mod_auth_ldap_build_filter(char *filtbuf, 
                                request_rec *r, 
                                mod_auth_ldap_config_t *sec)
{
    char *p, *q, *filtbuf_end;
    /* 
     * Create the first part of the filter, which consists of the 
     * config-supplied portions.
     */
    apr_snprintf(filtbuf, FILTER_LENGTH, "(&(%s)(%s=", sec->filter, sec->attribute);

    /* 
     * Now add the client-supplied username to the filter, ensuring that any
     * LDAP filter metachars are escaped.
     */
    filtbuf_end = filtbuf + FILTER_LENGTH - 1;
    for (p = r->user, q=filtbuf + strlen(filtbuf);
         *p && q < filtbuf_end; *q++ = *p++) {
        if (strchr("*()\\", *p) != NULL) {
            *q++ = '\\';
            if (q >= filtbuf_end) {
	        break;
	    }
        }
    }
    *q = '\0';

    /* 
     * Append the closing parens of the filter, unless doing so would 
     * overrun the buffer.
     */
    if (q + 2 <= filtbuf_end)
        strcat(filtbuf, "))");
}

static apr_status_t mod_auth_ldap_cleanup_connection_close(void *param)
{
    util_ldap_connection_t *ldc = param;
    util_ldap_connection_close(ldc);
    return APR_SUCCESS;
}


/*
 * Authentication Phase
 * --------------------
 *
 * This phase authenticates the credentials the user has sent with
 * the request (ie the username and password are checked). This is done
 * by making an attempt to bind to the LDAP server using this user's
 * DN and the supplied password.
 *
 */
int mod_auth_ldap_check_user_id(request_rec *r)
{
    int failures = 0;
    const char **vals = NULL;
    char filtbuf[FILTER_LENGTH];
    mod_auth_ldap_config_t *sec =
        (mod_auth_ldap_config_t *)ap_get_module_config(r->per_dir_config, &auth_ldap_module);

    util_ldap_connection_t *ldc = NULL;
    const char *sent_pw;
    int result = 0;
    const char *dn = NULL;

    mod_auth_ldap_request_t *req =
        (mod_auth_ldap_request_t *)apr_pcalloc(r->pool, sizeof(mod_auth_ldap_request_t));
    ap_set_module_config(r->request_config, &auth_ldap_module, req);

    if (!sec->enabled) {
        return DECLINED;
    }

    /* 
     * Basic sanity checks before any LDAP operations even happen.
     */
    if (!sec->have_ldap_url) {
        return DECLINED;
    }

start_over:

    /* There is a good AuthLDAPURL, right? */
    if (sec->host) {
        ldc = util_ldap_connection_find(r, sec->host, sec->port,
                                       sec->binddn, sec->bindpw, sec->deref,
                                       sec->netscapessl, sec->starttls);
    }
    else {
        ap_log_rerror(APLOG_MARK, APLOG_WARNING|APLOG_NOERRNO, 0, r, 
                      "[%d] auth_ldap authenticate: no sec->host - weird...?", getpid());
        return sec->auth_authoritative? HTTP_UNAUTHORIZED : DECLINED;
    }

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r,
		  "[%d] auth_ldap authenticate: using URL %s", getpid(), sec->url);

    /* Get the password that the client sent */
    if ((result = ap_get_basic_auth_pw(r, &sent_pw))) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r,
		      "[%d] auth_ldap authenticate: "
		      "ap_get_basic_auth_pw() returns %d", getpid(), result);
        util_ldap_connection_close(ldc);
        return result;
    }

    /* build the username filter */
    mod_auth_ldap_build_filter(filtbuf, r, sec);

    /* do the user search */
    result = util_ldap_cache_checkuserid(r, ldc, sec->url, sec->basedn, sec->scope,
                                         sec->attributes, filtbuf, sent_pw, &dn, &vals);
    util_ldap_connection_close(ldc);

    /* sanity check - if server is down, retry it up to 5 times */
    if (result == LDAP_SERVER_DOWN) {
        util_ldap_connection_destroy(ldc);
        if (failures++ <= 5) {
            goto start_over;
        }
    }

    /* handle bind failure */
    if (result != LDAP_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_WARNING|APLOG_NOERRNO, 0, r, 
                      "[%d] auth_ldap authenticate: "
                      "user %s authentication failed; URI %s [%s][%s]",
		      getpid(), r->user, r->uri, ldc->reason, ldap_err2string(result));
        if ((LDAP_INVALID_CREDENTIALS == result) || sec->auth_authoritative) {
            ap_note_basic_auth_failure(r);
            return HTTP_UNAUTHORIZED;
        }
        else {
            return DECLINED;
        }
    }

    /* mark the user and DN */
    req->dn = apr_pstrdup(r->pool, dn);
    req->user = r->user;
    if (sec->user_is_dn) {
        r->user = req->dn;
    }

    /* add environment variables */
    if (sec->attributes && vals) {
        apr_table_t *e = r->subprocess_env;
        int i = 0;
        while (sec->attributes[i]) {
            char *str = apr_pstrcat(r->pool, "AUTHENTICATE_", sec->attributes[i], NULL);
            int j = 13;
            while (str[j]) {
                if (str[j] >= 'a' && str[j] <= 'z') {
                    str[j] = str[j] - ('a' - 'A');
                }
                j++;
            }
            apr_table_setn(e, str, vals[i]);
            i++;
        }
    }

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r, 
		  "[%d] auth_ldap authenticate: accepting %s", getpid(), r->user);

    return OK;
}


/*
 * Authorisation Phase
 * -------------------
 *
 * After checking whether the username and password are correct, we need
 * to check whether that user is authorised to view this resource. The
 * require directive is used to do this:
 *
 *  require valid-user		Any authenticated is allowed in.
 *  require user <username>	This particular user is allowed in.
 *  require group <groupname>	The user must be a member of this group
 *                              in order to be allowed in.
 *  require dn <dn>             The user must have the following DN in the
 *                              LDAP tree to be let in.
 *
 */
int mod_auth_ldap_auth_checker(request_rec *r)
{
    int result = 0;
    mod_auth_ldap_request_t *req =
        (mod_auth_ldap_request_t *)ap_get_module_config(r->request_config,
        &auth_ldap_module);
    mod_auth_ldap_config_t *sec =
        (mod_auth_ldap_config_t *)ap_get_module_config(r->per_dir_config, 
        &auth_ldap_module);

    util_ldap_connection_t *ldc = NULL;
    int m = r->method_number;

    const apr_array_header_t *reqs_arr = ap_requires(r);
    require_line *reqs = reqs_arr ? (require_line *)reqs_arr->elts : NULL;

    register int x;
    const char *t;
    char *w;
    int method_restricted = 0;

    if (!sec->enabled) {
        return DECLINED;
    }

    if (!sec->have_ldap_url) {
        return DECLINED;
    }

    if (sec->host) {
        ldc = util_ldap_connection_find(r, sec->host, sec->port,
                                       sec->binddn, sec->bindpw, sec->deref,
                                       sec->netscapessl, sec->starttls);
        apr_pool_cleanup_register(r->pool, ldc,
                                  mod_auth_ldap_cleanup_connection_close,
                                  apr_pool_cleanup_null);
    }
    else {
        ap_log_rerror(APLOG_MARK, APLOG_WARNING|APLOG_NOERRNO, 0, r, 
                      "[%d] auth_ldap authorise: no sec->host - weird...?", getpid());
        return sec->auth_authoritative? HTTP_UNAUTHORIZED : DECLINED;
    }

    /* 
     * If there are no elements in the group attribute array, the default should be
     * member and uniquemember; populate the array now.
     */
    if (sec->groupattr->nelts == 0) {
        struct mod_auth_ldap_groupattr_entry_t *grp;
#if APR_HAS_THREADS
        apr_thread_mutex_lock(sec->lock);
#endif
        grp = apr_array_push(sec->groupattr);
        grp->name = "member";
        grp = apr_array_push(sec->groupattr);
        grp->name = "uniquemember";
#if APR_HAS_THREADS
        apr_thread_mutex_unlock(sec->lock);
#endif
    }

    if (!reqs_arr) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r,
		      "[%d] auth_ldap authorise: no requirements array", getpid());
        return sec->auth_authoritative? HTTP_UNAUTHORIZED : DECLINED;
    }

    /* Loop through the requirements array until there's no elements
     * left, or something causes a return from inside the loop */
    for(x=0; x < reqs_arr->nelts; x++) {
        if (! (reqs[x].method_mask & (1 << m))) {
            continue;
        }
        method_restricted = 1;
	
        t = reqs[x].requirement;
        w = ap_getword(r->pool, &t, ' ');
    
        if (strcmp(w, "valid-user") == 0) {
            /*
             * Valid user will always be true if we authenticated with ldap,
             * but when using front page, valid user should only be true if
             * he exists in the frontpage password file. This hack will get
             * auth_ldap to look up the user in the the pw file to really be
             * sure that he's valid. Naturally, it requires mod_auth to be
             * compiled in, but if mod_auth wasn't in there, then the need
             * for this hack wouldn't exist anyway.
             */
            if (sec->frontpage_hack) {
	        ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r, 
			      "[%d] auth_ldap authorise: "
			      "deferring authorisation to mod_auth (FP Hack)", 
			      getpid());
                return OK;
            }
            else {
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r, 
                              "[%d] auth_ldap authorise: "
                              "successful authorisation because user "
                              "is valid-user", getpid());
                return OK;
            }
        }
        else if (strcmp(w, "user") == 0) {
            if (req->dn == NULL || strlen(req->dn) == 0) {
	        ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r,
                              "[%d] auth_ldap authorise: "
                              "require user: user's DN has not been defined; failing authorisation", 
                              getpid());
                return sec->auth_authoritative? HTTP_UNAUTHORIZED : DECLINED;
            }
            /* 
             * First do a whole-line compare, in case it's something like
             *   require user Babs Jensen
             */
            result = util_ldap_cache_compare(r, ldc, sec->url, req->dn, sec->attribute, t);
            switch(result) {
                case LDAP_COMPARE_TRUE: {
                    ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r, 
                                  "[%d] auth_ldap authorise: "
                                  "require user: authorisation successful", getpid());
                    return OK;
                }
                default: {
                    ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r, 
                                  "[%d] auth_ldap authorise: require user: "
                                  "authorisation failed [%s][%s]", getpid(),
                                  ldc->reason, ldap_err2string(result));
                }
            }
            /* 
             * Now break apart the line and compare each word on it 
             */
            while (t[0]) {
	        w = ap_getword_conf(r->pool, &t);
                result = util_ldap_cache_compare(r, ldc, sec->url, req->dn, sec->attribute, w);
                switch(result) {
                    case LDAP_COMPARE_TRUE: {
                        ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r, 
                                      "[%d] auth_ldap authorise: "
                                      "require user: authorisation successful", getpid());
                        return OK;
                    }
                    default: {
                        ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r, 
                                      "[%d] auth_ldap authorise: "
                                      "require user: authorisation failed [%s][%s]",
                                      getpid(), ldc->reason, ldap_err2string(result));
                    }
                }
            }
        }
        else if (strcmp(w, "dn") == 0) {
            if (req->dn == NULL || strlen(req->dn) == 0) {
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r,
                              "[%d] auth_ldap authorise: "
                              "require dn: user's DN has not been defined; failing authorisation", 
                              getpid());
                return sec->auth_authoritative? HTTP_UNAUTHORIZED : DECLINED;
            }

            result = util_ldap_cache_comparedn(r, ldc, sec->url, req->dn, t, sec->compare_dn_on_server);
            switch(result) {
                case LDAP_COMPARE_TRUE: {
                    ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r, 
                                  "[%d] auth_ldap authorise: "
                                  "require dn: authorisation successful", getpid());
                    return OK;
                }
                default: {
                    ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r, 
                                  "[%d] auth_ldap authorise: "
                                  "require dn: LDAP error [%s][%s]",
                                  getpid(), ldc->reason, ldap_err2string(result));
                }
            }
        }
        else if (strcmp(w, "group") == 0) {
            struct mod_auth_ldap_groupattr_entry_t *ent = (struct mod_auth_ldap_groupattr_entry_t *) sec->groupattr->elts;
            int i;

            if (sec->group_attrib_is_dn) {
                if (req->dn == NULL || strlen(req->dn) == 0) {
                    ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r,
                                  "[%d] auth_ldap authorise: require group: user's DN has not been defined; failing authorisation", 
                                  getpid());
                    return sec->auth_authoritative? HTTP_UNAUTHORIZED : DECLINED;
                }
            }
            else {
                if (req->user == NULL || strlen(req->user) == 0) {
	            /* We weren't called in the authentication phase, so we didn't have a 
                     * chance to set the user field. Do so now. */
                    req->user = r->user;
                }
            }

            ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r, 
                          "[%d] auth_ldap authorise: require group: testing for group membership in `%s'", 
		          getpid(), t);

            for (i = 0; i < sec->groupattr->nelts; i++) {
	        ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r, 
                              "[%d] auth_ldap authorise: require group: testing for %s: %s (%s)", getpid(),
                              ent[i].name, sec->group_attrib_is_dn ? req->dn : req->user, t);

                result = util_ldap_cache_compare(r, ldc, sec->url, t, ent[i].name, 
                                     sec->group_attrib_is_dn ? req->dn : req->user);
                switch(result) {
                    case LDAP_COMPARE_TRUE: {
                        ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r, 
                                      "[%d] auth_ldap authorise: require group: "
                                      "authorisation successful (attribute %s) [%s][%s]",
                                      getpid(), ent[i].name, ldc->reason, ldap_err2string(result));
                        return OK;
                    }
                    default: {
                        ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r, 
                                      "[%d] auth_ldap authorise: require group: "
                                      "authorisation failed [%s][%s]",
                                      getpid(), ldc->reason, ldap_err2string(result));
                    }
                }
            }
        }
    }

    if (!method_restricted) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r, 
                      "[%d] auth_ldap authorise: agreeing because non-restricted", 
                      getpid());
        return OK;
    }

    if (!sec->auth_authoritative) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r, 
                      "[%d] auth_ldap authorise: declining to authorise", getpid());
        return DECLINED;
    }

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r, 
                  "[%d] auth_ldap authorise: authorisation denied", getpid());
    ap_note_basic_auth_failure (r);

    return HTTP_UNAUTHORIZED;
}


/* ---------------------------------------- */
/* config directives */


void *mod_auth_ldap_create_dir_config(apr_pool_t *p, char *d)
{
    mod_auth_ldap_config_t *sec = 
        (mod_auth_ldap_config_t *)apr_pcalloc(p, sizeof(mod_auth_ldap_config_t));

    sec->pool = p;
#if APR_HAS_THREADS
    apr_thread_mutex_create(&sec->lock, APR_THREAD_MUTEX_DEFAULT, p);
#endif
    sec->auth_authoritative = 1;
    sec->enabled = 1;
    sec->groupattr = apr_array_make(p, GROUPATTR_MAX_ELTS, 
				   sizeof(struct mod_auth_ldap_groupattr_entry_t));

    sec->have_ldap_url = 0;
    sec->url = "";
    sec->host = NULL;
    sec->binddn = NULL;
    sec->bindpw = NULL;
    sec->deref = always;
    sec->group_attrib_is_dn = 1;

    sec->frontpage_hack = 0;
    sec->netscapessl = 0;
    sec->starttls = 0;

    sec->user_is_dn = 0;
    sec->compare_dn_on_server = 0;

    return sec;
}

/* 
 * Use the ldap url parsing routines to break up the ldap url into
 * host and port.
 */
static const char *mod_auth_ldap_parse_url(cmd_parms *cmd, 
                                    void *config,
                                    const char *url)
{
    int result;
    apr_ldap_url_desc_t *urld;

    mod_auth_ldap_config_t *sec = config;

    ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0,
	         cmd->server, "[%d] auth_ldap url parse: `%s'", 
	         getpid(), url);

    result = apr_ldap_url_parse(url, &(urld));
    if (result != LDAP_SUCCESS) {
        switch (result) {
        case LDAP_URL_ERR_NOTLDAP:
            return "LDAP URL does not begin with ldap://";
        case LDAP_URL_ERR_NODN:
            return "LDAP URL does not have a DN";
        case LDAP_URL_ERR_BADSCOPE:
            return "LDAP URL has an invalid scope";
        case LDAP_URL_ERR_MEM:
            return "Out of memory parsing LDAP URL";
        default:
            return "Could not parse LDAP URL";
        }
    }
    sec->url = apr_pstrdup(cmd->pool, url);

    ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0,
	         cmd->server, "[%d] auth_ldap url parse: Host: %s", getpid(), urld->lud_host);
    ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0,
	         cmd->server, "[%d] auth_ldap url parse: Port: %d", getpid(), urld->lud_port);
    ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0,
	         cmd->server, "[%d] auth_ldap url parse: DN: %s", getpid(), urld->lud_dn);
    ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0,
	         cmd->server, "[%d] auth_ldap url parse: attrib: %s", getpid(), urld->lud_attrs? urld->lud_attrs[0] : "(null)");
    ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0,
	         cmd->server, "[%d] auth_ldap url parse: scope: %s", getpid(), 
	         (urld->lud_scope == LDAP_SCOPE_SUBTREE? "subtree" : 
		 urld->lud_scope == LDAP_SCOPE_BASE? "base" : 
		 urld->lud_scope == LDAP_SCOPE_ONELEVEL? "onelevel" : "unknown"));
    ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0,
	         cmd->server, "[%d] auth_ldap url parse: filter: %s", getpid(), urld->lud_filter);

    /* Set all the values, or at least some sane defaults */
    if (sec->host) {
        char *p = apr_palloc(cmd->pool, strlen(sec->host) + strlen(urld->lud_host) + 2);
        strcpy(p, urld->lud_host);
        strcat(p, " ");
        strcat(p, sec->host);
        sec->host = p;
    }
    else {
        sec->host = urld->lud_host? apr_pstrdup(cmd->pool, urld->lud_host) : "localhost";
    }
    sec->basedn = urld->lud_dn? apr_pstrdup(cmd->pool, urld->lud_dn) : "";
    if (urld->lud_attrs && urld->lud_attrs[0]) {
        int i = 1;
        while (urld->lud_attrs[i]) {
            i++;
        }
        sec->attributes = apr_pcalloc(cmd->pool, sizeof(char *) * (i+1));
        i = 0;
        while (urld->lud_attrs[i]) {
            sec->attributes[i] = apr_pstrdup(cmd->pool, urld->lud_attrs[i]);
            i++;
        }
        sec->attribute = sec->attributes[0];
    }
    else {
        sec->attribute = "uid";
    }

    sec->scope = urld->lud_scope == LDAP_SCOPE_ONELEVEL ?
        LDAP_SCOPE_ONELEVEL : LDAP_SCOPE_SUBTREE;

    if (urld->lud_filter) {
        if (urld->lud_filter[0] == '(') {
            /* 
	     * Get rid of the surrounding parens; later on when generating the
	     * filter, they'll be put back.
             */
            sec->filter = apr_pstrdup(cmd->pool, urld->lud_filter+1);
            sec->filter[strlen(sec->filter)-1] = '\0';
        }
        else {
            sec->filter = apr_pstrdup(cmd->pool, urld->lud_filter);
        }
    }
    else {
        sec->filter = "objectclass=*";
    }
    if (strncmp(url, "ldaps", 5) == 0) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0,
		     cmd->server, "[%d] auth_ldap parse url: requesting secure LDAP", getpid());
#ifdef APU_HAS_LDAP_STARTTLS
        sec->port = urld->lud_port? urld->lud_port : LDAPS_PORT;
        sec->starttls = 1;
#else
#ifdef APU_HAS_LDAP_NETSCAPE_SSL
        sec->port = urld->lud_port? urld->lud_port : LDAPS_PORT;
        sec->netscapessl = 1;
#else
        return "Secure LDAP (ldaps://) not supported. Rebuild APR-Util";
#endif
#endif
    }
    else {
        ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0,
		     cmd->server, "[%d] auth_ldap parse url: not requesting secure LDAP", getpid());
        sec->netscapessl = 0;
        sec->starttls = 0;
        sec->port = urld->lud_port? urld->lud_port : LDAP_PORT;
    }

    sec->have_ldap_url = 1;
    apr_ldap_free_urldesc(urld);
    return NULL;
}

static const char *mod_auth_ldap_set_deref(cmd_parms *cmd, void *config, const char *arg)
{
    mod_auth_ldap_config_t *sec = config;

    if (strcmp(arg, "never") == 0 || strcasecmp(arg, "off") == 0) {
        sec->deref = never;
    }
    else if (strcmp(arg, "searching") == 0) {
        sec->deref = searching;
    }
    else if (strcmp(arg, "finding") == 0) {
        sec->deref = finding;
    }
    else if (strcmp(arg, "always") == 0 || strcasecmp(arg, "on") == 0) {
        sec->deref = always;
    }
    else {
        return "Unrecognized value for AuthLDAPAliasDereference directive";
    }
    return NULL;
}

static const char *mod_auth_ldap_add_group_attribute(cmd_parms *cmd, void *config, const char *arg)
{
    struct mod_auth_ldap_groupattr_entry_t *new;

    mod_auth_ldap_config_t *sec = config;

    if (sec->groupattr->nelts > GROUPATTR_MAX_ELTS)
        return "Too many AuthLDAPGroupAttribute directives";

    new = apr_array_push(sec->groupattr);
    new->name = apr_pstrdup(cmd->pool, arg);
  
    return NULL;
}

command_rec mod_auth_ldap_cmds[] = {
    AP_INIT_TAKE1("AuthLDAPURL", mod_auth_ldap_parse_url, NULL, OR_AUTHCFG, 
                  "URL to define LDAP connection. This should be an RFC 2255 complaint\n"
                  "URL of the form ldap://host[:port]/basedn[?attrib[?scope[?filter]]].\n"
                  "<ul>\n"
                  "<li>Host is the name of the LDAP server. Use a space separated list of hosts \n"
                  "to specify redundant servers.\n"
                  "<li>Port is optional, and specifies the port to connect to.\n"
                  "<li>basedn specifies the base DN to start searches from\n"
                  "<li>Attrib specifies what attribute to search for in the directory. If not "
                  "provided, it defaults to <b>uid</b>.\n"
                  "<li>Scope is the scope of the search, and can be either <b>sub</b> or "
                  "<b>one</b>. If not provided, the default is <b>sub</b>.\n"
                  "<li>Filter is a filter to use in the search. If not provided, "
                  "defaults to <b>(objectClass=*)</b>.\n"
                  "</ul>\n"
                  "Searches are performed using the attribute and the filter combined. "
                  "For example, assume that the\n"
                  "LDAP URL is <b>ldap://ldap.airius.com/ou=People, o=Airius?uid?sub?(posixid=*)</b>. "
                  "Searches will\n"
                  "be done using the filter <b>(&((posixid=*))(uid=<i>username</i>))</b>, "
                  "where <i>username</i>\n"
                  "is the user name passed by the HTTP client. The search will be a subtree "
                  "search on the branch <b>ou=People, o=Airius</b>."),

    AP_INIT_TAKE1("AuthLDAPBindDN", ap_set_string_slot,
                  (void *)APR_OFFSETOF(mod_auth_ldap_config_t, binddn), OR_AUTHCFG,
                  "DN to use to bind to LDAP server. If not provided, will do an anonymous bind."),

    AP_INIT_TAKE1("AuthLDAPBindPassword", ap_set_string_slot,
                  (void *)APR_OFFSETOF(mod_auth_ldap_config_t, bindpw), OR_AUTHCFG,
                  "Password to use to bind to LDAP server. If not provided, will do an anonymous bind."),

    AP_INIT_FLAG("AuthLDAPRemoteUserIsDN", ap_set_flag_slot,
                 (void *)APR_OFFSETOF(mod_auth_ldap_config_t, user_is_dn), OR_AUTHCFG,
                 "Set to 'on' to set the REMOTE_USER environment variable to be the full "
                 "DN of the remote user. By default, this is set to off, meaning that "
                 "the REMOTE_USER variable will contain whatever value the remote user sent."),

    AP_INIT_FLAG("AuthLDAPAuthoritative", ap_set_flag_slot,
                 (void *)APR_OFFSETOF(mod_auth_ldap_config_t, auth_authoritative), OR_AUTHCFG,
                 "Set to 'off' to allow access control to be passed along to lower modules if "
                 "the UserID and/or group is not known to this module"),

    AP_INIT_FLAG("AuthLDAPCompareDNOnServer", ap_set_flag_slot,
                 (void *)APR_OFFSETOF(mod_auth_ldap_config_t, compare_dn_on_server), OR_AUTHCFG,
                 "Set to 'on' to force auth_ldap to do DN compares (for the \"require dn\" "
                 "directive) using the server, and set it 'off' to do the compares locally "
                 "(at the expense of possible false matches). See the documentation for "
                 "a complete description of this option."),

    AP_INIT_ITERATE("AuthLDAPGroupAttribute", mod_auth_ldap_add_group_attribute, NULL, OR_AUTHCFG,
                    "A list of attributes used to define group membership - defaults to "
                    "member and uniquemember"),

    AP_INIT_FLAG("AuthLDAPGroupAttributeIsDN", ap_set_flag_slot,
                 (void *)APR_OFFSETOF(mod_auth_ldap_config_t, group_attrib_is_dn), OR_AUTHCFG,
                 "If set to 'on', auth_ldap uses the DN that is retrieved from the server for"
                 "subsequent group comparisons. If set to 'off', auth_ldap uses the string"
                 "provided by the client directly. Defaults to 'on'."),

    AP_INIT_TAKE1("AuthLDAPDereferenceAliases", mod_auth_ldap_set_deref, NULL, OR_AUTHCFG,
                  "Determines how aliases are handled during a search. Can bo one of the"
                  "values \"never\", \"searching\", \"finding\", or \"always\". "
                  "Defaults to always."),

    AP_INIT_FLAG("AuthLDAPEnabled", ap_set_flag_slot,
                 (void *)APR_OFFSETOF(mod_auth_ldap_config_t, enabled), OR_AUTHCFG,
                 "Set to off to disable auth_ldap, even if it's been enabled in a higher tree"),
 
    AP_INIT_FLAG("AuthLDAPFrontPageHack", ap_set_flag_slot,
                 (void *)APR_OFFSETOF(mod_auth_ldap_config_t, frontpage_hack), OR_AUTHCFG,
                 "Set to 'on' to support Microsoft FrontPage"),

#ifdef APU_HAS_LDAP_STARTTLS
    AP_INIT_FLAG("AuthLDAPStartTLS", ap_set_flag_slot,
                 (void *)APR_OFFSETOF(mod_auth_ldap_config_t, starttls), OR_AUTHCFG,
                 "Set to 'on' to start TLS after connecting to the LDAP server."),
#endif /* APU_HAS_LDAP_STARTTLS */

    {NULL}
};

static void mod_auth_ldap_register_hooks(apr_pool_t *p)
{
    ap_hook_check_user_id(mod_auth_ldap_check_user_id, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_auth_checker(mod_auth_ldap_auth_checker, NULL, NULL, APR_HOOK_MIDDLE);
}

module auth_ldap_module = {
   STANDARD20_MODULE_STUFF,
   mod_auth_ldap_create_dir_config,	/* dir config creater */
   NULL,				/* dir merger --- default is to override */
   NULL,				/* server config */
   NULL,				/* merge server config */
   mod_auth_ldap_cmds,			/* command table */
   mod_auth_ldap_register_hooks,	/* set up request processing hooks */
};
