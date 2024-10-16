/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "ap_provider.h"
#include "httpd.h"
#include "http_config.h"
#include "ap_provider.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"
#include "util_ldap.h"

#include "mod_auth.h"

#include "apr_strings.h"
#include "apr_xlate.h"
#define APR_WANT_STRFUNC
#include "apr_want.h"
#include "apr_lib.h"
#include "apu_version.h"

#include <ctype.h>

#if !APR_HAS_LDAP
#error mod_authnz_ldap requires APR-util to have LDAP support built in. To fix add --with-ldap to ./configure.
#endif

static const char *default_attributes[3] = { "member", "uniqueMember", NULL };

typedef struct {
    apr_pool_t *pool;               /* Pool that this config is allocated from */
#if APR_HAS_THREADS
    apr_thread_mutex_t *lock;       /* Lock for this config */
#endif

    /* These parameters are all derived from the AuthLDAPURL directive */
    char *url;                      /* String representation of the URL */

    char *host;                     /* Name of the LDAP server (or space separated list) */
    int port;                       /* Port of the LDAP server */
    char *basedn;                   /* Base DN to do all searches from */
    const char *attribute;          /* Attribute to search for */
    const char **attributes;        /* Array of all the attributes to return */
    int scope;                      /* Scope of the search */
    char *filter;                   /* Filter to further limit the search  */
    apr_ldap_deref_e deref;         /* how to handle alias dereferening */
    char *binddn;                   /* DN to bind to server (can be NULL) */
    char *bindpw;                   /* Password to bind to server (can be NULL) */
    int bind_authoritative;         /* If true, will return errors when bind fails */

    int user_is_dn;                 /* If true, r->user is replaced by DN during authn */
    char *remote_user_attribute;    /* If set, r->user is replaced by this attribute during authn */
    int compare_dn_on_server;       /* If true, will use server to do DN compare */

    int have_ldap_url;              /* Set if we have found an LDAP url */

    apr_array_header_t *groupattr;  /* List of Group attributes identifying user members. Default:"member uniqueMember" */
    int group_attrib_is_dn;         /* If true, the group attribute is the DN, otherwise,
                                        it's the exact string passed by the HTTP client */
    const char **sgAttributes;      /* Array of strings constructed (post-config) from subgroupattrs. Last entry is NULL. */
    apr_array_header_t *subgroupclasses; /* List of object classes of sub-groups. Default:"groupOfNames groupOfUniqueNames" */
    int maxNestingDepth;            /* Maximum recursive nesting depth permitted during subgroup processing. Default: 10 */

    int secure;                     /* True if SSL connections are requested */
    char *authz_prefix;             /* Prefix for environment variables added during authz */
    int initial_bind_as_user;               /* true if we should try to bind (to lookup DN) directly with the basic auth username */
    ap_regex_t *bind_regex;         /* basic auth -> bind'able username regex */
    const char *bind_subst;         /* basic auth -> bind'able username substitution */
    int search_as_user;             /* true if authz searches should be done with the users credentials (when we did authn) */
    int compare_as_user;            /* true if authz compares should be done with the users credentials (when we did authn) */
} authn_ldap_config_t;

typedef struct {
    const char *dn;                 /* The saved dn from a successful search */
    const char *user;               /* The username provided by the client */
    apr_array_header_t **vals;      /* The additional values pulled during the DN search*/
    const char *password;           /* if this module successfully authenticates, the basic auth password, else null */
    apr_pool_t *ldc_pool;           /* a short-lived pool to trigger cleanups on any acquired LDCs */
} authn_ldap_request_t;

enum auth_ldap_phase {
    LDAP_AUTHN, LDAP_AUTHZ
};

enum auth_ldap_optype {
    LDAP_SEARCH, LDAP_COMPARE, LDAP_COMPARE_AND_SEARCH /* nested groups */
};

/* maximum group elements supported */
#define GROUPATTR_MAX_ELTS 10

module AP_MODULE_DECLARE_DATA authnz_ldap_module;

static APR_OPTIONAL_FN_TYPE(uldap_connection_close) *util_ldap_connection_close;
static APR_OPTIONAL_FN_TYPE(uldap_connection_find_uri) *util_ldap_connection_find_uri;
static APR_OPTIONAL_FN_TYPE(uldap_cache_comparedn) *util_ldap_cache_comparedn;
static APR_OPTIONAL_FN_TYPE(uldap_cache_compare) *util_ldap_cache_compare;
static APR_OPTIONAL_FN_TYPE(uldap_cache_check_subgroups) *util_ldap_cache_check_subgroups;
static APR_OPTIONAL_FN_TYPE(uldap_cache_checkuserid) *util_ldap_cache_checkuserid;
static APR_OPTIONAL_FN_TYPE(uldap_cache_getuserdn) *util_ldap_cache_getuserdn;

static apr_hash_t *charset_conversions = NULL;
static char *to_charset = NULL;           /* UTF-8 identifier derived from the charset.conv file */

/* Derive a code page ID give a language name or ID */
static char* derive_codepage_from_lang (apr_pool_t *p, char *language)
{
    char *charset;

    if (!language)          /* our default codepage */
        return apr_pstrdup(p, "ISO-8859-1");

    charset = (char*) apr_hash_get(charset_conversions, language, APR_HASH_KEY_STRING);

    /*
     * Test if language values like 'en-US' return a match from the charset
     * conversion map when shortened to 'en'.
     */
    if (!charset && strlen(language) > 3 && language[2] == '-') {
        char *language_short = apr_pstrndup(p, language, 2);
        charset = (char*) apr_hash_get(charset_conversions, language_short, APR_HASH_KEY_STRING);
    }

    if (charset) {
        charset = apr_pstrdup(p, charset);
    }

    return charset;
}

static apr_xlate_t* get_conv_set (request_rec *r)
{
    char *lang_line = (char*)apr_table_get(r->headers_in, "accept-language");
    char *lang;
    apr_xlate_t *convset;

    if (lang_line) {
        lang_line = apr_pstrdup(r->pool, lang_line);
        for (lang = lang_line;*lang;lang++) {
            if ((*lang == ',') || (*lang == ';')) {
                *lang = '\0';
                break;
            }
        }
        lang = derive_codepage_from_lang(r->pool, lang_line);

        if (lang && (apr_xlate_open(&convset, to_charset, lang, r->pool) == APR_SUCCESS)) {
            return convset;
        }
    }

    return NULL;
}


static const char* authn_ldap_xlate_password(request_rec *r,
                                             const char* sent_password)
{
    apr_xlate_t *convset = NULL;
    apr_size_t inbytes;
    apr_size_t outbytes;
    char *outbuf;

    if (charset_conversions && (convset = get_conv_set(r)) ) {
        inbytes = strlen(sent_password);
        outbytes = (inbytes+1)*3;
        outbuf = apr_pcalloc(r->pool, outbytes);

        /* Convert the password to UTF-8. */
        if (apr_xlate_conv_buffer(convset, sent_password, &inbytes, outbuf,
                                  &outbytes) == APR_SUCCESS)
            return outbuf;
    }

    return sent_password;
}


/*
 * Build the search filter, or at least as much of the search filter that
 * will fit in the buffer, and return APR_EGENERAL if it won't fit, otherwise
 * APR_SUCCESS.
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
static apr_status_t authn_ldap_build_filter(char filtbuf[FILTER_LENGTH],
                             request_rec *r,
                             const char *user,
                             const char *filter,
                             authn_ldap_config_t *sec)
{
    char *q;
    const char *p, *filtbuf_end;
    apr_xlate_t *convset = NULL;
    apr_size_t inbytes;
    apr_size_t outbytes;
    char *outbuf;
    int nofilter = 0, len;
    apr_status_t rv = APR_SUCCESS;

    if (!filter) {
        filter = sec->filter;
    }

    if (charset_conversions) {
        convset = get_conv_set(r);
    }

    if (convset) {
        inbytes = strlen(user);
        outbytes = (inbytes+1)*3;
        outbuf = apr_pcalloc(r->pool, outbytes);

        /* Convert the user name to UTF-8.  This is only valid for LDAP v3 */
        if (apr_xlate_conv_buffer(convset, user, &inbytes, outbuf, &outbytes) == APR_SUCCESS) {
            user = outbuf;
        }
    }

    /*
     * Create the first part of the filter, which consists of the
     * config-supplied portions.
     */

    if ((nofilter = (!filter || !*filter || !strcasecmp(filter, "none")))) { 
        len = apr_snprintf(filtbuf, FILTER_LENGTH, "(%s=", sec->attribute);
    }
    else { 
        len = apr_snprintf(filtbuf, FILTER_LENGTH, "(&(%s)(%s=", filter, sec->attribute);
    }

    /*
     * Now add the client-supplied username to the filter, ensuring that any
     * LDAP filter metachars are escaped.
     */
    filtbuf_end = filtbuf + FILTER_LENGTH - 1;
    for (p = user, q = filtbuf + len; *p; ) {
        if (strchr("*()\\", *p) != NULL) {
#if APR_HAS_MICROSOFT_LDAPSDK
            if (q + 3 >= filtbuf_end) { /* accounts for final \0 */
                rv = APR_EGENERAL;
                goto out;
            }
            *q++ = '\\';
            switch ( *p++ )
            {
              case '*':
                *q++ = '2';
                *q++ = 'a';
                break;
              case '(':
                *q++ = '2';
                *q++ = '8';
                break;
              case ')':
                *q++ = '2';
                *q++ = '9';
                break;
              case '\\':
                *q++ = '5';
                *q++ = 'c';
                break;
            }
#else
            if (q + 2 >= filtbuf_end) { /* accounts for final \0 */
                rv = APR_EGENERAL;
                goto out;
            }
            *q++ = '\\';
            *q++ = *p++;
#endif
        }
        else {
            if (q + 1 >= filtbuf_end) { /* accounts for final \0 */
                rv = APR_EGENERAL;
                goto out;
            }
            *q++ = *p++;
        }
    }

    /*
     * Append the closing parens of the filter, unless doing so would
     * overrun the buffer.
     */

    if (nofilter) { 
        if (q + 1 >= filtbuf_end) { /* accounts for final \0 */
            rv = APR_EGENERAL;
            goto out;
        }
        *q++ = ')';
    } 
    else { 
        if (q + 2 >= filtbuf_end) { /* accounts for final \0 */
            rv = APR_EGENERAL;
            goto out;
        }
        *q++ = ')';
        *q++ = ')';
    }

out:
    *q = '\0';
    return rv;
}

static void *create_authnz_ldap_dir_config(apr_pool_t *p, char *d)
{
    authn_ldap_config_t *sec =
        (authn_ldap_config_t *)apr_pcalloc(p, sizeof(authn_ldap_config_t));

    sec->pool = p;
#if APR_HAS_THREADS
    apr_thread_mutex_create(&sec->lock, APR_THREAD_MUTEX_DEFAULT, p);
#endif
/*
    sec->authz_enabled = 1;
*/
    sec->groupattr = apr_array_make(p, GROUPATTR_MAX_ELTS,
                                    sizeof(struct mod_auth_ldap_groupattr_entry_t));
    sec->subgroupclasses = apr_array_make(p, GROUPATTR_MAX_ELTS,
                                    sizeof(struct mod_auth_ldap_groupattr_entry_t));

    sec->have_ldap_url = 0;
    sec->url = "";
    sec->host = NULL;
    sec->binddn = NULL;
    sec->bindpw = NULL;
    sec->bind_authoritative = 1;
    sec->deref = APR_LDAP_DEREF_ALWAYS;
    sec->group_attrib_is_dn = 1;
    sec->secure = -1;   /*Initialize to unset*/
    sec->maxNestingDepth = 0;
    sec->sgAttributes = apr_pcalloc(p, sizeof (char *) * GROUPATTR_MAX_ELTS + 1);

    sec->user_is_dn = 0;
    sec->remote_user_attribute = NULL;
    sec->compare_dn_on_server = 0;

    sec->authz_prefix = AUTHZ_PREFIX;

    return sec;
}

static apr_status_t authnz_ldap_cleanup_connection_close(void *param)
{
    util_ldap_connection_t *ldc = param;
    ap_log_rerror(APLOG_MARK, APLOG_TRACE4, 0, ldc->r, "Release ldc %pp", ldc);
    util_ldap_connection_close(ldc);
    return APR_SUCCESS;
}

static int set_request_vars(request_rec *r, enum auth_ldap_phase phase, apr_array_header_t **vals)
{
    char *prefix = NULL;
    int prefix_len;
    int remote_user_attribute_set = 0;
    authn_ldap_config_t *sec =
        (authn_ldap_config_t *)ap_get_module_config(r->per_dir_config, &authnz_ldap_module);

    prefix = (phase == LDAP_AUTHN) ? AUTHN_PREFIX : sec->authz_prefix;
    prefix_len = strlen(prefix);

    if (sec->attributes && vals) {
        apr_table_t *e = r->subprocess_env;
        int i = 0;
        while (sec->attributes[i] && vals[i]) {
            char *val;
            char *str = apr_pstrcat(r->pool, prefix, sec->attributes[i], NULL);
            int j = prefix_len;
            while (str[j]) {
                str[j] = apr_toupper(str[j]);
                j++;
            }

            val = apr_buffer_pstrncat(r->pool,
                                      (const apr_buffer_t *)vals[i]->elts,
                                      vals[i]->nelts, "; ", APR_BUFFER_BASE64, NULL);

            apr_table_setn(e, str, val);

            /* handle remote_user_attribute, if set */
            if ((phase == LDAP_AUTHN) &&
                sec->remote_user_attribute &&
                !strcmp(sec->remote_user_attribute, sec->attributes[i])) {
                r->user = (char *)apr_pstrdup(r->pool, val);
                remote_user_attribute_set = 1;
            }
            i++;
        }
    }
    return remote_user_attribute_set;
}

static const char *ldap_determine_binddn(request_rec *r, const char *user)
{
    authn_ldap_config_t *sec =
        (authn_ldap_config_t *)ap_get_module_config(r->per_dir_config, &authnz_ldap_module);
    const char *result = user;
    ap_regmatch_t regm[AP_MAX_REG_MATCH];

    if (NULL == user || NULL == sec || !sec->bind_regex || !sec->bind_subst) {
        return result;
    }

    if (!ap_regexec(sec->bind_regex, user, AP_MAX_REG_MATCH, regm, 0)) {
        char *substituted = ap_pregsub(r->pool, sec->bind_subst, user, AP_MAX_REG_MATCH, regm);
        if (NULL != substituted) {
            result = substituted;
        }
    }

    apr_table_set(r->subprocess_env, "LDAP_BINDASUSER", result);

    return result;
}


/** 
 * Some LDAP servers restrict who can search or compare, and the hard-coded ID
 * might be good for the DN lookup but not for later operations. 
 * Requires the per-request config be set to ensure the connection is cleaned up
 */
static util_ldap_connection_t *get_connection_for_authz(request_rec *r, enum auth_ldap_optype type)
{
    authn_ldap_request_t *req =
        (authn_ldap_request_t *)ap_get_module_config(r->request_config, &authnz_ldap_module);
    authn_ldap_config_t *sec =
        (authn_ldap_config_t *)ap_get_module_config(r->per_dir_config, &authnz_ldap_module);
    util_ldap_connection_t *ldc = NULL;

    const char *binddn = sec->binddn;
    const char *bindpw = sec->bindpw;

    if (!req) { 
        ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0, r, APLOGNO(02659)
                      "module error: get_connection_for_authz without "
                      "per-request config");
        return NULL;
    }

    /* If the password isn't set in the per-request config, we didn't
     * authenticate this user, and leave the default credentials */
    if (req->password &&
         ((type == LDAP_SEARCH && sec->search_as_user)    ||
          (type == LDAP_COMPARE && sec->compare_as_user)  ||
          (type == LDAP_COMPARE_AND_SEARCH && sec->compare_as_user && sec->search_as_user))) {
            binddn = req->dn;
            bindpw = req->password;
    }

    ldc = util_ldap_connection_find_uri(r, sec->url,
                                        binddn, bindpw,
                                        sec->deref, sec->secure);

    ap_log_rerror(APLOG_MARK, APLOG_TRACE4, 0, r, "Obtain ldc %pp for authz", ldc);
    apr_pool_cleanup_register(req->ldc_pool, ldc,
                              authnz_ldap_cleanup_connection_close,
                              apr_pool_cleanup_null);
    return ldc;
}


static authn_ldap_request_t* build_request_config(request_rec *r)
{ 
    authn_ldap_request_t *req =
        (authn_ldap_request_t *)apr_pcalloc(r->pool, sizeof(authn_ldap_request_t));
    ap_set_module_config(r->request_config, &authnz_ldap_module, req);
    apr_pool_create(&(req->ldc_pool), r->pool);
    apr_pool_tag(req->ldc_pool, "authn_ldap_req_ldc");
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01740)
                 "ldap authorize: Creating LDAP req structure");
    return req;
}

static void release_ldc(request_rec *r, util_ldap_connection_t *ldc)
{
    authn_ldap_request_t *req =
        (authn_ldap_request_t *)ap_get_module_config(r->request_config, &authnz_ldap_module);

    if (req) { 
        apr_pool_cleanup_kill(req->ldc_pool, ldc, authnz_ldap_cleanup_connection_close);
    }
    authnz_ldap_cleanup_connection_close(ldc);
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
static authn_status authn_ldap_check_password(request_rec *r, const char *user,
                                              const char *password)
{
    char filtbuf[FILTER_LENGTH];
    authn_ldap_config_t *sec =
        (authn_ldap_config_t *)ap_get_module_config(r->per_dir_config, &authnz_ldap_module);

    util_ldap_connection_t *ldc = NULL;
    authn_ldap_request_t *req = NULL;
    apr_status_t result = 0;
    int remote_user_attribute_set = 0;
    const char *dn = NULL;
    const char *utfpassword;


/*
    if (!sec->enabled) {
        return AUTH_USER_NOT_FOUND;
    }
*/

    /*
     * Basic sanity checks before any LDAP operations even happen.
     */
    if (!sec->have_ldap_url) {
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, APLOGNO(02558) 
                      "no AuthLDAPURL");

        return AUTH_GENERAL_ERROR;
    }

    /* Get the password that the client sent */
    if (password == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01692)
                      "auth_ldap authenticate: no password specified");
        return AUTH_GENERAL_ERROR;
    }

    if (user == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01693)
                      "auth_ldap authenticate: no user specified");
        return AUTH_GENERAL_ERROR;
    }

    /*
     * A bind to the server with an empty password always succeeds, so
     * we check to ensure that the password is not empty. This implies
     * that users who actually do have empty passwords will never be
     * able to authenticate with this module. I don't see this as a big
     * problem.
     */
    if (!(*password)) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(10263)
                      "auth_ldap authenticate: empty password specified");
        return AUTH_DENIED;
    }

    /* There is a good AuthLDAPURL, right? */
    if (sec->url) {
        const char *binddn = sec->binddn;
        const char *bindpw = sec->bindpw;
        if (sec->initial_bind_as_user) {
            bindpw = password;
            binddn = ldap_determine_binddn(r, user);
        }

        req = build_request_config(r);
        ldc = util_ldap_connection_find_uri(r, sec->url,
                                            binddn, bindpw,
                                            sec->deref, sec->secure);
    }
    else {
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, APLOGNO(01690)
                      "auth_ldap authenticate: no sec->url - weird...?");
        return AUTH_GENERAL_ERROR;
    }

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01691)
                  "auth_ldap authenticate: using URL %s", sec->url);

    /* build the username filter */
    if (APR_SUCCESS != authn_ldap_build_filter(filtbuf, r, user, NULL, sec)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(02622)
                      "auth_ldap authenticate: ldap filter too long (>%d): %s",
                      FILTER_LENGTH, filtbuf);
        release_ldc(r, ldc);
        return AUTH_GENERAL_ERROR;
    }

    ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r,
                      "auth_ldap authenticate: final authn filter is %s", filtbuf);

    /* convert password to utf-8 */
    utfpassword = authn_ldap_xlate_password(r, password);

    /* do the user search */
    result = util_ldap_cache_checkuserid(r, ldc, sec->url, sec->basedn, sec->scope,
                                         sec->attributes, filtbuf, utfpassword,
                                         &dn, &(req->vals));
    release_ldc(r, ldc);

    /* handle bind failure */
    if (result != APR_SUCCESS) {
        if (!sec->bind_authoritative) {
           ap_log_rerror(APLOG_MARK, APLOG_DEBUG, result, r, APLOGNO(01694)
                      "auth_ldap authenticate: user %s authentication failed; "
                      "URI %s [%s][%s][%s](not authoritative)",
                      user, r->uri, ldc->reason, ldc->result.reason, ldc->result.msg);
           return AUTH_USER_NOT_FOUND;
        }

        ap_log_rerror(APLOG_MARK, APLOG_INFO, result, r, APLOGNO(01695)
                      "auth_ldap authenticate: "
                      "user %s authentication failed; URI %s [%s][%s][%s]",
                      user, r->uri, ldc->reason, ldc->result.reason, ldc->result.msg);

        /* talking to a primitive LDAP server (like RACF-over-LDAP) that doesn't return specific errors */
        if (!strcasecmp(sec->filter, "none") && APR_EGENERAL == result) { 
            return AUTH_USER_NOT_FOUND;
        }

        return (APR_NO_SUCH_OBJECT == result) ? AUTH_USER_NOT_FOUND
                 : (APR_INAPPROPRIATE_AUTH == result) ? AUTH_DENIED
                 : (APR_INVALID_CREDENTIALS == result) ? AUTH_DENIED
                 : (APR_INSUFFICIENT_ACCESS == result) ? AUTH_DENIED
                 : (APR_INSUFFICIENT_RIGHTS == result) ? AUTH_DENIED
                 : (APR_CONSTRAINT_VIOLATION == result) ? AUTH_DENIED
                 : AUTH_GENERAL_ERROR;
    }

    /* mark the user and DN */
    req->dn = dn;
    req->user = user;
    req->password = password;
    if (sec->user_is_dn) {
        r->user = (char *)req->dn;
    }

    /* add environment variables */
    remote_user_attribute_set = set_request_vars(r, LDAP_AUTHN, req->vals);

    /* sanity check */
    if (sec->remote_user_attribute && !remote_user_attribute_set) {
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, APLOGNO(01696)
                  "auth_ldap authenticate: "
                  "REMOTE_USER was to be set with attribute '%s', "
                  "but this attribute was not requested for in the "
                  "LDAP query for the user. REMOTE_USER will fall "
                  "back to username or DN as appropriate.",
                  sec->remote_user_attribute);
    }

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01697)
                  "auth_ldap authenticate: accepting %s", user);

    return AUTH_GRANTED;
}

static authz_status get_dn_for_nonldap_authn(request_rec *r, util_ldap_connection_t *ldc)
{
    apr_status_t result = APR_SUCCESS;
    char filtbuf[FILTER_LENGTH];
    authn_ldap_request_t *req =
        (authn_ldap_request_t *)ap_get_module_config(r->request_config, &authnz_ldap_module);
    authn_ldap_config_t *sec =
        (authn_ldap_config_t *)ap_get_module_config(r->per_dir_config, &authnz_ldap_module);
    const char *dn = NULL;
    int remote_user_attribute_set = 0;

    /* Build the username filter */
    if (APR_SUCCESS != authn_ldap_build_filter(filtbuf, r, r->user, NULL, sec)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(02623)
                "auth_ldap authorize: ldap filter too long (>%d): %s",
                FILTER_LENGTH, filtbuf);
        return AUTHZ_DENIED;
    }

    /* Search for the user DN */
    result = util_ldap_cache_getuserdn(r, ldc, sec->url, sec->basedn,
            sec->scope, sec->attributes, filtbuf, &dn, &(req->vals));

    /* Search failed, log error and return failure */
    if (result != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, result, r, APLOGNO(01701)
                "auth_ldap authorise: User DN not found, %s", ldc->reason);
        return AUTHZ_DENIED;
    }

    req->dn = dn;
    req->user = r->user;

    /* add environment variables */
    remote_user_attribute_set = set_request_vars(r, LDAP_AUTHN, req->vals);

    /* sanity check */
    if (sec->remote_user_attribute && !remote_user_attribute_set) {
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, APLOGNO(10450)
                  "auth_ldap non-ldap authenticate: "
                  "REMOTE_USER was to be set with attribute '%s', "
                  "but this attribute was not requested for in the "
                  "LDAP query for the user. REMOTE_USER will fall "
                  "back to username or DN as appropriate.",
                  sec->remote_user_attribute);
    }

    return AUTHZ_GRANTED;
}

static authz_status ldapuser_check_authorization(request_rec *r,
                                                 const char *require_args,
                                                 const void *parsed_require_args)
{
    apr_status_t result = 0;
    authn_ldap_request_t *req =
        (authn_ldap_request_t *)ap_get_module_config(r->request_config, &authnz_ldap_module);
    authn_ldap_config_t *sec =
        (authn_ldap_config_t *)ap_get_module_config(r->per_dir_config, &authnz_ldap_module);

    util_ldap_connection_t *ldc = NULL;

    const char *err = NULL;
    const ap_expr_info_t *expr = parsed_require_args;
    const char *require;

    const char *t;
    char *w;

    apr_buffer_t buf;

    if (!r->user) {
        return AUTHZ_DENIED_NO_USER;
    }

    if (!sec->have_ldap_url) {
        return AUTHZ_DENIED;
    }

    if (!sec->host) {
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, APLOGNO(01698)
                      "auth_ldap authorize: no sec->host - weird...?");
        return AUTHZ_DENIED;
    }

    /*
     * If we have been authenticated by some other module than mod_authnz_ldap,
     * the req structure needed for authorization needs to be created
     * and populated with the userid and DN of the account in LDAP
     */
    if (!req) {
        req = build_request_config(r);
    }
    ldc = get_connection_for_authz(r, LDAP_COMPARE);
    if (!req->dn) {
        authz_status rv;
        if (!*r->user) {
            ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, APLOGNO(01699)
                          "ldap authorize: Userid is blank, AuthType=%s",
                          r->ap_auth_type);
        }
        rv = get_dn_for_nonldap_authn(r, ldc);
        if (rv != AUTHZ_GRANTED) {
            return rv;
        }
    }
    if (req->dn == NULL || !*req->dn) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01702)
                      "auth_ldap authorize: require user: user's DN has not "
                      "been defined; failing authorization");
        return AUTHZ_DENIED;
    }

    require = ap_expr_str_exec(r, expr, &err);
    if (err) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(02585)
                      "auth_ldap authorize: require user: Can't evaluate expression: %s",
                      err);
        return AUTHZ_DENIED;
    }

    /*
     * First do a whole-line compare, in case it's something like
     *   require user Babs Jensen
     */
    apr_buffer_str_set(&buf, (char *)require, APR_BUFFER_STRING);

    result = util_ldap_cache_compare(r, ldc, sec->url, req->dn, sec->attribute, &buf);
    switch(result) {
        case APR_COMPARE_TRUE: {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01703)
                          "auth_ldap authorize: require user: authorization "
                          "successful");
            set_request_vars(r, LDAP_AUTHZ, req->vals);
            return AUTHZ_GRANTED;
        }
        default: {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, result, r, APLOGNO(01704)
                          "auth_ldap authorize: require user: "
                          "authorization failed [%s]",
                          ldc->reason);
        }
    }

    /*
     * Now break apart the line and compare each word on it
     */
    t = require;
    while ((w = ap_getword_conf(r->pool, &t)) && w[0]) {
        apr_buffer_str_set(&buf, w, APR_BUFFER_STRING);
        result = util_ldap_cache_compare(r, ldc, sec->url, req->dn, sec->attribute, &buf);
        switch(result) {
            case APR_COMPARE_TRUE: {
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01705)
                              "auth_ldap authorize: "
                              "require user: authorization successful");
                set_request_vars(r, LDAP_AUTHZ, req->vals);
                return AUTHZ_GRANTED;
            }
            default: {
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, result, r, APLOGNO(01706)
                              "auth_ldap authorize: "
                              "require user: authorization failed [%s]",
                              ldc->reason);
            }
        }
    }

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01707)
                  "auth_ldap authorize user: authorization denied for "
                  "user %s to %s",
                  r->user, r->uri);

    return AUTHZ_DENIED;
}

static authz_status ldapgroup_check_authorization(request_rec *r,
                                                  const char *require_args,
                                                  const void *parsed_require_args)
{
    apr_status_t result = 0;
    authn_ldap_request_t *req =
        (authn_ldap_request_t *)ap_get_module_config(r->request_config, &authnz_ldap_module);
    authn_ldap_config_t *sec =
        (authn_ldap_config_t *)ap_get_module_config(r->per_dir_config, &authnz_ldap_module);

    util_ldap_connection_t *ldc = NULL;

    const char *err = NULL;
    const ap_expr_info_t *expr = parsed_require_args;
    const char *require;

    const char *t;

    struct mod_auth_ldap_groupattr_entry_t *ent;
    int i;

    if (!r->user) {
        return AUTHZ_DENIED_NO_USER;
    }

    if (!sec->have_ldap_url) {
        return AUTHZ_DENIED;
    }

    if (!sec->host) {
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, APLOGNO(01708)
                      "auth_ldap authorize: no sec->host - weird...?");
        return AUTHZ_DENIED;
    }

    /*
     * If we have been authenticated by some other module than mod_authnz_ldap,
     * the req structure needed for authorization needs to be created
     * and populated with the userid and DN of the account in LDAP
     */
    if (!req) {
        req = build_request_config(r);
    }
    ldc = get_connection_for_authz(r, LDAP_COMPARE);
    if (!req->dn) {
        authz_status rv;
        if (!*r->user) {
            ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, APLOGNO(10490)
                          "ldap authorize: Userid is blank, AuthType=%s",
                          r->ap_auth_type);
        }
        rv = get_dn_for_nonldap_authn(r, ldc);
        if (rv != AUTHZ_GRANTED) {
            return rv;
        }
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
        apr_buffer_str_set(&grp->name, "member", APR_BUFFER_STRING);
        grp = apr_array_push(sec->groupattr);
        apr_buffer_str_set(&grp->name, "uniqueMember", APR_BUFFER_STRING);
#if APR_HAS_THREADS
        apr_thread_mutex_unlock(sec->lock);
#endif
    }

    /*
     * If there are no elements in the sub group classes array, the default
     * should be groupOfNames and groupOfUniqueNames; populate the array now.
     */
    if (sec->subgroupclasses->nelts == 0) {
        struct mod_auth_ldap_groupattr_entry_t *grp;
#if APR_HAS_THREADS
        apr_thread_mutex_lock(sec->lock);
#endif
        grp = apr_array_push(sec->subgroupclasses);
        apr_buffer_str_set(&grp->name, "groupOfNames", APR_BUFFER_STRING);
        grp = apr_array_push(sec->subgroupclasses);
        apr_buffer_str_set(&grp->name, "groupOfUniqueNames", APR_BUFFER_STRING);
#if APR_HAS_THREADS
        apr_thread_mutex_unlock(sec->lock);
#endif
    }

    /*
     * If we have been authenticated by some other module than mod_auth_ldap,
     * the req structure needed for authorization needs to be created
     * and populated with the userid and DN of the account in LDAP
     */

    if (!*r->user) {
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, APLOGNO(01709)
            "ldap authorize: Userid is blank, AuthType=%s",
            r->ap_auth_type);
    }

   
    ent = (struct mod_auth_ldap_groupattr_entry_t *) sec->groupattr->elts;

    if (sec->group_attrib_is_dn) {
        if (req->dn == NULL || !*req->dn) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01712)
                          "auth_ldap authorize: require group: user's DN has "
                          "not been defined; failing authorization for user %s",
                          r->user);
            return AUTHZ_DENIED;
        }
    }
    else {
        if (req->user == NULL || !*req->user) {
            /* We weren't called in the authentication phase, so we didn't have a
             * chance to set the user field. Do so now. */
            req->user = r->user;
        }
    }

    require = ap_expr_str_exec(r, expr, &err);
    if (err) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(02586)
                      "auth_ldap authorize: require group: Can't evaluate expression: %s",
                      err);
        return AUTHZ_DENIED;
    }

    t = require;

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01713)
                  "auth_ldap authorize: require group: testing for group "
                  "membership in \"%s\"",
                  t);

    /* PR52464 exhaust attrs in base group before checking subgroups */
    for (i = 0; i < sec->groupattr->nelts; i++) {

        apr_buffer_t buf;

        const char *name = apr_buffer_str(&ent[i].name);
        if (!name) {
            name = apr_buffer_pstrdup(r->pool, &ent[i].name);
        }

        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01714)
                      "auth_ldap authorize: require group: testing for %s: "
                      "%s (%s)",
                      name,
                      sec->group_attrib_is_dn ? req->dn : req->user, t);

        if (sec->group_attrib_is_dn) {
            apr_buffer_str_set(&buf, (char *)req->dn, APR_BUFFER_STRING);
        }
        else {
            apr_buffer_str_set(&buf, (char *)req->user, APR_BUFFER_STRING);
        }

        result = util_ldap_cache_compare(r, ldc, sec->url, t, name, &buf);
        if (result == APR_COMPARE_TRUE) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, result, r, APLOGNO(01715)
                          "auth_ldap authorize: require group: "
                          "authorization successful (attribute %s) "
                          "[%s]",
                          name, ldc->reason);
            set_request_vars(r, LDAP_AUTHZ, req->vals);
            return AUTHZ_GRANTED;
        }
        else { 
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, result, r, APLOGNO(01719)
                              "auth_ldap authorize: require group \"%s\": "
                              "didn't match with attr %s [%s]",
                              t, name, ldc->reason);
        }
    }
    
    /* nested groups need searches and compares, so grab a new handle */
    if (sec->groupattr->nelts > 0) { 
        release_ldc(r, ldc);
        ldc = get_connection_for_authz(r, LDAP_COMPARE_AND_SEARCH);
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, result, r, APLOGNO(01716)
                "auth_ldap authorise: require group \"%s\": "
                "failed [%s], checking sub-groups",
                t, ldc->reason);
    }


    for (i = 0; i < sec->groupattr->nelts; i++) {

        apr_buffer_t buf;

        const char *name = apr_buffer_str(&ent[i].name);
        if (!name) {
            name = apr_buffer_pstrdup(r->pool, &ent[i].name);
        }       

        if (sec->group_attrib_is_dn) {
            apr_buffer_str_set(&buf, (char *)req->dn, APR_BUFFER_STRING);
        }
        else {
            apr_buffer_str_set(&buf, (char *)req->user, APR_BUFFER_STRING);
        }

        result = util_ldap_cache_check_subgroups(r, ldc, sec->url, t, name, &buf,
                                                 sec->sgAttributes[0] ? sec->sgAttributes : default_attributes,
                                                 sec->subgroupclasses,
                                                 0, sec->maxNestingDepth);
        if (result == APR_COMPARE_TRUE) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, result, r, APLOGNO(01717)
                          "auth_ldap authorise: require group "
                          "(sub-group): authorisation successful "
                          "(attribute %s) [%s]",
                          name, ldc->reason);
            set_request_vars(r, LDAP_AUTHZ, req->vals);
            return AUTHZ_GRANTED;
        }
        else {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, result, r, APLOGNO(01718)
                          "auth_ldap authorise: require group "
                          "(sub-group) \"%s\": didn't match with attr %s "
                          "[%s]", t, ldc->reason, name);
        }
    }

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01720)
                  "auth_ldap authorize group: authorization denied for "
                  "user %s to %s",
                  r->user, r->uri);

    return AUTHZ_DENIED;
}

static authz_status ldapdn_check_authorization(request_rec *r,
                                               const char *require_args,
                                               const void *parsed_require_args)
{
    apr_status_t result = 0;
    authn_ldap_request_t *req =
        (authn_ldap_request_t *)ap_get_module_config(r->request_config, &authnz_ldap_module);
    authn_ldap_config_t *sec =
        (authn_ldap_config_t *)ap_get_module_config(r->per_dir_config, &authnz_ldap_module);

    util_ldap_connection_t *ldc = NULL;

    const char *err = NULL;
    const ap_expr_info_t *expr = parsed_require_args;
    const char *require;

    const char *t;

    if (!r->user) {
        return AUTHZ_DENIED_NO_USER;
    }

    if (!sec->have_ldap_url) {
        return AUTHZ_DENIED;
    }

    if (!sec->host) {
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, APLOGNO(01721)
                      "auth_ldap authorize: no sec->host - weird...?");
        return AUTHZ_DENIED;
    }

    /*
     * If we have been authenticated by some other module than mod_auth_ldap,
     * the req structure needed for authorization needs to be created
     * and populated with the userid and DN of the account in LDAP
     */
    if (!req) {
        req = build_request_config(r);
    }
    ldc = get_connection_for_authz(r, LDAP_SEARCH); /* comparedn is a search */
    if (!req->dn) {
        authz_status rv;
        if (!*r->user) {
            ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, APLOGNO(01722)
                          "ldap authorize: Userid is blank, AuthType=%s",
                          r->ap_auth_type);
        }
        rv = get_dn_for_nonldap_authn(r, ldc);
        if (rv != AUTHZ_GRANTED) {
            return rv;
        }
    }

    require = ap_expr_str_exec(r, expr, &err);
    if (err) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(02587)
                      "auth_ldap authorize: require dn: Can't evaluate expression: %s",
                      err);
        return AUTHZ_DENIED;
    }

    t = require;

    if (req->dn == NULL || !*req->dn) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01725)
                      "auth_ldap authorize: require dn: user's DN has not "
                      "been defined; failing authorization");
        return AUTHZ_DENIED;
    }

    result = util_ldap_cache_comparedn(r, ldc, sec->url, req->dn, t, sec->compare_dn_on_server);
    switch(result) {
        case APR_COMPARE_TRUE: {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01726)
                          "auth_ldap authorize: "
                          "require dn: authorization successful");
            set_request_vars(r, LDAP_AUTHZ, req->vals);
            return AUTHZ_GRANTED;
        }
        default: {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, result, r, APLOGNO(01727)
                          "auth_ldap authorize: "
                          "require dn \"%s\": LDAP error [%s]",
                          t, ldc->reason);
        }
    }


    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01728)
                  "auth_ldap authorize dn: authorization denied for "
                  "user %s to %s",
                  r->user, r->uri);

    return AUTHZ_DENIED;
}

static authz_status ldapattribute_check_authorization(request_rec *r,
                                                      const char *require_args,
                                                      const void *parsed_require_args)
{
    apr_status_t result = 0;
    authn_ldap_request_t *req =
        (authn_ldap_request_t *)ap_get_module_config(r->request_config, &authnz_ldap_module);
    authn_ldap_config_t *sec =
        (authn_ldap_config_t *)ap_get_module_config(r->per_dir_config, &authnz_ldap_module);

    util_ldap_connection_t *ldc = NULL;

    const char *err = NULL;
    const ap_expr_info_t *expr = parsed_require_args;
    const char *require;

    const char *t;
    char *w, *value;

    if (!r->user) {
        return AUTHZ_DENIED_NO_USER;
    }

    if (!sec->have_ldap_url) {
        return AUTHZ_DENIED;
    }

    if (!sec->host) {
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, APLOGNO(01729)
                      "auth_ldap authorize: no sec->host - weird...?");
        return AUTHZ_DENIED;
    }

    /*
     * If we have been authenticated by some other module than mod_auth_ldap,
     * the req structure needed for authorization needs to be created
     * and populated with the userid and DN of the account in LDAP
     */
    if (!req) {
        req = build_request_config(r);
    }
    ldc = get_connection_for_authz(r, LDAP_COMPARE);
    if (!req->dn) {
        authz_status rv;
        if (!*r->user) {
            ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, APLOGNO(01730)
                          "ldap authorize: Userid is blank, AuthType=%s",
                          r->ap_auth_type);
        }
        rv = get_dn_for_nonldap_authn(r, ldc);
        if (rv != AUTHZ_GRANTED) {
            return rv;
        }
    }
    if (req->dn == NULL || !*req->dn) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01733)
                      "auth_ldap authorize: require ldap-attribute: user's DN "
                      "has not been defined; failing authorization");
        return AUTHZ_DENIED;
    }

    require = ap_expr_str_exec(r, expr, &err);
    if (err) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(02588)
                      "auth_ldap authorize: require ldap-attribute: Can't "
                      "evaluate expression: %s", err);
        return AUTHZ_DENIED;
    }

    t = require;

    while (t[0]) {

        apr_buffer_t buf;

        w = ap_getword(r->pool, &t, '=');
        value = ap_getword_conf(r->pool, &t);

        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01734)
                      "auth_ldap authorize: checking attribute %s has value %s",
                      w, value);

        apr_buffer_str_set(&buf, value, APR_BUFFER_STRING);

        result = util_ldap_cache_compare(r, ldc, sec->url, req->dn, w, &buf);
        switch(result) {
            case APR_COMPARE_TRUE: {
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01735)
                              "auth_ldap authorize: "
                              "require attribute: authorization successful");
                set_request_vars(r, LDAP_AUTHZ, req->vals);
                return AUTHZ_GRANTED;
            }
            default: {
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, result, r, APLOGNO(01736)
                              "auth_ldap authorize: require attribute: "
                              "authorization failed [%s]",
                              ldc->reason);
            }
        }
    }

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01737)
                  "auth_ldap authorize attribute: authorization denied for "
                  "user %s to %s",
                  r->user, r->uri);

    return AUTHZ_DENIED;
}

static authz_status ldapfilter_check_authorization(request_rec *r,
                                                   const char *require_args,
                                                   const void *parsed_require_args)
{
    apr_status_t result = 0;
    authn_ldap_request_t *req =
        (authn_ldap_request_t *)ap_get_module_config(r->request_config, &authnz_ldap_module);
    authn_ldap_config_t *sec =
        (authn_ldap_config_t *)ap_get_module_config(r->per_dir_config, &authnz_ldap_module);

    util_ldap_connection_t *ldc = NULL;

    const char *err = NULL;
    const ap_expr_info_t *expr = parsed_require_args;
    const char *require;

    const char *t;

    char filtbuf[FILTER_LENGTH];
    const char *dn = NULL;

    if (!r->user) {
        return AUTHZ_DENIED_NO_USER;
    }

    if (!sec->have_ldap_url) {
        return AUTHZ_DENIED;
    }

    if (!sec->host) {
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, APLOGNO(01738)
                      "auth_ldap authorize: no sec->host - weird...?");
        return AUTHZ_DENIED;
    }

    /*
     * If we have been authenticated by some other module than mod_auth_ldap,
     * the req structure needed for authorization needs to be created
     * and populated with the userid and DN of the account in LDAP
     */
    if (!req) {
        req = build_request_config(r);
    }
    ldc = get_connection_for_authz(r, LDAP_SEARCH);
    if (!req->dn) {
        authz_status rv;
        if (!*r->user) {
            ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, APLOGNO(01739)
                          "ldap authorize: Userid is blank, AuthType=%s",
                          r->ap_auth_type);
        }
        rv = get_dn_for_nonldap_authn(r, ldc);
        if (rv != AUTHZ_GRANTED) {
            return rv;
        }
    }
    if (req->dn == NULL || !*req->dn) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01742)
                      "auth_ldap authorize: require ldap-filter: user's DN "
                      "has not been defined; failing authorization");
        return AUTHZ_DENIED;
    }

    require = ap_expr_str_exec(r, expr, &err);
    if (err) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(02589)
                      "auth_ldap authorize: require ldap-filter: Can't "
                      "evaluate require expression: %s", err);
        return AUTHZ_DENIED;
    }

    t = require;

    if (t[0]) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01743)
                      "auth_ldap authorize: checking filter %s", t);

        /* Build the username filter */
        if (APR_SUCCESS != authn_ldap_build_filter(filtbuf, r, req->user, t, sec)) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(02628)
                          "auth_ldap authorize: ldap filter too long (>%d): %s",
                          FILTER_LENGTH, filtbuf);
            return AUTHZ_DENIED;
        }

        /* Search for the user DN */
        result = util_ldap_cache_getuserdn(r, ldc, sec->url, sec->basedn,
             sec->scope, sec->attributes, filtbuf, &dn, &(req->vals));

        /* Make sure that the filtered search returned the correct user dn */
        if (result == APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01744)
                          "auth_ldap authorize: checking dn match %s", dn);
            if (sec->compare_as_user) {
                /* ldap-filter is the only authz that requires a search and a compare */
                release_ldc(r, ldc);
                ldc = get_connection_for_authz(r, LDAP_COMPARE);
            }
            result = util_ldap_cache_comparedn(r, ldc, sec->url, req->dn, dn,
                                               sec->compare_dn_on_server);
        }

        switch(result) {
            case APR_COMPARE_TRUE: {
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01745)
                              "auth_ldap authorize: require ldap-filter: "
                              "authorization successful");
                set_request_vars(r, LDAP_AUTHZ, req->vals);
                return AUTHZ_GRANTED;
            }
            case APR_FILTER_ERROR: {
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, result, r, APLOGNO(01746)
                              "auth_ldap authorize: require ldap-filter: "
                              "%s authorization failed [%s]",
                              filtbuf, ldc->reason);
                break;
            }
            default: {
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, result, r, APLOGNO(01747)
                              "auth_ldap authorize: require ldap-filter: "
                              "authorization failed [%s]",
                              ldc->reason);
            }
        }
    }

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01748)
                  "auth_ldap authorize filter: authorization denied for "
                  "user %s to %s",
                  r->user, r->uri);

    return AUTHZ_DENIED;
}

static authz_status ldapsearch_check_authorization(request_rec *r,
                                                   const char *require_args,
                                                   const void *parsed_require_args)
{
    apr_status_t result = 0;
    authn_ldap_request_t *req =
        (authn_ldap_request_t *)ap_get_module_config(r->request_config, &authnz_ldap_module);
    authn_ldap_config_t *sec =
        (authn_ldap_config_t *)ap_get_module_config(r->per_dir_config, &authnz_ldap_module);

    util_ldap_connection_t *ldc = NULL;

    const char *err = NULL;
    const ap_expr_info_t *expr = parsed_require_args;
    const char *require;
    const char *t;
    const char *dn = NULL;

    if (!sec->have_ldap_url) {
        return AUTHZ_DENIED;
    }

    if (!sec->host) {
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, APLOGNO(10486)
                      "auth_ldap authorize: no sec->host - weird...?");
        return AUTHZ_DENIED;
    }

    /*
     * If we have been authenticated by some other module than mod_auth_ldap,
     * the req structure needed for authorization needs to be created
     * and populated with the userid and DN of the account in LDAP
     */
    if (!req) {
        req = build_request_config(r);
    }
    ldc = get_connection_for_authz(r, LDAP_SEARCH);

    require = ap_expr_str_exec(r, expr, &err);
    if (err) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(02629)
                      "auth_ldap authorize: require ldap-search: Can't "
                      "evaluate require expression: %s", err);
        return AUTHZ_DENIED;
    }

    t = require;

    if (t[0]) {

        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(02630)
                      "auth_ldap authorize: checking filter %s", t);

        /* Search for the user DN */
        result = util_ldap_cache_getuserdn(r, ldc, sec->url, sec->basedn,
             sec->scope, sec->attributes, t, &dn, &(req->vals));

        /* Make sure that the filtered search returned a single dn */
        if (result == APR_SUCCESS && dn) {
            req->dn = dn;
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, result, r, APLOGNO(02631)
                          "auth_ldap authorize: require ldap-search: "
                          "authorization successful");
            set_request_vars(r, LDAP_AUTHZ, req->vals);
            return AUTHZ_GRANTED;
        }
        else {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, result, r, APLOGNO(02632)
                          "auth_ldap authorize: require ldap-search: "
                          "%s authorization failed [%s]",
                          t, ldc->reason);
        }
    }

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(02633)
                  "auth_ldap authorize search: authorization denied for "
                  "to %s", r->uri);

    return AUTHZ_DENIED;
}

static const char *ldap_parse_config(cmd_parms *cmd, const char *require_line,
                                     const void **parsed_require_line)
{
    const char *expr_err = NULL;
    ap_expr_info_t *expr;

    expr = ap_expr_parse_cmd(cmd, require_line, AP_EXPR_FLAG_STRING_RESULT,
            &expr_err, NULL);

    if (expr_err)
        return apr_pstrcat(cmd->temp_pool,
                           "Cannot parse expression in require line: ",
                           expr_err, NULL);

    *parsed_require_line = expr;

    return NULL;
}


/*
 * Use the ldap url parsing routines to break up the ldap url into
 * host and port.
 */
static const char *mod_auth_ldap_parse_url(cmd_parms *cmd,
                                           void *config,
                                           const char *url,
                                           const char *mode)
{
// FIXME - needed?
    int rc, i;
    apr_ldap_url_desc_t *urld;
#if (APU_MAJOR_VERSION == 1 && APU_MINOR_VERSION >= 7)
    apr_ldap_err_t *result;
#else
    apu_err_t *result;
#endif
    const char *end = url;

    authn_ldap_config_t *sec = config;

    rc = apr_ldap_url_parse(cmd->pool, url, &(urld), &(result));
    if (rc != APR_SUCCESS) {
        return result->reason;
    }

    /* isolate the host/port part of the URL */
    for (i = 0; end && i < 3; i++) {
        end = strchr((char *)end + 1, '/');
    }
    if (end) {
        sec->url = apr_pstrndup(cmd->pool, url, end - url);
    }
    else {
        sec->url = apr_pstrdup(cmd->pool, url);
    }

    /* Set all the values, or at least some sane defaults */
    if (sec->host) {
        sec->host = apr_pstrcat(cmd->pool, urld->lud_host, " ", sec->host, NULL);
    }
    else {
        sec->host = urld->lud_host? apr_pstrdup(cmd->pool, urld->lud_host) : "localhost";
    }
    sec->basedn = urld->lud_dn? apr_pstrdup(cmd->pool, urld->lud_dn) : "";
    if (urld->lud_attrs && urld->lud_attrs[0]) {
        char **attributes;
        int i = 1;
        while (urld->lud_attrs[i]) {
            i++;
        }
        attributes = apr_pcalloc(cmd->pool, sizeof(char *) * (i+1));
        i = 0;
        while (urld->lud_attrs[i]) {
            attributes[i] = apr_pstrdup(cmd->pool, urld->lud_attrs[i]);
            i++;
        }
        sec->attributes = (const char **)attributes;
        sec->attribute = sec->attributes[0];
    }
    else {
        sec->attribute = "uid";
    }

    sec->scope = urld->lud_scope == APR_LDAP_SCOPE_ONELEVEL ?
        APR_LDAP_SCOPE_ONELEVEL : APR_LDAP_SCOPE_SUBTREE;

    if (urld->lud_filter) {
        if (urld->lud_filter[0] == '(') {
            /*
             * Get rid of the surrounding parens; later on when generating the
             * filter, they'll be put back.
             */
            sec->filter = apr_pstrmemdup(cmd->pool, urld->lud_filter+1,
                                                    strlen(urld->lud_filter)-2);
        }
        else {
            sec->filter = apr_pstrdup(cmd->pool, urld->lud_filter);
        }
    }
    else {
        sec->filter = "objectclass=*";
    }

    if (mode) {
        if (0 == strcasecmp("NONE", mode)) {
            sec->secure = APR_LDAP_TLS_NONE;
        }
        else if (0 == strcasecmp("SSL", mode)) {
            sec->secure = APR_LDAP_TLS_SSL;
        }
        else if (0 == strcasecmp("TLS", mode) || 0 == strcasecmp("STARTTLS", mode)) {
            sec->secure = APR_LDAP_TLS_STARTTLS;
        }
        else {
            return "Invalid LDAP connection mode setting: must be one of NONE, "
                   "SSL, or TLS/STARTTLS";
        }
    }

      /* "ldaps" indicates secure ldap connections desired
      */
    if (strncasecmp(url, "ldaps", 5) == 0)
    {
        sec->secure = APR_LDAP_TLS_SSL;
        sec->port = urld->lud_port? urld->lud_port : APR_LDAPS_PORT;
    }
    else
    {
        sec->port = urld->lud_port? urld->lud_port : APR_LDAP_PORT;
    }

    sec->have_ldap_url = 1;

    ap_log_error(APLOG_MARK, APLOG_TRACE1, 0, cmd->server,
                 "auth_ldap url parse: `%s', Url: %s, Host: %s, Port: %d, DN: %s, "
                 "attrib: %s, scope: %s, filter: %s, connection mode: %s",
                 url,
                 sec->url,
                 urld->lud_host,
                 urld->lud_port,
                 urld->lud_dn,
                 urld->lud_attrs? urld->lud_attrs[0] : "(null)",
                 (urld->lud_scope == APR_LDAP_SCOPE_SUBTREE ? "subtree" :
                  urld->lud_scope == APR_LDAP_SCOPE_BASE ? "base" :
                  urld->lud_scope == APR_LDAP_SCOPE_ONELEVEL ? "onelevel" :
                  urld->lud_scope == APR_LDAP_SCOPE_SUBORDINATE ? "subordinate" : "unknown"),
                 urld->lud_filter,
                 sec->secure == APR_LDAP_TLS_SSL  ? "using SSL": "not using SSL"
                 );

    return NULL;
}

static const char *mod_auth_ldap_set_deref(cmd_parms *cmd, void *config, const char *arg)
{
    authn_ldap_config_t *sec = config;

    if (strcmp(arg, "never") == 0 || strcasecmp(arg, "off") == 0) {
        sec->deref = APR_LDAP_DEREF_NEVER;
    }
    else if (strcmp(arg, "searching") == 0) {
        sec->deref = APR_LDAP_DEREF_SEARCHING;
    }
    else if (strcmp(arg, "finding") == 0) {
        sec->deref = APR_LDAP_DEREF_FINDING;
    }
    else if (strcmp(arg, "always") == 0 || strcasecmp(arg, "on") == 0) {
        sec->deref = APR_LDAP_DEREF_ALWAYS;
    }
    else {
        return "Unrecognized value for AuthLDAPDereferenceAliases directive";
    }
    return NULL;
}

static const char *mod_auth_ldap_add_subgroup_attribute(cmd_parms *cmd, void *config, const char *arg)
{
    int i;
    authn_ldap_config_t *sec = config;

    for (i = 0; sec->sgAttributes[i]; i++) {
        ;
    }
    if (i == GROUPATTR_MAX_ELTS)
        return "Too many AuthLDAPSubGroupAttribute values";

    sec->sgAttributes[i] = apr_pstrdup(cmd->pool, arg);

    return NULL;
}

static const char *mod_auth_ldap_add_subgroup_class(cmd_parms *cmd, void *config, const char *arg)
{
    struct mod_auth_ldap_groupattr_entry_t *new;

    authn_ldap_config_t *sec = config;

    if (sec->subgroupclasses->nelts > GROUPATTR_MAX_ELTS)
        return "Too many AuthLDAPSubGroupClass values";

    new = apr_array_push(sec->subgroupclasses);
    apr_buffer_str_set(&new->name, apr_pstrdup(cmd->pool, arg), APR_BUFFER_STRING);

    return NULL;
}

static const char *mod_auth_ldap_set_subgroup_maxdepth(cmd_parms *cmd,
                                                       void *config,
                                                       const char *max_depth)
{
    authn_ldap_config_t *sec = config;

    sec->maxNestingDepth = atol(max_depth);

    return NULL;
}

static const char *mod_auth_ldap_add_group_attribute(cmd_parms *cmd, void *config, const char *arg)
{
    struct mod_auth_ldap_groupattr_entry_t *new;

    authn_ldap_config_t *sec = config;

    if (sec->groupattr->nelts > GROUPATTR_MAX_ELTS)
        return "Too many AuthLDAPGroupAttribute directives";

    new = apr_array_push(sec->groupattr);
    apr_buffer_str_set(&new->name, apr_pstrdup(cmd->pool, arg), APR_BUFFER_STRING);

    return NULL;
}

static const char *set_charset_config(cmd_parms *cmd, void *config, const char *arg)
{
    ap_set_module_config(cmd->server->module_config, &authnz_ldap_module,
                         (void *)arg);
    return NULL;
}

static const char *set_bind_pattern(cmd_parms *cmd, void *_cfg, const char *exp, const char *subst)
{
    authn_ldap_config_t *sec = _cfg;
    ap_regex_t *regexp;

    regexp = ap_pregcomp(cmd->pool, exp, AP_REG_EXTENDED);

    if (!regexp) {
        return apr_pstrcat(cmd->pool, "AuthLDAPInitialBindPattern: cannot compile regular "
                                      "expression '", exp, "'", NULL);
    }

    sec->bind_regex = regexp;
    sec->bind_subst = subst;

    return NULL;
}

static const char *set_bind_password(cmd_parms *cmd, void *_cfg, const char *arg)
{
    authn_ldap_config_t *sec = _cfg;
    int arglen = strlen(arg);
    char **argv;
    char *result;

    if ((arglen > 5) && strncmp(arg, "exec:", 5) == 0) {
        if (apr_tokenize_to_argv(arg+5, &argv, cmd->temp_pool) != APR_SUCCESS) {
            return apr_pstrcat(cmd->pool,
                               "Unable to parse exec arguments from ",
                               arg+5, NULL);
        }
        argv[0] = ap_server_root_relative(cmd->temp_pool, argv[0]);

        if (!argv[0]) {
            return apr_pstrcat(cmd->pool,
                               "Invalid AuthLDAPBindPassword exec location:",
                               arg+5, NULL);
        }
        result = ap_get_exec_line(cmd->pool,
                                  (const char*)argv[0], (const char * const *)argv);

        if (!result) {
            return apr_pstrcat(cmd->pool,
                               "Unable to get bind password from exec of ",
                               arg+5, NULL);
        }
        sec->bindpw = result;
    }
    else {
        sec->bindpw = (char *)arg;
    }

    if (!(*sec->bindpw)) {
        return "Empty passwords are invalid for AuthLDAPBindPassword";
    }

    return NULL;
}

static const command_rec authnz_ldap_cmds[] =
{
    AP_INIT_TAKE12("AuthLDAPURL", mod_auth_ldap_parse_url, NULL, OR_AUTHCFG,
                  "URL to define LDAP connection. This should be an RFC 2255 compliant\n"
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
                  (void *)APR_OFFSETOF(authn_ldap_config_t, binddn), OR_AUTHCFG,
                  "DN to use to bind to LDAP server. If not provided, will do an anonymous bind."),

    AP_INIT_TAKE1("AuthLDAPBindPassword", set_bind_password, NULL, OR_AUTHCFG,
                  "Password to use to bind to LDAP server. If not provided, will do an anonymous bind."),

    AP_INIT_FLAG("AuthLDAPBindAuthoritative", ap_set_flag_slot,
                  (void *)APR_OFFSETOF(authn_ldap_config_t, bind_authoritative), OR_AUTHCFG,
                  "Set to 'on' to return failures when user-specific bind fails - defaults to on."),

    AP_INIT_FLAG("AuthLDAPRemoteUserIsDN", ap_set_flag_slot,
                 (void *)APR_OFFSETOF(authn_ldap_config_t, user_is_dn), OR_AUTHCFG,
                 "Set to 'on' to set the REMOTE_USER environment variable to be the full "
                 "DN of the remote user. By default, this is set to off, meaning that "
                 "the REMOTE_USER variable will contain whatever value the remote user sent."),

    AP_INIT_TAKE1("AuthLDAPRemoteUserAttribute", ap_set_string_slot,
                 (void *)APR_OFFSETOF(authn_ldap_config_t, remote_user_attribute), OR_AUTHCFG,
                 "Override the user supplied username and place the "
                 "contents of this attribute in the REMOTE_USER "
                 "environment variable."),

    AP_INIT_FLAG("AuthLDAPCompareDNOnServer", ap_set_flag_slot,
                 (void *)APR_OFFSETOF(authn_ldap_config_t, compare_dn_on_server), OR_AUTHCFG,
                 "Set to 'on' to force auth_ldap to do DN compares (for the \"require dn\" "
                 "directive) using the server, and set it 'off' to do the compares locally "
                 "(at the expense of possible false matches). See the documentation for "
                 "a complete description of this option."),

    AP_INIT_ITERATE("AuthLDAPSubGroupAttribute", mod_auth_ldap_add_subgroup_attribute, NULL, OR_AUTHCFG,
                    "Attribute labels used to define sub-group (or nested group) membership in groups - "
                    "defaults to member and uniqueMember"),

    AP_INIT_ITERATE("AuthLDAPSubGroupClass", mod_auth_ldap_add_subgroup_class, NULL, OR_AUTHCFG,
                     "LDAP objectClass values used to identify sub-group instances - "
                     "defaults to groupOfNames and groupOfUniqueNames"),

    AP_INIT_TAKE1("AuthLDAPMaxSubGroupDepth", mod_auth_ldap_set_subgroup_maxdepth, NULL, OR_AUTHCFG,
                      "Maximum subgroup nesting depth to be evaluated - defaults to 10 (top-level group = 0)"),

    AP_INIT_ITERATE("AuthLDAPGroupAttribute", mod_auth_ldap_add_group_attribute, NULL, OR_AUTHCFG,
                    "A list of attribute labels used to identify the user members of groups - defaults to "
                    "member and uniquemember"),

    AP_INIT_FLAG("AuthLDAPGroupAttributeIsDN", ap_set_flag_slot,
                 (void *)APR_OFFSETOF(authn_ldap_config_t, group_attrib_is_dn), OR_AUTHCFG,
                 "If set to 'on', auth_ldap uses the DN that is retrieved from the server for "
                 "subsequent group comparisons. If set to 'off', auth_ldap uses the string "
                 "provided by the client directly. Defaults to 'on'."),

    AP_INIT_TAKE1("AuthLDAPDereferenceAliases", mod_auth_ldap_set_deref, NULL, OR_AUTHCFG,
                  "Determines how aliases are handled during a search. Can be one of the "
                  "values \"never\", \"searching\", \"finding\", or \"always\". "
                  "Defaults to always."),

    AP_INIT_TAKE1("AuthLDAPCharsetConfig", set_charset_config, NULL, RSRC_CONF,
                  "Character set conversion configuration file. If omitted, character set "
                  "conversion is disabled."),

    AP_INIT_TAKE1("AuthLDAPAuthorizePrefix", ap_set_string_slot,
                  (void *)APR_OFFSETOF(authn_ldap_config_t, authz_prefix), OR_AUTHCFG,
                  "The prefix to add to environment variables set during "
                  "successful authorization, default '" AUTHZ_PREFIX "'"),

    AP_INIT_FLAG("AuthLDAPInitialBindAsUser", ap_set_flag_slot,
                 (void *)APR_OFFSETOF(authn_ldap_config_t, initial_bind_as_user), OR_AUTHCFG,
                 "Set to 'on' to perform the initial DN lookup with the basic auth credentials "
                 "instead of anonymous or hard-coded credentials"),

     AP_INIT_TAKE2("AuthLDAPInitialBindPattern", set_bind_pattern, NULL, OR_AUTHCFG,
                   "The regex and substitution to determine a username that can bind based on an HTTP basic auth username"),

     AP_INIT_FLAG("AuthLDAPSearchAsUser", ap_set_flag_slot,
                  (void *)APR_OFFSETOF(authn_ldap_config_t, search_as_user), OR_AUTHCFG,
                  "Set to 'on' to perform authorization-based searches with the users credentials, when this module "
                  "has also performed authentication.  Does not affect nested groups lookup."),
     AP_INIT_FLAG("AuthLDAPCompareAsUser", ap_set_flag_slot,
                  (void *)APR_OFFSETOF(authn_ldap_config_t, compare_as_user), OR_AUTHCFG,
                  "Set to 'on' to perform authorization-based compares with the users credentials, when this module "
                  "has also performed authentication.  Does not affect nested groups lookups."),
    {NULL}
};

static int authnz_ldap_post_config(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s)
{
    ap_configfile_t *f;
    char l[MAX_STRING_LEN];
    const char *charset_confname = ap_get_module_config(s->module_config,
                                                      &authnz_ldap_module);
    apr_status_t status;

#if 0
    authn_ldap_config_t *sec = (authn_ldap_config_t *)
                                    ap_get_module_config(s->module_config,
                                                         &authnz_ldap_module);

    if (sec->secure)
    {
        if (!util_ldap_ssl_supported(s))
        {
            ap_log_error(APLOG_MARK, APLOG_CRIT, 0, s, APLOGNO(03159)
                         "LDAP: SSL connections (ldaps://) not supported by utilLDAP");
            return(!OK);
        }
    }
#endif

    /* make sure that mod_ldap (util_ldap) is loaded */
    if (ap_find_linked_module("util_ldap.c") == NULL) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, APLOGNO(01749)
                     "Module mod_ldap missing. Mod_ldap (aka. util_ldap) "
                     "must be loaded in order for mod_authnz_ldap to function properly");
        return HTTP_INTERNAL_SERVER_ERROR;

    }

    if (!charset_confname) {
        return OK;
    }

    charset_confname = ap_server_root_relative(p, charset_confname);
    if (!charset_confname) {
        ap_log_error(APLOG_MARK, APLOG_ERR, APR_EBADPATH, s, APLOGNO(01750)
                     "Invalid charset conversion config path %s",
                     (const char *)ap_get_module_config(s->module_config,
                                                        &authnz_ldap_module));
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    if ((status = ap_pcfg_openfile(&f, ptemp, charset_confname))
                != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, status, s, APLOGNO(01751)
                     "could not open charset conversion config file %s.",
                     charset_confname);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    charset_conversions = apr_hash_make(p);

    while (!(ap_cfg_getline(l, MAX_STRING_LEN, f))) {
        const char *ll = l;
        char *lang;

        if (l[0] == '#') {
            continue;
        }
        lang = ap_getword_conf(p, &ll);
        ap_str_tolower(lang);

        if (ll[0]) {
            char *charset = ap_getword_conf(p, &ll);
            apr_hash_set(charset_conversions, lang, APR_HASH_KEY_STRING, charset);
        }
    }
    ap_cfg_closefile(f);

    to_charset = derive_codepage_from_lang (p, "utf-8");
    if (to_charset == NULL) {
        ap_log_error(APLOG_MARK, APLOG_ERR, status, s, APLOGNO(01752)
                     "could not find the UTF-8 charset in the file %s.",
                     charset_confname);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    return OK;
}

static const authn_provider authn_ldap_provider =
{
    &authn_ldap_check_password,
    NULL,
};

static const authz_provider authz_ldapuser_provider =
{
    &ldapuser_check_authorization,
    &ldap_parse_config,
};
static const authz_provider authz_ldapgroup_provider =
{
    &ldapgroup_check_authorization,
    &ldap_parse_config,
};

static const authz_provider authz_ldapdn_provider =
{
    &ldapdn_check_authorization,
    &ldap_parse_config,
};

static const authz_provider authz_ldapattribute_provider =
{
    &ldapattribute_check_authorization,
    &ldap_parse_config,
};

static const authz_provider authz_ldapfilter_provider =
{
    &ldapfilter_check_authorization,
    &ldap_parse_config,
};

static const authz_provider authz_ldapsearch_provider =
{
    &ldapsearch_check_authorization,
    &ldap_parse_config,
};

static void ImportULDAPOptFn(void)
{
    util_ldap_connection_close      = APR_RETRIEVE_OPTIONAL_FN(uldap_connection_close);
    util_ldap_connection_find_uri   = APR_RETRIEVE_OPTIONAL_FN(uldap_connection_find_uri);
    util_ldap_cache_comparedn       = APR_RETRIEVE_OPTIONAL_FN(uldap_cache_comparedn);
    util_ldap_cache_compare         = APR_RETRIEVE_OPTIONAL_FN(uldap_cache_compare);
    util_ldap_cache_checkuserid     = APR_RETRIEVE_OPTIONAL_FN(uldap_cache_checkuserid);
    util_ldap_cache_getuserdn       = APR_RETRIEVE_OPTIONAL_FN(uldap_cache_getuserdn);
    util_ldap_cache_check_subgroups = APR_RETRIEVE_OPTIONAL_FN(uldap_cache_check_subgroups);
}


/** Cleanup LDAP connections before EOR. Note, if the authorization is unsuccessful,
 *  this will not run, but EOR is unlikely to be delayed as in a successful request.
 */
static apr_status_t authnz_ldap_fixups(request_rec *r)
{ 
    authn_ldap_request_t *req =
        (authn_ldap_request_t *)ap_get_module_config(r->request_config, &authnz_ldap_module);
    if (req && req->ldc_pool) { 
        apr_pool_destroy(req->ldc_pool);
    }
    return OK;
}

static void register_hooks(apr_pool_t *p)
{
    /* Register authn provider */
    ap_register_auth_provider(p, AUTHN_PROVIDER_GROUP, "ldap",
                              AUTHN_PROVIDER_VERSION,
                              &authn_ldap_provider, AP_AUTH_INTERNAL_PER_CONF);

    /* Register authz providers */
    ap_register_auth_provider(p, AUTHZ_PROVIDER_GROUP, "ldap-user",
                              AUTHZ_PROVIDER_VERSION,
                              &authz_ldapuser_provider,
                              AP_AUTH_INTERNAL_PER_CONF);
    ap_register_auth_provider(p, AUTHZ_PROVIDER_GROUP, "ldap-group",
                              AUTHZ_PROVIDER_VERSION,
                              &authz_ldapgroup_provider,
                              AP_AUTH_INTERNAL_PER_CONF);
    ap_register_auth_provider(p, AUTHZ_PROVIDER_GROUP, "ldap-dn",
                              AUTHZ_PROVIDER_VERSION,
                              &authz_ldapdn_provider,
                              AP_AUTH_INTERNAL_PER_CONF);
    ap_register_auth_provider(p, AUTHZ_PROVIDER_GROUP, "ldap-attribute",
                              AUTHZ_PROVIDER_VERSION,
                              &authz_ldapattribute_provider,
                              AP_AUTH_INTERNAL_PER_CONF);
    ap_register_auth_provider(p, AUTHZ_PROVIDER_GROUP, "ldap-filter",
                              AUTHZ_PROVIDER_VERSION,
                              &authz_ldapfilter_provider,
                              AP_AUTH_INTERNAL_PER_CONF);
    ap_register_auth_provider(p, AUTHZ_PROVIDER_GROUP, "ldap-search",
                              AUTHZ_PROVIDER_VERSION,
                              &authz_ldapsearch_provider,
                              AP_AUTH_INTERNAL_PER_CONF);

    ap_hook_post_config(authnz_ldap_post_config,NULL,NULL,APR_HOOK_MIDDLE);
    ap_hook_fixups(authnz_ldap_fixups,NULL,NULL,APR_HOOK_MIDDLE);

    ap_hook_optional_fn_retrieve(ImportULDAPOptFn,NULL,NULL,APR_HOOK_MIDDLE);
}

AP_DECLARE_MODULE(authnz_ldap) =
{
    STANDARD20_MODULE_STUFF,
    create_authnz_ldap_dir_config,   /* dir config creater */
    NULL,                            /* dir merger --- default is to override */
    NULL,                            /* server config */
    NULL,                            /* merge server config */
    authnz_ldap_cmds,                /* command apr_table_t */
    register_hooks                   /* register hooks */
};
