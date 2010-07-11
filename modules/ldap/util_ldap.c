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

/*
 * util_ldap.c: LDAP things
 *
 * Original code from auth_ldap module for Apache v1.3:
 * Copyright 1998, 1999 Enbridge Pipelines Inc.
 * Copyright 1999-2001 Dave Carrigan
 */

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"
#include "util_ldap.h"
#include "util_ldap_cache.h"

#include <apr_strings.h>

#if APR_HAVE_UNISTD_H
#include <unistd.h>
#endif

#if !APR_HAS_LDAP
#error mod_ldap requires APR-util to have LDAP support built in
#endif

#ifdef AP_NEED_SET_MUTEX_PERMS
#include "unixd.h"
#endif

    /* defines for certificate file types
    */
#define LDAP_CA_TYPE_UNKNOWN            0
#define LDAP_CA_TYPE_DER                1
#define LDAP_CA_TYPE_BASE64             2
#define LDAP_CA_TYPE_CERT7_DB           3

/* Default define for ldap functions that need a SIZELIMIT but
 * do not have the define
 * XXX This should be removed once a supporting #define is 
 *  released through APR-Util.
 */
#ifndef APR_LDAP_SIZELIMIT
#define APR_LDAP_SIZELIMIT -1
#endif

module AP_MODULE_DECLARE_DATA ldap_module;

#define LDAP_CACHE_LOCK() do {                                  \
    if (st->util_ldap_cache_lock)                               \
        apr_global_mutex_lock(st->util_ldap_cache_lock);        \
} while (0)

#define LDAP_CACHE_UNLOCK() do {                                \
    if (st->util_ldap_cache_lock)                               \
        apr_global_mutex_unlock(st->util_ldap_cache_lock);      \
} while (0)

static void util_ldap_strdup (char **str, const char *newstr)
{
    if (*str) {
        free(*str);
        *str = NULL;
    }

    if (newstr) {
        *str = strdup(newstr);
    }
}

/*
 * Status Handler
 * --------------
 *
 * This handler generates a status page about the current performance of
 * the LDAP cache. It is enabled as follows:
 *
 * <Location /ldap-status>
 *   SetHandler ldap-status
 * </Location>
 *
 */
static int util_ldap_handler(request_rec *r)
{
    util_ldap_state_t *st = (util_ldap_state_t *)
                            ap_get_module_config(r->server->module_config,
                                                 &ldap_module);

    r->allowed |= (1 << M_GET);
    if (r->method_number != M_GET)
        return DECLINED;

    if (strcmp(r->handler, "ldap-status")) {
        return DECLINED;
    }

    r->content_type = "text/html; charset=ISO-8859-1";
    if (r->header_only)
        return OK;

    ap_rputs(DOCTYPE_HTML_3_2
             "<html><head><title>LDAP Cache Information</title></head>\n", r);
    ap_rputs("<body bgcolor='#ffffff'><h1 align=center>LDAP Cache Information"
             "</h1>\n", r);

    util_ald_cache_display(r, st);

    return OK;
}

/* ------------------------------------------------------------------ */


/*
 * Closes an LDAP connection by unlocking it. The next time
 * uldap_connection_find() is called this connection will be
 * available for reuse.
 */
static void uldap_connection_close(util_ldap_connection_t *ldc)
{

    /*
     * QUESTION:
     *
     * Is it safe leaving bound connections floating around between the
     * different modules? Keeping the user bound is a performance boost,
     * but it is also a potential security problem - maybe.
     *
     * For now we unbind the user when we finish with a connection, but
     * we don't have to...
     */

    /* mark our connection as available for reuse */

#if APR_HAS_THREADS
    apr_thread_mutex_unlock(ldc->lock);
#endif
}


/*
 * Destroys an LDAP connection by unbinding and closing the connection to
 * the LDAP server. It is used to bring the connection back to a known
 * state after an error, and during pool cleanup.
 */
static apr_status_t uldap_connection_unbind(void *param)
{
    util_ldap_connection_t *ldc = param;

    if (ldc) {
        if (ldc->ldap) {
            ldap_unbind_s(ldc->ldap);
            ldc->ldap = NULL;
        }
        ldc->bound = 0;
    }

    return APR_SUCCESS;
}


/*
 * Clean up an LDAP connection by unbinding and unlocking the connection.
 * This function is registered with the pool cleanup function - causing
 * the LDAP connections to be shut down cleanly on graceful restart.
 */
static apr_status_t uldap_connection_cleanup(void *param)
{
    util_ldap_connection_t *ldc = param;

    if (ldc) {

        /* unbind and disconnect from the LDAP server */
        uldap_connection_unbind(ldc);

        /* free the username and password */
        if (ldc->bindpw) {
            free((void*)ldc->bindpw);
        }
        if (ldc->binddn) {
            free((void*)ldc->binddn);
        }

        /* unlock this entry */
        uldap_connection_close(ldc);

    }

    return APR_SUCCESS;
}

static int uldap_connection_init(request_rec *r,
                                 util_ldap_connection_t *ldc )
{
    int rc = 0, ldap_option = 0;
    int version  = LDAP_VERSION3;
    apr_ldap_err_t *result = NULL;
#ifdef LDAP_OPT_NETWORK_TIMEOUT
    struct timeval timeOut = {10,0};    /* 10 second connection timeout */
#endif
    util_ldap_state_t *st =
        (util_ldap_state_t *)ap_get_module_config(r->server->module_config,
        &ldap_module);

    /* Since the host will include a port if the default port is not used,
     * always specify the default ports for the port parameter.  This will
     * allow a host string that contains multiple hosts the ability to mix
     * some hosts with ports and some without. All hosts which do not
     * specify a port will use the default port.
     */
    apr_ldap_init(r->pool, &(ldc->ldap),
                  ldc->host,
                  APR_LDAP_SSL == ldc->secure ? LDAPS_PORT : LDAP_PORT,
                  APR_LDAP_NONE,
                  &(result));


    if (NULL == result) {
        /* something really bad happened */
        ldc->bound = 0;
        if (NULL == ldc->reason) {
            ldc->reason = "LDAP: ldap initialization failed";
        }
        return(APR_EGENERAL);
    }

    if (result->rc) {
        ldc->reason = result->reason;
    }

    if (NULL == ldc->ldap)
    {
        ldc->bound = 0;
        if (NULL == ldc->reason) {
            ldc->reason = "LDAP: ldap initialization failed";
        }
        else {
            ldc->reason = result->reason;
        }
        return(result->rc);
    }

    /* always default to LDAP V3 */
    ldap_set_option(ldc->ldap, LDAP_OPT_PROTOCOL_VERSION, &version);

    /* set client certificates */
    if (!apr_is_empty_array(ldc->client_certs)) {
        apr_ldap_set_option(r->pool, ldc->ldap, APR_LDAP_OPT_TLS_CERT,
                            ldc->client_certs, &(result));
        if (LDAP_SUCCESS != result->rc) {
            uldap_connection_unbind( ldc );
            ldc->reason = result->reason;
            return(result->rc);
        }
    }

    /* switch on SSL/TLS */
    if (APR_LDAP_NONE != ldc->secure) {
        apr_ldap_set_option(r->pool, ldc->ldap,
                            APR_LDAP_OPT_TLS, &ldc->secure, &(result));
        if (LDAP_SUCCESS != result->rc) {
            uldap_connection_unbind( ldc );
            ldc->reason = result->reason;
            return(result->rc);
        }
    }

    /* Set the alias dereferencing option */
    ldap_option = ldc->deref;
    ldap_set_option(ldc->ldap, LDAP_OPT_DEREF, &ldap_option);

/*XXX All of the #ifdef's need to be removed once apr-util 1.2 is released */
#ifdef APR_LDAP_OPT_VERIFY_CERT
    apr_ldap_set_option(r->pool, ldc->ldap,
                        APR_LDAP_OPT_VERIFY_CERT, &(st->verify_svr_cert), &(result));
#else
#if defined(LDAPSSL_VERIFY_SERVER)
    if (st->verify_svr_cert) {
        result->rc = ldapssl_set_verify_mode(LDAPSSL_VERIFY_SERVER);
    }
    else {
        result->rc = ldapssl_set_verify_mode(LDAPSSL_VERIFY_NONE);
    }
#elif defined(LDAP_OPT_X_TLS_REQUIRE_CERT)
    /* This is not a per-connection setting so just pass NULL for the
       Ldap connection handle */
    if (st->verify_svr_cert) {
        int i = LDAP_OPT_X_TLS_DEMAND;
        result->rc = ldap_set_option(NULL, LDAP_OPT_X_TLS_REQUIRE_CERT, &i);
    }
    else {
        int i = LDAP_OPT_X_TLS_NEVER;
        result->rc = ldap_set_option(NULL, LDAP_OPT_X_TLS_REQUIRE_CERT, &i);
    }
#endif
#endif

#ifdef LDAP_OPT_NETWORK_TIMEOUT
    if (st->connectionTimeout > 0) {
        timeOut.tv_sec = st->connectionTimeout;
    }

    if (st->connectionTimeout >= 0) {
        rc = apr_ldap_set_option(r->pool, ldc->ldap, LDAP_OPT_NETWORK_TIMEOUT,
                                 (void *)&timeOut, &(result));
        if (APR_SUCCESS != rc) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                             "LDAP: Could not set the connection timeout");
        }
    }
#endif

    return(rc);
}

/*
 * Connect to the LDAP server and binds. Does not connect if already
 * connected (i.e. ldc->ldap is non-NULL.) Does not bind if already bound.
 *
 * Returns LDAP_SUCCESS on success; and an error code on failure
 */
static int uldap_connection_open(request_rec *r,
                                 util_ldap_connection_t *ldc)
{
    int rc = 0;
    int failures = 0;

    /* sanity check for NULL */
    if (!ldc) {
        return -1;
    }

    /* If the connection is already bound, return
    */
    if (ldc->bound)
    {
        ldc->reason = "LDAP: connection open successful (already bound)";
        return LDAP_SUCCESS;
    }

    /* create the ldap session handle
    */
    if (NULL == ldc->ldap)
    {
       rc = uldap_connection_init( r, ldc );
       if (LDAP_SUCCESS != rc)
       {
           return rc;
       }
    }


    /* loop trying to bind up to 10 times if LDAP_SERVER_DOWN error is
     * returned.  Break out of the loop on Success or any other error.
     *
     * NOTE: Looping is probably not a great idea. If the server isn't
     * responding the chances it will respond after a few tries are poor.
     * However, the original code looped and it only happens on
     * the error condition.
      */
    for (failures=0; failures<10; failures++)
    {
        rc = ldap_simple_bind_s(ldc->ldap,
                                (char *)ldc->binddn,
                                (char *)ldc->bindpw);
        if (!AP_LDAP_IS_SERVER_DOWN(rc)) {
            break;
        } else if (failures == 5) {
           /* attempt to init the connection once again */
           uldap_connection_unbind( ldc );
           rc = uldap_connection_init( r, ldc );
           if (LDAP_SUCCESS != rc)
           {
               break;
           }
       }
    }

    /* free the handle if there was an error
    */
    if (LDAP_SUCCESS != rc)
    {
       uldap_connection_unbind(ldc);
        ldc->reason = "LDAP: ldap_simple_bind_s() failed";
    }
    else {
        ldc->bound = 1;
        ldc->reason = "LDAP: connection open successful";
    }

    return(rc);
}


/*
 * Compare client certificate arrays.
 *
 * Returns 1 on compare failure, 0 otherwise.
 */
static int compare_client_certs(apr_array_header_t *srcs,
                                apr_array_header_t *dests)
{
    int i = 0;
    struct apr_ldap_opt_tls_cert_t *src, *dest;

    /* arrays both NULL? if so, then equal */
    if (srcs == NULL && dests == NULL) {
        return 0;
    }

    /* arrays different length or either NULL? If so, then not equal */
    if (srcs == NULL || dests == NULL || srcs->nelts != dests->nelts) {
        return 1;
    }

    /* run an actual comparison */
    src = (struct apr_ldap_opt_tls_cert_t *)srcs->elts;
    dest = (struct apr_ldap_opt_tls_cert_t *)dests->elts;
    for (i = 0; i < srcs->nelts; i++) {
        if (strcmp(src[i].path, dest[i].path) ||
            strcmp(src[i].password, dest[i].password) ||
            src[i].type != dest[i].type) {
            return 1;
        }
    }

    /* if we got here, the cert arrays were identical */
    return 0;

}


/*
 * Find an existing ldap connection struct that matches the
 * provided ldap connection parameters.
 *
 * If not found in the cache, a new ldc structure will be allocated
 * from st->pool and returned to the caller.  If found in the cache,
 * a pointer to the existing ldc structure will be returned.
 */
static util_ldap_connection_t *
            uldap_connection_find(request_rec *r,
                                  const char *host, int port,
                                  const char *binddn, const char *bindpw,
                                  deref_options deref, int secure)
{
    struct util_ldap_connection_t *l, *p; /* To traverse the linked list */
    int secureflag = secure;

    util_ldap_state_t *st =
        (util_ldap_state_t *)ap_get_module_config(r->server->module_config,
        &ldap_module);


#if APR_HAS_THREADS
    /* mutex lock this function */
    apr_thread_mutex_lock(st->mutex);
#endif

    if (secure < APR_LDAP_NONE) {
        secureflag = st->secure;
    }

    /* Search for an exact connection match in the list that is not
     * being used.
     */
    for (l=st->connections,p=NULL; l; l=l->next) {
#if APR_HAS_THREADS
        if (APR_SUCCESS == apr_thread_mutex_trylock(l->lock)) {
#endif
        if (   (l->port == port) && (strcmp(l->host, host) == 0)
            && ((!l->binddn && !binddn) || (l->binddn && binddn
                                             && !strcmp(l->binddn, binddn)))
            && ((!l->bindpw && !bindpw) || (l->bindpw && bindpw
                                             && !strcmp(l->bindpw, bindpw)))
            && (l->deref == deref) && (l->secure == secureflag)
            && !compare_client_certs(st->client_certs, l->client_certs))
        {
            break;
        }
#if APR_HAS_THREADS
            /* If this connection didn't match the criteria, then we
             * need to unlock the mutex so it is available to be reused.
             */
            apr_thread_mutex_unlock(l->lock);
        }
#endif
        p = l;
    }

    /* If nothing found, search again, but we don't care about the
     * binddn and bindpw this time.
     */
    if (!l) {
        for (l=st->connections,p=NULL; l; l=l->next) {
#if APR_HAS_THREADS
            if (APR_SUCCESS == apr_thread_mutex_trylock(l->lock)) {

#endif
            if ((l->port == port) && (strcmp(l->host, host) == 0) &&
                (l->deref == deref) && (l->secure == secureflag) &&
                !compare_client_certs(st->client_certs, l->client_certs))
            {
                /* the bind credentials have changed */
                l->bound = 0;
                util_ldap_strdup((char**)&(l->binddn), binddn);
                util_ldap_strdup((char**)&(l->bindpw), bindpw);
                break;
            }
#if APR_HAS_THREADS
                /* If this connection didn't match the criteria, then we
                 * need to unlock the mutex so it is available to be reused.
                 */
                apr_thread_mutex_unlock(l->lock);
            }
#endif
            p = l;
        }
    }

/* artificially disable cache */
/* l = NULL; */

    /* If no connection what found after the second search, we
     * must create one.
     */
    if (!l) {

        /*
         * Add the new connection entry to the linked list. Note that we
         * don't actually establish an LDAP connection yet; that happens
         * the first time authentication is requested.
         */
        /* create the details to the pool in st */
        l = apr_pcalloc(st->pool, sizeof(util_ldap_connection_t));
        if (apr_pool_create(&l->pool, st->pool) != APR_SUCCESS) { 
            ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0, r,
                          "util_ldap: Failed to create memory pool");
#if APR_HAS_THREADS
            apr_thread_mutex_unlock(st->mutex);
#endif
            return NULL;
    
        }
#if APR_HAS_THREADS
        apr_thread_mutex_create(&l->lock, APR_THREAD_MUTEX_DEFAULT, st->pool);
        apr_thread_mutex_lock(l->lock);
#endif
        l->bound = 0;
        l->host = apr_pstrdup(st->pool, host);
        l->port = port;
        l->deref = deref;
        util_ldap_strdup((char**)&(l->binddn), binddn);
        util_ldap_strdup((char**)&(l->bindpw), bindpw);

        /* The security mode after parsing the URL will always be either
         * APR_LDAP_NONE (ldap://) or APR_LDAP_SSL (ldaps://).
         * If the security setting is NONE, override it to the security
         * setting optionally supplied by the admin using LDAPTrustedMode
         */
        l->secure = secureflag;

        /* save away a copy of the client cert list that is presently valid */
        l->client_certs = apr_array_copy_hdr(l->pool, st->client_certs);

        /* add the cleanup to the pool */
        apr_pool_cleanup_register(l->pool, l,
                                  uldap_connection_cleanup,
                                  apr_pool_cleanup_null);

        if (p) {
            p->next = l;
        }
        else {
            st->connections = l;
        }
    }

#if APR_HAS_THREADS
    apr_thread_mutex_unlock(st->mutex);
#endif
    return l;
}

/* ------------------------------------------------------------------ */

/*
 * Compares two DNs to see if they're equal. The only way to do this correctly
 * is to search for the dn and then do ldap_get_dn() on the result. This should
 * match the initial dn, since it would have been also retrieved with
 * ldap_get_dn(). This is expensive, so if the configuration value
 * compare_dn_on_server is false, just does an ordinary strcmp.
 *
 * The lock for the ldap cache should already be acquired.
 */
static int uldap_cache_comparedn(request_rec *r, util_ldap_connection_t *ldc,
                                 const char *url, const char *dn,
                                 const char *reqdn, int compare_dn_on_server)
{
    int result = 0;
    util_url_node_t *curl;
    util_url_node_t curnode;
    util_dn_compare_node_t *node;
    util_dn_compare_node_t newnode;
    int failures = 0;
    LDAPMessage *res, *entry;
    char *searchdn;

    util_ldap_state_t *st = (util_ldap_state_t *)
                            ap_get_module_config(r->server->module_config,
                                                 &ldap_module);

    /* get cache entry (or create one) */
    LDAP_CACHE_LOCK();

    curnode.url = url;
    curl = util_ald_cache_fetch(st->util_ldap_cache, &curnode);
    if (curl == NULL) {
        curl = util_ald_create_caches(st, url);
    }
    LDAP_CACHE_UNLOCK();

    /* a simple compare? */
    if (!compare_dn_on_server) {
        /* unlock this read lock */
        if (strcmp(dn, reqdn)) {
            ldc->reason = "DN Comparison FALSE (direct strcmp())";
            return LDAP_COMPARE_FALSE;
        }
        else {
            ldc->reason = "DN Comparison TRUE (direct strcmp())";
            return LDAP_COMPARE_TRUE;
        }
    }

    if (curl) {
        /* no - it's a server side compare */
        LDAP_CACHE_LOCK();

        /* is it in the compare cache? */
        newnode.reqdn = (char *)reqdn;
        node = util_ald_cache_fetch(curl->dn_compare_cache, &newnode);
        if (node != NULL) {
            /* If it's in the cache, it's good */
            /* unlock this read lock */
            LDAP_CACHE_UNLOCK();
            ldc->reason = "DN Comparison TRUE (cached)";
            return LDAP_COMPARE_TRUE;
        }

        /* unlock this read lock */
        LDAP_CACHE_UNLOCK();
    }

start_over:
    if (failures++ > 10) {
        /* too many failures */
        return result;
    }

    /* make a server connection */
    if (LDAP_SUCCESS != (result = uldap_connection_open(r, ldc))) {
        /* connect to server failed */
        return result;
    }

    /* search for reqdn */
    result = ldap_search_ext_s(ldc->ldap, (char *)reqdn, LDAP_SCOPE_BASE,
                               "(objectclass=*)", NULL, 1,
                               NULL, NULL, NULL, APR_LDAP_SIZELIMIT, &res);
    if (AP_LDAP_IS_SERVER_DOWN(result))
    {
        ldc->reason = "DN Comparison ldap_search_ext_s() "
                      "failed with server down";
        uldap_connection_unbind(ldc);
        goto start_over;
    }
    if (result != LDAP_SUCCESS) {
        /* search for reqdn failed - no match */
        ldc->reason = "DN Comparison ldap_search_ext_s() failed";
        return result;
    }

    entry = ldap_first_entry(ldc->ldap, res);
    searchdn = ldap_get_dn(ldc->ldap, entry);

    ldap_msgfree(res);
    if (strcmp(dn, searchdn) != 0) {
        /* compare unsuccessful */
        ldc->reason = "DN Comparison FALSE (checked on server)";
        result = LDAP_COMPARE_FALSE;
    }
    else {
        if (curl) {
            /* compare successful - add to the compare cache */
            LDAP_CACHE_LOCK();
            newnode.reqdn = (char *)reqdn;
            newnode.dn = (char *)dn;

            node = util_ald_cache_fetch(curl->dn_compare_cache, &newnode);
            if (   (node == NULL)
                || (strcmp(reqdn, node->reqdn) != 0)
                || (strcmp(dn, node->dn) != 0))
            {
                util_ald_cache_insert(curl->dn_compare_cache, &newnode);
            }
            LDAP_CACHE_UNLOCK();
        }
        ldc->reason = "DN Comparison TRUE (checked on server)";
        result = LDAP_COMPARE_TRUE;
    }
    ldap_memfree(searchdn);
    return result;

}

/*
 * Does an generic ldap_compare operation. It accepts a cache that it will use
 * to lookup the compare in the cache. We cache two kinds of compares
 * (require group compares) and (require user compares). Each compare has a different
 * cache node: require group includes the DN; require user does not because the
 * require user cache is owned by the
 *
 */
static int uldap_cache_compare(request_rec *r, util_ldap_connection_t *ldc,
                               const char *url, const char *dn,
                               const char *attrib, const char *value)
{
    int result = 0;
    util_url_node_t *curl;
    util_url_node_t curnode;
    util_compare_node_t *compare_nodep;
    util_compare_node_t the_compare_node;
    apr_time_t curtime = 0; /* silence gcc -Wall */
    int failures = 0;

    util_ldap_state_t *st = (util_ldap_state_t *)
                            ap_get_module_config(r->server->module_config,
                                                 &ldap_module);

    /* get cache entry (or create one) */
    LDAP_CACHE_LOCK();
    curnode.url = url;
    curl = util_ald_cache_fetch(st->util_ldap_cache, &curnode);
    if (curl == NULL) {
        curl = util_ald_create_caches(st, url);
    }
    LDAP_CACHE_UNLOCK();

    if (curl) {
        /* make a comparison to the cache */
        LDAP_CACHE_LOCK();
        curtime = apr_time_now();

        the_compare_node.dn = (char *)dn;
        the_compare_node.attrib = (char *)attrib;
        the_compare_node.value = (char *)value;
        the_compare_node.result = 0;

        compare_nodep = util_ald_cache_fetch(curl->compare_cache,
                                             &the_compare_node);

        if (compare_nodep != NULL) {
            /* found it... */
            if (curtime - compare_nodep->lastcompare > st->compare_cache_ttl) {
                /* ...but it is too old */
                util_ald_cache_remove(curl->compare_cache, compare_nodep);
            }
            else {
                /* ...and it is good */
                /* unlock this read lock */
                LDAP_CACHE_UNLOCK();
                if (LDAP_COMPARE_TRUE == compare_nodep->result) {
                    ldc->reason = "Comparison true (cached)";
                    return compare_nodep->result;
                }
                else if (LDAP_COMPARE_FALSE == compare_nodep->result) {
                    ldc->reason = "Comparison false (cached)";
                    return compare_nodep->result;
                }
                else if (LDAP_NO_SUCH_ATTRIBUTE == compare_nodep->result) {
                    ldc->reason = "Comparison no such attribute (cached)";
                    return compare_nodep->result;
                }
                else {
                    ldc->reason = "Comparison undefined (cached)";
                    return compare_nodep->result;
                }
            }
        }
        /* unlock this read lock */
        LDAP_CACHE_UNLOCK();
    }

start_over:
    if (failures++ > 10) {
        /* too many failures */
        return result;
    }
    if (LDAP_SUCCESS != (result = uldap_connection_open(r, ldc))) {
        /* connect failed */
        return result;
    }

    result = ldap_compare_s(ldc->ldap,
                            (char *)dn,
                            (char *)attrib,
                            (char *)value);
    if (AP_LDAP_IS_SERVER_DOWN(result)) { 
        /* connection failed - try again */
        ldc->reason = "ldap_compare_s() failed with server down";
        uldap_connection_unbind(ldc);
        goto start_over;
    }

    ldc->reason = "Comparison complete";
    if ((LDAP_COMPARE_TRUE == result) ||
        (LDAP_COMPARE_FALSE == result) ||
        (LDAP_NO_SUCH_ATTRIBUTE == result)) {
        if (curl) {
            /* compare completed; caching result */
            LDAP_CACHE_LOCK();
            the_compare_node.lastcompare = curtime;
            the_compare_node.result = result;

            /* If the node doesn't exist then insert it, otherwise just update
             * it with the last results
             */
            compare_nodep = util_ald_cache_fetch(curl->compare_cache,
                                                 &the_compare_node);
            if (   (compare_nodep == NULL)
                || (strcmp(the_compare_node.dn, compare_nodep->dn) != 0)
                || (strcmp(the_compare_node.attrib,compare_nodep->attrib) != 0)
                || (strcmp(the_compare_node.value, compare_nodep->value) != 0))
            {
                util_ald_cache_insert(curl->compare_cache, &the_compare_node);
            }
            else {
                compare_nodep->lastcompare = curtime;
                compare_nodep->result = result;
            }
            LDAP_CACHE_UNLOCK();
        }
        if (LDAP_COMPARE_TRUE == result) {
            ldc->reason = "Comparison true (adding to cache)";
            return LDAP_COMPARE_TRUE;
        }
        else if (LDAP_COMPARE_FALSE == result) {
            ldc->reason = "Comparison false (adding to cache)";
            return LDAP_COMPARE_FALSE;
        }
        else {
            ldc->reason = "Comparison no such attribute (adding to cache)";
            return LDAP_NO_SUCH_ATTRIBUTE;
        }
    }
    return result;
}

static int uldap_cache_checkuserid(request_rec *r, util_ldap_connection_t *ldc,
                                   const char *url, const char *basedn,
                                   int scope, char **attrs, const char *filter,
                                   const char *bindpw, const char **binddn,
                                   const char ***retvals)
{
    const char **vals = NULL;
    int numvals = 0;
    int result = 0;
    LDAPMessage *res, *entry;
    char *dn;
    int count;
    int failures = 0;
    util_url_node_t *curl;              /* Cached URL node */
    util_url_node_t curnode;
    util_search_node_t *search_nodep;   /* Cached search node */
    util_search_node_t the_search_node;
    apr_time_t curtime;

    util_ldap_state_t *st =
        (util_ldap_state_t *)ap_get_module_config(r->server->module_config,
        &ldap_module);

    /* Get the cache node for this url */
    LDAP_CACHE_LOCK();
    curnode.url = url;
    curl = (util_url_node_t *)util_ald_cache_fetch(st->util_ldap_cache,
                                                   &curnode);
    if (curl == NULL) {
        curl = util_ald_create_caches(st, url);
    }
    LDAP_CACHE_UNLOCK();

    if (curl) {
        LDAP_CACHE_LOCK();
        the_search_node.username = filter;
        search_nodep = util_ald_cache_fetch(curl->search_cache,
                                            &the_search_node);
        if (search_nodep != NULL) {

            /* found entry in search cache... */
            curtime = apr_time_now();

            /*
             * Remove this item from the cache if its expired. If the sent
             * password doesn't match the storepassword, the entry will
             * be removed and readded later if the credentials pass
             * authentication.
             */
            if ((curtime - search_nodep->lastbind) > st->search_cache_ttl) {
                /* ...but entry is too old */
                util_ald_cache_remove(curl->search_cache, search_nodep);
            }
            else if (   (search_nodep->bindpw)
                     && (search_nodep->bindpw[0] != '\0')
                     && (strcmp(search_nodep->bindpw, bindpw) == 0))
            {
                /* ...and entry is valid */
                *binddn = apr_pstrdup(r->pool, search_nodep->dn);
                if (attrs) {
                    int i;
                    *retvals = apr_pcalloc(r->pool, sizeof(char *) * search_nodep->numvals);
                    for (i = 0; i < search_nodep->numvals; i++) {
                        (*retvals)[i] = apr_pstrdup(r->pool, search_nodep->vals[i]);
                    }
                }
                LDAP_CACHE_UNLOCK();
                ldc->reason = "Authentication successful (cached)";
                return LDAP_SUCCESS;
            }
        }
        /* unlock this read lock */
        LDAP_CACHE_UNLOCK();
    }

    /*
     * At this point, there is no valid cached search, so lets do the search.
     */

    /*
     * If LDAP operation fails due to LDAP_SERVER_DOWN, control returns here.
     */
start_over:
    if (failures++ > 10) {
        return result;
    }
    if (LDAP_SUCCESS != (result = uldap_connection_open(r, ldc))) {
        return result;
    }

    /* try do the search */
    result = ldap_search_ext_s(ldc->ldap,
                               (char *)basedn, scope,
                               (char *)filter, attrs, 0,
                               NULL, NULL, NULL, APR_LDAP_SIZELIMIT, &res);
    if (AP_LDAP_IS_SERVER_DOWN(result))
    {
        ldc->reason = "ldap_search_ext_s() for user failed with server down";
        uldap_connection_unbind(ldc);
        goto start_over;
    }

    /* if there is an error (including LDAP_NO_SUCH_OBJECT) return now */
    if (result != LDAP_SUCCESS) {
        ldc->reason = "ldap_search_ext_s() for user failed";
        return result;
    }

    /*
     * We should have found exactly one entry; to find a different
     * number is an error.
     */
    count = ldap_count_entries(ldc->ldap, res);
    if (count != 1)
    {
        if (count == 0 )
            ldc->reason = "User not found";
        else
            ldc->reason = "User is not unique (search found two "
                          "or more matches)";
        ldap_msgfree(res);
        return LDAP_NO_SUCH_OBJECT;
    }

    entry = ldap_first_entry(ldc->ldap, res);

    /* Grab the dn, copy it into the pool, and free it again */
    dn = ldap_get_dn(ldc->ldap, entry);
    *binddn = apr_pstrdup(r->pool, dn);
    ldap_memfree(dn);

    /*
     * A bind to the server with an empty password always succeeds, so
     * we check to ensure that the password is not empty. This implies
     * that users who actually do have empty passwords will never be
     * able to authenticate with this module. I don't see this as a big
     * problem.
     */
    if (!bindpw || strlen(bindpw) <= 0) {
        ldap_msgfree(res);
        ldc->reason = "Empty password not allowed";
        return LDAP_INVALID_CREDENTIALS;
    }

    /*
     * Attempt to bind with the retrieved dn and the password. If the bind
     * fails, it means that the password is wrong (the dn obviously
     * exists, since we just retrieved it)
     */
    result = ldap_simple_bind_s(ldc->ldap,
                                (char *)*binddn,
                                (char *)bindpw);
    if (AP_LDAP_IS_SERVER_DOWN(result)) {
        ldc->reason = "ldap_simple_bind_s() to check user credentials "
                      "failed with server down";
        ldap_msgfree(res);
        uldap_connection_unbind(ldc);
        goto start_over;
    }

    /* failure? if so - return */
    if (result != LDAP_SUCCESS) {
        ldc->reason = "ldap_simple_bind_s() to check user credentials failed";
        ldap_msgfree(res);
        uldap_connection_unbind(ldc);
        return result;
    }
    else {
        /*
         * We have just bound the connection to a different user and password
         * combination, which might be reused unintentionally next time this
         * connection is used from the connection pool. To ensure no confusion,
         * we mark the connection as unbound.
         */
        ldc->bound = 0;
    }

    /*
     * Get values for the provided attributes.
     */
    if (attrs) {
        int k = 0;
        int i = 0;
        while (attrs[k++]);
        vals = apr_pcalloc(r->pool, sizeof(char *) * (k+1));
        numvals = k;
        while (attrs[i]) {
            char **values;
            int j = 0;
            char *str = NULL;
            /* get values */
            values = ldap_get_values(ldc->ldap, entry, attrs[i]);
            while (values && values[j]) {
                str = str ? apr_pstrcat(r->pool, str, "; ", values[j], NULL)
                          : apr_pstrdup(r->pool, values[j]);
                j++;
            }
            ldap_value_free(values);
            vals[i] = str;
            i++;
        }
        *retvals = vals;
    }

    /*
     * Add the new username to the search cache.
     */
    if (curl) {
        LDAP_CACHE_LOCK();
        the_search_node.username = filter;
        the_search_node.dn = *binddn;
        the_search_node.bindpw = bindpw;
        the_search_node.lastbind = apr_time_now();
        the_search_node.vals = vals;
        the_search_node.numvals = numvals;

        /* Search again to make sure that another thread didn't ready insert
         * this node into the cache before we got here. If it does exist then
         * update the lastbind
         */
        search_nodep = util_ald_cache_fetch(curl->search_cache,
                                            &the_search_node);
        if ((search_nodep == NULL) ||
            (strcmp(*binddn, search_nodep->dn) != 0)) {

            /* Nothing in cache, insert new entry */
            util_ald_cache_insert(curl->search_cache, &the_search_node);
        }
        else if ((!search_nodep->bindpw) ||
            (strcmp(bindpw, search_nodep->bindpw) != 0)) {

            /* Entry in cache is invalid, remove it and insert new one */
            util_ald_cache_remove(curl->search_cache, search_nodep);
            util_ald_cache_insert(curl->search_cache, &the_search_node);
        }
        else {
            /* Cache entry is valid, update lastbind */
            search_nodep->lastbind = the_search_node.lastbind;
        }
        LDAP_CACHE_UNLOCK();
    }
    ldap_msgfree(res);

    ldc->reason = "Authentication successful";
    return LDAP_SUCCESS;
}

/*
 * This function will return the DN of the entry matching userid.
 * It is used to get the DN in case some other module than mod_auth_ldap
 * has authenticated the user.
 * The function is basically a copy of uldap_cache_checkuserid
 * with password checking removed.
 */
static int uldap_cache_getuserdn(request_rec *r, util_ldap_connection_t *ldc,
                                 const char *url, const char *basedn,
                                 int scope, char **attrs, const char *filter,
                                 const char **binddn, const char ***retvals)
{
    const char **vals = NULL;
    int numvals = 0;
    int result = 0;
    LDAPMessage *res, *entry;
    char *dn;
    int count;
    int failures = 0;
    util_url_node_t *curl;              /* Cached URL node */
    util_url_node_t curnode;
    util_search_node_t *search_nodep;   /* Cached search node */
    util_search_node_t the_search_node;
    apr_time_t curtime;

    util_ldap_state_t *st =
        (util_ldap_state_t *)ap_get_module_config(r->server->module_config,
        &ldap_module);

    /* Get the cache node for this url */
    LDAP_CACHE_LOCK();
    curnode.url = url;
    curl = (util_url_node_t *)util_ald_cache_fetch(st->util_ldap_cache,
                                                   &curnode);
    if (curl == NULL) {
        curl = util_ald_create_caches(st, url);
    }
    LDAP_CACHE_UNLOCK();

    if (curl) {
        LDAP_CACHE_LOCK();
        the_search_node.username = filter;
        search_nodep = util_ald_cache_fetch(curl->search_cache,
                                            &the_search_node);
        if (search_nodep != NULL) {

            /* found entry in search cache... */
            curtime = apr_time_now();

            /*
             * Remove this item from the cache if its expired.
             */
            if ((curtime - search_nodep->lastbind) > st->search_cache_ttl) {
                /* ...but entry is too old */
                util_ald_cache_remove(curl->search_cache, search_nodep);
            }
            else {
                /* ...and entry is valid */
                *binddn = apr_pstrdup(r->pool, search_nodep->dn);
                if (attrs) {
                    int i;
                    *retvals = apr_pcalloc(r->pool, sizeof(char *) * search_nodep->numvals);
                    for (i = 0; i < search_nodep->numvals; i++) {
                        (*retvals)[i] = apr_pstrdup(r->pool, search_nodep->vals[i]);
                    }
                }
                LDAP_CACHE_UNLOCK();
                ldc->reason = "Search successful (cached)";
                return LDAP_SUCCESS;
            }
        }
        /* unlock this read lock */
        LDAP_CACHE_UNLOCK();
    }

    /*
     * At this point, there is no valid cached search, so lets do the search.
     */

    /*
     * If LDAP operation fails due to LDAP_SERVER_DOWN, control returns here.
     */
start_over:
    if (failures++ > 10) {
        return result;
    }
    if (LDAP_SUCCESS != (result = uldap_connection_open(r, ldc))) {
        return result;
    }

    /* try do the search */
    result = ldap_search_ext_s(ldc->ldap,
                               (char *)basedn, scope,
                               (char *)filter, attrs, 0,
                               NULL, NULL, NULL, APR_LDAP_SIZELIMIT, &res);
    if (AP_LDAP_IS_SERVER_DOWN(result))
    {
        ldc->reason = "ldap_search_ext_s() for user failed with server down";
        uldap_connection_unbind(ldc);
        goto start_over;
    }

    /* if there is an error (including LDAP_NO_SUCH_OBJECT) return now */
    if (result != LDAP_SUCCESS) {
        ldc->reason = "ldap_search_ext_s() for user failed";
        return result;
    }

    /*
     * We should have found exactly one entry; to find a different
     * number is an error.
     */
    count = ldap_count_entries(ldc->ldap, res);
    if (count != 1)
    {
        if (count == 0 )
            ldc->reason = "User not found";
        else
            ldc->reason = "User is not unique (search found two "
                          "or more matches)";
        ldap_msgfree(res);
        return LDAP_NO_SUCH_OBJECT;
    }

    entry = ldap_first_entry(ldc->ldap, res);

    /* Grab the dn, copy it into the pool, and free it again */
    dn = ldap_get_dn(ldc->ldap, entry);
    *binddn = apr_pstrdup(r->pool, dn);
    ldap_memfree(dn);

    /*
     * Get values for the provided attributes.
     */
    if (attrs) {
        int k = 0;
        int i = 0;
        while (attrs[k++]);
        vals = apr_pcalloc(r->pool, sizeof(char *) * (k+1));
        numvals = k;
        while (attrs[i]) {
            char **values;
            int j = 0;
            char *str = NULL;
            /* get values */
            values = ldap_get_values(ldc->ldap, entry, attrs[i]);
            while (values && values[j]) {
                str = str ? apr_pstrcat(r->pool, str, "; ", values[j], NULL)
                          : apr_pstrdup(r->pool, values[j]);
                j++;
            }
            ldap_value_free(values);
            vals[i] = str;
            i++;
        }
        *retvals = vals;
    }

    /*
     * Add the new username to the search cache.
     */
    if (curl) {
        LDAP_CACHE_LOCK();
        the_search_node.username = filter;
        the_search_node.dn = *binddn;
        the_search_node.bindpw = NULL;
        the_search_node.lastbind = apr_time_now();
        the_search_node.vals = vals;
        the_search_node.numvals = numvals;

        /* Search again to make sure that another thread didn't ready insert
         * this node into the cache before we got here. If it does exist then
         * update the lastbind
         */
        search_nodep = util_ald_cache_fetch(curl->search_cache,
                                            &the_search_node);
        if ((search_nodep == NULL) ||
            (strcmp(*binddn, search_nodep->dn) != 0)) {

            /* Nothing in cache, insert new entry */
            util_ald_cache_insert(curl->search_cache, &the_search_node);
        }
        /*
         * Don't update lastbind on entries with bindpw because
         * we haven't verified that password. It's OK to update
         * the entry if there is no password in it.
         */
        else if (!search_nodep->bindpw) {
            /* Cache entry is valid, update lastbind */
            search_nodep->lastbind = the_search_node.lastbind;
        }
        LDAP_CACHE_UNLOCK();
    }

    ldap_msgfree(res);

    ldc->reason = "Search successful";
    return LDAP_SUCCESS;
}

/*
 * Reports if ssl support is enabled
 *
 * 1 = enabled, 0 = not enabled
 */
static int uldap_ssl_supported(request_rec *r)
{
   util_ldap_state_t *st = (util_ldap_state_t *)ap_get_module_config(
                                r->server->module_config, &ldap_module);

   return(st->ssl_supported);
}


/* ---------------------------------------- */
/* config directives */


static const char *util_ldap_set_cache_bytes(cmd_parms *cmd, void *dummy,
                                             const char *bytes)
{
    util_ldap_state_t *st =
        (util_ldap_state_t *)ap_get_module_config(cmd->server->module_config,
                                                  &ldap_module);
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);

    if (err != NULL) {
        return err;
    }

    st->cache_bytes = atol(bytes);

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, cmd->server,
                 "[%" APR_PID_T_FMT "] ldap cache: Setting shared memory "
                 " cache size to %" APR_SIZE_T_FMT " bytes.",
                 getpid(), st->cache_bytes);

    return NULL;
}

static const char *util_ldap_set_cache_file(cmd_parms *cmd, void *dummy,
                                            const char *file)
{
    util_ldap_state_t *st =
        (util_ldap_state_t *)ap_get_module_config(cmd->server->module_config,
                                                  &ldap_module);
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);

    if (err != NULL) {
        return err;
    }

    if (file) {
        st->cache_file = ap_server_root_relative(st->pool, file);
    }
    else {
        st->cache_file = NULL;
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, cmd->server,
                 "LDAP cache: Setting shared memory cache file to %s bytes.",
                 st->cache_file);

    return NULL;
}

static const char *util_ldap_set_cache_ttl(cmd_parms *cmd, void *dummy,
                                           const char *ttl)
{
    util_ldap_state_t *st =
        (util_ldap_state_t *)ap_get_module_config(cmd->server->module_config,
                                                  &ldap_module);
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);

    if (err != NULL) {
        return err;
    }

    st->search_cache_ttl = atol(ttl) * 1000000;

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, cmd->server,
                 "[%" APR_PID_T_FMT "] ldap cache: Setting cache TTL to %ld microseconds.",
                 getpid(), st->search_cache_ttl);

    return NULL;
}

static const char *util_ldap_set_cache_entries(cmd_parms *cmd, void *dummy,
                                               const char *size)
{
    util_ldap_state_t *st =
        (util_ldap_state_t *)ap_get_module_config(cmd->server->module_config,
                                                  &ldap_module);
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);

    if (err != NULL) {
        return err;
    }

    st->search_cache_size = atol(size);
    if (st->search_cache_size < 0) {
        st->search_cache_size = 0;
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, cmd->server,
                 "[%" APR_PID_T_FMT "] ldap cache: Setting search cache size to %ld entries.",
                 getpid(), st->search_cache_size);

    return NULL;
}

static const char *util_ldap_set_opcache_ttl(cmd_parms *cmd, void *dummy,
                                             const char *ttl)
{
    util_ldap_state_t *st =
        (util_ldap_state_t *)ap_get_module_config(cmd->server->module_config,
                                                  &ldap_module);
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);

    if (err != NULL) {
        return err;
    }

    st->compare_cache_ttl = atol(ttl) * 1000000;

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, cmd->server,
                 "[%" APR_PID_T_FMT "] ldap cache: Setting operation cache TTL to %ld microseconds.",
                 getpid(), st->compare_cache_ttl);

    return NULL;
}

static const char *util_ldap_set_opcache_entries(cmd_parms *cmd, void *dummy,
                                                 const char *size)
{
    util_ldap_state_t *st =
        (util_ldap_state_t *)ap_get_module_config(cmd->server->module_config,
                                                  &ldap_module);
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);

    if (err != NULL) {
        return err;
    }

    st->compare_cache_size = atol(size);
    if (st->compare_cache_size < 0) {
        st->compare_cache_size = 0;
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, cmd->server,
                 "[%" APR_PID_T_FMT "] ldap cache: Setting operation cache size to %ld "
                 "entries.", getpid(), st->compare_cache_size);

    return NULL;
}


/**
 * Parse the certificate type.
 *
 * The type can be one of the following:
 * CA_DER, CA_BASE64, CA_CERT7_DB, CA_SECMOD, CERT_DER, CERT_BASE64,
 * CERT_KEY3_DB, CERT_NICKNAME, KEY_DER, KEY_BASE64
 *
 * If no matches are found, APR_LDAP_CA_TYPE_UNKNOWN is returned.
 */
static int util_ldap_parse_cert_type(const char *type)
{
    /* Authority file in binary DER format */
    if (0 == strcasecmp("CA_DER", type)) {
        return APR_LDAP_CA_TYPE_DER;
    }

    /* Authority file in Base64 format */
    else if (0 == strcasecmp("CA_BASE64", type)) {
        return APR_LDAP_CA_TYPE_BASE64;
    }

    /* Netscape certificate database file/directory */
    else if (0 == strcasecmp("CA_CERT7_DB", type)) {
        return APR_LDAP_CA_TYPE_CERT7_DB;
    }

    /* Netscape secmod file/directory */
    else if (0 == strcasecmp("CA_SECMOD", type)) {
        return APR_LDAP_CA_TYPE_SECMOD;
    }

    /* Client cert file in DER format */
    else if (0 == strcasecmp("CERT_DER", type)) {
        return APR_LDAP_CERT_TYPE_DER;
    }

    /* Client cert file in Base64 format */
    else if (0 == strcasecmp("CERT_BASE64", type)) {
        return APR_LDAP_CERT_TYPE_BASE64;
    }

    /* Client cert file in PKCS#12 format */
    else if (0 == strcasecmp("CERT_PFX", type)) {
        return APR_LDAP_CERT_TYPE_PFX;
    }

    /* Netscape client cert database file/directory */
    else if (0 == strcasecmp("CERT_KEY3_DB", type)) {
        return APR_LDAP_CERT_TYPE_KEY3_DB;
    }

    /* Netscape client cert nickname */
    else if (0 == strcasecmp("CERT_NICKNAME", type)) {
        return APR_LDAP_CERT_TYPE_NICKNAME;
    }

    /* Client cert key file in DER format */
    else if (0 == strcasecmp("KEY_DER", type)) {
        return APR_LDAP_KEY_TYPE_DER;
    }

    /* Client cert key file in Base64 format */
    else if (0 == strcasecmp("KEY_BASE64", type)) {
        return APR_LDAP_KEY_TYPE_BASE64;
    }

    /* Client cert key file in PKCS#12 format */
    else if (0 == strcasecmp("KEY_PFX", type)) {
        return APR_LDAP_KEY_TYPE_PFX;
    }

    else {
        return APR_LDAP_CA_TYPE_UNKNOWN;
    }

}


/**
 * Set LDAPTrustedGlobalCert.
 *
 * This directive takes either two or three arguments:
 * - certificate type
 * - certificate file / directory / nickname
 * - certificate password (optional)
 *
 * This directive may only be used globally.
 */
static const char *util_ldap_set_trusted_global_cert(cmd_parms *cmd,
                                                     void *dummy,
                                                     const char *type,
                                                     const char *file,
                                                     const char *password)
{
    util_ldap_state_t *st =
        (util_ldap_state_t *)ap_get_module_config(cmd->server->module_config,
                                                  &ldap_module);
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    apr_finfo_t finfo;
    apr_status_t rv;
    int cert_type = 0;
    apr_ldap_opt_tls_cert_t *cert;

    if (err != NULL) {
        return err;
    }

    /* handle the certificate type */
    if (type) {
        cert_type = util_ldap_parse_cert_type(type);
        if (APR_LDAP_CA_TYPE_UNKNOWN == cert_type) {
           return apr_psprintf(cmd->pool, "The certificate type %s is "
                                          "not recognised. It should be one "
                                          "of CA_DER, CA_BASE64, CA_CERT7_DB, "
                                          "CA_SECMOD, CERT_DER, CERT_BASE64, "
                                          "CERT_KEY3_DB, CERT_NICKNAME, "
                                          "KEY_DER, KEY_BASE64", type);
        }
    }
    else {
        return "Certificate type was not specified.";
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, cmd->server,
                      "LDAP: SSL trusted global cert - %s (type %s)",
                       file, type);

    /* add the certificate to the global array */
    cert = (apr_ldap_opt_tls_cert_t *)apr_array_push(st->global_certs);
    cert->type = cert_type;
    cert->path = file;
    cert->password = password;

    /* if file is a file or path, fix the path */
    if (cert_type != APR_LDAP_CA_TYPE_UNKNOWN &&
        cert_type != APR_LDAP_CERT_TYPE_NICKNAME) {

        cert->path = ap_server_root_relative(cmd->pool, file);
        if (cert->path &&
            ((rv = apr_stat (&finfo, cert->path, APR_FINFO_MIN, cmd->pool))
                != APR_SUCCESS))
        {
            ap_log_error(APLOG_MARK, APLOG_ERR, rv, cmd->server,
                         "LDAP: Could not open SSL trusted certificate "
                         "authority file - %s",
                         cert->path == NULL ? file : cert->path);
            return "Invalid global certificate file path";
        }
    }

    return(NULL);
}


/**
 * Set LDAPTrustedClientCert.
 *
 * This directive takes either two or three arguments:
 * - certificate type
 * - certificate file / directory / nickname
 * - certificate password (optional)
 */
static const char *util_ldap_set_trusted_client_cert(cmd_parms *cmd,
                                                     void *config,
                                                     const char *type,
                                                     const char *file,
                                                     const char *password)
{
    util_ldap_state_t *st =
        (util_ldap_state_t *)ap_get_module_config(cmd->server->module_config,
                                                  &ldap_module);
    apr_finfo_t finfo;
    apr_status_t rv;
    int cert_type = 0;
    apr_ldap_opt_tls_cert_t *cert;

    /* handle the certificate type */
    if (type) {
        cert_type = util_ldap_parse_cert_type(type);
        if (APR_LDAP_CA_TYPE_UNKNOWN == cert_type) {
            return apr_psprintf(cmd->pool, "The certificate type \"%s\" is "
                                           "not recognised. It should be one "
                                           "of CERT_DER, CERT_BASE64, "
                                           "CERT_NICKNAME, CERT_PFX,"
                                           "KEY_DER, KEY_BASE64, KEY_PFX",
                                           type);
        }
        else if (APR_LDAP_CA_TYPE_DER == cert_type ||
                 APR_LDAP_CA_TYPE_BASE64 == cert_type ||
                 APR_LDAP_CA_TYPE_CERT7_DB == cert_type ||
                 APR_LDAP_CA_TYPE_SECMOD == cert_type ||
                 APR_LDAP_CERT_TYPE_PFX == cert_type ||
                 APR_LDAP_CERT_TYPE_KEY3_DB == cert_type) {
            return apr_psprintf(cmd->pool, "The certificate type \"%s\" is "
                                           "only valid within a "
                                           "LDAPTrustedGlobalCert directive. "
                                           "Only CERT_DER, CERT_BASE64, "
                                           "CERT_NICKNAME, KEY_DER, and "
                                           "KEY_BASE64 may be used.", type);
        }
    }
    else {
        return "Certificate type was not specified.";
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, cmd->server,
                      "LDAP: SSL trusted client cert - %s (type %s)",
                       file, type);

    /* add the certificate to the global array */
    cert = (apr_ldap_opt_tls_cert_t *)apr_array_push(st->global_certs);
    cert->type = cert_type;
    cert->path = file;
    cert->password = password;

    /* if file is a file or path, fix the path */
    if (cert_type != APR_LDAP_CA_TYPE_UNKNOWN &&
        cert_type != APR_LDAP_CERT_TYPE_NICKNAME) {

        cert->path = ap_server_root_relative(cmd->pool, file);
        if (cert->path &&
            ((rv = apr_stat (&finfo, cert->path, APR_FINFO_MIN, cmd->pool))
                != APR_SUCCESS))
        {
            ap_log_error(APLOG_MARK, APLOG_ERR, rv, cmd->server,
                         "LDAP: Could not open SSL client certificate "
                         "file - %s",
                         cert->path == NULL ? file : cert->path);
            return "Invalid client certificate file path";
        }

    }

    return(NULL);
}


/**
 * Set LDAPTrustedMode.
 *
 * This directive sets what encryption mode to use on a connection:
 * - None (No encryption)
 * - SSL (SSL encryption)
 * - STARTTLS (TLS encryption)
 */
static const char *util_ldap_set_trusted_mode(cmd_parms *cmd, void *dummy,
                                              const char *mode)
{
    util_ldap_state_t *st =
    (util_ldap_state_t *)ap_get_module_config(cmd->server->module_config,
                                              &ldap_module);

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, cmd->server,
                      "LDAP: SSL trusted mode - %s",
                       mode);

    if (0 == strcasecmp("NONE", mode)) {
        st->secure = APR_LDAP_NONE;
    }
    else if (0 == strcasecmp("SSL", mode)) {
        st->secure = APR_LDAP_SSL;
    }
    else if (   (0 == strcasecmp("TLS", mode))
             || (0 == strcasecmp("STARTTLS", mode))) {
        st->secure = APR_LDAP_STARTTLS;
    }
    else {
        return "Invalid LDAPTrustedMode setting: must be one of NONE, "
               "SSL, or TLS/STARTTLS";
    }

    st->secure_set = 1;
    return(NULL);
}

static const char *util_ldap_set_verify_srv_cert(cmd_parms *cmd,
                                                 void *dummy,
                                                 int mode)
{
    util_ldap_state_t *st =
    (util_ldap_state_t *)ap_get_module_config(cmd->server->module_config,
                                              &ldap_module);
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);

    if (err != NULL) {
        return err;
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, cmd->server,
                      "LDAP: SSL verify server certificate - %s",
                      mode?"TRUE":"FALSE");

    st->verify_svr_cert = mode;

    return(NULL);
}


static const char *util_ldap_set_connection_timeout(cmd_parms *cmd,
                                                    void *dummy,
                                                    const char *ttl)
{
#ifdef LDAP_OPT_NETWORK_TIMEOUT
    util_ldap_state_t *st =
        (util_ldap_state_t *)ap_get_module_config(cmd->server->module_config,
                                                  &ldap_module);
#endif
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);

    if (err != NULL) {
        return err;
    }

#ifdef LDAP_OPT_NETWORK_TIMEOUT
    st->connectionTimeout = atol(ttl);

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, cmd->server,
                 "[%" APR_PID_T_FMT "] ldap connection: Setting connection timeout to "
                 "%ld seconds.", getpid(), st->connectionTimeout);
#else
    ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, cmd->server,
                 "LDAP: Connection timout option not supported by the "
                 "LDAP SDK in use." );
#endif

    return NULL;
}


static void *util_ldap_create_config(apr_pool_t *p, server_rec *s)
{
    util_ldap_state_t *st =
        (util_ldap_state_t *)apr_pcalloc(p, sizeof(util_ldap_state_t));

    /* Create a per vhost pool for mod_ldap to use, serialized with 
     * st->mutex (also one per vhost) 
     */
    apr_pool_create(&st->pool, p);
#if APR_HAS_THREADS
    apr_thread_mutex_create(&st->mutex, APR_THREAD_MUTEX_DEFAULT, st->pool);
#endif

    st->cache_bytes = 500000;
    st->search_cache_ttl = 600000000;
    st->search_cache_size = 1024;
    st->compare_cache_ttl = 600000000;
    st->compare_cache_size = 1024;
    st->connections = NULL;
    st->ssl_supported = 0;
    st->global_certs = apr_array_make(p, 10, sizeof(apr_ldap_opt_tls_cert_t));
    st->client_certs = apr_array_make(p, 10, sizeof(apr_ldap_opt_tls_cert_t));
    st->secure = APR_LDAP_NONE;
    st->secure_set = 0;
    st->connectionTimeout = 10;
    st->verify_svr_cert = 1;

    return st;
}

/* cache-related settings are not merged here, but in the post_config hook,
 * since the cache has not yet sprung to life
 */
static void *util_ldap_merge_config(apr_pool_t *p, void *basev,
                                    void *overridesv)
{
    util_ldap_state_t *st = apr_pcalloc(p, sizeof(util_ldap_state_t));
    util_ldap_state_t *base = (util_ldap_state_t *) basev;
    util_ldap_state_t *overrides = (util_ldap_state_t *) overridesv;

    st->pool = overrides->pool;
#if APR_HAS_THREADS
    st->mutex = overrides->mutex;
#endif

    /* The cache settings can not be modified in a 
        virtual host since all server use the same
        shared memory cache. */
    st->cache_bytes = base->cache_bytes;
    st->search_cache_ttl = base->search_cache_ttl;
    st->search_cache_size = base->search_cache_size;
    st->compare_cache_ttl = base->compare_cache_ttl;
    st->compare_cache_size = base->compare_cache_size;
    st->util_ldap_cache_lock = base->util_ldap_cache_lock; 

    st->connections = NULL;
    st->ssl_supported = 0;
    st->global_certs = apr_array_append(p, base->global_certs,
                                           overrides->global_certs);
    st->client_certs = apr_array_append(p, base->client_certs,
                                           overrides->client_certs);
    st->secure = (overrides->secure_set == 0) ? base->secure
                                              : overrides->secure;

    /* These LDAP connection settings can not be overwritten in 
        a virtual host. Once set in the base server, they must 
        remain the same. None of the LDAP SDKs seem to be able
        to handle setting the verify_svr_cert flag on a 
        per-connection basis.  The OpenLDAP client appears to be
        able to handle the connection timeout per-connection
        but the Novell SDK cannot.  Allowing the timeout to
        be set by each vhost is of little value so rather than
        trying to make special expections for one LDAP SDK, GLOBAL_ONLY 
        is being enforced on this setting as well. */
    st->connectionTimeout = base->connectionTimeout;
    st->verify_svr_cert = base->verify_svr_cert;

    return st;
}

static apr_status_t util_ldap_cleanup_module(void *data)
{

    server_rec *s = data;
    util_ldap_state_t *st = (util_ldap_state_t *)ap_get_module_config(
        s->module_config, &ldap_module);

    if (st->ssl_supported) {
        apr_ldap_ssl_deinit();
    }

    return APR_SUCCESS;

}

static int util_ldap_post_config(apr_pool_t *p, apr_pool_t *plog,
                                 apr_pool_t *ptemp, server_rec *s)
{
    apr_status_t result;
    server_rec *s_vhost;
    util_ldap_state_t *st_vhost;

    util_ldap_state_t *st = (util_ldap_state_t *)
                            ap_get_module_config(s->module_config,
                                                 &ldap_module);

    void *data;
    const char *userdata_key = "util_ldap_init";
    apr_ldap_err_t *result_err = NULL;
    int rc;

    /* util_ldap_post_config() will be called twice. Don't bother
     * going through all of the initialization on the first call
     * because it will just be thrown away.*/
    apr_pool_userdata_get(&data, userdata_key, s->process->pool);
    if (!data) {
        apr_pool_userdata_set((const void *)1, userdata_key,
                               apr_pool_cleanup_null, s->process->pool);

#if APR_HAS_SHARED_MEMORY
        /* If the cache file already exists then delete it.  Otherwise we are
         * going to run into problems creating the shared memory. */
        if (st->cache_file) {
            char *lck_file = apr_pstrcat(ptemp, st->cache_file, ".lck",
                                         NULL);
            apr_file_remove(lck_file, ptemp);
        }
#endif
        return OK;
    }

#if APR_HAS_SHARED_MEMORY
    /* initializing cache if shared memory size is not zero and we already
     * don't have shm address
     */
    if (!st->cache_shm && st->cache_bytes > 0) {
#endif
        result = util_ldap_cache_init(p, st);
        if (result != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_ERR, result, s,
                         "LDAP cache: could not create shared memory segment");
            return DONE;
        }


#if APR_HAS_SHARED_MEMORY
        if (st->cache_file) {
            st->lock_file = apr_pstrcat(st->pool, st->cache_file, ".lck",
                                        NULL);
        }
#endif

        result = apr_global_mutex_create(&st->util_ldap_cache_lock,
                                         st->lock_file, APR_LOCK_DEFAULT,
                                         st->pool);
        if (result != APR_SUCCESS) {
            return result;
        }

#ifdef AP_NEED_SET_MUTEX_PERMS
        result = unixd_set_global_mutex_perms(st->util_ldap_cache_lock);
        if (result != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_CRIT, result, s,
                         "LDAP cache: failed to set mutex permissions");
            return result;
        }
#endif

        /* merge config in all vhost */
        s_vhost = s->next;
        while (s_vhost) {
            st_vhost = (util_ldap_state_t *)
                       ap_get_module_config(s_vhost->module_config,
                                            &ldap_module);

#if APR_HAS_SHARED_MEMORY
            st_vhost->cache_shm = st->cache_shm;
            st_vhost->cache_rmm = st->cache_rmm;
            st_vhost->cache_file = st->cache_file;
            st_vhost->util_ldap_cache = st->util_ldap_cache;
            ap_log_error(APLOG_MARK, APLOG_DEBUG, result, s,
                         "LDAP merging Shared Cache conf: shm=0x%pp rmm=0x%pp "
                         "for VHOST: %s", st->cache_shm, st->cache_rmm,
                         s_vhost->server_hostname);
#endif
            st_vhost->lock_file = st->lock_file;
            s_vhost = s_vhost->next;
        }
#if APR_HAS_SHARED_MEMORY
    }
    else {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                     "LDAP cache: LDAPSharedCacheSize is zero, disabling "
                     "shared memory cache");
    }
#endif

    /* log the LDAP SDK used
     */
    {
        apr_ldap_err_t *result = NULL;
        apr_ldap_info(p, &(result));
        if (result != NULL) {
            ap_log_error(APLOG_MARK, APLOG_INFO, 0, s, "%s", result->reason);
        }
    }

    apr_pool_cleanup_register(p, s, util_ldap_cleanup_module,
                              util_ldap_cleanup_module);

    /*
     * Initialize SSL support, and log the result for the benefit of the admin.
     *
     * If SSL is not supported it is not necessarily an error, as the
     * application may not want to use it.
     */
    rc = apr_ldap_ssl_init(p,
                      NULL,
                      0,
                      &(result_err));
    if (APR_SUCCESS == rc) {
        rc = apr_ldap_set_option(ptemp, NULL, APR_LDAP_OPT_TLS_CERT,
                                 (void *)st->global_certs, &(result_err));
    }

    if (APR_SUCCESS == rc) {
        st->ssl_supported = 1;
        ap_log_error(APLOG_MARK, APLOG_INFO, 0, s,
                     "LDAP: SSL support available" );
    }
    else {
        st->ssl_supported = 0;
        ap_log_error(APLOG_MARK, APLOG_INFO, 0, s,
                     "LDAP: SSL support unavailable%s%s",
                     result_err ? ": " : "",
                     result_err ? result_err->reason : "");
    }

    return(OK);
}

static void util_ldap_child_init(apr_pool_t *p, server_rec *s)
{
    apr_status_t sts;
    util_ldap_state_t *st = ap_get_module_config(s->module_config,
                                                 &ldap_module);

    if (!st->util_ldap_cache_lock) return;

    sts = apr_global_mutex_child_init(&st->util_ldap_cache_lock,
                                      st->lock_file, p);
    if (sts != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, sts, s,
                     "Failed to initialise global mutex %s in child process %"
                     APR_PID_T_FMT ".",
                     st->lock_file, getpid());
    }
}

static const command_rec util_ldap_cmds[] = {
    AP_INIT_TAKE1("LDAPSharedCacheSize", util_ldap_set_cache_bytes,
                  NULL, RSRC_CONF,
                  "Set the size of the shared memory cache (in bytes). Use "
                  "0 to disable the shared memory cache. (default: 100000)"),

    AP_INIT_TAKE1("LDAPSharedCacheFile", util_ldap_set_cache_file,
                  NULL, RSRC_CONF,
                  "Set the file name for the shared memory cache."),

    AP_INIT_TAKE1("LDAPCacheEntries", util_ldap_set_cache_entries,
                  NULL, RSRC_CONF,
                  "Set the maximum number of entries that are possible in the "
                  "LDAP search cache. Use 0 or -1 to disable the search cache " 
                  "(default: 1024)"),
                  
    AP_INIT_TAKE1("LDAPCacheTTL", util_ldap_set_cache_ttl,
                  NULL, RSRC_CONF,
                  "Set the maximum time (in seconds) that an item can be "
                  "cached in the LDAP search cache. Use 0 for no limit. "
                  "(default 600)"),

    AP_INIT_TAKE1("LDAPOpCacheEntries", util_ldap_set_opcache_entries,
                  NULL, RSRC_CONF,
                  "Set the maximum number of entries that are possible "
                  "in the LDAP compare cache. Use 0 or -1 to disable the compare cache " 
                  "(default: 1024)"),

    AP_INIT_TAKE1("LDAPOpCacheTTL", util_ldap_set_opcache_ttl,
                  NULL, RSRC_CONF,
                  "Set the maximum time (in seconds) that an item is cached "
                  "in the LDAP operation cache. Use 0 for no limit. "
                  "(default: 600)"),

    AP_INIT_TAKE23("LDAPTrustedGlobalCert", util_ldap_set_trusted_global_cert,
                   NULL, RSRC_CONF,
                   "Takes three args; the file and/or directory containing "
                   "the trusted CA certificates (and global client certs "
                   "for Netware) used to validate the LDAP server.  Second "
                   "arg is the cert type for the first arg, one of CA_DER, "
                   "CA_BASE64, CA_CERT7_DB, CA_SECMOD, CERT_DER, CERT_BASE64, "
                   "CERT_KEY3_DB, CERT_NICKNAME, KEY_DER, or KEY_BASE64. "
                   "Third arg is an optional passphrase if applicable."),

    AP_INIT_TAKE23("LDAPTrustedClientCert", util_ldap_set_trusted_client_cert,
                   NULL, RSRC_CONF,
                   "Takes three args; the file and/or directory containing "
                   "the client certificate, or certificate ID used to "
                   "validate this LDAP client.  Second arg is the cert type "
                   "for the first arg, one of CA_DER, CA_BASE64, CA_CERT7_DB, "
                   "CA_SECMOD, CERT_DER, CERT_BASE64, CERT_KEY3_DB, "
                   "CERT_NICKNAME, KEY_DER, or KEY_BASE64. Third arg is an "
                   "optional passphrase if applicable."),

    AP_INIT_TAKE1("LDAPTrustedMode", util_ldap_set_trusted_mode,
                  NULL, RSRC_CONF,
                  "Specify the type of security that should be applied to "
                  "an LDAP connection. One of; NONE, SSL or STARTTLS."),

    AP_INIT_FLAG("LDAPVerifyServerCert", util_ldap_set_verify_srv_cert,
                  NULL, RSRC_CONF,
                  "Set to 'ON' requires that the server certificate be verified "
                  "before a secure LDAP connection can be establish.  Default 'ON'"),

    AP_INIT_TAKE1("LDAPConnectionTimeout", util_ldap_set_connection_timeout,
                  NULL, RSRC_CONF,
                  "Specify the LDAP socket connection timeout in seconds "
                  "(default: 10)"),

    {NULL}
};

static void util_ldap_register_hooks(apr_pool_t *p)
{
    APR_REGISTER_OPTIONAL_FN(uldap_connection_open);
    APR_REGISTER_OPTIONAL_FN(uldap_connection_close);
    APR_REGISTER_OPTIONAL_FN(uldap_connection_unbind);
    APR_REGISTER_OPTIONAL_FN(uldap_connection_cleanup);
    APR_REGISTER_OPTIONAL_FN(uldap_connection_find);
    APR_REGISTER_OPTIONAL_FN(uldap_cache_comparedn);
    APR_REGISTER_OPTIONAL_FN(uldap_cache_compare);
    APR_REGISTER_OPTIONAL_FN(uldap_cache_checkuserid);
    APR_REGISTER_OPTIONAL_FN(uldap_cache_getuserdn);
    APR_REGISTER_OPTIONAL_FN(uldap_ssl_supported);

    ap_hook_post_config(util_ldap_post_config,NULL,NULL,APR_HOOK_MIDDLE);
    ap_hook_handler(util_ldap_handler, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_child_init(util_ldap_child_init, NULL, NULL, APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA ldap_module = {
   STANDARD20_MODULE_STUFF,
   NULL,                        /* create dir config */
   NULL,                        /* merge dir config */
   util_ldap_create_config,     /* create server config */
   util_ldap_merge_config,      /* merge server config */
   util_ldap_cmds,              /* command table */
   util_ldap_register_hooks,    /* set up request processing hooks */
};
