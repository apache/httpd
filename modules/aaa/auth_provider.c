/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000-2002 The Apache Software Foundation.  All rights
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
 */

#include "apr_pools.h"
#include "apr_hash.h"

#include "mod_auth.h"

static apr_hash_t *authn_repos_providers = NULL;
static apr_hash_t *authz_repos_providers = NULL;

static apr_status_t authn_cleanup_providers(void *ctx)
{
    authn_repos_providers = NULL;
    return APR_SUCCESS;
}

static apr_status_t authz_cleanup_providers(void *ctx)
{
    authz_repos_providers = NULL;
    return APR_SUCCESS;
}

AP_DECLARE(void) authn_register_provider(apr_pool_t *p, const char *name,
                                         const authn_provider *provider)
{
    if (authn_repos_providers == NULL) {
        authn_repos_providers = apr_hash_make(p);
        apr_pool_cleanup_register(p, NULL, authn_cleanup_providers,
                                  apr_pool_cleanup_null);
    }

    /* just set it. no biggy if it was there before. */
    apr_hash_set(authn_repos_providers, name, APR_HASH_KEY_STRING, provider);
}

AP_DECLARE(const authn_provider *) authn_lookup_provider(const char *name)
{
    /* Better watch out against no registered providers */
    if (authn_repos_providers == NULL) {
        return NULL;
    }

    return apr_hash_get(authn_repos_providers, name, APR_HASH_KEY_STRING);
}

AP_DECLARE(void) authz_register_provider(apr_pool_t *p, const char *name,
                                         const authz_provider *provider)
{
    if (authz_repos_providers == NULL) {
        authz_repos_providers = apr_hash_make(p);
        apr_pool_cleanup_register(p, NULL, authz_cleanup_providers,
                                  apr_pool_cleanup_null);
    }

    /* just set it. no biggy if it was there before. */
    apr_hash_set(authz_repos_providers, name, APR_HASH_KEY_STRING, provider);
}

AP_DECLARE(const authz_provider *) authz_lookup_provider(const char *name)
{
    /* Better watch out against no registered providers */
    if (authz_repos_providers == NULL) {
        return NULL;
    }

    return apr_hash_get(authz_repos_providers, name, APR_HASH_KEY_STRING);
}
