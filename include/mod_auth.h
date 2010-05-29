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

/**
 * @file  mod_auth.h
 * @brief Authentication and Authorization Extension for Apache
 *
 * @defgroup MOD_AUTH mod_auth
 * @ingroup  APACHE_MODS
 */

#ifndef APACHE_MOD_AUTH_H
#define APACHE_MOD_AUTH_H

#include "apr_pools.h"
#include "apr_hash.h"
#include "apr_optional.h"

#include "httpd.h"
#include "http_config.h"

#ifdef __cplusplus
extern "C" {
#endif

#define AUTHN_PROVIDER_GROUP "authn"
#define AUTHZ_PROVIDER_GROUP "authz"
#define AUTHN_PROVIDER_VERSION "0"
#define AUTHZ_PROVIDER_VERSION "0"
#define AUTHN_DEFAULT_PROVIDER "file"

#define AUTHN_PROVIDER_NAME_NOTE "authn_provider_name"
#define AUTHZ_PROVIDER_NAME_NOTE "authz_provider_name"

#define AUTHN_PREFIX "AUTHENTICATE_"
#define AUTHZ_PREFIX "AUTHORIZE_"

/** all of the requirements must be met */
#ifndef SATISFY_ALL
#define SATISFY_ALL 0
#endif
/**  any of the requirements must be met */
#ifndef SATISFY_ANY
#define SATISFY_ANY 1
#endif
/** There are no applicable satisfy lines */
#ifndef SATISFY_NOSPEC
#define SATISFY_NOSPEC 2
#endif

typedef enum {
    AUTH_DENIED,
    AUTH_GRANTED,
    AUTH_USER_FOUND,
    AUTH_USER_NOT_FOUND,
    AUTH_GENERAL_ERROR
} authn_status;

typedef enum {
    AUTHZ_DENIED,
    AUTHZ_GRANTED,
    AUTHZ_NEUTRAL,
    AUTHZ_GENERAL_ERROR
} authz_status;

typedef struct {
    /* Given a username and password, expected to return AUTH_GRANTED
     * if we can validate this user/password combination.
     */
    authn_status (*check_password)(request_rec *r, const char *user,
                                   const char *password);

    /* Given a user and realm, expected to return AUTH_USER_FOUND if we
     * can find a md5 hash of 'user:realm:password'
     */
    authn_status (*get_realm_hash)(request_rec *r, const char *user,
                                   const char *realm, char **rethash);
} authn_provider;

/* A linked-list of authn providers. */
typedef struct authn_provider_list authn_provider_list;

struct authn_provider_list {
    const char *provider_name;
    const authn_provider *provider;
    authn_provider_list *next;
};

typedef struct {
    /* Given a request_rec, expected to return AUTHZ_GRANTED
     * if we can authorize user access.
     */
    authz_status (*check_authorization)(request_rec *r,
                                        const char *require_line);
} authz_provider;

#ifdef __cplusplus
}
#endif

#endif
