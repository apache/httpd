/*
**  Licensed to the Apache Software Foundation (ASF) under one or more
** contributor license agreements.  See the NOTICE file distributed with
** this work for additional information regarding copyright ownership.
** The ASF licenses this file to You under the Apache License, Version 2.0
** (the "License"); you may not use this file except in compliance with
** the License.  You may obtain a copy of the License at
**
**      http://www.apache.org/licenses/LICENSE-2.0
**
**  Unless required by applicable law or agreed to in writing, software
**  distributed under the License is distributed on an "AS IS" BASIS,
**  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
**  See the License for the specific language governing permissions and
**  limitations under the License.
*/

#ifndef APREQ_COOKIE_H
#define APREQ_COOKIE_H

#include "apreq.h"
#include "apr_time.h"

#ifdef  __cplusplus
extern "C" {
#endif

/**
 * @file apreq_cookie.h
 * @brief Cookies and Jars.
 * @ingroup libapreq2
 *
 * apreq_cookie.h describes a common server-side API for request (incoming)
 * and response (outgoing) cookies.  It aims towards compliance with the
 * standard cookie specifications listed below.
 *
 * @see http://wp.netscape.com/newsref/std/cookie_spec.html
 * @see http://www.ietf.org/rfc/rfc2109.txt
 * @see http://www.ietf.org/rfc/rfc2964.txt
 * @see http://www.ietf.org/rfc/rfc2965.txt
 *
 */

/** This macro is deprecated.
 *
 * Maximum length of a single Set-Cookie(2) header. 
 */
#define APREQ_COOKIE_MAX_LENGTH            4096

/** @brief Cookie type, supporting both Netscape and RFC cookie specifications.
 */

typedef struct apreq_cookie_t {

    char           *path;        /**< Restricts url path */
    char           *domain;      /**< Restricts server domain */
    char           *port;        /**< Restricts server port */
    char           *comment;     /**< RFC cookies may send a comment */
    char           *commentURL;  /**< RFC cookies may place an URL here */
    apr_time_t      max_age;     /**< total duration of cookie: -1 == session */
    unsigned        flags;       /**< charsets, taint marks, app-specific bits */
    const apreq_value_t   v;     /**< "raw" cookie value */

} apreq_cookie_t;


/** Upgrades a jar's table values to apreq_cookie_t structs. */
static APR_INLINE
apreq_cookie_t *apreq_value_to_cookie(const char *val)
{
    union { const char *in; char *out; } deconst;

    deconst.in = val;
    return apreq_attr_to_type(apreq_cookie_t, v,
           apreq_attr_to_type(apreq_value_t, data, deconst.out));
}

/**@return 1 if this is an RFC cookie, 0 if its a Netscape cookie. */
static APR_INLINE
unsigned apreq_cookie_version(const apreq_cookie_t *c) {
    return APREQ_FLAGS_GET(c->flags, APREQ_COOKIE_VERSION);
}

/** Sets the cookie's protocol version. */
static APR_INLINE
void apreq_cookie_version_set(apreq_cookie_t *c, unsigned v) {
    APREQ_FLAGS_SET(c->flags, APREQ_COOKIE_VERSION, v);
}

/** @return 1 if the secure flag is set, 0 otherwise. */
static APR_INLINE
unsigned apreq_cookie_is_secure(const apreq_cookie_t *c) {
    return APREQ_FLAGS_GET(c->flags, APREQ_COOKIE_SECURE);
}

/** Sets the cookie's secure flag, meaning it only
 *  comes back over an SSL-encrypted connction.
 */
static APR_INLINE
void apreq_cookie_secure_on(apreq_cookie_t *c) {
    APREQ_FLAGS_ON(c->flags, APREQ_COOKIE_SECURE);
}

/** Turns off the cookie's secure flag. */
static APR_INLINE
void apreq_cookie_secure_off(apreq_cookie_t *c) {
    APREQ_FLAGS_OFF(c->flags, APREQ_COOKIE_SECURE);
}

/** @return 1 if the HttpOnly flag is set, 0 otherwise. */
static APR_INLINE
unsigned apreq_cookie_is_httponly(const apreq_cookie_t *c) {
    return APREQ_FLAGS_GET(c->flags, APREQ_COOKIE_HTTPONLY);
}

/** Sets the cookie's HttpOnly flag, meaning it is not
 *  accessible through client-side script in supported
 *  browsers.
 */
static APR_INLINE
void apreq_cookie_httponly_on(apreq_cookie_t *c) {
    APREQ_FLAGS_ON(c->flags, APREQ_COOKIE_HTTPONLY);
}

/** Turns off the cookie's HttpOnly flag. */
static APR_INLINE
void apreq_cookie_httponly_off(apreq_cookie_t *c) {
    APREQ_FLAGS_OFF(c->flags, APREQ_COOKIE_HTTPONLY);
}


/** @return 1 if the taint flag is set, 0 otherwise. */
static APR_INLINE
unsigned apreq_cookie_is_tainted(const apreq_cookie_t *c) {
    return APREQ_FLAGS_GET(c->flags, APREQ_TAINTED);
}

/** Sets the cookie's tainted flag. */
static APR_INLINE
void apreq_cookie_tainted_on(apreq_cookie_t *c) {
    APREQ_FLAGS_ON(c->flags, APREQ_TAINTED);
}

/** Turns off the cookie's tainted flag. */
static APR_INLINE
void apreq_cookie_tainted_off(apreq_cookie_t *c) {
    APREQ_FLAGS_OFF(c->flags, APREQ_TAINTED);
}

/**
 * Parse a cookie header and store the cookies in an apr_table_t.
 *
 * @param pool pool which allocates the cookies
 * @param jar table where parsed cookies are stored
 * @param header the header value
 *
 * @return APR_SUCCESS.
 * @return ::APREQ_ERROR_BADSEQ if an unparseable character sequence appears.
 * @return ::APREQ_ERROR_MISMATCH if an rfc-cookie attribute appears in a
 *         netscape cookie header.
 * @return ::APR_ENOTIMPL if an unrecognized rfc-cookie attribute appears.
 * @return ::APREQ_ERROR_NOTOKEN if a required token was not present.
 * @return ::APREQ_ERROR_BADCHAR if an unexpected token was present.
 */
APREQ_DECLARE(apr_status_t) apreq_parse_cookie_header(apr_pool_t *pool,
                                                      apr_table_t *jar,
                                                      const char *header);

/**
 * Returns a new cookie, made from the argument list.
 *
 * @param pool  Pool which allocates the cookie.
 * @param name  The cookie's name.
 * @param nlen  Length of name.
 * @param value The cookie's value.
 * @param vlen  Length of value.
 *
 * @return the new cookie
 */
APREQ_DECLARE(apreq_cookie_t *) apreq_cookie_make(apr_pool_t *pool,
                                                  const char *name,
                                                  const apr_size_t nlen,
                                                  const char *value,
                                                  const apr_size_t vlen);

/**
 * Returns a string that represents the cookie as it would appear
 * in a valid "Set-Cookie*" header.
 *
 * @param c cookie.
 * @param p pool which allocates the returned string.
 *
 * @return header string.
 */
APREQ_DECLARE(char*) apreq_cookie_as_string(const apreq_cookie_t *c,
                                            apr_pool_t *p);


/**
 * Same functionality as apreq_cookie_as_string.  Stores the string
 * representation in buf, using up to len bytes in buf as storage.
 * The return value has the same semantics as that of apr_snprintf,
 * including the special behavior for a "len = 0" argument.
 *
 * @param c   cookie.
 * @param buf storage location for the result.
 * @param len size of buf's storage area.
 *
 * @return size of resulting header string.
 */
APREQ_DECLARE(int) apreq_cookie_serialize(const apreq_cookie_t *c,
                                          char *buf, apr_size_t len);

/**
 * Set the Cookie's expiration date.
 *
 * @param c The cookie.
 * @param time_str If NULL, the Cookie's expiration date is unset,
 * making it a session cookie.  This means no "expires" or "max-age"
 * attribute will appear in the cookie's serialized form. If time_str
 * is not NULL, the expiration date will be reset to the offset (from now)
 * represented by time_str.  The time_str should be in a format that
 * apreq_atoi64t() can understand, namely /[+-]?\\d+\\s*[YMDhms]/.
 *
 * @remarks Now time_str may also be a fixed date; see apr_date_parse_rfc()
 * for admissible formats.
 */
APREQ_DECLARE(void) apreq_cookie_expires(apreq_cookie_t *c,
                                         const char *time_str);

#ifdef __cplusplus
 }
#endif

#endif /*APREQ_COOKIE_H*/


