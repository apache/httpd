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
 * @file  mod_request.h
 * @brief mod_request private header file
 *
 * @defgroup MOD_REQUEST mod_request
 * @ingroup  APACHE_MODS
 * @{
 */

#ifndef MOD_REQUEST_H
#define MOD_REQUEST_H

#include "apr.h"
#include "apr_buckets.h"
#include "apr_optional.h"

#include "httpd.h"
#include "util_filter.h"


#ifdef __cplusplus
extern "C" {
#endif

extern module AP_MODULE_DECLARE_DATA request_module;

#define KEEP_BODY_FILTER "KEEP_BODY"
#define KEPT_BODY_FILTER "KEPT_BODY"

/**
 * Core per-directory configuration.
 */
typedef struct {
    apr_off_t keep_body;
    int keep_body_set;
} request_dir_conf;

/**
 * Structure to store the contents of an HTTP form of the type
 * application/x-www-form-urlencoded.
 * 
 * Currently it contains the name as a char* of maximum length
 * HUGE_STRING_LEN, and a value in the form of a bucket brigade
 * of arbitrary length.
 */
typedef struct {
    const char *name;
    apr_bucket_brigade *value;
} ap_form_pair_t;

/**
 * Read the body and parse any form found, which must be of the
 * type application/x-www-form-urlencoded.
 *
 * Name/value pairs are returned in an array, with the names as
 * strings with a maximum length of HUGE_STRING_LEN, and the
 * values as bucket brigades. This allows values to be arbitrarily
 * large.
 *
 * All url-encoding is removed from both the names and the values
 * on the fly. The names are interpreted as strings, while the
 * values are interpreted as blocks of binary data, that may
 * contain the 0 character.
 *
 * In order to ensure that resource limits are not exceeded, a
 * maximum size must be provided. If the sum of the lengths of
 * the names and the values exceed this size, this function
 * will return HTTP_REQUEST_ENTITY_TOO_LARGE.
 *
 * An optional number of parameters can be provided, if the number
 * of parameters provided exceeds this amount, this function will
 * return HTTP_REQUEST_ENTITY_TOO_LARGE. If this value is negative,
 * no limit is imposed, and the number of parameters is in turn
 * constrained by the size parameter above.
 * 
 * This function honours any kept_body configuration, and the
 * original raw request body will be saved to the kept_body brigade
 * if so configured, just as ap_discard_request_body does.
 * 
 * NOTE: File upload is not yet supported, but can be without change
 * to the function call.
 */

APR_DECLARE_OPTIONAL_FN(int, ap_parse_request_form, (request_rec * r, ap_filter_t * f, 
                                                     apr_array_header_t ** ptr,
                                                     apr_size_t num, apr_size_t size));

APR_DECLARE_OPTIONAL_FN(void, ap_request_insert_filter, (request_rec * r));

APR_DECLARE_OPTIONAL_FN(void, ap_request_remove_filter, (request_rec * r));

#ifdef __cplusplus
}
#endif

#endif /* !MOD_REQUEST_H */
/** @} */
