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

#ifndef APREQ_MODULE_H
#define APREQ_MODULE_H

#include "apreq_cookie.h"
#include "apreq_parser.h"
#include "apreq_error.h"

#ifdef  __cplusplus
 extern "C" {
#endif

/**
 * @file apreq_module.h
 * @brief Module API
 * @ingroup libapreq2
 */


/**
 * An apreq handle associated with a module. The structure
 * may have variable size, because the module may append its own data
 * structures after it.
 */
typedef struct apreq_handle_t {
    /** the apreq module which implements this handle */
    const struct apreq_module_t *module;
    /** the pool which defines the lifetime of the parsed data */
    apr_pool_t *pool;
    /** the allocator, which persists at least as long as the pool */
    apr_bucket_alloc_t *bucket_alloc;

} apreq_handle_t;

/**
 * @brief Vtable describing the necessary module functions.
 */


typedef struct apreq_module_t {
    /** name of this apreq module */
    const char *name;
    /** magic number identifying the module and version */
    apr_uint32_t magic_number;

    /** get a table with all cookies */
    apr_status_t (*jar)(apreq_handle_t *, const apr_table_t **);
    /** get a table with all query string parameters */
    apr_status_t (*args)(apreq_handle_t *, const apr_table_t **);
    /** get a table with all body parameters */
    apr_status_t (*body)(apreq_handle_t *, const apr_table_t **);

    /** get a cookie by its name */
    apreq_cookie_t *(*jar_get)(apreq_handle_t *, const char *);
    /** get a query string parameter by its name */
    apreq_param_t *(*args_get)(apreq_handle_t *, const char *);
    /** get a body parameter by its name */
    apreq_param_t *(*body_get)(apreq_handle_t *, const char *);

    /** gets the parser associated with the request body */
    apr_status_t (*parser_get)(apreq_handle_t *, const apreq_parser_t **);
    /** manually set a parser for the request body */
    apr_status_t (*parser_set)(apreq_handle_t *, apreq_parser_t *);
    /** add a hook function */
    apr_status_t (*hook_add)(apreq_handle_t *, apreq_hook_t *);

    /** determine the maximum in-memory bytes a brigade may use */
    apr_status_t (*brigade_limit_get)(apreq_handle_t *, apr_size_t *);
    /** set the maximum in-memory bytes a brigade may use */
    apr_status_t (*brigade_limit_set)(apreq_handle_t *, apr_size_t);

    /** determine the maximum amount of data that will be fed into a parser */
    apr_status_t (*read_limit_get)(apreq_handle_t *, apr_uint64_t *);
    /** set the maximum amount of data that will be fed into a parser */
    apr_status_t (*read_limit_set)(apreq_handle_t *, apr_uint64_t);

    /** determine the directory used by the parser for temporary files */
    apr_status_t (*temp_dir_get)(apreq_handle_t *, const char **);
    /** set the directory used by the parser for temporary files */
    apr_status_t (*temp_dir_set)(apreq_handle_t *, const char *);

} apreq_module_t;


/**
 * Defines the module-specific status codes which
 * are commonly considered to be non-fatal.
 *
 * @param s status code returned by an apreq_module_t method.
 *
 * @return 1 if s is fatal, 0 otherwise.
 */
static APR_INLINE
unsigned apreq_module_status_is_error(apr_status_t s) {
    switch (s) {
    case APR_SUCCESS:
    case APR_INCOMPLETE:
    case APR_EINIT:
    case APREQ_ERROR_NODATA:
    case APREQ_ERROR_NOPARSER:
    case APREQ_ERROR_NOHEADER:
        return 0;
    default:
        return 1;
    }
}


/**
 * Expose the parsed "cookie" header associated to this handle.
 *
 * @param req The request handle
 * @param t   The resulting table, which will either be NULL or a
 *            valid table object on return.
 *
 * @return    APR_SUCCESS or a module-specific error status code.
 */
static APR_INLINE
apr_status_t apreq_jar(apreq_handle_t *req, const apr_table_t **t)
{
    return req->module->jar(req,t);
}

/**
 * Expose the parsed "query string" associated to this handle.
 *
 * @param req The request handle
 * @param t   The resulting table, which will either be NULL or a
 *            valid table object on return.
 *
 * @return    APR_SUCCESS or a module-specific error status code.
 */
static APR_INLINE
apr_status_t apreq_args(apreq_handle_t *req, const apr_table_t **t)
{
    return req->module->args(req,t);
}

/**
 * Expose the parsed "request body" associated to this handle.
 *
 * @param req The request handle
 * @param t   The resulting table, which will either be NULL or a
 *            valid table object on return.
 *
 * @return    APR_SUCCESS or a module-specific error status code.
 */
static APR_INLINE
apr_status_t apreq_body(apreq_handle_t *req, const apr_table_t **t)
{
    return req->module->body(req, t);
}


/**
 * Fetch the first cookie with the given name.
 *
 * @param req  The request handle
 * @param name Case-insensitive cookie name.
 *
 * @return     First matching cookie, or NULL if none match.
 */
static APR_INLINE
apreq_cookie_t *apreq_jar_get(apreq_handle_t *req, const char *name)
{
    return req->module->jar_get(req, name);
}

/**
 * Fetch the first query string param with the given name.
 *
 * @param req  The request handle
 * @param name Case-insensitive param name.
 *
 * @return     First matching param, or NULL if none match.
 */
static APR_INLINE
apreq_param_t *apreq_args_get(apreq_handle_t *req, const char *name)
{
    return req->module->args_get(req, name);
}

/**
 * Fetch the first body param with the given name.
 *
 * @param req  The request handle
 * @param name Case-insensitive cookie name.
 *
 * @return     First matching param, or NULL if none match.
 */
static APR_INLINE
apreq_param_t *apreq_body_get(apreq_handle_t *req, const char *name)
{
    return req->module->body_get(req, name);
}

/**
 * Fetch the active body parser.
 *
 * @param req    The request handle
 * @param parser Points to the active parser on return.
 *
 * @return       APR_SUCCESS or module-specific error.
 *
 */
static APR_INLINE
apr_status_t apreq_parser_get(apreq_handle_t *req,
                              const apreq_parser_t **parser)
{
    return req->module->parser_get(req, parser);
}


/**
 * Set the body parser for this request.
 *
 * @param req    The request handle
 * @param parser New parser to use.
 *
 * @return       APR_SUCCESS or module-specific error.
 */
static APR_INLINE
apr_status_t apreq_parser_set(apreq_handle_t *req,
                              apreq_parser_t *parser)
{
    return req->module->parser_set(req, parser);
}

/**
 * Add a parser hook for this request.
 *
 * @param req  The request handle
 * @param hook Hook to add.
 *
 * @return     APR_SUCCESS or module-specific error.
 */
static APR_INLINE
apr_status_t apreq_hook_add(apreq_handle_t *req, apreq_hook_t *hook)
{
    return req->module->hook_add(req, hook);
}


/**
 * Set the active brigade limit.
 *
 * @param req   The handle.
 * @param bytes New limit to use.
 *
 * @return APR_SUCCESS or module-specific error.
 *
 */
static APR_INLINE
apr_status_t apreq_brigade_limit_set(apreq_handle_t *req,
                                     apr_size_t bytes)
{
    return req->module->brigade_limit_set(req, bytes);
}

/**
 * Get the active brigade limit.
 *
 * @param req   The handle.
 * @param bytes Pointer to resulting (current) limit.
 *
 * @return APR_SUCCESS or a module-specific error,
 *         which may leave bytes undefined.
 */
static APR_INLINE
apr_status_t apreq_brigade_limit_get(apreq_handle_t *req,
                                     apr_size_t *bytes)
{
    return req->module->brigade_limit_get(req, bytes);
}

/**
 * Set the active read limit.
 *
 * @param req   The handle.
 * @param bytes New limit to use.
 *
 * @return APR_SUCCESS or a module-specific error.
 *
 */
static APR_INLINE
apr_status_t apreq_read_limit_set(apreq_handle_t *req,
                                  apr_uint64_t bytes)
{
    return req->module->read_limit_set(req, bytes);
}

/**
 * Get the active read limit.
 *
 * @param req   The request handle.
 * @param bytes Pointer to resulting (current) limit.
 *
 * @return APR_SUCCESS or a module-specific error,
 *         which may leave bytes undefined.
 */
static APR_INLINE
apr_status_t apreq_read_limit_get(apreq_handle_t *req,
                                  apr_uint64_t *bytes)
{
    return req->module->read_limit_get(req, bytes);
}

/**
 * Set the active temp directory.
 *
 * @param req  The handle.
 * @param path New path to use; may be NULL.
 *
 * @return APR_SUCCESS or a module-specific error .
 */
static APR_INLINE
apr_status_t apreq_temp_dir_set(apreq_handle_t *req, const char *path)
{
    return req->module->temp_dir_set(req, path);
}

/**
 * Get the active temp directory.
 *
 * @param req   The handle.
 * @param path  Resulting path to temp dir.
 *
 * @return APR_SUCCESS implies path is valid, but may also be NULL.
 *         Any other return value is module-specific, and may leave
 *         path undefined.
 */
static APR_INLINE
apr_status_t apreq_temp_dir_get(apreq_handle_t *req, const char **path)
{
    return req->module->temp_dir_get(req, path);
}



/**
 * Convenience macro for defining a module by mapping
 * a function prefix to an associated apreq_module_t structure.
 *
 * @param pre Prefix to define new module.  All attributes of
 *            the apreq_module_t struct are defined with this as their
 *            prefix. The generated struct is named by appending "_module" to
 *            the prefix.
 * @param mmn Magic number (i.e. version number) of this module.
 */
#define APREQ_MODULE(pre, mmn) const apreq_module_t     \
  pre##_module = { #pre, mmn,                           \
  pre##_jar,        pre##_args,       pre##_body,       \
  pre##_jar_get,    pre##_args_get,   pre##_body_get,   \
  pre##_parser_get, pre##_parser_set, pre##_hook_add,   \
  pre##_brigade_limit_get, pre##_brigade_limit_set,     \
  pre##_read_limit_get,    pre##_read_limit_set,        \
  pre##_temp_dir_get,      pre##_temp_dir_set,          \
  }


/**
 * Create an apreq handle which is suitable for a CGI program. It
 * reads input from stdin and writes output to stdout.
 *
 * @param pool Pool associated to this handle.
 *
 * @return New handle; can only be NULL if the pool allocation failed.
 *
 * @remarks The handle gets cached in the pool's userdata, so subsequent
 *          calls will retrieve the original cached handle.
 */
APREQ_DECLARE(apreq_handle_t*) apreq_handle_cgi(apr_pool_t *pool);

/**
 * Create a custom apreq handle which knows only some static
 * values. Useful if you want to test the parser code or if you have
 * got data from a custom source (neither Apache 2 nor CGI).
 *
 * @param pool         allocates the parse data,
 * @param query_string parsed into args table
 * @param cookie       value of the request "Cookie" header
 * @param parser       parses the request body
 * @param read_limit   maximum bytes to read from the body
 * @param in           brigade containing the request body
 *
 * @return new handle; can only be NULL if the pool allocation failed.
 */
APREQ_DECLARE(apreq_handle_t*) apreq_handle_custom(apr_pool_t *pool,
                                                   const char *query_string,
                                                   const char *cookie,
                                                   apreq_parser_t *parser,
                                                   apr_uint64_t read_limit,
                                                   apr_bucket_brigade *in);

/**
 * Find the first query string parameter or body parameter with the
 * specified name.  The match is case-insensitive.
 *
 * @param req request handle.
 * @param key desired parameter name
 *
 * @return The first matching parameter (with args searched first) or NULL.
 */
APREQ_DECLARE(apreq_param_t *)apreq_param(apreq_handle_t *req, const char *key);

/**
 * Find the first cookie with the specified name.
 * The match is case-insensitive.
 *
 * @param req request handle.
 * @param name desired cookie name
 *
 * @return The first matching cookie or NULL.
 */
#define apreq_cookie(req, name) apreq_jar_get(req, name)

/**
 * Returns a table containing key-value pairs for the full request
 * (args + body).
 *
 * @param req request handle
 * @param p   allocates the returned table.
 *
 * @return table representing all available params; is never NULL.
 */
APREQ_DECLARE(apr_table_t *) apreq_params(apreq_handle_t *req, apr_pool_t *p);


/**
 * Returns a table containing all request cookies.
 *
 * @param req the apreq request handle
 * @param p Allocates the returned table.
 */
APREQ_DECLARE(apr_table_t *)apreq_cookies(apreq_handle_t *req, apr_pool_t *p);

#ifdef __cplusplus
 }
#endif

#endif /* APREQ_MODULE_H */
