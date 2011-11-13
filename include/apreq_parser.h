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

#ifndef APREQ_PARSERS_H
#define APREQ_PARSERS_H
/* These structs are defined below */

#include "apreq_param.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * @file apreq_parser.h
 * @brief Request body parser API
 * @ingroup libapreq2
 */

/**
 * A hook is called by the parser whenever data arrives in a file
 * upload parameter of the request body. You may associate any number
 * of hooks with a parser instance with apreq_parser_add_hook().
 */
typedef struct apreq_hook_t apreq_hook_t;

/**
 * A request body parser instance.
 */
typedef struct apreq_parser_t apreq_parser_t;

/** Parser arguments. */
#define APREQ_PARSER_ARGS  apreq_parser_t *parser,     \
                           apr_table_t *t,             \
                           apr_bucket_brigade *bb

/** Hook arguments */
#define APREQ_HOOK_ARGS    apreq_hook_t *hook,         \
                           apreq_param_t *param,       \
                           apr_bucket_brigade *bb

/**
 * The callback function implementing a request body parser.
 */
typedef apr_status_t (*apreq_parser_function_t)(APREQ_PARSER_ARGS);

/**
 * The callback function of a hook. See apreq_hook_t.
 */
typedef apr_status_t (*apreq_hook_function_t)(APREQ_HOOK_ARGS);

/**
 * Declares a API parser.
 */
#define APREQ_DECLARE_PARSER(f) APREQ_DECLARE_NONSTD(apr_status_t) \
                                (f) (APREQ_PARSER_ARGS)

/**
 * Declares an API hook.
 */
#define APREQ_DECLARE_HOOK(f)   APREQ_DECLARE_NONSTD(apr_status_t) \
                                (f) (APREQ_HOOK_ARGS)

/**
 * A hook is called by the parser whenever data arrives in a file
 * upload parameter of the request body. You may associate any number
 * of hooks with a parser instance with apreq_parser_add_hook().
 */
struct apreq_hook_t {
    apreq_hook_function_t hook; /**< the hook function */
    apreq_hook_t         *next; /**< next item in the linked list */
    apr_pool_t           *pool; /**< pool which allocated this hook */
    void *ctx; /**< a user defined pointer passed to the hook function */
};

/**
 * A request body parser instance.
 */
struct apreq_parser_t {
    /** the function which parses chunks of body data */
    apreq_parser_function_t parser;
    /** the Content-Type request header */
    const char             *content_type;
    /** a pool which outlasts the bucket_alloc. */
    apr_pool_t             *pool;
    /** bucket allocator used to create bucket brigades */
    apr_bucket_alloc_t     *bucket_alloc;
    /** the maximum in-memory bytes a brigade may use */
    apr_size_t              brigade_limit;
    /** the directory for generating temporary files */
    const char             *temp_dir;
    /** linked list of hooks */
    apreq_hook_t           *hook;
    /** internal context pointer used by the parser function */
    void                   *ctx;
};


/**
 * Parse the incoming brigade into a table.  Parsers normally
 * consume all the buckets of the brigade during parsing. However
 * parsers may leave "rejected" data in the brigade, even during a
 * successful parse, so callers may need to clean up the brigade
 * themselves (in particular, rejected buckets should not be
 * passed back to the parser again).
 * @remark  bb == NULL is valid: the parser should return its
 * public status: APR_INCOMPLETE, APR_SUCCESS, or an error code.
 */
static APR_INLINE
apr_status_t apreq_parser_run(struct apreq_parser_t *psr, apr_table_t *t,
                              apr_bucket_brigade *bb)
{
    return psr->parser(psr, t, bb);
}

/**
 * Run the hook with the current parameter and the incoming
 * bucket brigade.  The hook may modify the brigade if necessary.
 * Once all hooks have completed, the contents of the brigade will
 * be added to the parameter's bb attribute.
 * @return APR_SUCCESS on success. All other values represent errors.
 */
static APR_INLINE
apr_status_t apreq_hook_run(struct apreq_hook_t *h, apreq_param_t *param,
                            apr_bucket_brigade *bb)
{
    return h->hook(h, param, bb);
}


/**
 * RFC 822 Header parser. It will reject all data
 * after the first CRLF CRLF sequence (an empty line).
 * See apreq_parser_run() for more info on rejected data.
 */
APREQ_DECLARE_PARSER(apreq_parse_headers);

/**
 * RFC 2396 application/x-www-form-urlencoded parser.
 */
APREQ_DECLARE_PARSER(apreq_parse_urlencoded);

/**
 * RFC 2388 multipart/form-data (and XForms 1.0 multipart/related)
 * parser. It will reject any buckets representing preamble and
 * postamble text (this is normal behavior, not an error condition).
 * See apreq_parser_run() for more info on rejected data.
 */
APREQ_DECLARE_PARSER(apreq_parse_multipart);

/**
 * Generic parser.  No table entries will be added to
 * the req->body table by this parser.  The parser creates
 * a dummy apreq_param_t to pass to any configured hooks.  If
 * no hooks are configured, the dummy param's bb slot will
 * contain a copy of the request body.  It can be retrieved
 * by casting the parser's ctx pointer to (apreq_param_t **).
 */
APREQ_DECLARE_PARSER(apreq_parse_generic);

/**
 * apr_xml_parser hook. It will parse until EOS appears.
 * The parsed document isn't available until parsing has
 * completed successfully.  The hook's ctx pointer may
 * be cast as (apr_xml_doc **) to retrieve the
 * parsed document.
 */
APREQ_DECLARE_HOOK(apreq_hook_apr_xml_parser);

/**
 * Construct a parser.
 *
 * @param pool Pool used to allocate the parser.
 * @param ba bucket allocator used to create bucket brigades
 * @param content_type Content-type that this parser can deal with.
 * @param pfn The parser function.
 * @param brigade_limit the maximum in-memory bytes a brigade may use
 * @param temp_dir the directory used by the parser for temporary files
 * @param hook Hooks to associate this parser with.
 * @param ctx Parser's internal scratch pad.
 * @return New parser.
 */
APREQ_DECLARE(apreq_parser_t *) apreq_parser_make(apr_pool_t *pool,
                                                  apr_bucket_alloc_t *ba,
                                                  const char *content_type,
                                                  apreq_parser_function_t pfn,
                                                  apr_size_t brigade_limit,
                                                  const char *temp_dir,
                                                  apreq_hook_t *hook,
                                                  void *ctx);

/**
 * Construct a hook.
 *
 * @param pool used to allocate the hook.
 * @param hook The hook function.
 * @param next List of other hooks for this hook to call on.
 * @param ctx Hook's internal scratch pad.
 * @return New hook.
 */
APREQ_DECLARE(apreq_hook_t *) apreq_hook_make(apr_pool_t *pool,
                                              apreq_hook_function_t hook,
                                              apreq_hook_t *next,
                                              void *ctx);


/**
 * Add a new hook to the end of the parser's hook list.
 *
 * @param p Parser.
 * @param h Hook to append.
 */
APREQ_DECLARE(apr_status_t) apreq_parser_add_hook(apreq_parser_t *p,
                                                  apreq_hook_t *h);


/**
 * Fetch the default parser function associated with the given MIME type.
 * @param enctype The desired enctype (can also be a full "Content-Type"
 *        header).
 * @return The parser function, or NULL if the enctype is unrecognized.
 */
APREQ_DECLARE(apreq_parser_function_t)apreq_parser(const char *enctype);


/**
 * Register a new parsing function with a MIME enctype.
 * Registered parsers are added to apreq_parser()'s
 * internal lookup table.
 *
 * @param enctype The MIME type.
 * @param pfn     The function to use during parsing. Setting
 *                parser == NULL will remove an existing parser.
 *
 * @return APR_SUCCESS or error.
 */

APREQ_DECLARE(apr_status_t) apreq_register_parser(const char *enctype,
                                                  apreq_parser_function_t pfn);


/**
 * Returns APREQ_ERROR_GENERAL.  Effectively disables mfd parser
 * if a file-upload field is present.
 *
 */
APREQ_DECLARE_HOOK(apreq_hook_disable_uploads);

/**
 * Calls apr_brigade_cleanup on the incoming brigade
 * after passing the brigade to any subsequent hooks.
 */
APREQ_DECLARE_HOOK(apreq_hook_discard_brigade);

/**
 * Context struct for the apreq_hook_find_param hook.
 */
typedef struct apreq_hook_find_param_ctx_t {
    const char    *name;
    apreq_param_t *param;
    apreq_hook_t  *prev;
} apreq_hook_find_param_ctx_t;


/**
 * Special purpose utility for locating a parameter
 * during parsing.  The hook's ctx shoud be initialized
 * to an apreq_hook_find_param_ctx_t *, with the name
 * attribute set to the sought parameter name, the param
 * attribute set to NULL, and the prev attribute set to
 * the address of the previous hook.  The param attribute
 * will be reassigned to the first param found, and once
 * that happens this hook is immediately removed from the chain.
 *
 * @remarks When used, this should always be the first hook
 * invoked, so add it manually with ctx->prev = &parser->hook
 * instead of using apreq_parser_add_hook.
 */
APREQ_DECLARE_HOOK(apreq_hook_find_param);


#ifdef __cplusplus
}

#endif
#endif /* APREQ_PARSERS_H */
