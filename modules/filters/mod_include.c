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
 *
 * Portions of this software are based upon public domain software
 * originally written at the National Center for Supercomputing Applications,
 * University of Illinois, Urbana-Champaign.
 */

/*
 * http_include.c: Handles the server-parsed HTML documents
 * 
 * Original by Rob McCool; substantial fixups by David Robinson;
 * incorporated into the Apache module framework by rst.
 * 
 */

#include "apr.h"
#include "apr_strings.h"
#include "apr_thread_proc.h"
#include "apr_hash.h"
#include "apr_user.h"
#include "apr_lib.h"
#include "apr_optional.h"

#define APR_WANT_STRFUNC
#define APR_WANT_MEMFUNC
#include "apr_want.h"

#include "ap_config.h"
#include "util_filter.h"
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_request.h"
#include "http_core.h"
#include "http_protocol.h"
#include "http_log.h"
#include "http_main.h"
#include "util_script.h"
#include "http_core.h"
#include "mod_include.h"

/* helper for Latin1 <-> entity encoding */
#if APR_CHARSET_EBCDIC
#include "util_ebcdic.h"
#define RAW_ASCII_CHAR(ch)  apr_xlate_conv_byte(ap_hdrs_from_ascii, \
                                                (unsigned char)ch)
#else /* APR_CHARSET_EBCDIC */
#define RAW_ASCII_CHAR(ch)  (ch)
#endif /* !APR_CHARSET_EBCDIC */


/*
 * +-------------------------------------------------------+
 * |                                                       |
 * |                  Debugging Macros
 * |                                                       |
 * +-------------------------------------------------------+
 */

#ifdef DEBUG_INCLUDE

#define MAX_DEBUG_SIZE MAX_STRING_LEN

#define LOG_COND_STATUS(ctx, f, bb, text)                                   \
do {                                                                        \
    char *cond_txt = apr_pstrcat((ctx)->dpool, "**** ", (text),             \
        " conditional_status=\"", ((ctx)->flags & FLAG_COND_TRUE)?"1":"0",  \
        "\"\n", NULL);                                                      \
    APR_BRIGADE_INSERT_TAIL((bb), apr_bucket_heap_create(cond_txt,          \
                            strlen(cond_txt), NULL, (f)->c->bucket_alloc)); \
} while(0)

#define DUMP_PARSE_EXPR_DEBUG(buf, f, bb)                                   \
do {                                                                        \
    APR_BRIGADE_INSERT_TAIL((bb), apr_bucket_heap_create((buf),             \
                            strlen((buf)), NULL, (f)->c->bucket_alloc));    \
} while(0)

#else

#define MAX_DEBUG_SIZE 10
#define LOG_COND_STATUS(ctx, f, bb, text)
#define DUMP_PARSE_EXPR_DEBUG(buf, f, bb)

#endif


/*
 * +-------------------------------------------------------+
 * |                                                       |
 * |                 Types and Structures
 * |                                                       |
 * +-------------------------------------------------------+
 */

typedef enum {
    XBITHACK_OFF,
    XBITHACK_ON,
    XBITHACK_FULL
} xbithack_t;

typedef struct {
    unsigned int T[256];
    unsigned int x;
    apr_size_t pattern_len;
} bndm_t;

typedef struct {
    const char *default_error_msg;
    const char *default_time_fmt;
    xbithack_t  xbithack;
} include_dir_config;

typedef struct {
    const char *default_start_tag;
    const char *default_end_tag;
    const char *undefined_echo;
    apr_size_t  undefined_echo_len;
} include_server_config;

/* main parser states */
typedef enum {
    PARSE_PRE_HEAD,
    PARSE_HEAD,
    PARSE_DIRECTIVE,
    PARSE_DIRECTIVE_POSTNAME,
    PARSE_DIRECTIVE_TAIL,
    PARSE_DIRECTIVE_POSTTAIL,
    PARSE_PRE_ARG,
    PARSE_ARG,
    PARSE_ARG_NAME,
    PARSE_ARG_POSTNAME,
    PARSE_ARG_EQ,
    PARSE_ARG_PREVAL,
    PARSE_ARG_VAL,
    PARSE_ARG_VAL_ESC,
    PARSE_ARG_POSTVAL,
    PARSE_TAIL,
    PARSE_TAIL_SEQ,
    PARSE_EXECUTE
} parse_state_t;

typedef struct arg_item {
    struct arg_item  *next;
    char             *name;
    apr_size_t        name_len;
    char             *value;
    apr_size_t        value_len;
} arg_item_t;

struct ssi_internal_ctx {
    parse_state_t state;
    int           seen_eos;
    int           error;
    char          quote;         /* quote character value (or \0) */
    apr_size_t    parse_pos;     /* parse position of partial matches */
    apr_size_t    bytes_read;

    apr_bucket_brigade *tmp_bb;

    request_rec  *r;
    const char   *start_seq;
    bndm_t       *start_seq_pat;
    const char   *end_seq;
    apr_size_t    end_seq_len;
    char         *directive;     /* name of the current directive */
    apr_size_t    directive_len; /* length of the current directive name */

    arg_item_t   *current_arg;   /* currently parsed argument */
    arg_item_t   *argv;          /* all arguments */

    char         *error_str_override;
    char         *time_str_override;
    char         *re_string;
    regmatch_t   (*re_result)[10];
};


/*
 * +-------------------------------------------------------+
 * |                                                       |
 * |                 Static Module Data
 * |                                                       |
 * +-------------------------------------------------------+
 */

/* global module structure */
module AP_MODULE_DECLARE_DATA include_module;

/* function handlers for include directives */
static apr_hash_t *include_handlers;

/* forward declaration of handler registry */
static APR_OPTIONAL_FN_TYPE(ap_register_include_handler) *ssi_pfn_register;

/* Sentinel value to store in subprocess_env for items that
 * shouldn't be evaluated until/unless they're actually used
 */
static const char lazy_eval_sentinel;
#define LAZY_VALUE (&lazy_eval_sentinel)

/* default values */
#define DEFAULT_START_SEQUENCE "<!--#"
#define DEFAULT_END_SEQUENCE "-->"
#define DEFAULT_ERROR_MSG "[an error occurred while processing this directive]"
#define DEFAULT_TIME_FORMAT "%A, %d-%b-%Y %H:%M:%S %Z"
#define DEFAULT_UNDEFINED_ECHO "(none)"

#ifdef XBITHACK
#define DEFAULT_XBITHACK XBITHACK_FULL
#else
#define DEFAULT_XBITHACK XBITHACK_OFF
#endif


/*
 * +-------------------------------------------------------+
 * |                                                       |
 * |            Environment/Expansion Functions
 * |                                                       |
 * +-------------------------------------------------------+
 */

/*
 * decodes a string containing html entities or numeric character references.
 * 's' is overwritten with the decoded string.
 * If 's' is syntatically incorrect, then the followed fixups will be made:
 *   unknown entities will be left undecoded;
 *   references to unused numeric characters will be deleted.
 *   In particular, &#00; will not be decoded, but will be deleted.
 */

/* maximum length of any ISO-LATIN-1 HTML entity name. */
#define MAXENTLEN (6)

/* The following is a shrinking transformation, therefore safe. */

static void decodehtml(char *s)
{
    int val, i, j;
    char *p;
    const char *ents;
    static const char * const entlist[MAXENTLEN + 1] =
    {
        NULL,                   /* 0 */
        NULL,                   /* 1 */
        "lt\074gt\076",         /* 2 */
        "amp\046ETH\320eth\360",        /* 3 */
        "quot\042Auml\304Euml\313Iuml\317Ouml\326Uuml\334auml\344euml\353\
iuml\357ouml\366uuml\374yuml\377",      /* 4 */
        "Acirc\302Aring\305AElig\306Ecirc\312Icirc\316Ocirc\324Ucirc\333\
THORN\336szlig\337acirc\342aring\345aelig\346ecirc\352icirc\356ocirc\364\
ucirc\373thorn\376",            /* 5 */
        "Agrave\300Aacute\301Atilde\303Ccedil\307Egrave\310Eacute\311\
Igrave\314Iacute\315Ntilde\321Ograve\322Oacute\323Otilde\325Oslash\330\
Ugrave\331Uacute\332Yacute\335agrave\340aacute\341atilde\343ccedil\347\
egrave\350eacute\351igrave\354iacute\355ntilde\361ograve\362oacute\363\
otilde\365oslash\370ugrave\371uacute\372yacute\375"     /* 6 */
    };

    /* Do a fast scan through the string until we find anything
     * that needs more complicated handling
     */
    for (; *s != '&'; s++) {
        if (*s == '\0') {
            return;
        }
    }

    for (p = s; *s != '\0'; s++, p++) {
        if (*s != '&') {
            *p = *s;
            continue;
        }
        /* find end of entity */
        for (i = 1; s[i] != ';' && s[i] != '\0'; i++) {
            continue;
        }

        if (s[i] == '\0') {     /* treat as normal data */
            *p = *s;
            continue;
        }

        /* is it numeric ? */
        if (s[1] == '#') {
            for (j = 2, val = 0; j < i && apr_isdigit(s[j]); j++) {
                val = val * 10 + s[j] - '0';
            }
            s += i;
            if (j < i || val <= 8 || (val >= 11 && val <= 31) ||
                (val >= 127 && val <= 160) || val >= 256) {
                p--;            /* no data to output */
            }
            else {
                *p = RAW_ASCII_CHAR(val);
            }
        }
        else {
            j = i - 1;
            if (j > MAXENTLEN || entlist[j] == NULL) {
                /* wrong length */
                *p = '&';
                continue;       /* skip it */
            }
            for (ents = entlist[j]; *ents != '\0'; ents += i) {
                if (strncmp(s + 1, ents, j) == 0) {
                    break;
                }
            }

            if (*ents == '\0') {
                *p = '&';       /* unknown */
            }
            else {
                *p = RAW_ASCII_CHAR(((const unsigned char *) ents)[j]);
                s += i;
            }
        }
    }

    *p = '\0';
}

static void add_include_vars(request_rec *r, const char *timefmt)
{
    apr_table_t *e = r->subprocess_env;
    char *t;

    apr_table_setn(e, "DATE_LOCAL", LAZY_VALUE);
    apr_table_setn(e, "DATE_GMT", LAZY_VALUE);
    apr_table_setn(e, "LAST_MODIFIED", LAZY_VALUE);
    apr_table_setn(e, "DOCUMENT_URI", r->uri);
    if (r->path_info && *r->path_info) {
        apr_table_setn(e, "DOCUMENT_PATH_INFO", r->path_info);
    }
    apr_table_setn(e, "USER_NAME", LAZY_VALUE);
    if ((t = strrchr(r->filename, '/'))) {
        apr_table_setn(e, "DOCUMENT_NAME", ++t);
    }
    else {
        apr_table_setn(e, "DOCUMENT_NAME", r->uri);
    }
    if (r->args) {
        char *arg_copy = apr_pstrdup(r->pool, r->args);

        ap_unescape_url(arg_copy);
        apr_table_setn(e, "QUERY_STRING_UNESCAPED",
                  ap_escape_shell_cmd(r->pool, arg_copy));
    }
}

static const char *add_include_vars_lazy(request_rec *r, const char *var)
{
    char *val;
    if (!strcasecmp(var, "DATE_LOCAL")) {
        include_dir_config *conf =
            (include_dir_config *)ap_get_module_config(r->per_dir_config,
                                                       &include_module);
        val = ap_ht_time(r->pool, r->request_time, conf->default_time_fmt, 0);
    }
    else if (!strcasecmp(var, "DATE_GMT")) {
        include_dir_config *conf =
            (include_dir_config *)ap_get_module_config(r->per_dir_config,
                                                       &include_module);
        val = ap_ht_time(r->pool, r->request_time, conf->default_time_fmt, 1);
    }
    else if (!strcasecmp(var, "LAST_MODIFIED")) {
        include_dir_config *conf =
            (include_dir_config *)ap_get_module_config(r->per_dir_config,
                                                       &include_module);
        val = ap_ht_time(r->pool, r->finfo.mtime, conf->default_time_fmt, 0);
    }
    else if (!strcasecmp(var, "USER_NAME")) {
        if (apr_get_username(&val, r->finfo.user, r->pool) != APR_SUCCESS) {
            val = "<unknown>";
        }
    }
    else {
        val = NULL;
    }

    if (val) {
        apr_table_setn(r->subprocess_env, var, val);
    }
    return val;
}

static const char *get_include_var(request_rec *r, include_ctx_t *ctx, 
                                   const char *var)
{
    const char *val;
    if (apr_isdigit(*var) && !var[1]) {
        /* Handle $0 .. $9 from the last regex evaluated.
         * The choice of returning NULL strings on not-found,
         * v.s. empty strings on an empty match is deliberate.
         */
        if (!ctx->intern->re_result || !ctx->intern->re_string) {
            return NULL;
        }
        else {
            int idx = atoi(var);
            apr_size_t len = (*ctx->intern->re_result)[idx].rm_eo
                           - (*ctx->intern->re_result)[idx].rm_so;
            if (    (*ctx->intern->re_result)[idx].rm_so < 0
                 || (*ctx->intern->re_result)[idx].rm_eo < 0) {
                return NULL;
            }
            val = apr_pstrmemdup(r->pool, ctx->intern->re_string
                                 + (*ctx->intern->re_result)[idx].rm_so, len);
        }
    }
    else {
        val = apr_table_get(r->subprocess_env, var);

        if (val == LAZY_VALUE)
            val = add_include_vars_lazy(r, var);
    }
    return val;
}

/* initial buffer size for power-of-two allocator in ap_ssi_parse_string */
#define PARSE_STRING_INITIAL_SIZE 64

/*
 * Do variable substitution on strings
 * (Note: If out==NULL, this function allocs a buffer for the resulting
 * string from r->pool.  The return value is the parsed string)
 */
static char *ap_ssi_parse_string(request_rec *r, include_ctx_t *ctx, 
                                 const char *in, char *out,
                                 apr_size_t length, int leave_name)
{
    char ch;
    char *next;
    char *end_out;
    apr_size_t out_size;

    /* allocate an output buffer if needed */
    if (!out) {
        out_size = PARSE_STRING_INITIAL_SIZE;
        if (out_size > length) {
            out_size = length;
        }
        out = apr_palloc(r->pool, out_size);
    }
    else {
        out_size = length;
    }

    /* leave room for nul terminator */
    end_out = out + out_size - 1;

    next = out;
    while ((ch = *in++) != '\0') {
        switch (ch) {
        case '\\':
            if (next == end_out) {
                if (out_size < length) {
                    /* double the buffer size */
                    apr_size_t new_out_size = out_size * 2;
                    apr_size_t current_length = next - out;
                    char *new_out;
                    if (new_out_size > length) {
                        new_out_size = length;
                    }
                    new_out = apr_palloc(r->pool, new_out_size);
                    memcpy(new_out, out, current_length);
                    out = new_out;
                    out_size = new_out_size;
                    end_out = out + out_size - 1;
                    next = out + current_length;
                }
                else {
                    /* truncated */
                    *next = '\0';
                    return out;
                }
            }
            if (*in == '$') {
                *next++ = *in++;
            }
            else {
                *next++ = ch;
            }
            break;
        case '$':
            {
                const char *start_of_var_name;
                char *end_of_var_name;        /* end of var name + 1 */
                const char *expansion, *temp_end, *val;
                char        tmp_store;
                apr_size_t l;

                /* guess that the expansion won't happen */
                expansion = in - 1;
                if (*in == '{') {
                    ++in;
                    start_of_var_name = in;
                    in = ap_strchr_c(in, '}');
                    if (in == NULL) {
                        ap_log_rerror(APLOG_MARK, APLOG_ERR,
                                      0, r, "Missing '}' on variable \"%s\"",
                                      expansion);
                        *next = '\0';
                        return out;
                    }
                    temp_end = in;
                    end_of_var_name = (char *)temp_end;
                    ++in;
                }
                else {
                    start_of_var_name = in;
                    while (apr_isalnum(*in) || *in == '_') {
                        ++in;
                    }
                    temp_end = in;
                    end_of_var_name = (char *)temp_end;
                }
                /* what a pain, too bad there's no table_getn where you can
                 * pass a non-nul terminated string */
                l = end_of_var_name - start_of_var_name;
                if (l != 0) {
                    tmp_store        = *end_of_var_name;
                    *end_of_var_name = '\0';
                    val = get_include_var(r, ctx, start_of_var_name);
                    *end_of_var_name = tmp_store;

                    if (val) {
                        expansion = val;
                        l = strlen(expansion);
                    }
                    else if (leave_name) {
                        l = in - expansion;
                    }
                    else {
                        /* no expansion to be done */
                        break;
                    }
                }
                else {
                    /* zero-length variable name causes just the $ to be 
                     * copied */
                    l = 1;
                }
                if ((next + l > end_out) && (out_size < length)) {
                    /* increase the buffer size to accommodate l more chars */
                    apr_size_t new_out_size = out_size;
                    apr_size_t current_length = next - out;
                    char *new_out;
                    do {
                        new_out_size *= 2;
                    } while (new_out_size < current_length + l);
                    if (new_out_size > length) {
                        new_out_size = length;
                    }
                    new_out = apr_palloc(r->pool, new_out_size);
                    memcpy(new_out, out, current_length);
                    out = new_out;
                    out_size = new_out_size;
                    end_out = out + out_size - 1;
                    next = out + current_length;
                }
                l = ((int)l > end_out - next) ? (end_out - next) : l;
                memcpy(next, expansion, l);
                next += l;
                break;
            }
        default:
            if (next == end_out) {
                if (out_size < length) {
                    /* double the buffer size */
                    apr_size_t new_out_size = out_size * 2;
                    apr_size_t current_length = next - out;
                    char *new_out;
                    if (new_out_size > length) {
                        new_out_size = length;
                    }
                    new_out = apr_palloc(r->pool, new_out_size);
                    memcpy(new_out, out, current_length);
                    out = new_out;
                    out_size = new_out_size;
                    end_out = out + out_size - 1;
                    next = out + current_length;
                }
                else {
                    /* truncated */
                    *next = '\0';
                    return out;
                }
            }
            *next++ = ch;
            break;
        }
    }
    *next = '\0';
    return out;
}


/*
 * +-------------------------------------------------------+
 * |                                                       |
 * |              Conditional Expression Parser
 * |                                                       |
 * +-------------------------------------------------------+
 */

static int re_check(request_rec *r, include_ctx_t *ctx, 
                    char *string, char *rexp)
{
    regex_t *compiled;
    const apr_size_t nres = sizeof(*ctx->intern->re_result) / sizeof(regmatch_t);
    int regex_error;

    compiled = ap_pregcomp(r->pool, rexp, REG_EXTENDED | REG_NOSUB);
    if (compiled == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "unable to compile pattern \"%s\"", rexp);
        return -1;
    }
    if (!ctx->intern->re_result) {
        ctx->intern->re_result = apr_pcalloc(r->pool, sizeof(*ctx->intern->re_result));
    }
    ctx->intern->re_string = string;
    regex_error = ap_regexec(compiled, string, nres, *ctx->intern->re_result, 0);
    ap_pregfree(r->pool, compiled);
    return (!regex_error);
}

enum token_type {
    token_string, token_re,
    token_and, token_or, token_not, token_eq, token_ne,
    token_rbrace, token_lbrace, token_group,
    token_ge, token_le, token_gt, token_lt
};
struct token {
    enum token_type type;
    char* value;
};

static const char *get_ptoken(request_rec *r, const char *string, 
                              struct token *token, int *unmatched)
{
    char ch;
    int next = 0;
    char qs = 0;
    int tkn_fnd = 0;

    token->value = NULL;

    /* Skip leading white space */
    if (string == (char *) NULL) {
        return (char *) NULL;
    }
    while ((ch = *string++)) {
        if (!apr_isspace(ch)) {
            break;
        }
    }
    if (ch == '\0') {
        return (char *) NULL;
    }

    token->type = token_string; /* the default type */
    switch (ch) {
    case '(':
        token->type = token_lbrace;
        return (string);
    case ')':
        token->type = token_rbrace;
        return (string);
    case '=':
        token->type = token_eq;
        return (string);
    case '!':
        if (*string == '=') {
            token->type = token_ne;
            return (string + 1);
        }
        else {
            token->type = token_not;
            return (string);
        }
    case '\'':
        /* already token->type == token_string */
        qs = '\'';
        break;
    case '/':
        token->type = token_re;
        qs = '/';
        break;
    case '|':
        if (*string == '|') {
            token->type = token_or;
            return (string + 1);
        }
        break;
    case '&':
        if (*string == '&') {
            token->type = token_and;
            return (string + 1);
        }
        break;
    case '>':
        if (*string == '=') {
            token->type = token_ge;
            return (string + 1);
        }
        else {
            token->type = token_gt;
            return (string);
        }
    case '<':
        if (*string == '=') {
            token->type = token_le;
            return (string + 1);
        }
        else {
            token->type = token_lt;
            return (string);
        }
    default:
        /* already token->type == token_string */
        break;
    }
    /* We should only be here if we are in a string */
    token->value = apr_palloc(r->pool, strlen(string) + 2); /* 2 for ch plus
                                                               trailing null */
    if (!qs) {
        token->value[next++] = ch;
    }

    /* 
     * I used the ++string throughout this section so that string
     * ends up pointing to the next token and I can just return it
     */
    for (ch = *string; ((ch != '\0') && (!tkn_fnd)); ch = *++string) {
        if (ch == '\\') {
            if ((ch = *++string) == '\0') {
                tkn_fnd = 1;
            }
            else {
                token->value[next++] = ch;
            }
        }
        else {
            if (!qs) {
                if (apr_isspace(ch)) {
                    tkn_fnd = 1;
                }
                else {
                    switch (ch) {
                    case '(':
                    case ')':
                    case '=':
                    case '!':
                    case '<':
                    case '>':
                        tkn_fnd = 1;
                        break;
                    case '|':
                        if (*(string + 1) == '|') {
                            tkn_fnd = 1;
                        }
                        break;
                    case '&':
                        if (*(string + 1) == '&') {
                            tkn_fnd = 1;
                        }
                        break;
                    }
                    if (!tkn_fnd) {
                        token->value[next++] = ch;
                    }
                }
            }
            else {
                if (ch == qs) {
                    qs = 0;
                    tkn_fnd = 1;
                    string++;
                }
                else {
                    token->value[next++] = ch;
                }
            }
        }
        if (tkn_fnd) {
            break;
        }
    }

    /* If qs is still set, we have an unmatched quote */
    if (qs) {
        *unmatched = 1;
        next = 0;
    }
    token->value[next] = '\0';

    return (string);
}


/* there is an implicit assumption here that expr is at most MAX_STRING_LEN-1
 * characters long...
 */
static int parse_expr(request_rec *r, include_ctx_t *ctx, const char *expr,
                      int *was_error, int *was_unmatched, char *debug)
{
    struct parse_node {
        struct parse_node *left, *right, *parent;
        struct token token;
        int value, done;
    } *root, *current, *new;
    const char *parse;
    char* buffer;
    int retval = 0;
    apr_size_t debug_pos = 0;

    debug[debug_pos] = '\0';
    *was_error       = 0;
    *was_unmatched   = 0;
    if ((parse = expr) == (char *) NULL) {
        return (0);
    }
    root = current = (struct parse_node *) NULL;

    /* Create Parse Tree */
    while (1) {
        new = (struct parse_node *) apr_palloc(r->pool,
                                           sizeof(struct parse_node));
        new->parent = new->left = new->right = (struct parse_node *) NULL;
        new->done = 0;
        if ((parse = get_ptoken(r, parse, &new->token, was_unmatched)) == 
            (char *) NULL) {
            break;
        }
        switch (new->token.type) {

        case token_string:
#ifdef DEBUG_INCLUDE
            debug_pos += sprintf (&debug[debug_pos], 
                                  "     Token: string (%s)\n", 
                                  new->token.value);
#endif
            if (current == (struct parse_node *) NULL) {
                root = current = new;
                break;
            }
            switch (current->token.type) {
            case token_string:
                current->token.value = apr_pstrcat(r->pool,
                                                   current->token.value,
                                                   current->token.value[0] ? " " : "",
                                                   new->token.value,
                                                   NULL);
                                                   
                break;
            case token_eq:
            case token_ne:
            case token_and:
            case token_or:
            case token_lbrace:
            case token_not:
            case token_ge:
            case token_gt:
            case token_le:
            case token_lt:
                new->parent = current;
                current = current->right = new;
                break;
            default:
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                            "Invalid expression \"%s\" in file %s",
                            expr, r->filename);
                *was_error = 1;
                return retval;
            }
            break;

        case token_re:
#ifdef DEBUG_INCLUDE
            debug_pos += sprintf (&debug[debug_pos], 
                                  "     Token: regex (%s)\n", 
                                  new->token.value);
#endif
            if (current == (struct parse_node *) NULL) {
                root = current = new;
                break;
            }
            switch (current->token.type) {
            case token_eq:
            case token_ne:
            case token_and:
            case token_or:
            case token_lbrace:
            case token_not:
                new->parent = current;
                current = current->right = new;
                break;
            default:
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                            "Invalid expression \"%s\" in file %s",
                            expr, r->filename);
                *was_error = 1;
                return retval;
            }
            break;

        case token_and:
        case token_or:
#ifdef DEBUG_INCLUDE
            memcpy (&debug[debug_pos], "     Token: and/or\n",
                    sizeof ("     Token: and/or\n"));
            debug_pos += sizeof ("     Token: and/or\n");
#endif
            if (current == (struct parse_node *) NULL) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                            "Invalid expression \"%s\" in file %s",
                            expr, r->filename);
                *was_error = 1;
                return retval;
            }
            /* Percolate upwards */
            while (current != (struct parse_node *) NULL) {
                switch (current->token.type) {
                case token_string:
                case token_re:
                case token_group:
                case token_not:
                case token_eq:
                case token_ne:
                case token_and:
                case token_or:
                case token_ge:
                case token_gt:
                case token_le:
                case token_lt:
                    current = current->parent;
                    continue;
                case token_lbrace:
                    break;
                default:
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                                "Invalid expression \"%s\" in file %s",
                                expr, r->filename);
                    *was_error = 1;
                    return retval;
                }
                break;
            }
            if (current == (struct parse_node *) NULL) {
                new->left = root;
                new->left->parent = new;
                new->parent = (struct parse_node *) NULL;
                root = new;
            }
            else {
                new->left = current->right;
                current->right = new;
                new->parent = current;
            }
            current = new;
            break;

        case token_not:
#ifdef DEBUG_INCLUDE
            memcpy(&debug[debug_pos], "     Token: not\n",
                    sizeof("     Token: not\n"));
            debug_pos += sizeof("     Token: not\n");
#endif
            if (current == (struct parse_node *) NULL) {
                root = current = new;
                break;
            }
            /* Percolate upwards */
            if (current != (struct parse_node *) NULL) {
                switch (current->token.type) {
                case token_not:
                case token_eq:
                case token_ne:
                case token_and:
                case token_or:
                case token_lbrace:
                case token_ge:
                case token_gt:
                case token_le:
                case token_lt:
                    break;
                default:
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                                  "Invalid expression \"%s\" in file %s",
                                  expr, r->filename);
                    *was_error = 1;
                    return retval;
                }
            }
            if (current == (struct parse_node *) NULL) {
                new->left = root;
                new->left->parent = new;
                new->parent = (struct parse_node *) NULL;
                root = new;
            }
            else {
                new->left = current->right;
                current->right = new;
                new->parent = current;
            }
            current = new;
            break;

        case token_eq:
        case token_ne:
        case token_ge:
        case token_gt:
        case token_le:
        case token_lt:
#ifdef DEBUG_INCLUDE
            memcpy(&debug[debug_pos], "     Token: eq/ne/ge/gt/le/lt\n",
                    sizeof("     Token: eq/ne/ge/gt/le/lt\n"));
            debug_pos += sizeof("     Token: eq/ne/ge/gt/le/lt\n");
#endif
            if (current == (struct parse_node *) NULL) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                              "Invalid expression \"%s\" in file %s",
                              expr, r->filename);
                *was_error = 1;
                return retval;
            }
            /* Percolate upwards */
            while (current != (struct parse_node *) NULL) {
                switch (current->token.type) {
                case token_string:
                case token_re:
                case token_group:
                    current = current->parent;
                    continue;
                case token_lbrace:
                case token_and:
                case token_or:
                    break;
                case token_not:
                case token_eq:
                case token_ne:
                case token_ge:
                case token_gt:
                case token_le:
                case token_lt:
                default:
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                                "Invalid expression \"%s\" in file %s",
                                expr, r->filename);
                    *was_error = 1;
                    return retval;
                }
                break;
            }
            if (current == (struct parse_node *) NULL) {
                new->left = root;
                new->left->parent = new;
                new->parent = (struct parse_node *) NULL;
                root = new;
            }
            else {
                new->left = current->right;
                current->right = new;
                new->parent = current;
            }
            current = new;
            break;

        case token_rbrace:
#ifdef DEBUG_INCLUDE
            memcpy (&debug[debug_pos], "     Token: rbrace\n",
                    sizeof ("     Token: rbrace\n"));
            debug_pos += sizeof ("     Token: rbrace\n");
#endif
            while (current != (struct parse_node *) NULL) {
                if (current->token.type == token_lbrace) {
                    current->token.type = token_group;
                    break;
                }
                current = current->parent;
            }
            if (current == (struct parse_node *) NULL) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                            "Unmatched ')' in \"%s\" in file %s",
                            expr, r->filename);
                *was_error = 1;
                return retval;
            }
            break;

        case token_lbrace:
#ifdef DEBUG_INCLUDE
            memcpy (&debug[debug_pos], "     Token: lbrace\n",
                    sizeof ("     Token: lbrace\n"));
            debug_pos += sizeof ("     Token: lbrace\n");
#endif
            if (current == (struct parse_node *) NULL) {
                root = current = new;
                break;
            }
            /* Percolate upwards */
            if (current != (struct parse_node *) NULL) {
                switch (current->token.type) {
                case token_not:
                case token_eq:
                case token_ne:
                case token_and:
                case token_or:
                case token_lbrace:
                case token_ge:
                case token_gt:
                case token_le:
                case token_lt:
                    break;
                case token_string:
                case token_re:
                case token_group:
                default:
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                                "Invalid expression \"%s\" in file %s",
                                expr, r->filename);
                    *was_error = 1;
                    return retval;
                }
            }
            if (current == (struct parse_node *) NULL) {
                new->left = root;
                new->left->parent = new;
                new->parent = (struct parse_node *) NULL;
                root = new;
            }
            else {
                new->left = current->right;
                current->right = new;
                new->parent = current;
            }
            current = new;
            break;
        default:
            break;
        }
    }

    /* Evaluate Parse Tree */
    current = root;
    while (current != (struct parse_node *) NULL) {
        switch (current->token.type) {
        case token_string:
#ifdef DEBUG_INCLUDE
            memcpy (&debug[debug_pos], "     Evaluate string\n",
                    sizeof ("     Evaluate string\n"));
            debug_pos += sizeof ("     Evaluate string\n");
#endif
            buffer = ap_ssi_parse_string(r, ctx, current->token.value, NULL, 
                                         MAX_STRING_LEN, 0);
            current->token.value = buffer;
            current->value = (current->token.value[0] != '\0');
            current->done = 1;
            current = current->parent;
            break;

        case token_re:
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "No operator before regex of expr \"%s\" in file %s",
                          expr, r->filename);
            *was_error = 1;
            return retval;

        case token_and:
        case token_or:
#ifdef DEBUG_INCLUDE
            memcpy(&debug[debug_pos], "     Evaluate and/or\n",
                    sizeof("     Evaluate and/or\n"));
            debug_pos += sizeof("     Evaluate and/or\n");
#endif
            if (current->left  == (struct parse_node *) NULL ||
                current->right == (struct parse_node *) NULL) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                              "Invalid expression \"%s\" in file %s",
                              expr, r->filename);
                *was_error = 1;
                return retval;
            }
            if (!current->left->done) {
                switch (current->left->token.type) {
                case token_string:
                    buffer = ap_ssi_parse_string(r, ctx, current->left->token.value,
                                                 NULL, MAX_STRING_LEN, 0);
                    current->left->token.value = buffer;
                    current->left->value = 
                                       (current->left->token.value[0] != '\0');
                    current->left->done = 1;
                    break;
                default:
                    current = current->left;
                    continue;
                }
            }
            if (!current->right->done) {
                switch (current->right->token.type) {
                case token_string:
                    buffer = ap_ssi_parse_string(r, ctx, current->right->token.value,
                                                 NULL, MAX_STRING_LEN, 0);
                    current->right->token.value = buffer;
                    current->right->value = 
                                      (current->right->token.value[0] != '\0');
                    current->right->done = 1;
                    break;
                default:
                    current = current->right;
                    continue;
                }
            }
#ifdef DEBUG_INCLUDE
            debug_pos += sprintf (&debug[debug_pos], "     Left: %c\n",
                                  current->left->value ? '1' : '0');
            debug_pos += sprintf (&debug[debug_pos], "     Right: %c\n",
                                  current->right->value ? '1' : '0');
#endif
            if (current->token.type == token_and) {
                current->value = current->left->value && current->right->value;
            }
            else {
                current->value = current->left->value || current->right->value;
            }
#ifdef DEBUG_INCLUDE
            debug_pos += sprintf (&debug[debug_pos], "     Returning %c\n",
                                  current->value ? '1' : '0');
#endif
            current->done = 1;
            current = current->parent;
            break;

        case token_eq:
        case token_ne:
#ifdef DEBUG_INCLUDE
            memcpy (&debug[debug_pos], "     Evaluate eq/ne\n",
                    sizeof ("     Evaluate eq/ne\n"));
            debug_pos += sizeof ("     Evaluate eq/ne\n");
#endif
            if ((current->left == (struct parse_node *) NULL) ||
                (current->right == (struct parse_node *) NULL) ||
                (current->left->token.type != token_string) ||
                ((current->right->token.type != token_string) &&
                 (current->right->token.type != token_re))) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                            "Invalid expression \"%s\" in file %s",
                            expr, r->filename);
                *was_error = 1;
                return retval;
            }
            buffer = ap_ssi_parse_string(r, ctx, current->left->token.value,
                                         NULL, MAX_STRING_LEN, 0);
            current->left->token.value = buffer;
            buffer = ap_ssi_parse_string(r, ctx, current->right->token.value,
                                         NULL, MAX_STRING_LEN, 0);
            current->right->token.value = buffer;
            if (current->right->token.type == token_re) {
#ifdef DEBUG_INCLUDE
                debug_pos += sprintf (&debug[debug_pos],
                                      "     Re Compare (%s) with /%s/\n",
                                      current->left->token.value,
                                      current->right->token.value);
#endif
                current->value =
                    re_check(r, ctx, current->left->token.value,
                             current->right->token.value);
            }
            else {
#ifdef DEBUG_INCLUDE
                debug_pos += sprintf (&debug[debug_pos],
                                      "     Compare (%s) with (%s)\n",
                                      current->left->token.value,
                                      current->right->token.value);
#endif
                current->value =
                    (strcmp(current->left->token.value,
                            current->right->token.value) == 0);
            }
            if (current->token.type == token_ne) {
                current->value = !current->value;
            }
#ifdef DEBUG_INCLUDE
            debug_pos += sprintf (&debug[debug_pos], "     Returning %c\n",
                                  current->value ? '1' : '0');
#endif
            current->done = 1;
            current = current->parent;
            break;
        case token_ge:
        case token_gt:
        case token_le:
        case token_lt:
#ifdef DEBUG_INCLUDE
            memcpy (&debug[debug_pos], "     Evaluate ge/gt/le/lt\n",
                    sizeof ("     Evaluate ge/gt/le/lt\n"));
            debug_pos += sizeof ("     Evaluate ge/gt/le/lt\n");
#endif
            if ((current->left == (struct parse_node *) NULL) ||
                (current->right == (struct parse_node *) NULL) ||
                (current->left->token.type != token_string) ||
                (current->right->token.type != token_string)) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                            "Invalid expression \"%s\" in file %s",
                            expr, r->filename);
                *was_error = 1;
                return retval;
            }
            buffer = ap_ssi_parse_string(r, ctx, current->left->token.value,
                                         NULL, MAX_STRING_LEN, 0);
            current->left->token.value = buffer;
            buffer = ap_ssi_parse_string(r, ctx, current->right->token.value,
                                         NULL, MAX_STRING_LEN, 0);
            current->right->token.value = buffer;
#ifdef DEBUG_INCLUDE
            debug_pos += sprintf (&debug[debug_pos],
                                  "     Compare (%s) with (%s)\n",
                                  current->left->token.value,
                                  current->right->token.value);
#endif
            current->value =
                strcmp(current->left->token.value,
                       current->right->token.value);
            if (current->token.type == token_ge) {
                current->value = current->value >= 0;
            }
            else if (current->token.type == token_gt) {
                current->value = current->value > 0;
            }
            else if (current->token.type == token_le) {
                current->value = current->value <= 0;
            }
            else if (current->token.type == token_lt) {
                current->value = current->value < 0;
            }
            else {
                current->value = 0;     /* Don't return -1 if unknown token */
            }
#ifdef DEBUG_INCLUDE
            debug_pos += sprintf (&debug[debug_pos], "     Returning %c\n",
                                  current->value ? '1' : '0');
#endif
            current->done = 1;
            current = current->parent;
            break;

        case token_not:
            if (current->right != (struct parse_node *) NULL) {
                if (!current->right->done) {
                    current = current->right;
                    continue;
                }
                current->value = !current->right->value;
            }
            else {
                current->value = 0;
            }
#ifdef DEBUG_INCLUDE
            debug_pos += sprintf (&debug[debug_pos], "     Evaluate !: %c\n",
                                  current->value ? '1' : '0');
#endif
            current->done = 1;
            current = current->parent;
            break;

        case token_group:
            if (current->right != (struct parse_node *) NULL) {
                if (!current->right->done) {
                    current = current->right;
                    continue;
                }
                current->value = current->right->value;
            }
            else {
                current->value = 1;
            }
#ifdef DEBUG_INCLUDE
            debug_pos += sprintf (&debug[debug_pos], "     Evaluate (): %c\n",
                                  current->value ? '1' : '0');
#endif
            current->done = 1;
            current = current->parent;
            break;

        case token_lbrace:
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                        "Unmatched '(' in \"%s\" in file %s",
                        expr, r->filename);
            *was_error = 1;
            return retval;

        case token_rbrace:
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                        "Unmatched ')' in \"%s\" in file %s",
                        expr, r->filename);
            *was_error = 1;
            return retval;

        default:
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "bad token type");
            *was_error = 1;
            return retval;
        }
    }

    retval = (root == (struct parse_node *) NULL) ? 0 : root->value;
    return (retval);
}


/*
 * +-------------------------------------------------------+
 * |                                                       |
 * |                    Action Handlers
 * |                                                       |
 * +-------------------------------------------------------+
 */

/*
 * Extract the next tag name and value.
 * If there are no more tags, set the tag name to NULL.
 * The tag value is html decoded if dodecode is non-zero.
 * The tag value may be NULL if there is no tag value..
 */
static void ap_ssi_get_tag_and_value(include_ctx_t *ctx, char **tag,
                                     char **tag_val, int dodecode)
{
    if (!ctx->intern->argv) {
        *tag = NULL;
        *tag_val = NULL;

        return;
    }

    *tag_val = ctx->intern->argv->value;
    *tag = ctx->intern->argv->name;

    ctx->intern->argv = ctx->intern->argv->next;

    if (dodecode && *tag_val) {
        decodehtml(*tag_val);
    }

    return;
}

/* ensure that path is relative, and does not contain ".." elements
 * ensentially ensure that it does not match the regex:
 * (^/|(^|/)\.\.(/|$))
 * XXX: Simply replace with apr_filepath_merge                    
 */
static int is_only_below(const char *path)
{
#ifdef HAVE_DRIVE_LETTERS
    if (path[1] == ':') 
        return 0;
#endif
#ifdef NETWARE
    if (ap_strchr_c(path, ':'))
        return 0;
#endif
    if (path[0] == '/') {
        return 0;
    }
    while (*path) {
        int dots = 0;
        while (path[dots] == '.')
            ++dots;
#if defined(WIN32) 
        /* If the name is canonical this is redundant
         * but in security, redundancy is worthwhile.
         * Does OS2 belong here (accepts ... for ..)?
         */
        if (dots > 1 && (!path[dots] || path[dots] == '/'))
            return 0;
#else
        if (dots == 2 && (!path[dots] || path[dots] == '/'))
            return 0;
#endif
        path += dots;
        /* Advance to either the null byte at the end of the
         * string or the character right after the next slash,
         * whichever comes first
         */
        while (*path && (*path++ != '/')) {
            continue;
        }
    }
    return 1;
}

static int find_file(request_rec *r, const char *directive, const char *tag,
                     char *tag_val, apr_finfo_t *finfo)
{
    char *to_send = tag_val;
    request_rec *rr = NULL;
    int ret=0;
    char *error_fmt = NULL;
    apr_status_t rv = APR_SUCCESS;

    if (!strcmp(tag, "file")) {
        /* XXX: Port to apr_filepath_merge
         * be safe; only files in this directory or below allowed 
         */
        if (!is_only_below(tag_val)) {
            error_fmt = "unable to access file \"%s\" "
                        "in parsed file %s";
        }
        else {
            ap_getparents(tag_val);    /* get rid of any nasties */

            /* note: it is okay to pass NULL for the "next filter" since
               we never attempt to "run" this sub request. */
            rr = ap_sub_req_lookup_file(tag_val, r, NULL);

            if (rr->status == HTTP_OK && rr->finfo.filetype != 0) {
                to_send = rr->filename;
                if ((rv = apr_stat(finfo, to_send, 
                    APR_FINFO_GPROT | APR_FINFO_MIN, rr->pool)) != APR_SUCCESS
                    && rv != APR_INCOMPLETE) {
                    error_fmt = "unable to get information about \"%s\" "
                        "in parsed file %s";
                }
            }
            else {
                error_fmt = "unable to lookup information about \"%s\" "
                            "in parsed file %s";
            }
        }

        if (error_fmt) {
            ret = -1;
            ap_log_rerror(APLOG_MARK, APLOG_ERR,
                          rv, r, error_fmt, to_send, r->filename);
        }

        if (rr) ap_destroy_sub_req(rr);
        
        return ret;
    }
    else if (!strcmp(tag, "virtual")) {
        /* note: it is okay to pass NULL for the "next filter" since
           we never attempt to "run" this sub request. */
        rr = ap_sub_req_lookup_uri(tag_val, r, NULL);

        if (rr->status == HTTP_OK && rr->finfo.filetype != 0) {
            memcpy((char *) finfo, (const char *) &rr->finfo,
                   sizeof(rr->finfo));
            ap_destroy_sub_req(rr);
            return 0;
        }
        else {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                        "unable to get information about \"%s\" "
                        "in parsed file %s",
                        tag_val, r->filename);
            ap_destroy_sub_req(rr);
            return -1;
        }
    }
    else {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                    "unknown parameter \"%s\" to tag %s in %s",
                    tag, directive, r->filename);
        return -1;
    }
}

/*
 * <!--#include virtual|file="..." [virtual|file="..."] ... -->
 */
static apr_status_t handle_include(include_ctx_t *ctx, ap_filter_t *f,
                                   apr_bucket_brigade *bb)
{
    request_rec *r = f->r;

    if (!ctx->argc) {
        ap_log_rerror(APLOG_MARK,
                      (ctx->flags & SSI_FLAG_PRINTING)
                          ? APLOG_ERR : APLOG_WARNING,
                      0, r, "missing argument for include element in %s",
                      r->filename);
    }

    if (!(ctx->flags & SSI_FLAG_PRINTING)) {
        return APR_SUCCESS;
    }

    if (!ctx->argc) {
        SSI_CREATE_ERROR_BUCKET(ctx, f, bb);
        return APR_SUCCESS;
    }

    while (1) {
        char *tag     = NULL;
        char *tag_val = NULL;
        request_rec *rr = NULL;
        char *error_fmt = NULL;
        char *parsed_string;

        ap_ssi_get_tag_and_value(ctx, &tag, &tag_val, SSI_VALUE_DECODED);
        if (!tag || !tag_val) {
            break;
        }

        if (strcmp(tag, "virtual") && strcmp(tag, "file")) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "unknown parameter "
                          "\"%s\" to tag include in %s", tag, r->filename);
            SSI_CREATE_ERROR_BUCKET(ctx, f, bb);
            break;
        }

        parsed_string = ap_ssi_parse_string(r, ctx, tag_val, NULL,
                                            MAX_STRING_LEN,
                                            SSI_EXPAND_DROP_NAME);
        if (tag[0] == 'f') {
            /* XXX: Port to apr_filepath_merge
             * be safe; only files in this directory or below allowed 
             */
            if (!is_only_below(parsed_string)) {
                error_fmt = "unable to include file \"%s\" in parsed file %s";
            }
            else {
                rr = ap_sub_req_lookup_uri(parsed_string, r, f->next);
            }
        }
        else {
            rr = ap_sub_req_lookup_uri(parsed_string, r, f->next);
        }

        if (!error_fmt && rr->status != HTTP_OK) {
            error_fmt = "unable to include \"%s\" in parsed file %s";
        }

        if (!error_fmt && (ctx->flags & SSI_FLAG_NO_EXEC) &&
            rr->content_type && strncmp(rr->content_type, "text/", 5)) {

            error_fmt = "unable to include potential exec \"%s\" in parsed "
                        "file %s";
        }

        if (!error_fmt) {
            int founddupe = 0;
            request_rec *p, *q;

            /* try to avoid recursive includes.  We do this by walking
             * up the r->main list of subrequests, and at each level
             * walking back through any internal redirects.  At each
             * step, we compare the filenames and the URIs.  
             *
             * The filename comparison catches a recursive include
             * with an ever-changing URL, eg.
             * <!--#include virtual=
             *      "$REQUEST_URI/$QUERY_STRING?$QUERY_STRING/x" -->
             * which, although they would eventually be caught because
             * we have a limit on the length of files, etc., can 
             * recurse for a while.
             *
             * The URI comparison catches the case where the filename
             * is changed while processing the request, so the 
             * current name is never the same as any previous one.
             * This can happen with "DocumentRoot /foo" when you
             * request "/" on the server and it includes "/".
             * This only applies to modules such as mod_dir that 
             * (somewhat improperly) mess with r->filename outside 
             * of a filename translation phase.
             */
             for (p = r; p && !founddupe; p = p->main) {
                for (q = p; q; q = q->prev) {
                    if ((q->filename && rr->filename && 
                        (strcmp(q->filename, rr->filename) == 0)) ||
                        ((*q->uri == '/') && 
                        (strcmp(q->uri, rr->uri) == 0))) {

                        founddupe = 1;
                        break;
                    }
                }
            }

            if (p) {
                error_fmt = "Recursive include of \"%s\" in parsed file %s";
            }
        }

        /* See the Kludge in includes_filter for why.
         * Basically, it puts a bread crumb in here, then looks
         * for the crumb later to see if its been here.
         */
        if (rr) {
            ap_set_module_config(rr->request_config, &include_module, r);
        }

        if (!error_fmt && ap_run_sub_req(rr)) {
            error_fmt = "unable to include \"%s\" in parsed file %s";
        }

        if (error_fmt) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, error_fmt, tag_val,
                          r->filename);
            SSI_CREATE_ERROR_BUCKET(ctx, f, bb);
        }

        /* destroy the sub request */
        if (rr) {
            ap_destroy_sub_req(rr);
        }

        if (error_fmt) {
            break;
        }
    }

    return APR_SUCCESS;
}

/*
 * <!--#echo [encoding="..."] var="..." [encoding="..."] var="..." ... -->
 */
static apr_status_t handle_echo(include_ctx_t *ctx, ap_filter_t *f,
                                apr_bucket_brigade *bb)
{
    enum {E_NONE, E_URL, E_ENTITY} encode;
    request_rec *r = f->r;

    if (!ctx->argc) {
        ap_log_rerror(APLOG_MARK,
                      (ctx->flags & SSI_FLAG_PRINTING)
                          ? APLOG_ERR : APLOG_WARNING,
                      0, r, "missing argument for echo element in %s",
                      r->filename);
    }

    if (!(ctx->flags & SSI_FLAG_PRINTING)) {
        return APR_SUCCESS;
    }

    if (!ctx->argc) {
        SSI_CREATE_ERROR_BUCKET(ctx, f, bb);
        return APR_SUCCESS;
    }

    encode = E_ENTITY;

    while (1) {
        char *tag = NULL;
        char *tag_val = NULL;

        ap_ssi_get_tag_and_value(ctx, &tag, &tag_val, SSI_VALUE_DECODED);
        if (!tag || !tag_val) {
            break;
        }

        if (!strcmp(tag, "var")) {
            const char *val;
            const char *echo_text = NULL;
            apr_size_t e_len;

            val = get_include_var(r, ctx,
                                  ap_ssi_parse_string(r, ctx, tag_val, NULL,
                                                      MAX_STRING_LEN,
                                                      SSI_EXPAND_DROP_NAME));
            if (val) {
                switch(encode) {
                case E_NONE:
                    echo_text = val;
                    break;
                case E_URL:
                    echo_text = ap_escape_uri(ctx->dpool, val);
                    break;
                case E_ENTITY:
                    echo_text = ap_escape_html(ctx->dpool, val);
                    break;
                }

                e_len = strlen(echo_text);
            }
            else {
                include_server_config *sconf;

                sconf = ap_get_module_config(r->server->module_config,
                                             &include_module);
                echo_text = sconf->undefined_echo;
                e_len = sconf->undefined_echo_len;
            }

            APR_BRIGADE_INSERT_TAIL(bb, apr_bucket_pool_create(
                                    apr_pstrmemdup(ctx->pool, echo_text, e_len),
                                    e_len, ctx->pool, f->c->bucket_alloc));
        }
        else if (!strcmp(tag, "encoding")) {
            if (!strcasecmp(tag_val, "none")) {
                encode = E_NONE;
            }
            else if (!strcasecmp(tag_val, "url")) {
                encode = E_URL;
            }
            else if (!strcasecmp(tag_val, "entity")) {
                encode = E_ENTITY;
            }
            else {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "unknown value "
                              "\"%s\" to parameter \"encoding\" of tag echo in "
                              "%s", tag_val, r->filename);
                SSI_CREATE_ERROR_BUCKET(ctx, f, bb);
                break;
            }
        }
        else {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "unknown parameter "
                          "\"%s\" in tag echo of %s", tag, r->filename);
            SSI_CREATE_ERROR_BUCKET(ctx, f, bb);
            break;
        }
    }

    return APR_SUCCESS;
}

/*
 * <!--#config [timefmt="..."] [sizefmt="..."] [errmsg="..."] -->
 */
static apr_status_t handle_config(include_ctx_t *ctx, ap_filter_t *f,
                                  apr_bucket_brigade *bb)
{
    request_rec *r = f->r;
    apr_table_t *env = r->subprocess_env;

    if (!ctx->argc) {
        ap_log_rerror(APLOG_MARK,
                      (ctx->flags & SSI_FLAG_PRINTING)
                          ? APLOG_ERR : APLOG_WARNING,
                      0, r, "missing argument for config element in %s",
                      r->filename);
    }

    if (!(ctx->flags & SSI_FLAG_PRINTING)) {
        return APR_SUCCESS;
    }

    if (!ctx->argc) {
        SSI_CREATE_ERROR_BUCKET(ctx, f, bb);
        return APR_SUCCESS;
    }

    while (1) {
        char *tag     = NULL;
        char *tag_val = NULL;
        char *parsed_string;

        ap_ssi_get_tag_and_value(ctx, &tag, &tag_val, SSI_VALUE_RAW);
        if (!tag || !tag_val) {
            break;
        }

        if (!strcmp(tag, "errmsg")) {
            if (!ctx->intern->error_str_override) {
                ctx->intern->error_str_override = apr_palloc(ctx->pool,
                                                             MAX_STRING_LEN);
                ctx->error_str = ctx->intern->error_str_override;
            }

            ap_ssi_parse_string(r, ctx, tag_val,ctx->intern->error_str_override,
                                MAX_STRING_LEN, SSI_EXPAND_DROP_NAME);
        }
        else if (!strcmp(tag, "timefmt")) {
            apr_time_t date = r->request_time;
            if (!ctx->intern->time_str_override) {
                ctx->intern->time_str_override = apr_palloc(ctx->pool,
                                                            MAX_STRING_LEN);
                ctx->time_str = ctx->intern->time_str_override;
            }
            ap_ssi_parse_string(r, ctx, tag_val, ctx->intern->time_str_override,
                                MAX_STRING_LEN, SSI_EXPAND_DROP_NAME);

            apr_table_setn(env, "DATE_LOCAL", ap_ht_time(r->pool, date, 
                           ctx->time_str, 0));
            apr_table_setn(env, "DATE_GMT", ap_ht_time(r->pool, date, 
                           ctx->time_str, 1));
            apr_table_setn(env, "LAST_MODIFIED",
                           ap_ht_time(r->pool, r->finfo.mtime, 
                           ctx->time_str, 0));
        }
        else if (!strcmp(tag, "sizefmt")) {
            parsed_string = ap_ssi_parse_string(r, ctx, tag_val, NULL, 
                                                MAX_STRING_LEN,
                                                SSI_EXPAND_DROP_NAME);
            if (!strcmp(parsed_string, "bytes")) {
                ctx->flags |= SSI_FLAG_SIZE_IN_BYTES;
            }
            else if (!strcmp(parsed_string, "abbrev")) {
                ctx->flags &= SSI_FLAG_SIZE_ABBREV;
            }
            else {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "unknown value "
                              "\"%s\" to parameter \"sizefmt\" of tag config "
                              "in %s", parsed_string, r->filename);
                SSI_CREATE_ERROR_BUCKET(ctx, f, bb);
                break;
            }
        }
        else {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "unknown parameter "
                          "\"%s\" to tag config in %s", tag, r->filename);
            SSI_CREATE_ERROR_BUCKET(ctx, f, bb);
            break;
        }
    }

    return APR_SUCCESS;
}

static apr_status_t handle_fsize(include_ctx_t *ctx, ap_filter_t *f,
                                 apr_bucket_brigade *bb)
{
    char *tag     = NULL;
    char *tag_val = NULL;
    apr_finfo_t  finfo;
    apr_size_t  s_len;
    apr_bucket   *tmp_buck;
    char *parsed_string;
    request_rec *r = f->r;

    if (ctx->flags & SSI_FLAG_PRINTING) {
        while (1) {
            ap_ssi_get_tag_and_value(ctx, &tag, &tag_val, SSI_VALUE_DECODED);
            if (!tag || !tag_val) {
                return APR_SUCCESS;
            }
            else {
                parsed_string = ap_ssi_parse_string(r, ctx, tag_val, NULL, 
                                                    MAX_STRING_LEN,
                                                    SSI_EXPAND_DROP_NAME);
                if (!find_file(r, "fsize", tag, parsed_string, &finfo)) {
                    /* XXX: if we *know* we're going to have to copy the
                     * thing off of the stack anyway, why not palloc buff
                     * instead of sticking it on the stack; then we can just
                     * use a pool bucket and skip the copy
                     */
                    char buff[50];

                    if (!(ctx->flags & SSI_FLAG_SIZE_IN_BYTES)) {
                        apr_strfsize(finfo.size, buff);
                        s_len = strlen (buff);
                    }
                    else {
                        int l, x, pos = 0;
                        char tmp_buff[50];

                        apr_snprintf(tmp_buff, sizeof(tmp_buff), 
                                     "%" APR_OFF_T_FMT, finfo.size);
                        l = strlen(tmp_buff);    /* grrr */
                        for (x = 0; x < l; x++) {
                            if (x && (!((l - x) % 3))) {
                                buff[pos++] = ',';
                            }
                            buff[pos++] = tmp_buff[x];
                        }
                        buff[pos] = '\0';
                        s_len = pos;
                    }

                    tmp_buck = apr_bucket_heap_create(buff, s_len, NULL,
                                                  r->connection->bucket_alloc);
                    APR_BRIGADE_INSERT_TAIL(bb, tmp_buck);
                }
                else {
                    SSI_CREATE_ERROR_BUCKET(ctx, f, bb);
                }
            }
        }
    }

    return APR_SUCCESS;
}

static apr_status_t handle_flastmod(include_ctx_t *ctx, ap_filter_t *f,
                                    apr_bucket_brigade *bb)
{
    char *tag     = NULL;
    char *tag_val = NULL;
    apr_finfo_t  finfo;
    apr_size_t  t_len;
    apr_bucket   *tmp_buck;
    char *parsed_string;
    request_rec *r = f->r;

    if (ctx->flags & SSI_FLAG_PRINTING) {
        while (1) {
            ap_ssi_get_tag_and_value(ctx, &tag, &tag_val, SSI_VALUE_DECODED);
            if (!tag || !tag_val) {
                return APR_SUCCESS;
            }
            else {
                parsed_string = ap_ssi_parse_string(r, ctx, tag_val, NULL, 
                                                    MAX_STRING_LEN,
                                                    SSI_EXPAND_DROP_NAME);
                if (!find_file(r, "flastmod", tag, parsed_string, &finfo)) {
                    char *t_val;

                    t_val = ap_ht_time(r->pool, finfo.mtime, ctx->time_str, 0);
                    t_len = strlen(t_val);

                    tmp_buck = apr_bucket_pool_create(t_val, t_len, r->pool,
                                                  r->connection->bucket_alloc);
                    APR_BRIGADE_INSERT_TAIL(bb, tmp_buck);
                }
                else {
                    SSI_CREATE_ERROR_BUCKET(ctx, f, bb);
                }
            }
        }
    }

    return APR_SUCCESS;
}

/* pjr - These seem to allow expr="fred" expr="joe" where joe overwrites fred. */
static apr_status_t handle_if(include_ctx_t *ctx, ap_filter_t *f,
                              apr_bucket_brigade *bb)
{
    char *tag     = NULL;
    char *tag_val = NULL;
    char *expr    = NULL;
    int   expr_ret, was_error, was_unmatched;
    char debug_buf[MAX_DEBUG_SIZE];
    request_rec *r = f->r;

    if (!(ctx->flags & SSI_FLAG_PRINTING)) {
        ctx->if_nesting_level++;
    }
    else {
        while (1) {
            ap_ssi_get_tag_and_value(ctx, &tag, &tag_val, SSI_VALUE_RAW);
            if (!tag) {
                if (!expr) {
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                                  "missing expr in if statement: %s", 
                                  r->filename);
                    SSI_CREATE_ERROR_BUCKET(ctx, f, bb);
                    return APR_SUCCESS;
                }
                expr_ret = parse_expr(r, ctx, expr, &was_error, 
                                      &was_unmatched, debug_buf);
                if (was_error) {
                    SSI_CREATE_ERROR_BUCKET(ctx, f, bb);
                    return APR_SUCCESS;
                }
                if (was_unmatched) {
                    DUMP_PARSE_EXPR_DEBUG("\nUnmatched '\n", f, bb);
                }
                DUMP_PARSE_EXPR_DEBUG(debug_buf, f, bb);

                if (expr_ret) {
                    ctx->flags |= (SSI_FLAG_PRINTING | SSI_FLAG_COND_TRUE);
                }
                else {
                    ctx->flags &= SSI_FLAG_CLEAR_PRINT_COND;
                }
                LOG_COND_STATUS(ctx, f, bb, "   if");
                ctx->if_nesting_level = 0;
                return APR_SUCCESS;
            }
            else if (!strcmp(tag, "expr")) {
                expr = tag_val;
#ifdef DEBUG_INCLUDE
                if (1) {
                    apr_bucket *tmp_buck;
                    apr_size_t d_len = 0;
                    d_len = sprintf(debug_buf, "**** if expr=\"%s\"\n", expr);
                    tmp_buck = apr_bucket_heap_create(debug_buf, d_len, NULL,
                                                  r->connection->bucket_alloc);
                    APR_BRIGADE_INSERT_TAIL(bb, tmp_buck);
                }
#endif
            }
            else {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                            "unknown parameter \"%s\" to tag if in %s", tag, 
                            r->filename);
                SSI_CREATE_ERROR_BUCKET(ctx, f, bb);
            }

        }
    }

    return APR_SUCCESS;
}

static apr_status_t handle_elif(include_ctx_t *ctx, ap_filter_t *f,
                                apr_bucket_brigade *bb)
{
    char *tag     = NULL;
    char *tag_val = NULL;
    char *expr    = NULL;
    int   expr_ret, was_error, was_unmatched;
    char debug_buf[MAX_DEBUG_SIZE];
    request_rec *r = f->r;

    if (!ctx->if_nesting_level) {
        while (1) {
            ap_ssi_get_tag_and_value(ctx, &tag, &tag_val, SSI_VALUE_RAW);
            if (!tag) {
                LOG_COND_STATUS(ctx, f, bb, " elif");
                
                if (ctx->flags & SSI_FLAG_COND_TRUE) {
                    ctx->flags &= SSI_FLAG_CLEAR_PRINTING;
                    return APR_SUCCESS;
                }
                if (!expr) {
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                                  "missing expr in elif statement: %s", 
                                  r->filename);
                    SSI_CREATE_ERROR_BUCKET(ctx, f, bb);
                    return APR_SUCCESS;
                }
                expr_ret = parse_expr(r, ctx, expr, &was_error, 
                                      &was_unmatched, debug_buf);
                if (was_error) {
                    SSI_CREATE_ERROR_BUCKET(ctx, f, bb);
                    return APR_SUCCESS;
                }
                if (was_unmatched) {
                    DUMP_PARSE_EXPR_DEBUG("\nUnmatched '\n", f, bb);
                }
                DUMP_PARSE_EXPR_DEBUG(debug_buf, f, bb);
                
                if (expr_ret) {
                    ctx->flags |= (SSI_FLAG_PRINTING | SSI_FLAG_COND_TRUE);
                }
                else {
                    ctx->flags &= SSI_FLAG_CLEAR_PRINT_COND;
                }
                LOG_COND_STATUS(ctx, f, bb, " elif");
                return APR_SUCCESS;
            }
            else if (!strcmp(tag, "expr")) {
                expr = tag_val;
#ifdef DEBUG_INCLUDE
                if (1) {
                    apr_bucket *tmp_buck;
                    apr_size_t d_len = 0;
                    d_len = sprintf(debug_buf, "**** elif expr=\"%s\"\n", expr);
                    tmp_buck = apr_bucket_heap_create(debug_buf, d_len, NULL,
                                                  r->connection->bucket_alloc);
                    APR_BRIGADE_INSERT_TAIL(bb, tmp_buck);
                }
#endif
            }
            else {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                               "unknown parameter \"%s\" to tag if in %s", tag, 
                               r->filename);
                SSI_CREATE_ERROR_BUCKET(ctx, f, bb);
            }
        }
    }

    return APR_SUCCESS;
}

static apr_status_t handle_else(include_ctx_t *ctx, ap_filter_t *f,
                                apr_bucket_brigade *bb)
{
    char *tag = NULL;
    char *tag_val = NULL;
    request_rec *r = f->r;

    if (!ctx->if_nesting_level) {
        ap_ssi_get_tag_and_value(ctx, &tag, &tag_val, SSI_VALUE_RAW);
        if (tag || tag_val) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                        "else directive does not take tags in %s", r->filename);
            if (ctx->flags & SSI_FLAG_PRINTING) {
                SSI_CREATE_ERROR_BUCKET(ctx, f, bb);
            }
            return APR_SUCCESS;
        }
        else {
            LOG_COND_STATUS(ctx, f, bb, " else");
            
            if (ctx->flags & SSI_FLAG_COND_TRUE) {
                ctx->flags &= SSI_FLAG_CLEAR_PRINTING;
            }
            else {
                ctx->flags |= (SSI_FLAG_PRINTING | SSI_FLAG_COND_TRUE);
            }
            return APR_SUCCESS;
        }
    }

    return APR_SUCCESS;
}

static apr_status_t handle_endif(include_ctx_t *ctx, ap_filter_t *f,
                                 apr_bucket_brigade *bb)
{
    char *tag     = NULL;
    char *tag_val = NULL;
    request_rec *r = f->r;

    if (!ctx->if_nesting_level) {
        ap_ssi_get_tag_and_value(ctx, &tag, &tag_val, SSI_VALUE_RAW);
        if (tag || tag_val) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                       "endif directive does not take tags in %s", r->filename);
            SSI_CREATE_ERROR_BUCKET(ctx, f, bb);
            return APR_SUCCESS;
        }
        else {
            LOG_COND_STATUS(ctx, f, bb, "endif");
            ctx->flags |= (SSI_FLAG_PRINTING | SSI_FLAG_COND_TRUE);
            return APR_SUCCESS;
        }
    }
    else {
        ctx->if_nesting_level--;
        return APR_SUCCESS;
    }
}

static apr_status_t handle_set(include_ctx_t *ctx, ap_filter_t *f,
                               apr_bucket_brigade *bb)
{
    char *tag     = NULL;
    char *tag_val = NULL;
    char *var     = NULL;
    char *parsed_string;
    request_rec *r = f->r;
    request_rec *sub = r->main;
    apr_pool_t *p = r->pool;

    /* we need to use the 'main' request pool to set notes as that is 
     * a notes lifetime
     */
    while (sub) {
        p = sub->pool;
        sub = sub->main;
    }

    if (ctx->flags & SSI_FLAG_PRINTING) {
        while (1) {
            ap_ssi_get_tag_and_value(ctx, &tag, &tag_val, SSI_VALUE_DECODED);
            if (!tag && !tag_val) {
                return APR_SUCCESS;
            }
            else if (!tag_val) {
                return APR_SUCCESS;
            }
            else if (!strcmp(tag, "var")) {
                var = ap_ssi_parse_string(r, ctx, tag_val, NULL,
                                          MAX_STRING_LEN, SSI_EXPAND_DROP_NAME);
            }
            else if (!strcmp(tag, "value")) {
                if (var == (char *) NULL) {
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                           "variable must precede value in set directive in %s",
                           r->filename);
                    SSI_CREATE_ERROR_BUCKET(ctx, f, bb);
                    return APR_SUCCESS;
                }
                parsed_string = ap_ssi_parse_string(r, ctx, tag_val, NULL, 
                                                    MAX_STRING_LEN,
                                                    SSI_EXPAND_DROP_NAME);
                apr_table_setn(r->subprocess_env, apr_pstrdup(p, var),
                               apr_pstrdup(p, parsed_string));
            }
            else {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                            "Invalid tag for set directive in %s", r->filename);
                SSI_CREATE_ERROR_BUCKET(ctx, f, bb);
                return APR_SUCCESS;
            }
        }
    }

    return APR_SUCCESS;
}

static apr_status_t handle_printenv(include_ctx_t *ctx, ap_filter_t *f,
                                    apr_bucket_brigade *bb)
{
    char *tag     = NULL;
    char *tag_val = NULL;
    apr_bucket *tmp_buck;
    request_rec *r = f->r;

    if (ctx->flags & SSI_FLAG_PRINTING) {
        ap_ssi_get_tag_and_value(ctx, &tag, &tag_val, SSI_VALUE_DECODED);
        if (!tag && !tag_val) {
            const apr_array_header_t *arr = apr_table_elts(r->subprocess_env);
            const apr_table_entry_t *elts = (const apr_table_entry_t *)arr->elts;
            int i;
            const char *key_text, *val_text;
            char *key_val, *next;
            apr_size_t   k_len, v_len, kv_length;

            for (i = 0; i < arr->nelts; ++i) {
                key_text = ap_escape_html(r->pool, elts[i].key);
                val_text = elts[i].val;
                if (val_text == LAZY_VALUE) {
                    val_text = add_include_vars_lazy(r, elts[i].key);
                }
                val_text = ap_escape_html(r->pool, elts[i].val);
                k_len = strlen(key_text);
                v_len = strlen(val_text);
                kv_length = k_len + v_len + sizeof("=\n");
                key_val = apr_palloc(r->pool, kv_length);
                next = key_val;
                memcpy(next, key_text, k_len);
                next += k_len;
                *next++ = '=';
                memcpy(next, val_text, v_len);
                next += v_len;
                *next++ = '\n';
                *next = 0;
                tmp_buck = apr_bucket_pool_create(key_val, kv_length - 1,
                                                  r->pool,
                                                  r->connection->bucket_alloc);
                APR_BRIGADE_INSERT_TAIL(bb, tmp_buck);
            }
            return APR_SUCCESS;
        }
        else {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                        "printenv directive does not take tags in %s", 
                        r->filename);
            SSI_CREATE_ERROR_BUCKET(ctx, f, bb);
            return APR_SUCCESS;
        }
    }

    return APR_SUCCESS;
}


/*
 * +-------------------------------------------------------+
 * |                                                       |
 * |               Main Includes-Filter Engine
 * |                                                       |
 * +-------------------------------------------------------+
 */

/* This is an implementation of the BNDM search algorithm.
 *
 * Fast and Flexible String Matching by Combining Bit-parallelism and 
 * Suffix Automata (2001) 
 * Gonzalo Navarro, Mathieu Raffinot
 *
 * http://www-igm.univ-mlv.fr/~raffinot/ftp/jea2001.ps.gz
 *
 * Initial code submitted by Sascha Schumann.
 */
   
/* Precompile the bndm_t data structure. */
static bndm_t *bndm_compile(apr_pool_t *pool, const char *n, apr_size_t nl)
{
    unsigned int x;
    const char *ne = n + nl;
    bndm_t *t = apr_palloc(pool, sizeof(*t));

    memset(t->T, 0, sizeof(unsigned int) * 256);
    t->pattern_len = nl;

    for (x = 1; n < ne; x <<= 1) {
        t->T[(unsigned char) *n++] |= x;
    }

    t->x = x - 1;

    return t;
}

/* Implements the BNDM search algorithm (as described above).
 *
 * h  - the string to look in
 * hl - length of the string to look for
 * t  - precompiled bndm structure against the pattern 
 *
 * Returns the count of character that is the first match or hl if no
 * match is found.
 */
static apr_size_t bndm(bndm_t *t, const char *h, apr_size_t hl)
{
    const char *skip;
    const char *he, *p, *pi;
    unsigned int *T, x, d;
    apr_size_t nl;

    he = h + hl;

    T = t->T;
    x = t->x;
    nl = t->pattern_len;

    pi = h - 1; /* pi: p initial */
    p = pi + nl; /* compare window right to left. point to the first char */

    while (p < he) {
        skip = p;
        d = x;
        do {
            d &= T[(unsigned char) *p--];
            if (!d) {
                break;
            }
            if ((d & 1)) {
                if (p != pi) {
                    skip = p;
                }
                else {
                    return p - h + 1;
                }
            }
            d >>= 1;
        } while (d);

        pi = skip;
        p = pi + nl;
    }

    return hl;
}

/*
 * returns the index position of the first byte of start_seq (or the len of
 * the buffer as non-match)
 */
static apr_size_t find_start_sequence(include_ctx_t *ctx, const char *data,
                                      apr_size_t len)
{
    struct ssi_internal_ctx *intern = ctx->intern;
    apr_size_t slen = intern->start_seq_pat->pattern_len;
    apr_size_t index;
    const char *p, *ep;

    if (len < slen) {
        p = data; /* try partial match at the end of the buffer (below) */
    }
    else {
        /* try fast bndm search over the buffer
         * (hopefully the whole start sequence can be found in this buffer)
         */
        index = bndm(intern->start_seq_pat, data, len);

        /* wow, found it. ready. */
        if (index < len) {
            intern->state = PARSE_DIRECTIVE;
            return index;
        }
        else {
            /* ok, the pattern can't be found as whole in the buffer,
             * check the end for a partial match
             */
            p = data + len - slen + 1;
        }
    }

    ep = data + len;
    do {
        while (p < ep && *p != *intern->start_seq) {
            ++p;
        }

        index = p - data;

        /* found a possible start_seq start */
        if (p < ep) {
            apr_size_t pos = 1;

            ++p;
            while (p < ep && *p == intern->start_seq[pos]) {
                ++p;
                ++pos;
            }

            /* partial match found. Store the info for the next round */
            if (p == ep) {
                intern->state = PARSE_HEAD;
                intern->parse_pos = pos;
                return index;
            }
        }

        /* we must try all combinations; consider (e.g.) SSIStartTag "--->"
         * and a string data of "--.-" and the end of the buffer
         */
        p = data + index + 1;
    } while (p < ep);

    /* no match */
    return len;
}

/*
 * returns the first byte *after* the partial (or final) match.
 *
 * If we had to trick with the start_seq start, 'release' returns the
 * number of chars of the start_seq which appeared not to be part of a
 * full tag and may have to be passed down the filter chain.
 */
static apr_size_t find_partial_start_sequence(include_ctx_t *ctx,
                                              const char *data,
                                              apr_size_t len,
                                              apr_size_t *release)
{
    struct ssi_internal_ctx *intern = ctx->intern;
    apr_size_t pos, spos = 0;
    apr_size_t slen = intern->start_seq_pat->pattern_len;
    const char *p, *ep;

    pos = intern->parse_pos;
    ep = data + len;
    *release = 0;

    do {
        p = data;

        while (p < ep && pos < slen && *p == intern->start_seq[pos]) {
            ++p;
            ++pos;
        }

        /* full match */
        if (pos == slen) {
            intern->state = PARSE_DIRECTIVE;
            return (p - data);
        }

        /* the whole buffer is a partial match */
        if (p == ep) {
            intern->parse_pos = pos;
            return (p - data);
        }

        /* No match so far, but again:
         * We must try all combinations, since the start_seq is a random
         * user supplied string
         *
         * So: look if the first char of start_seq appears somewhere within
         * the current partial match. If it does, try to start a match that
         * begins with this offset. (This can happen, if a strange
         * start_seq like "---->" spans buffers)
         */
        if (spos < intern->parse_pos) {
            do {
                ++spos;
                ++*release;
                p = intern->start_seq + spos;
                pos = intern->parse_pos - spos;

                while (pos && *p != *intern->start_seq) {
                    ++p;
                    ++spos;
                    ++*release;
                    --pos;
                }

                /* if a matching beginning char was found, try to match the
                 * remainder of the old buffer.
                 */
                if (pos > 1) {
                    apr_size_t t = 1;

                    ++p;
                    while (t < pos && *p == intern->start_seq[t]) {
                        ++p;
                        ++t;
                    }

                    if (t == pos) {
                        /* yeah, another partial match found in the *old*
                         * buffer, now test the *current* buffer for
                         * continuing match
                         */
                        break;
                    }
                }
            } while (pos > 1);

            if (pos) {
                continue;
            }
        }

        break;
    } while (1); /* work hard to find a match ;-) */

    /* no match at all, release all (wrongly) matched chars so far */
    *release = intern->parse_pos;
    intern->state = PARSE_PRE_HEAD;
    return 0;
}

/*
 * returns the position after the directive
 */
static apr_size_t find_directive(include_ctx_t *ctx, const char *data,
                                 apr_size_t len, char ***store,
                                 apr_size_t **store_len)
{
    struct ssi_internal_ctx *intern = ctx->intern;
    const char *p = data;
    const char *ep = data + len;
    apr_size_t pos;

    switch (intern->state) {
    case PARSE_DIRECTIVE:
        while (p < ep && !apr_isspace(*p)) {
            /* we have to consider the case of missing space between directive
             * and end_seq (be somewhat lenient), e.g. <!--#printenv-->
             */
            if (*p == *intern->end_seq) {
                intern->state = PARSE_DIRECTIVE_TAIL;
                intern->parse_pos = 1;
                ++p;
                return (p - data);
            }
            ++p;
        }

        if (p < ep) { /* found delimiter whitespace */
            intern->state = PARSE_DIRECTIVE_POSTNAME;
            *store = &intern->directive;
            *store_len = &intern->directive_len;
        }

        break;

    case PARSE_DIRECTIVE_TAIL:
        pos = intern->parse_pos;

        while (p < ep && pos < intern->end_seq_len &&
               *p == intern->end_seq[pos]) {
            ++p;
            ++pos;
        }

        /* full match, we're done */
        if (pos == intern->end_seq_len) {
            intern->state = PARSE_DIRECTIVE_POSTTAIL;
            *store = &intern->directive;
            *store_len = &intern->directive_len;
            break;
        }

        /* partial match, the buffer is too small to match fully */
        if (p == ep) {
            intern->parse_pos = pos;
            break;
        }

        /* no match. continue normal parsing */
        intern->state = PARSE_DIRECTIVE;
        return 0;

    case PARSE_DIRECTIVE_POSTTAIL:
        intern->state = PARSE_EXECUTE;
        intern->directive_len -= intern->end_seq_len;
        /* continue immediately with the next state */

    case PARSE_DIRECTIVE_POSTNAME:
        if (PARSE_DIRECTIVE_POSTNAME == intern->state) {
            intern->state = PARSE_PRE_ARG;
        }
        ctx->argc = 0;
        intern->argv = NULL;

        if (!intern->directive_len) {
            intern->error = 1;
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, intern->r, "missing "
                          "directive name in parsed document %s",
                          intern->r->filename);
        }
        else {
            char *sp = intern->directive;
            char *sep = intern->directive + intern->directive_len;

            /* normalize directive name */
            for (; sp < sep; ++sp) {
                *sp = apr_tolower(*sp);
            }
        }

        return 0;

    default:
        /* get a rid of a gcc warning about unhandled enumerations */
        break;
    }

    return (p - data);
}

/*
 * find out whether the next token is (a possible) end_seq or an argument
 */
static apr_size_t find_arg_or_tail(include_ctx_t *ctx, const char *data,
                                   apr_size_t len)
{
    struct ssi_internal_ctx *intern = ctx->intern;
    const char *p = data;
    const char *ep = data + len;

    /* skip leading WS */
    while (p < ep && apr_isspace(*p)) {
        ++p;
    }

    /* buffer doesn't consist of whitespaces only */
    if (p < ep) {
        intern->state = (*p == *intern->end_seq) ? PARSE_TAIL : PARSE_ARG;
    }

    return (p - data);
}

/*
 * test the stream for end_seq. If it doesn't match at all, it must be an
 * argument
 */
static apr_size_t find_tail(include_ctx_t *ctx, const char *data,
                            apr_size_t len)
{
    struct ssi_internal_ctx *intern = ctx->intern;
    const char *p = data;
    const char *ep = data + len;
    apr_size_t pos = intern->parse_pos;

    if (PARSE_TAIL == intern->state) {
        intern->state = PARSE_TAIL_SEQ;
        pos = intern->parse_pos = 0;
    }

    while (p < ep && pos < intern->end_seq_len && *p == intern->end_seq[pos]) {
        ++p;
        ++pos;
    }

    /* bingo, full match */
    if (pos == intern->end_seq_len) {
        intern->state = PARSE_EXECUTE;
        return (p - data);
    }

    /* partial match, the buffer is too small to match fully */
    if (p == ep) {
        intern->parse_pos = pos;
        return (p - data);
    }

    /* no match. It must be an argument string then
     * The caller should cleanup and rewind to the reparse point
     */
    intern->state = PARSE_ARG;
    return 0;
}

/*
 * extract name=value from the buffer
 * A pcre-pattern could look (similar to):
 * name\s*(?:=\s*(["'`]?)value\1(?>\s*))?
 */
static apr_size_t find_argument(include_ctx_t *ctx, const char *data,
                                apr_size_t len, char ***store,
                                apr_size_t **store_len)
{
    struct ssi_internal_ctx *intern = ctx->intern;
    const char *p = data;
    const char *ep = data + len;

    switch (intern->state) {
    case PARSE_ARG:
        /*
         * create argument structure and append it to the current list
         */
        intern->current_arg = apr_palloc(ctx->dpool,
                                         sizeof(*intern->current_arg));
        intern->current_arg->next = NULL;

        ++(ctx->argc);
        if (!intern->argv) {
            intern->argv = intern->current_arg;
        }
        else {
            arg_item_t *newarg = intern->argv;

            while (newarg->next) {
                newarg = newarg->next;
            }
            newarg->next = intern->current_arg;
        }

        /* check whether it's a valid one. If it begins with a quote, we
         * can safely assume, someone forgot the name of the argument
         */
        switch (*p) {
        case '"': case '\'': case '`':
            *store = NULL;

            intern->state = PARSE_ARG_VAL;
            intern->quote = *p++;
            intern->current_arg->name = NULL;
            intern->current_arg->name_len = 0;
            intern->error = 1;

            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, intern->r, "missing "
                          "argument name for value to tag %s in %s",
                          apr_pstrmemdup(intern->r->pool, intern->directive,
                                         intern->directive_len),
                                         intern->r->filename);

            return (p - data);

        default:
            intern->state = PARSE_ARG_NAME;
        }
        /* continue immediately with next state */

    case PARSE_ARG_NAME:
        while (p < ep && !apr_isspace(*p) && *p != '=') {
            ++p;
        }

        if (p < ep) {
            intern->state = PARSE_ARG_POSTNAME;
            *store = &intern->current_arg->name;
            *store_len = &intern->current_arg->name_len;
            return (p - data);
        }
        break;

    case PARSE_ARG_POSTNAME:
        intern->current_arg->name = apr_pstrmemdup(ctx->dpool,
                                                 intern->current_arg->name,
                                                 intern->current_arg->name_len);
        if (!intern->current_arg->name_len) {
            intern->error = 1;
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, intern->r, "missing "
                          "argument name for value to tag %s in %s",
                          apr_pstrmemdup(intern->r->pool, intern->directive,
                                         intern->directive_len),
                                         intern->r->filename);
        }
        else {
            char *sp = intern->current_arg->name;

            /* normalize the name */
            while (*sp) {
                *sp = apr_tolower(*sp);
                ++sp;
            }
        }

        intern->state = PARSE_ARG_EQ;
        /* continue with next state immediately */

    case PARSE_ARG_EQ:
        *store = NULL;

        while (p < ep && apr_isspace(*p)) {
            ++p;
        }

        if (p < ep) {
            if (*p == '=') {
                intern->state = PARSE_ARG_PREVAL;
                ++p;
            }
            else { /* no value */
                intern->current_arg->value = NULL;
                intern->state = PARSE_PRE_ARG;
            }

            return (p - data);
        }
        break;

    case PARSE_ARG_PREVAL:
        *store = NULL;

        while (p < ep && apr_isspace(*p)) {
            ++p;
        }

        /* buffer doesn't consist of whitespaces only */
        if (p < ep) {
            intern->state = PARSE_ARG_VAL;
            switch (*p) {
            case '"': case '\'': case '`':
                intern->quote = *p++;
                break;
            default:
                intern->quote = '\0';
                break;
            }

            return (p - data);
        }
        break;

    case PARSE_ARG_VAL_ESC:
        if (*p == intern->quote) {
            ++p;
        }
        intern->state = PARSE_ARG_VAL;
        /* continue with next state immediately */

    case PARSE_ARG_VAL:
        for (; p < ep; ++p) {
            if (intern->quote && *p == '\\') {
                ++p;
                if (p == ep) {
                    intern->state = PARSE_ARG_VAL_ESC;
                    break;
                }

                if (*p != intern->quote) {
                    --p;
                }
            }
            else if (intern->quote && *p == intern->quote) {
                ++p;
                *store = &intern->current_arg->value;
                *store_len = &intern->current_arg->value_len;
                intern->state = PARSE_ARG_POSTVAL;
                break;
            }
            else if (!intern->quote && apr_isspace(*p)) {
                ++p;
                *store = &intern->current_arg->value;
                *store_len = &intern->current_arg->value_len;
                intern->state = PARSE_ARG_POSTVAL;
                break;
            }
        }

        return (p - data);

    case PARSE_ARG_POSTVAL:
        /*
         * The value is still the raw input string. Finally clean it up.
         */
        --(intern->current_arg->value_len);
        intern->current_arg->value[intern->current_arg->value_len] = '\0';

        /* strip quote escaping \ from the string */
        if (intern->quote) {
            apr_size_t shift = 0;
            char *sp;

            sp = intern->current_arg->value;
            ep = intern->current_arg->value + intern->current_arg->value_len;
            while (sp < ep && *sp != '\\') {
                ++sp;
            }
            for (; sp < ep; ++sp) {
                if (*sp == '\\' && sp[1] == intern->quote) {
                    ++sp;
                    ++shift;
                }
                if (shift) {
                    *(sp-shift) = *sp;
                }
            }

            intern->current_arg->value_len -= shift;
        }

        intern->current_arg->value[intern->current_arg->value_len] = '\0';
        intern->state = PARSE_PRE_ARG;

        return 0;

    default:
        /* get a rid of a gcc warning about unhandled enumerations */
        break;
    }

    return len; /* partial match of something */
}

/*
 * This is the main loop over the current bucket brigade.
 */
static apr_status_t send_parsed_content(ap_filter_t *f, apr_bucket_brigade *bb)
{
    include_ctx_t *ctx = f->ctx;
    struct ssi_internal_ctx *intern = ctx->intern;
    request_rec *r = f->r;
    apr_bucket *b = APR_BRIGADE_FIRST(bb);
    apr_bucket_brigade *pass_bb;
    apr_status_t rv = APR_SUCCESS;
    char *magic; /* magic pointer for sentinel use */

    /* fast exit */
    if (APR_BRIGADE_EMPTY(bb)) {
        return APR_SUCCESS;
    }

    /* we may crash, since already cleaned up; hand over the responsibility
     * to the next filter;-)
     */
    if (intern->seen_eos) {
        return ap_pass_brigade(f->next, bb);
    }

    /* All stuff passed along has to be put into that brigade */
    pass_bb = apr_brigade_create(ctx->pool, f->c->bucket_alloc);

    /* initialization for this loop */
    intern->bytes_read = 0;
    intern->error = 0;
    intern->r = r;
    ctx->flush_now = 0;

    /* loop over the current bucket brigade */
    while (b != APR_BRIGADE_SENTINEL(bb)) {
        const char *data = NULL;
        apr_size_t len, index, release;
        apr_bucket *newb = NULL;
        char **store = &magic;
        apr_size_t *store_len;

        /* handle meta buckets before reading any data */
        if (APR_BUCKET_IS_METADATA(b)) {
            newb = APR_BUCKET_NEXT(b);

            APR_BUCKET_REMOVE(b);

            if (APR_BUCKET_IS_EOS(b)) {
                intern->seen_eos = 1;

                /* Hit end of stream, time for cleanup ... But wait!
                 * Perhaps we're not ready yet. We may have to loop one or
                 * two times again to finish our work. In that case, we
                 * just re-insert the EOS bucket to allow for an extra loop.
                 *
                 * PARSE_EXECUTE means, we've hit a directive just before the
                 *    EOS, which is now waiting for execution.
                 *
                 * PARSE_DIRECTIVE_POSTTAIL means, we've hit a directive with
                 *    no argument and no space between directive and end_seq
                 *    just before the EOS. (consider <!--#printenv--> as last
                 *    or only string within the stream). This state, however,
                 *    just cleans up and turns itself to PARSE_EXECUTE, which
                 *    will be passed through within the next (and actually
                 *    last) round.
                 */
                if (PARSE_EXECUTE            == intern->state ||
                    PARSE_DIRECTIVE_POSTTAIL == intern->state) {
                    APR_BUCKET_INSERT_BEFORE(newb, b);
                }
                else {
                    break; /* END OF STREAM */
                }
            }
            else {
                APR_BRIGADE_INSERT_TAIL(pass_bb, b);

                if (APR_BUCKET_IS_FLUSH(b)) {
                    ctx->flush_now = 1;
                }

                b = newb;
                continue;
            }
        }

        /* enough is enough ... */
        if (ctx->flush_now ||
            intern->bytes_read > AP_MIN_BYTES_TO_WRITE) {

            if (!APR_BRIGADE_EMPTY(pass_bb)) {
                rv = ap_pass_brigade(f->next, pass_bb);
                if (!APR_STATUS_IS_SUCCESS(rv)) {
                    apr_brigade_destroy(pass_bb);
                    return rv;
                }
            }

            ctx->flush_now = 0;
            intern->bytes_read = 0;
        }

        /* read the current bucket data */
        len = 0;
        if (!intern->seen_eos) {
            if (intern->bytes_read > 0) {
                rv = apr_bucket_read(b, &data, &len, APR_NONBLOCK_READ);
                if (APR_STATUS_IS_EAGAIN(rv)) {
                    ctx->flush_now = 1;
                    continue;
                }
            }

            if (!len || !APR_STATUS_IS_SUCCESS(rv)) {
                rv = apr_bucket_read(b, &data, &len, APR_BLOCK_READ);
            }

            if (!APR_STATUS_IS_SUCCESS(rv)) {
                apr_brigade_destroy(pass_bb);
                return rv;
            }

            intern->bytes_read += len;
        }

        /* zero length bucket, fetch next one */
        if (!len && !intern->seen_eos) {
            b = APR_BUCKET_NEXT(b);
            continue;
        }

        /*
         * it's actually a data containing bucket, start/continue parsing
         */

        switch (intern->state) {
        /* no current tag; search for start sequence */
        case PARSE_PRE_HEAD:
            index = find_start_sequence(ctx, data, len);

            if (index < len) {
                apr_bucket_split(b, index);
            }

            newb = APR_BUCKET_NEXT(b);
            if (ctx->flags & SSI_FLAG_PRINTING) {
                APR_BUCKET_REMOVE(b);
                APR_BRIGADE_INSERT_TAIL(pass_bb, b);
            }
            else {
                apr_bucket_delete(b);
            }

            if (index < len) {
                /* now delete the start_seq stuff from the remaining bucket */
                if (PARSE_DIRECTIVE == intern->state) { /* full match */
                    apr_bucket_split(newb, intern->start_seq_pat->pattern_len);
                    ctx->flush_now = 1; /* pass pre-tag stuff */
                }

                b = APR_BUCKET_NEXT(newb);
                apr_bucket_delete(newb);
            }
            else {
                b = newb;
            }

            break;

        /* we're currently looking for the end of the start sequence */
        case PARSE_HEAD:
            index = find_partial_start_sequence(ctx, data, len, &release);

            /* check if we mismatched earlier and have to release some chars */
            if (release && (ctx->flags & SSI_FLAG_PRINTING)) {
                char *to_release = apr_palloc(ctx->pool, release);

                memcpy(to_release, intern->start_seq, release);
                newb = apr_bucket_pool_create(to_release, release, ctx->pool,
                                              f->c->bucket_alloc);
                APR_BRIGADE_INSERT_TAIL(pass_bb, newb);
            }

            if (index) { /* any match */
                /* now delete the start_seq stuff from the remaining bucket */
                if (PARSE_DIRECTIVE == intern->state) { /* final match */
                    apr_bucket_split(b, index);
                    ctx->flush_now = 1; /* pass pre-tag stuff */
                }
                newb = APR_BUCKET_NEXT(b);
                apr_bucket_delete(b);
                b = newb;
            }

            break;

        /* we're currently grabbing the directive name */
        case PARSE_DIRECTIVE:
        case PARSE_DIRECTIVE_POSTNAME:
        case PARSE_DIRECTIVE_TAIL:
        case PARSE_DIRECTIVE_POSTTAIL:
            index = find_directive(ctx, data, len, &store, &store_len);

            if (index) {
                apr_bucket_split(b, index);
                newb = APR_BUCKET_NEXT(b);
            }

            if (store) {
                if (index) {
                    APR_BUCKET_REMOVE(b);
                    APR_BRIGADE_INSERT_TAIL(intern->tmp_bb, b);
                    b = newb;
                }

                /* time for cleanup? */
                if (store != &magic) {
                    apr_brigade_pflatten(intern->tmp_bb, store, store_len,
                                         ctx->dpool);
                    apr_brigade_cleanup(intern->tmp_bb);
                }
            }
            else if (index) {
                apr_bucket_delete(b);
                b = newb;
            }

            break;

        /* skip WS and find out what comes next (arg or end_seq) */
        case PARSE_PRE_ARG:
            index = find_arg_or_tail(ctx, data, len);

            if (index) { /* skipped whitespaces */
                if (index < len) {
                    apr_bucket_split(b, index);
                }
                newb = APR_BUCKET_NEXT(b);
                apr_bucket_delete(b);
                b = newb;
            }

            break;

        /* currently parsing name[=val] */
        case PARSE_ARG:
        case PARSE_ARG_NAME:
        case PARSE_ARG_POSTNAME:
        case PARSE_ARG_EQ:
        case PARSE_ARG_PREVAL:
        case PARSE_ARG_VAL:
        case PARSE_ARG_VAL_ESC:
        case PARSE_ARG_POSTVAL:
            index = find_argument(ctx, data, len, &store, &store_len);

            if (index) {
                apr_bucket_split(b, index);
                newb = APR_BUCKET_NEXT(b);
            }

            if (store) {
                if (index) {
                    APR_BUCKET_REMOVE(b);
                    APR_BRIGADE_INSERT_TAIL(intern->tmp_bb, b);
                    b = newb;
                }

                /* time for cleanup? */
                if (store != &magic) {
                    apr_brigade_pflatten(intern->tmp_bb, store, store_len,
                                         ctx->dpool);
                    apr_brigade_cleanup(intern->tmp_bb);
                }
            }
            else if (index) {
                apr_bucket_delete(b);
                b = newb;
            }

            break;

        /* try to match end_seq at current pos. */
        case PARSE_TAIL:
        case PARSE_TAIL_SEQ:
            index = find_tail(ctx, data, len);

            switch (intern->state) {
            case PARSE_EXECUTE:  /* full match */
                apr_bucket_split(b, index);
                newb = APR_BUCKET_NEXT(b);
                apr_bucket_delete(b);
                b = newb;
                break;

            case PARSE_ARG:      /* no match */
                /* PARSE_ARG must reparse at the beginning */
                APR_BRIGADE_PREPEND(bb, intern->tmp_bb);
                b = APR_BRIGADE_FIRST(bb);
                break;

            default:             /* partial match */
                newb = APR_BUCKET_NEXT(b);
                APR_BUCKET_REMOVE(b);
                APR_BRIGADE_INSERT_TAIL(intern->tmp_bb, b);
                b = newb;
                break;
            }

            break;

        /* now execute the parsed directive, cleanup the space and
         * start again with PARSE_PRE_HEAD
         */
        case PARSE_EXECUTE:
            /* if there was an error, it was already logged; just stop here */
            if (intern->error) {
                if (ctx->flags & SSI_FLAG_PRINTING) {
                    SSI_CREATE_ERROR_BUCKET(ctx, f, pass_bb);
                    intern->error = 0;
                }
            }
            else {
                include_handler_fn_t *handle_func;

                handle_func = apr_hash_get(include_handlers, intern->directive,
                                           intern->directive_len);

                if (handle_func) {
                    rv = handle_func(ctx, f, pass_bb);
                    if (!APR_STATUS_IS_SUCCESS(rv)) {
                        apr_brigade_destroy(pass_bb);
                        return rv;
                    }
                }
                else {
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                                  "unknown directive \"%s\" in parsed doc %s",
                                  apr_pstrmemdup(r->pool, intern->directive,
                                                 intern->directive_len),
                                                 r->filename);
                    if (ctx->flags & SSI_FLAG_PRINTING) {
                        SSI_CREATE_ERROR_BUCKET(ctx, f, pass_bb);
                    }
                }
            }

            /* cleanup */
            apr_pool_clear(ctx->dpool);
            apr_brigade_cleanup(intern->tmp_bb);

            /* Oooof. Done here, start next round */
            intern->state = PARSE_PRE_HEAD;
            break;

        } /* switch(ctx->state) */

    } /* while(brigade) */

    /* End of stream. Final cleanup */
    if (intern->seen_eos) {
        if (PARSE_HEAD == intern->state) {
            if (ctx->flags & SSI_FLAG_PRINTING) {
                char *to_release = apr_palloc(ctx->pool, intern->parse_pos);

                memcpy(to_release, intern->start_seq, intern->parse_pos);
                APR_BRIGADE_INSERT_TAIL(pass_bb,
                                        apr_bucket_pool_create(to_release,
                                        intern->parse_pos, ctx->pool,
                                        f->c->bucket_alloc));
            }
        }
        else if (PARSE_PRE_HEAD != intern->state) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "SSI directive was not properly finished at the end "
                          "of parsed document %s", r->filename);
            if (ctx->flags & SSI_FLAG_PRINTING) {
                SSI_CREATE_ERROR_BUCKET(ctx, f, pass_bb);
            }
        }

        if (!(ctx->flags & SSI_FLAG_PRINTING)) {
            ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
                          "missing closing endif directive in parsed document"
                          " %s", r->filename);
        }

        /* cleanup our temporary memory */
        apr_brigade_destroy(intern->tmp_bb);
        apr_pool_destroy(ctx->dpool);

        /* don't forget to finally insert the EOS bucket */
        APR_BRIGADE_INSERT_TAIL(pass_bb, b);
    }

    /* if something's left over, pass it along */
    if (!APR_BRIGADE_EMPTY(pass_bb)) {
        rv = ap_pass_brigade(f->next, pass_bb);
    }
    else {
        rv = APR_SUCCESS;
    }

    apr_brigade_destroy(pass_bb);
    return rv;
}


/*
 * +-------------------------------------------------------+
 * |                                                       |
 * |                     Runtime Hooks
 * |                                                       |
 * +-------------------------------------------------------+
 */

static int includes_setup(ap_filter_t *f)
{
    include_dir_config *conf = ap_get_module_config(f->r->per_dir_config,
                                                    &include_module);

    /* When our xbithack value isn't set to full or our platform isn't
     * providing group-level protection bits or our group-level bits do not
     * have group-execite on, we will set the no_local_copy value to 1 so
     * that we will not send 304s.
     */
    if ((conf->xbithack != XBITHACK_FULL)
        || !(f->r->finfo.valid & APR_FINFO_GPROT)
        || !(f->r->finfo.protection & APR_GEXECUTE)) {
        f->r->no_local_copy = 1;
    }

    return OK;
}

static apr_status_t includes_filter(ap_filter_t *f, apr_bucket_brigade *b)
{
    request_rec *r = f->r;
    include_ctx_t *ctx = f->ctx;
    request_rec *parent;
    include_dir_config *conf = ap_get_module_config(r->per_dir_config,
                                                    &include_module);

    include_server_config *sconf= ap_get_module_config(r->server->module_config,
                                                       &include_module);

    if (!(ap_allow_options(r) & OPT_INCLUDES)) {
        return ap_pass_brigade(f->next, b);
    }

    if (!f->ctx) {
        struct ssi_internal_ctx *intern;

        /* create context for this filter */
        f->ctx = ctx = apr_palloc(r->pool, sizeof(*ctx));
        ctx->intern = intern = apr_palloc(r->pool, sizeof(*ctx->intern));
        ctx->pool = r->pool;
        apr_pool_create(&ctx->dpool, ctx->pool);

        /* runtime data */
        intern->tmp_bb = apr_brigade_create(ctx->pool, f->c->bucket_alloc);
        intern->seen_eos = 0;
        intern->state = PARSE_PRE_HEAD;
        ctx->flags = (SSI_FLAG_PRINTING | SSI_FLAG_COND_TRUE);
        if (ap_allow_options(r) & OPT_INCNOEXEC) {
            ctx->flags |= SSI_FLAG_NO_EXEC;
        }

        ctx->if_nesting_level = 0;
        intern->re_string = NULL;
        intern->error_str_override = NULL;
        intern->time_str_override = NULL;

        ctx->error_str = conf->default_error_msg;
        ctx->time_str = conf->default_time_fmt;
        intern->start_seq  = sconf->default_start_tag;
        intern->start_seq_pat = bndm_compile(ctx->pool, intern->start_seq,
                                             strlen(intern->start_seq));
        intern->end_seq = sconf->default_end_tag;
        intern->end_seq_len = strlen(intern->end_seq);
    }

    if ((parent = ap_get_module_config(r->request_config, &include_module))) {
        /* Kludge --- for nested includes, we want to keep the subprocess
         * environment of the base document (for compatibility); that means
         * torquing our own last_modified date as well so that the
         * LAST_MODIFIED variable gets reset to the proper value if the
         * nested document resets <!--#config timefmt -->.
         */
        r->subprocess_env = r->main->subprocess_env;
        apr_pool_join(r->main->pool, r->pool);
        r->finfo.mtime = r->main->finfo.mtime;
    }
    else {
        /* we're not a nested include, so we create an initial
         * environment */
        ap_add_common_vars(r);
        ap_add_cgi_vars(r);
        add_include_vars(r, conf->default_time_fmt);
    }
    /* Always unset the content-length.  There is no way to know if
     * the content will be modified at some point by send_parsed_content.
     * It is very possible for us to not find any content in the first
     * 9k of the file, but still have to modify the content of the file.
     * If we are going to pass the file through send_parsed_content, then
     * the content-length should just be unset.
     */
    apr_table_unset(f->r->headers_out, "Content-Length");

    /* Always unset the ETag/Last-Modified fields - see RFC2616 - 13.3.4.
     * We don't know if we are going to be including a file or executing
     * a program which may change the Last-Modified header or make the 
     * content completely dynamic.  Therefore, we can't support these
     * headers.
     * Exception: XBitHack full means we *should* set the Last-Modified field.
     */
    apr_table_unset(f->r->headers_out, "ETag");

    /* Assure the platform supports Group protections */
    if ((conf->xbithack == XBITHACK_FULL)
        && (r->finfo.valid & APR_FINFO_GPROT)
        && (r->finfo.protection & APR_GEXECUTE)) {
        ap_update_mtime(r, r->finfo.mtime);
        ap_set_last_modified(r);
    }
    else {
        apr_table_unset(f->r->headers_out, "Last-Modified");
    }

    /* add QUERY stuff to env cause it ain't yet */
    if (r->args) {
        char *arg_copy = apr_pstrdup(r->pool, r->args);

        apr_table_setn(r->subprocess_env, "QUERY_STRING", r->args);
        ap_unescape_url(arg_copy);
        apr_table_setn(r->subprocess_env, "QUERY_STRING_UNESCAPED",
                  ap_escape_shell_cmd(r->pool, arg_copy));
    }

    return send_parsed_content(f, b);
}

static int include_fixup(request_rec *r)
{
    include_dir_config *conf;
 
    conf = ap_get_module_config(r->per_dir_config, &include_module);
 
    if (r->handler && (strcmp(r->handler, "server-parsed") == 0)) 
    {
        if (!r->content_type || !*r->content_type) {
            ap_set_content_type(r, "text/html");
        }
        r->handler = "default-handler";
    }
    else 
#if defined(OS2) || defined(WIN32) || defined(NETWARE)
    /* These OS's don't support xbithack. This is being worked on. */
    {
        return DECLINED;
    }
#else
    {
        if (conf->xbithack == XBITHACK_OFF) {
            return DECLINED;
        }

        if (!(r->finfo.protection & APR_UEXECUTE)) {
            return DECLINED;
        }

        if (!r->content_type || strcmp(r->content_type, "text/html")) {
            return DECLINED;
        }
    }
#endif

    /* We always return declined, because the default handler actually
     * serves the file.  All we have to do is add the filter.
     */
    ap_add_output_filter("INCLUDES", NULL, r, r->connection);
    return DECLINED;
}


/*
 * +-------------------------------------------------------+
 * |                                                       |
 * |                Configuration Handling
 * |                                                       |
 * +-------------------------------------------------------+
 */

static void *create_includes_dir_config(apr_pool_t *p, char *dummy)
{
    include_dir_config *result = apr_palloc(p, sizeof(include_dir_config));

    result->default_error_msg = DEFAULT_ERROR_MSG;
    result->default_time_fmt  = DEFAULT_TIME_FORMAT;
    result->xbithack          = DEFAULT_XBITHACK;

    return result;
}

static void *create_includes_server_config(apr_pool_t *p, server_rec *server)
{
    include_server_config *result;

    result = apr_palloc(p, sizeof(include_server_config));
    result->default_end_tag    = DEFAULT_END_SEQUENCE;
    result->default_start_tag  = DEFAULT_START_SEQUENCE;
    result->undefined_echo     = DEFAULT_UNDEFINED_ECHO;
    result->undefined_echo_len = sizeof(DEFAULT_UNDEFINED_ECHO) - 1;

    return result; 
}

static const char *set_xbithack(cmd_parms *cmd, void *mconfig, const char *arg)
{
    include_dir_config *conf = mconfig;

    if (!strcasecmp(arg, "off")) {
        conf->xbithack = XBITHACK_OFF;
    }
    else if (!strcasecmp(arg, "on")) {
        conf->xbithack = XBITHACK_ON;
    }
    else if (!strcasecmp(arg, "full")) {
        conf->xbithack = XBITHACK_FULL;
    }
    else {
        return "XBitHack must be set to Off, On, or Full";
    }

    return NULL;
}

static const char *set_default_start_tag(cmd_parms *cmd, void *mconfig,
                                         const char *tag)
{
    include_server_config *conf;
    const char *p = tag;

    /* be consistent. (See below in set_default_end_tag) */
    while (*p) {
        if (apr_isspace(*p)) {
            return "SSIStartTag may not contain any whitespaces";
        }
        ++p;
    }

    conf= ap_get_module_config(cmd->server->module_config , &include_module);
    conf->default_start_tag = tag;

    return NULL;
}

static const char *set_default_end_tag(cmd_parms *cmd, void *mconfig,
                                       const char *tag)
{
    include_server_config *conf;
    const char *p = tag;

    /* sanity check. The parser may fail otherwise */
    while (*p) {
        if (apr_isspace(*p)) {
            return "SSIEndTag may not contain any whitespaces";
        }
        ++p;
    }

    conf= ap_get_module_config(cmd->server->module_config , &include_module);
    conf->default_end_tag = tag;

    return NULL;
}

static const char *set_undefined_echo(cmd_parms *cmd, void *mconfig,
                                      const char *msg)
{
    include_server_config *conf;

    conf = ap_get_module_config(cmd->server->module_config, &include_module);
    conf->undefined_echo = msg;
    conf->undefined_echo_len = strlen(msg);

    return NULL;
}

static const char *set_default_error_msg(cmd_parms *cmd, void *mconfig,
                                         const char *msg)
{
    include_dir_config *conf = mconfig;
    conf->default_error_msg = msg;

    return NULL;
}

static const char *set_default_time_fmt(cmd_parms *cmd, void *mconfig,
                                        const char *fmt)
{
    include_dir_config *conf = mconfig;
    conf->default_time_fmt = fmt;

    return NULL;
}


/*
 * +-------------------------------------------------------+
 * |                                                       |
 * |        Module Initialization and Configuration
 * |                                                       |
 * +-------------------------------------------------------+
 */

static int include_post_config(apr_pool_t *p, apr_pool_t *plog,
                                apr_pool_t *ptemp, server_rec *s)
{
    include_handlers = apr_hash_make(p);

    ssi_pfn_register = APR_RETRIEVE_OPTIONAL_FN(ap_register_include_handler);

    if(ssi_pfn_register) {
        ssi_pfn_register("if", handle_if);
        ssi_pfn_register("set", handle_set);
        ssi_pfn_register("else", handle_else);
        ssi_pfn_register("elif", handle_elif);
        ssi_pfn_register("echo", handle_echo);
        ssi_pfn_register("endif", handle_endif);
        ssi_pfn_register("fsize", handle_fsize);
        ssi_pfn_register("config", handle_config);
        ssi_pfn_register("include", handle_include);
        ssi_pfn_register("flastmod", handle_flastmod);
        ssi_pfn_register("printenv", handle_printenv);
    }

    return OK;
}

static const command_rec includes_cmds[] =
{
    AP_INIT_TAKE1("XBitHack", set_xbithack, NULL, OR_OPTIONS, 
                  "Off, On, or Full"),
    AP_INIT_TAKE1("SSIErrorMsg", set_default_error_msg, NULL, OR_ALL, 
                  "a string"),
    AP_INIT_TAKE1("SSITimeFormat", set_default_time_fmt, NULL, OR_ALL,
                  "a strftime(3) formatted string"),
    AP_INIT_TAKE1("SSIStartTag", set_default_start_tag, NULL, RSRC_CONF,
                  "SSI Start String Tag"),
    AP_INIT_TAKE1("SSIEndTag", set_default_end_tag, NULL, RSRC_CONF,
                  "SSI End String Tag"),
    AP_INIT_TAKE1("SSIUndefinedEcho", set_undefined_echo, NULL, RSRC_CONF,
                  "String to be displayed if an echoed variable is undefined"),
    {NULL}
};

static void ap_register_include_handler(char *tag, include_handler_fn_t *func)
{
    apr_hash_set(include_handlers, tag, strlen(tag), (const void *)func);
}

static void register_hooks(apr_pool_t *p)
{
    APR_REGISTER_OPTIONAL_FN(ap_ssi_get_tag_and_value);
    APR_REGISTER_OPTIONAL_FN(ap_ssi_parse_string);
    APR_REGISTER_OPTIONAL_FN(ap_register_include_handler);
    ap_hook_post_config(include_post_config, NULL, NULL, APR_HOOK_REALLY_FIRST);
    ap_hook_fixups(include_fixup, NULL, NULL, APR_HOOK_LAST);
    ap_register_output_filter("INCLUDES", includes_filter, includes_setup,
                              AP_FTYPE_RESOURCE);
}

module AP_MODULE_DECLARE_DATA include_module =
{
    STANDARD20_MODULE_STUFF,
    create_includes_dir_config,   /* dir config creater */
    NULL,                         /* dir merger --- default is to override */
    create_includes_server_config,/* server config */
    NULL,                         /* merge server config */
    includes_cmds,                /* command apr_table_t */
    register_hooks                /* register hooks */
};
