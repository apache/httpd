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

#include "apr.h"
#include "apr_strings.h"
#include "apr_lib.h"

#define APR_WANT_STRFUNC
#define APR_WANT_MEMFUNC
#include "apr_want.h"

#include "httpd.h"
#include "http_log.h"
#include "http_core.h"

#include "ap_expr.h"
#if 1
/*
 * +-------------------------------------------------------+
 * |                                                       |
 * |                  Debugging Utilities
 * |                                                       |
 * +-------------------------------------------------------+
 */

#ifdef DEBUG_INCLUDE

#define TYPE_TOKEN(token, ttype) do { \
    (token)->type = ttype;            \
    (token)->s = #ttype;              \
} while(0)

#define CREATE_NODE(pool,name) do {                          \
    (name) = apr_pcalloc(pool, sizeof(*(name)));             \
} while(0)

static void debug_printf(request_rec *r, const char *fmt, ...)
{
    va_list ap;
    char *debug__str;

    va_start(ap, fmt);
    debug__str = apr_pvsprintf(r->pool, fmt, ap);
    va_end(ap);
/*
    APR_BRIGADE_INSERT_TAIL(ctx->intern->debug.bb, apr_bucket_pool_create(
                            debug__str, strlen(debug__str), ctx->pool,
                            ctx->intern->debug.f->c->bucket_alloc));
                            */
}

#define DUMP__CHILD(ctx, is, node, child) if (1) {                           \
    ap_parse_node_t *d__c = node->child;                                     \
    if (d__c) {                                                              \
        if (!d__c->dump_done) {                                              \
            if (d__c->parent != node) {                                      \
                debug_printf(ctx, "!!! Parse tree is not consistent !!!\n"); \
                if (!d__c->parent) {                                         \
                    debug_printf(ctx, "Parent of " #child " child node is "  \
                                 "NULL.\n");                                 \
                }                                                            \
                else {                                                       \
                    debug_printf(ctx, "Parent of " #child " child node "     \
                                 "points to another node (of type %s)!\n",   \
                                 d__c->parent->token.s);                     \
                }                                                            \
                return;                                                      \
            }                                                                \
            node = d__c;                                                     \
            continue;                                                        \
        }                                                                    \
    }                                                                        \
    else {                                                                   \
        debug_printf(ctx, "%s(missing)\n", is);                              \
    }                                                                        \
}

static void debug_dump_tree(include_ctx_t *ctx, ap_parse_node_t *root)
{
    ap_parse_node_t *current;
    char *is;

    if (!root) {
        debug_printf(ctx, "     -- Parse Tree empty --\n\n");
        return;
    }

    debug_printf(ctx, "     ----- Parse Tree -----\n");
    current = root;
    is = "     ";

    while (current) {
        switch (current->token.type) {
        case TOKEN_STRING:
        case TOKEN_RE:
            debug_printf(ctx, "%s%s (%s)\n", is, current->token.s,
                         current->token.value);
            current->dump_done = 1;
            current = current->parent;
            continue;

        case TOKEN_NOT:
        case TOKEN_GROUP:
        case TOKEN_RBRACE:
        case TOKEN_LBRACE:
            if (!current->dump_done) {
                debug_printf(ctx, "%s%s\n", is, current->token.s);
                is = apr_pstrcat(ctx->dpool, is, "    ", NULL);
                current->dump_done = 1;
            }

            DUMP__CHILD(ctx, is, current, right)

            if (!current->right || current->right->dump_done) {
                is = apr_pstrmemdup(ctx->dpool, is, strlen(is) - 4);
                if (current->right) current->right->dump_done = 0;
                current = current->parent;
            }
            continue;

        default:
            if (!current->dump_done) {
                debug_printf(ctx, "%s%s\n", is, current->token.s);
                is = apr_pstrcat(ctx->dpool, is, "    ", NULL);
                current->dump_done = 1;
            }

            DUMP__CHILD(ctx, is, current, left)
            DUMP__CHILD(ctx, is, current, right)

            if ((!current->left || current->left->dump_done) &&
                (!current->right || current->right->dump_done)) {

                is = apr_pstrmemdup(ctx->dpool, is, strlen(is) - 4);
                if (current->left) current->left->dump_done = 0;
                if (current->right) current->right->dump_done = 0;
                current = current->parent;
            }
            continue;
        }
    }

    /* it is possible to call this function within the parser loop, to see
     * how the tree is built. That way, we must cleanup after us to dump
     * always the whole tree
     */
    root->dump_done = 0;
    if (root->left) root->left->dump_done = 0;
    if (root->right) root->right->dump_done = 0;

    debug_printf(ctx, "     --- End Parse Tree ---\n\n");

    return;
}

#define DEBUG_INIT(ctx, filter, brigade) do { \
    (ctx)->intern->debug.f = filter;          \
    (ctx)->intern->debug.bb = brigade;        \
} while(0)

#define DEBUG_PRINTF(arg) debug_printf arg

#define DEBUG_DUMP_TOKEN(ctx, token) do {                                     \
    token_t *d__t = (token);                                                  \
                                                                              \
    if (d__t->type == TOKEN_STRING || d__t->type == TOKEN_RE) {               \
        DEBUG_PRINTF(((ctx), "     Found: %s (%s)\n", d__t->s, d__t->value)); \
    }                                                                         \
    else {                                                                    \
        DEBUG_PRINTF((ctx, "     Found: %s\n", d__t->s));                     \
    }                                                                         \
} while(0)

#define DEBUG_DUMP_EVAL(r, node) do {                                       \
    char c = '"';                                                             \
    switch ((node)->token.type) {                                             \
    case TOKEN_STRING:                                                        \
        debug_printf((r), "     Evaluate: %s (%s) -> %c\n", (node)->token.s,\
                     (node)->token.value, ((node)->value) ? '1':'0');         \
        break;                                                                \
    case TOKEN_AND:                                                           \
    case TOKEN_OR:                                                            \
        debug_printf((r), "     Evaluate: %s (Left: %s; Right: %s) -> %c\n",\
                     (node)->token.s,                                         \
                     (((node)->left->done) ? ((node)->left->value ?"1":"0")   \
                                          : "short circuited"),               \
                     (((node)->right->done) ? ((node)->right->value?"1":"0")  \
                                          : "short circuited"),               \
                     (node)->value ? '1' : '0');                              \
        break;                                                                \
    case TOKEN_EQ:                                                            \
    case TOKEN_NE:                                                            \
    case TOKEN_GT:                                                            \
    case TOKEN_GE:                                                            \
    case TOKEN_LT:                                                            \
    case TOKEN_LE:                                                            \
        if ((node)->right->token.type == TOKEN_RE) c = '/';                   \
        debug_printf((r), "     Compare:  %s (\"%s\" with %c%s%c) -> %c\n", \
                     (node)->token.s,                                         \
                     (node)->left->token.value,                               \
                     c, (node)->right->token.value, c,                        \
                     (node)->value ? '1' : '0');                              \
        break;                                                                \
    default:                                                                  \
        debug_printf((r), "     Evaluate: %s -> %c\n", (node)->token.s,     \
                     (node)->value ? '1' : '0');                              \
        break;                                                                \
    }                                                                         \
} while(0)

#define DEBUG_DUMP_UNMATCHED(r, unmatched) do {                        \
    if (unmatched) {                                                     \
        DEBUG_PRINTF(((r), "     Unmatched %c\n", (char)(unmatched))); \
    }                                                                    \
} while(0)

#define DEBUG_DUMP_COND(ctx, text)                                 \
    DEBUG_PRINTF(((ctx), "**** %s cond status=\"%c\"\n", (text),   \
                  ((ctx)->flags & SSI_FLAG_COND_TRUE) ? '1' : '0'))

#define DEBUG_DUMP_TREE(ctx, root) debug_dump_tree(ctx, root)

#else /* DEBUG_INCLUDE */

#define TYPE_TOKEN(token, ttype) (token)->type = ttype

#define CREATE_NODE(pool,name) do {               \
    (name) = apr_pcalloc(pool, sizeof(*(name)));  \
} while(0)

#define DEBUG_INIT(ctx, f, bb)
#define DEBUG_PRINTF(arg)
#define DEBUG_DUMP_TOKEN(ctx, token)
#define DEBUG_DUMP_EVAL(ctx, node)
#define DEBUG_DUMP_UNMATCHED(ctx, unmatched)
#define DEBUG_DUMP_COND(ctx, text)
#define DEBUG_DUMP_TREE(ctx, root)

#endif /* !DEBUG_INCLUDE */

#endif /* 0 */


/*
 * +-------------------------------------------------------+
 * |                                                       |
 * |              Conditional Expression Parser
 * |                                                       |
 * +-------------------------------------------------------+
 */
static APR_INLINE int re_check(request_rec *r, const char *string,
                               const char *rexp, backref_t **reptr)
{
    ap_regex_t *compiled;
    backref_t *re = reptr ? *reptr : NULL;

    compiled = ap_pregcomp(r->pool, rexp, AP_REG_EXTENDED);
    if (!compiled) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "unable to "
                      "compile pattern \"%s\"", rexp);
        return -1;
    }

    if (!re) {
        re = apr_palloc(r->pool, sizeof(*re));
        if (reptr) {
            *reptr = re;
        }
    }

    re->source = apr_pstrdup(r->pool, string);
    re->rexp = apr_pstrdup(r->pool, rexp);
    re->nsub = compiled->re_nsub;
    re->have_match = !ap_regexec(compiled, string, AP_MAX_REG_MATCH,
                                 re->match, 0);

    ap_pregfree(r->pool, compiled);
    return re->have_match;
}

static int get_ptoken(apr_pool_t *pool, const char **parse, token_t *token,
                      token_t *previous)
{
    const char *p;
    apr_size_t shift;
    int unmatched;

    token->value = NULL;

    if (!*parse) {
        return 0;
    }

    /* Skip leading white space */
    while (apr_isspace(**parse)) {
        ++*parse;
    }

    if (!**parse) {
        *parse = NULL;
        return 0;
    }

    TYPE_TOKEN(token, TOKEN_STRING); /* the default type */
    p = *parse;
    unmatched = 0;

    switch (*(*parse)++) {
    case '(':
        TYPE_TOKEN(token, TOKEN_LBRACE);
        return 0;
    case ')':
        TYPE_TOKEN(token, TOKEN_RBRACE);
        return 0;
    case '=':
        if (**parse == '=') ++*parse;
        TYPE_TOKEN(token, TOKEN_EQ);
        return 0;
    case '!':
        if (**parse == '=') {
            TYPE_TOKEN(token, TOKEN_NE);
            ++*parse;
            return 0;
        }
        TYPE_TOKEN(token, TOKEN_NOT);
        return 0;
    case '\'':
        unmatched = '\'';
        break;
    case '/':
        /* if last token was ACCESS, this token is STRING */
        if (previous != NULL && TOKEN_ACCESS == previous->type) {
            break;
        }
        TYPE_TOKEN(token, TOKEN_RE);
        unmatched = '/';
        break;
    case '|':
        if (**parse == '|') {
            TYPE_TOKEN(token, TOKEN_OR);
            ++*parse;
            return 0;
        }
        break;
    case '&':
        if (**parse == '&') {
            TYPE_TOKEN(token, TOKEN_AND);
            ++*parse;
            return 0;
        }
        break;
    case '>':
        if (**parse == '=') {
            TYPE_TOKEN(token, TOKEN_GE);
            ++*parse;
            return 0;
        }
        TYPE_TOKEN(token, TOKEN_GT);
        return 0;
    case '<':
        if (**parse == '=') {
            TYPE_TOKEN(token, TOKEN_LE);
            ++*parse;
            return 0;
        }
        TYPE_TOKEN(token, TOKEN_LT);
        return 0;
    case '-':
        if (apr_isalnum(**parse) && apr_isspace((*parse)[1])) {
            TYPE_TOKEN(token, TOKEN_ACCESS);
            token->value = *parse;
            ++*parse;
            return 0;
        }
        break;
    }

    /* It's a string or regex token
     * Now search for the next token, which finishes this string
     */
    shift = 0;
    p = *parse = token->value = unmatched ? *parse : p;

    for (; **parse; p = ++*parse) {
        if (**parse == '\\') {
            if (!*(++*parse)) {
                p = *parse;
                break;
            }

            ++shift;
        }
        else {
            if (unmatched) {
                if (**parse == unmatched) {
                    unmatched = 0;
                    ++*parse;
                    break;
                }
            }
            else if (apr_isspace(**parse)) {
                break;
            }
            else {
                int found = 0;

                switch (**parse) {
                case '(':
                case ')':
                case '=':
                case '!':
                case '<':
                case '>':
                    ++found;
                    break;

                case '|':
                case '&':
                    if ((*parse)[1] == **parse) {
                        ++found;
                    }
                    break;
                }

                if (found) {
                    break;
                }
            }
        }
    }

    if (unmatched) {
        token->value = apr_pstrdup(pool, "");
    }
    else {
        apr_size_t len = p - token->value - shift;
        char *c = apr_palloc(pool, len + 1);

        p = token->value;
        token->value = c;

        while (shift--) {
            const char *e = ap_strchr_c(p, '\\');

            memcpy(c, p, e-p);
            c   += e-p;
            *c++ = *++e;
            len -= e-p;
            p    = e+1;
        }

        if (len) {
            memcpy(c, p, len);
        }
        c[len] = '\0';
    }

    return unmatched;
}

/* This is what we export.  We can split it in two. */
AP_DECLARE(ap_parse_node_t*) ap_expr_parse(apr_pool_t* pool, const char *expr,
                                           int *was_error)
{
    ap_parse_node_t *new, *root = NULL, *current = NULL;
    const char *error = "Invalid expression \"%s\" in file %s";
    const char *parse = expr;
    int was_unmatched = 0;
    unsigned regex = 0;

    *was_error = 0;

    if (!parse) {
        return 0;
    }

    /* Create Parse Tree */
    while (1) {
        /* uncomment this to see how the tree a built:
         *
         * DEBUG_DUMP_TREE(ctx, root);
         */
        CREATE_NODE(pool, new);

        was_unmatched = get_ptoken(pool, &parse, &new->token,
                     (current != NULL ? &current->token : NULL));
        if (!parse) {
            break;
        }

        DEBUG_DUMP_UNMATCHED(ctx, was_unmatched);
        DEBUG_DUMP_TOKEN(ctx, &new->token);

        if (!current) {
            switch (new->token.type) {
            case TOKEN_STRING:
            case TOKEN_NOT:
            case TOKEN_ACCESS:
            case TOKEN_LBRACE:
                root = current = new;
                continue;

            default:
                *was_error = 1;
                return 0;
            }
        }

        switch (new->token.type) {
        case TOKEN_STRING:
            switch (current->token.type) {
            case TOKEN_STRING:
                current->token.value =
                    apr_pstrcat(pool, current->token.value,
                                *current->token.value ? " " : "",
                                new->token.value, NULL);
                continue;

            case TOKEN_RE:
            case TOKEN_RBRACE:
            case TOKEN_GROUP:
                break;

            default:
                new->parent = current;
                current = current->right = new;
                continue;
            }
            break;

        case TOKEN_RE:
            switch (current->token.type) {
            case TOKEN_EQ:
            case TOKEN_NE:
                new->parent = current;
                current = current->right = new;
                ++regex;
                continue;

            default:
                break;
            }
            break;

        case TOKEN_AND:
        case TOKEN_OR:
            switch (current->token.type) {
            case TOKEN_STRING:
            case TOKEN_RE:
            case TOKEN_GROUP:
                current = current->parent;

                while (current) {
                    switch (current->token.type) {
                    case TOKEN_AND:
                    case TOKEN_OR:
                    case TOKEN_LBRACE:
                        break;

                    default:
                        current = current->parent;
                        continue;
                    }
                    break;
                }

                if (!current) {
                    new->left = root;
                    root->parent = new;
                    current = root = new;
                    continue;
                }

                new->left = current->right;
                new->left->parent = new;
                new->parent = current;
                current = current->right = new;
                continue;

            default:
                break;
            }
            break;

        case TOKEN_EQ:
        case TOKEN_NE:
        case TOKEN_GE:
        case TOKEN_GT:
        case TOKEN_LE:
        case TOKEN_LT:
            if (current->token.type == TOKEN_STRING) {
                current = current->parent;

                if (!current) {
                    new->left = root;
                    root->parent = new;
                    current = root = new;
                    continue;
                }

                switch (current->token.type) {
                case TOKEN_LBRACE:
                case TOKEN_AND:
                case TOKEN_OR:
                    new->left = current->right;
                    new->left->parent = new;
                    new->parent = current;
                    current = current->right = new;
                    continue;

                default:
                    break;
                }
            }
            break;

        case TOKEN_RBRACE:
            while (current && current->token.type != TOKEN_LBRACE) {
                current = current->parent;
            }

            if (current) {
                TYPE_TOKEN(&current->token, TOKEN_GROUP);
                continue;
            }

            error = "Unmatched ')' in \"%s\" in file %s";
            break;

        case TOKEN_NOT:
        case TOKEN_ACCESS:
        case TOKEN_LBRACE:
            switch (current->token.type) {
            case TOKEN_STRING:
            case TOKEN_RE:
            case TOKEN_RBRACE:
            case TOKEN_GROUP:
                break;

            default:
                current->right = new;
                new->parent = current;
                current = new;
                continue;
            }
            break;

        default:
            break;
        }

        *was_error = 1;
        return 0;
    }

    DEBUG_DUMP_TREE(ctx, root);
    return root;
}

static ap_parse_node_t *ap_expr_clone_tree(apr_pool_t *pool,
                                           ap_parse_node_t *pnode,
                                           ap_parse_node_t *parent)
{
    ap_parse_node_t *ret;
    ret = apr_pmemdup(pool, pnode, sizeof(ap_parse_node_t));
    if (pnode->left) {
        ret->left = ap_expr_clone_tree(pool, pnode->left, ret);
    }
    if (pnode->right) {
        ret->right = ap_expr_clone_tree(pool, pnode->right, ret);
    }
    ret->parent = parent;
    return ret;
}

#define PARSE_STRING(r,s) (string_func ? string_func((r),(s)) : (s))
static int expr_eval(request_rec *r, ap_parse_node_t *root,
                     int *was_error, backref_t **reptr,
                     string_func_t string_func, opt_func_t eval_func)
{
    ap_parse_node_t *current = root;
    const char *error = NULL;
    unsigned int regex = 0;
    const char *val;
    const char *lval;
    const char *rval;

    /* Evaluate Parse Tree */
    while (current) {
        switch (current->token.type) {
        case TOKEN_STRING:
            val = PARSE_STRING(r, current->token.value);
            current->value = !!*val;
            break;

        case TOKEN_AND:
        case TOKEN_OR:
            if (!current->left || !current->right) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                              "Invalid expression in file %s", r->filename);
                *was_error = 1;
                return 0;
            }

            if (!current->left->done) {
                switch (current->left->token.type) {
                case TOKEN_STRING:
                    lval = PARSE_STRING(r, current->left->token.value);
                    current->left->value = !!*lval;
                    DEBUG_DUMP_EVAL(ctx, current->left);
                    current->left->done = 1;
                    break;

                default:
                    current = current->left;
                    continue;
                }
            }

            /* short circuit evaluation */
            if (!current->right->done && !regex &&
                ((current->token.type == TOKEN_AND && !current->left->value) ||
                (current->token.type == TOKEN_OR && current->left->value))) {
                current->value = current->left->value;
            }
            else {
                if (!current->right->done) {
                    switch (current->right->token.type) {
                    case TOKEN_STRING:
                        rval = PARSE_STRING(r,current->right->token.value);
                        current->right->value = !!*rval;
                        DEBUG_DUMP_EVAL(r, current->right);
                        current->right->done = 1;
                        break;

                    default:
                        current = current->right;
                        continue;
                    }
                }

                if (current->token.type == TOKEN_AND) {
                    current->value = current->left->value &&
                                     current->right->value;
                }
                else {
                    current->value = current->left->value ||
                                     current->right->value;
                }
            }
            break;

        case TOKEN_EQ:
        case TOKEN_NE:
            if (!current->left || !current->right ||
                current->left->token.type != TOKEN_STRING ||
                (current->right->token.type != TOKEN_STRING &&
                 current->right->token.type != TOKEN_RE)) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                            "Invalid expression in file %s", r->filename);
                *was_error = 1;
                return 0;
            }
            lval = PARSE_STRING(r, current->left->token.value);
            rval = PARSE_STRING(r, current->right->token.value);

            if (current->right->token.type == TOKEN_RE) {
                current->value = re_check(r, lval, rval, reptr);
                --regex;
            }
            else {
                current->value = !strcmp(lval, rval);
            }

            if (current->token.type == TOKEN_NE) {
                current->value = !current->value;
            }
            break;

        case TOKEN_GE:
        case TOKEN_GT:
        case TOKEN_LE:
        case TOKEN_LT:
            if (!current->left || !current->right ||
                current->left->token.type != TOKEN_STRING ||
                current->right->token.type != TOKEN_STRING) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                              "Invalid expression in file %s", r->filename);
                *was_error = 1;
                return 0;
            }

            lval = PARSE_STRING(r, current->left->token.value);
            rval = PARSE_STRING(r, current->right->token.value);

            current->value = strcmp(lval, rval);

            switch (current->token.type) {
            case TOKEN_GE: current->value = current->value >= 0; break;
            case TOKEN_GT: current->value = current->value >  0; break;
            case TOKEN_LE: current->value = current->value <= 0; break;
            case TOKEN_LT: current->value = current->value <  0; break;
            default: current->value = 0; break; /* should not happen */
            }
            break;

        case TOKEN_NOT:
        case TOKEN_GROUP:
            if (current->right) {
                if (!current->right->done) {
                    current = current->right;
                    continue;
                }
                current->value = current->right->value;
            }
            else {
                current->value = 1;
            }

            if (current->token.type == TOKEN_NOT) {
                current->value = !current->value;
            }
            break;
        case TOKEN_ACCESS:
            if (eval_func) {
                *was_error = eval_func(r, current, string_func);
                if (*was_error) {
                    return 0;
                }
            }
            break;

        case TOKEN_RE:
            if (!error) {
                error = "No operator before regex in file %s";
            }
        case TOKEN_LBRACE:
            if (!error) {
                error = "Unmatched '(' in file %s";
            }
        default:
            if (!error) {
                error = "internal parser error in file %s";
            }

            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, error, r->filename);
            *was_error = 1;
            return 0;
        }

        DEBUG_DUMP_EVAL(r, current);
        current->done = 1;
        current = current->parent;
    }

    return (root ? root->value : 0);
}
AP_DECLARE(int) ap_expr_eval(request_rec *r, ap_parse_node_t *root,
                             int *was_error, backref_t **reptr,
                             string_func_t string_func, opt_func_t eval_func)
{
    ap_parse_node_t *clone;
    if (root == NULL) {  /* no condition == unconditional */
        return 1;
    }
    clone = ap_expr_clone_tree(r->pool, root, NULL);
    return expr_eval(r, clone, was_error, reptr, string_func, eval_func);
}
AP_DECLARE(int) ap_expr_evalstring(request_rec *r, const char *expr,
                                   int *was_error, backref_t **reptr,
                                   string_func_t string_func,
                                   opt_func_t eval_func)
{
    ap_parse_node_t *root = ap_expr_parse(r->pool, expr, was_error);
    if (*was_error || !root) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "Error parsing expression in %s", r->filename);   
        return 0;
    }
    return expr_eval(r, root, was_error, reptr, string_func, eval_func);
}


static ap_regex_t *isvar = NULL;
AP_DECLARE_NONSTD(const char*) ap_expr_string(request_rec *r, 
                                              const char *str)
{
    /* a default string evaluator: support headers and env */
    const char *ret = str;
    ap_regmatch_t match[3];
    const char *p;

    ap_assert(isvar != NULL);
    if (ap_regexec(isvar, str, 3, match, 0) == 0) {
        apr_table_t *table = NULL;
        int len = match[1].rm_eo-match[1].rm_so;
        const char *name = str+match[1].rm_so;
        if (!strncasecmp("req", name, len)) {
            table = r->headers_in;
        }
        else if (!strncasecmp("resp", name, len)) {
            table = r->headers_out;
        }
        else if (!strncasecmp("env", name, len)) {
            table = r->subprocess_env;
        }
        if (table != NULL) {
            char *key = apr_pstrndup(r->pool, str+match[2].rm_so,
                                     match[2].rm_eo-match[2].rm_so);
            ret = apr_table_get(table, key);
        }
    }
    else if (str[0] == '$') {
        if (!strcasecmp(str, "$handler")) {
            ret = r->handler;
        }
        else if (!strcasecmp(str, "$content-type")) {
            ret = r->content_type;
        }
    }

    /* copy wholesale from mod_rewrite to support its %{varname} vars */
    else if ((str[0] == '%') && (str[1] == '{')
             && (p = ap_strchr_c(str, '}'), p != NULL)) {
        char *ch, *var;
        apr_time_exp_t tm;

        var = apr_pstrndup(r->pool, str+2, p-str-3);
        for (ch = var; *ch; ++ch) {
            *ch = apr_toupper(*ch);
        }

        switch (strlen(var)) {
        case  4:
            if (!strcmp(var, "TIME")) {
                apr_time_exp_lt(&tm, apr_time_now());
                ret = apr_psprintf(r->pool, "%04d%02d%02d%02d%02d%02d",
                                      tm.tm_year+1900, tm.tm_mon+1, tm.tm_mday,
                                      tm.tm_hour, tm.tm_min, tm.tm_sec);
                return (char *)ret;
            }
            else if (!strcmp(var, "IPV6")) {
                int flag = FALSE;
#if APR_HAVE_IPV6
                apr_sockaddr_t *addr = r->connection->remote_addr;
                flag = (addr->family == AF_INET6 &&
                        !IN6_IS_ADDR_V4MAPPED((struct in6_addr *)addr->ipaddr_ptr));
#endif
                ret = (flag ? "on" : "off");
            }
            break;

#if FIXME
        case  5:
            if (!strcmp(var, "HTTPS")) {
                int flag = rewrite_is_https && rewrite_is_https(r->connection);
                return apr_pstrdup(r->pool, flag ? "on" : "off");
            }
            break;
#endif
        case  8:
            switch (var[6]) {
            case 'A':
                if (!strcmp(var, "TIME_DAY")) {
                    apr_time_exp_lt(&tm, apr_time_now());
                    return apr_psprintf(r->pool, "%02d", tm.tm_mday);
                }
                break;

            case 'E':
                if (!strcmp(var, "TIME_SEC")) {
                    apr_time_exp_lt(&tm, apr_time_now());
                    return apr_psprintf(r->pool, "%02d", tm.tm_sec);
                }
                break;

            case 'I':
                if (!strcmp(var, "TIME_MIN")) {
                    apr_time_exp_lt(&tm, apr_time_now());
                    return apr_psprintf(r->pool, "%02d", tm.tm_min);
                }
                break;

            case 'O':
                if (!strcmp(var, "TIME_MON")) {
                    apr_time_exp_lt(&tm, apr_time_now());
                    return apr_psprintf(r->pool, "%02d", tm.tm_mon+1);
                }
                break;
            }
            break;

        case  9:
            switch (var[7]) {
            case 'A':
                if (var[8] == 'Y' && !strcmp(var, "TIME_WDAY")) {
                    apr_time_exp_lt(&tm, apr_time_now());
                    return apr_psprintf(r->pool, "%d", tm.tm_wday);
                }
                else if (!strcmp(var, "TIME_YEAR")) {
                    apr_time_exp_lt(&tm, apr_time_now());
                    return apr_psprintf(r->pool, "%04d", tm.tm_year+1900);
                }
                break;

            case 'E':
                if (!strcmp(var, "IS_SUBREQ")) {
                    ret = (r->main ? "true" : "false");
                }
                break;

            case 'F':
                if (!strcmp(var, "PATH_INFO")) {
                    ret = r->path_info;
                }
                break;

            case 'P':
                if (!strcmp(var, "AUTH_TYPE")) {
                    ret = r->ap_auth_type;
                }
                break;

            case 'S':
                if (!strcmp(var, "HTTP_HOST")) {
                    ret = apr_table_get(r->headers_in, "Host");
                }
                break;

            case 'U':
                if (!strcmp(var, "TIME_HOUR")) {
                    apr_time_exp_lt(&tm, apr_time_now());
                    return apr_psprintf(r->pool, "%02d", tm.tm_hour);
                }
                break;
            }
            break;

        case 11:
            switch (var[8]) {
            case 'A':
                if (!strcmp(var, "SERVER_NAME")) {
                    ret = ap_get_server_name(r);
                }
                break;

            case 'D':
                if (*var == 'R' && !strcmp(var, "REMOTE_ADDR")) {
                    ret = r->connection->remote_ip;
                }
                else if (!strcmp(var, "SERVER_ADDR")) {
                    ret = r->connection->local_ip;
                }
                break;

            case 'E':
                if (*var == 'H' && !strcmp(var, "HTTP_ACCEPT")) {
                    ret = apr_table_get(r->headers_in, "Accept");
                }
                else if (!strcmp(var, "THE_REQUEST")) {
                    ret = r->the_request;
                }
                break;

            case 'I':
                if (!strcmp(var, "API_VERSION")) {
                    return apr_psprintf(r->pool, "%d:%d",
                                        MODULE_MAGIC_NUMBER_MAJOR,
                                        MODULE_MAGIC_NUMBER_MINOR);
                }
                break;

            case 'K':
                if (!strcmp(var, "HTTP_COOKIE")) {
                    ret = apr_table_get(r->headers_in, "Cookie");
                }
                break;

            case 'O':
                if (*var == 'S' && !strcmp(var, "SERVER_PORT")) {
                    return apr_psprintf(r->pool, "%u", ap_get_server_port(r));
                }
                else if (var[7] == 'H' && !strcmp(var, "REMOTE_HOST")) {
                    ret = ap_get_remote_host(r->connection,r->per_dir_config,
                                                REMOTE_NAME, NULL);
                }
                else if (!strcmp(var, "REMOTE_PORT")) {
                    return apr_itoa(r->pool, r->connection->remote_addr->port);
                }
                break;

            case 'S':
                if (*var == 'R' && !strcmp(var, "REMOTE_USER")) {
                    ret = r->user;
                }
                else if (!strcmp(var, "SCRIPT_USER")) {
                    ret = "<unknown>";
                    if (r->finfo.valid & APR_FINFO_USER) {
                        apr_uid_name_get((char **)&ret, r->finfo.user,
                                         r->pool);
                    }
                }
                break;

            case 'U':
                if (!strcmp(var, "REQUEST_URI")) {
                    ret = r->uri;
                }
                break;
            }
            break;

        case 12:
            switch (var[3]) {
            case 'I':
                if (!strcmp(var, "SCRIPT_GROUP")) {
                    ret = "<unknown>";
                    if (r->finfo.valid & APR_FINFO_GROUP) {
                        apr_gid_name_get((char **)&ret, r->finfo.group,
                                         r->pool);
                    }
                }
                break;

            case 'O':
                if (!strcmp(var, "REMOTE_IDENT")) {
                    ret = ap_get_remote_logname(r);
                }
                break;

            case 'P':
                if (!strcmp(var, "HTTP_REFERER")) {
                    ret = apr_table_get(r->headers_in, "Referer");
                }
                break;

            case 'R':
                if (!strcmp(var, "QUERY_STRING")) {
                    ret = r->args;
                }
                break;

            case 'V':
                if (!strcmp(var, "SERVER_ADMIN")) {
                    ret = r->server->server_admin;
                }
                break;
            }
            break;

        case 13:
            if (!strcmp(var, "DOCUMENT_ROOT")) {
                ret = ap_document_root(r);
            }
            break;

        case 14:
            if (*var == 'H' && !strcmp(var, "HTTP_FORWARDED")) {
                ret = apr_table_get(r->headers_in, "Forwarded");
            }
            else if (!strcmp(var, "REQUEST_METHOD")) {
                ret = r->method;
            }
            break;

        case 15:
            switch (var[7]) {
            case 'E':
                if (!strcmp(var, "HTTP_USER_AGENT")) {
                    ret = apr_table_get(r->headers_in, "User-Agent");
                }
                break;

            case 'F':
                if (!strcmp(var, "SCRIPT_FILENAME")) {
                    ret = r->filename; /* same as request_filename (16) */
                }
                break;

            case 'P':
                if (!strcmp(var, "SERVER_PROTOCOL")) {
                    ret = r->protocol;
                }
                break;

            case 'S':
                if (!strcmp(var, "SERVER_SOFTWARE")) {
                    ret = ap_get_server_banner();
                }
                break;
            }
            break;

        case 16:
            if (!strcmp(var, "REQUEST_FILENAME")) {
                ret = r->filename; /* same as script_filename (15) */
            }
            break;

        case 21:
            if (!strcmp(var, "HTTP_PROXY_CONNECTION")) {
                ret = apr_table_get(r->headers_in, "Proxy-Connection");
            }
            break;
        }
    }

    /* TODO: provide a hook so modules can interpret other patterns */
    /* OhBugger, where's the regexp for backreferences ? */
    if (!ret) {
        ret = "";
    }
    return ret;  /* default - literal string as-is */
}
static apr_status_t ap_expr_term(void *expr)
{
    if (isvar) {
        ap_regfree(isvar);
        isvar = NULL;
    }
    return APR_SUCCESS;
}
AP_DECLARE(apr_status_t) ap_expr_init(apr_pool_t *pool)
{
    static ap_regex_t var;
    if (!isvar) {
        isvar = &var;
        if (ap_regcomp(isvar, "\\$([A-Za-z0-9]+)\\{([^\\}]+)\\}", 0)) {
            isvar = NULL;
        }
        else {
            apr_pool_cleanup_register(pool, isvar, ap_expr_term,
                                      apr_pool_cleanup_null);
        }
    }
    return isvar ? APR_SUCCESS : APR_EGENERAL;
}
