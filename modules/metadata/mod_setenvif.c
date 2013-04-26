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
 * mod_setenvif.c
 * Set environment variables based on matching request headers or
 * attributes against regex strings
 *
 * Paul Sutton <paul@ukweb.com> 27 Oct 1996
 * Based on mod_browser by Alexei Kosut <akosut@organic.com>
 */

/*
 * Used to set environment variables based on the incoming request headers,
 * or some selected other attributes of the request (e.g., the remote host
 * name).
 *
 * Usage:
 *
 *   SetEnvIf name regex var ...
 *
 * where name is either a HTTP request header name, or one of the
 * special values (see below). 'name' may be a regex when it is used
 * to specify an HTTP request header name. The 'value' of the header
 & (or the value of the special value from below) are compared against
 * the regex argument. If this is a simple string, a simple sub-string
 * match is performed. Otherwise, a request expression match is
 * done. If the value matches the string or regular expression, the
 * environment variables listed as var ... are set. Each var can
 * be in one of three formats: var, which sets the named variable
 * (the value value "1"); var=value, which sets the variable to
 * the given value; or !var, which unsets the variable is it has
 * been previously set.
 *
 * Normally the strings are compared with regard to case. To ignore
 * case, use the directive SetEnvIfNoCase instead.
 *
 * Special values for 'name' are:
 *
 *   server_addr        IP address of interface on which request arrived
 *                      (analogous to SERVER_ADDR set in ap_add_common_vars())
 *   remote_host        Remote host name (if available)
 *   remote_addr        Remote IP address
 *   request_method     Request method (GET, POST, etc)
 *   request_uri        Requested URI
 *
 * Examples:
 *
 * To set the environment variable LOCALHOST if the client is the local
 * machine:
 *
 *    SetEnvIf remote_addr 127.0.0.1 LOCALHOST
 *
 * To set LOCAL if the client is the local host, or within our company's
 * domain (192.168.10):
 *
 *    SetEnvIf remote_addr 192.168.10. LOCAL
 *    SetEnvIf remote_addr 127.0.0.1   LOCALHOST
 *
 * This could be written as:
 *
 *    SetEnvIf remote_addr (127.0.0.1|192.168.10.) LOCAL
 *
 * To set HAVE_TS if the client request contains any header beginning
 * with "TS" with a value beginning with a lower case alphabet:
 *
 *    SetEnvIf ^TS* ^[a-z].* HAVE_TS
 */

#include "apr.h"
#include "apr_strings.h"
#include "apr_strmatch.h"

#define APR_WANT_STRFUNC
#include "apr_want.h"

#include "ap_config.h"
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"

enum special {
    SPECIAL_NOT,
    SPECIAL_REMOTE_ADDR,
    SPECIAL_REMOTE_HOST,
    SPECIAL_REQUEST_URI,
    SPECIAL_REQUEST_METHOD,
    SPECIAL_REQUEST_PROTOCOL,
    SPECIAL_SERVER_ADDR
};
typedef struct {
    char *name;                 /* header name */
    ap_regex_t *pnamereg;       /* compiled header name regex */
    char *regex;                /* regex to match against */
    ap_regex_t *preg;           /* compiled regex */
    const apr_strmatch_pattern *pattern; /* non-regex pattern to match */
    ap_expr_info_t *expr;       /* parsed expression */
    apr_table_t *features;      /* env vars to set (or unset) */
    enum special special_type;  /* is it a "special" header ? */
    int icase;                  /* ignoring case? */
} sei_entry;

typedef struct {
    apr_array_header_t *conditionals;
} sei_cfg_rec;

module AP_MODULE_DECLARE_DATA setenvif_module;

/*
 * These routines, the create- and merge-config functions, are called
 * for both the server-wide and the per-directory contexts.  This is
 * because the different definitions are used at different times; the
 * server-wide ones are used in the post-read-request phase, and the
 * per-directory ones are used during the header-parse phase (after
 * the URI has been mapped to a file and we have anything from the
 * .htaccess file and <Directory> and <Files> containers).
 */
static void *create_setenvif_config(apr_pool_t *p)
{
    sei_cfg_rec *new = (sei_cfg_rec *) apr_palloc(p, sizeof(sei_cfg_rec));

    new->conditionals = apr_array_make(p, 20, sizeof(sei_entry));
    return (void *) new;
}

static void *create_setenvif_config_svr(apr_pool_t *p, server_rec *dummy)
{
    return create_setenvif_config(p);
}

static void *create_setenvif_config_dir(apr_pool_t *p, char *dummy)
{
    return create_setenvif_config(p);
}

static void *merge_setenvif_config(apr_pool_t *p, void *basev, void *overridesv)
{
    sei_cfg_rec *a = apr_pcalloc(p, sizeof(sei_cfg_rec));
    sei_cfg_rec *base = basev, *overrides = overridesv;

    a->conditionals = apr_array_append(p, base->conditionals,
                                       overrides->conditionals);
    return a;
}

/*
 * any non-NULL magic constant will do... used to indicate if AP_REG_ICASE should
 * be used
 */
#define ICASE_MAGIC  ((void *)(&setenvif_module))
#define SEI_MAGIC_HEIRLOOM "setenvif-phase-flag"

static ap_regex_t *is_header_regex_regex;

static int is_header_regex(apr_pool_t *p, const char* name)
{
    /* If a Header name contains characters other than:
     *    -,_,[A-Z\, [a-z] and [0-9].
     * assume the header name is a regular expression.
     */
    if (ap_regexec(is_header_regex_regex, name, 0, NULL, 0)) {
        return 1;
    }

    return 0;
}

/* If the input string does not take advantage of regular
 * expression metacharacters, return a pointer to an equivalent
 * string that can be searched using apr_strmatch().  (The
 * returned string will often be the input string.  But if
 * the input string contains escaped characters, the returned
 * string will be a copy with the escapes removed.)
 */
static const char *non_regex_pattern(apr_pool_t *p, const char *s)
{
    const char *src = s;
    int escapes_found = 0;
    int in_escape = 0;

    while (*src) {
        switch (*src) {
        case '^':
        case '.':
        case '$':
        case '|':
        case '(':
        case ')':
        case '[':
        case ']':
        case '*':
        case '+':
        case '?':
        case '{':
        case '}':
            if (!in_escape) {
                return NULL;
            }
            in_escape = 0;
            break;
        case '\\':
            if (!in_escape) {
                in_escape = 1;
                escapes_found = 1;
            }
            else {
                in_escape = 0;
            }
            break;
        default:
            if (in_escape) {
                return NULL;
            }
            break;
        }
        src++;
    }
    if (!escapes_found) {
        return s;
    }
    else {
        char *unescaped = (char *)apr_palloc(p, src - s + 1);
        char *dst = unescaped;
        src = s;
        do {
            if (*src == '\\') {
                src++;
            }
        } while ((*dst++ = *src++));
        return unescaped;
    }
}

static const char *add_envvars(cmd_parms *cmd, const char *args, sei_entry *new)
{
    const char *feature;
    int beenhere = 0;
    char *var;

    for ( ; ; ) {
        feature = ap_getword_conf(cmd->pool, &args);
        if (!*feature) {
            break;
        }
        beenhere++;

        var = ap_getword(cmd->pool, &feature, '=');
        if (*feature) {
            apr_table_setn(new->features, var, feature);
        }
        else if (*var == '!') {
            apr_table_setn(new->features, var + 1, "!");
        }
        else {
            apr_table_setn(new->features, var, "1");
        }
    }

    if (!beenhere) {
        return apr_pstrcat(cmd->pool, "Missing envariable expression for ",
                           cmd->cmd->name, NULL);
    }

    return NULL;
}

static const char *add_setenvif_core(cmd_parms *cmd, void *mconfig,
                                     char *fname, const char *args)
{
    char *regex;
    const char *simple_pattern;
    sei_cfg_rec *sconf;
    sei_entry *new;
    sei_entry *entries;
    int i;
    int icase;

    /*
     * Determine from our context into which record to put the entry.
     * cmd->path == NULL means we're in server-wide context; otherwise,
     * we're dealing with a per-directory setting.
     */
    sconf = (cmd->path != NULL)
      ? (sei_cfg_rec *) mconfig
      : (sei_cfg_rec *) ap_get_module_config(cmd->server->module_config,
                                               &setenvif_module);
    entries = (sei_entry *) sconf->conditionals->elts;
    /* get regex */
    regex = ap_getword_conf(cmd->pool, &args);
    if (!*regex) {
        return apr_pstrcat(cmd->pool, "Missing regular expression for ",
                           cmd->cmd->name, NULL);
    }

    /*
     * If we've already got a sei_entry with the same name we want to
     * just copy the name pointer... so that later on we can compare
     * two header names just by comparing the pointers.
     */
    for (i = 0; i < sconf->conditionals->nelts; ++i) {
        new = &entries[i];
        if (new->name && !strcasecmp(new->name, fname)) {
            fname = new->name;
            break;
        }
    }

    /* if the last entry has an identical headername and regex then
     * merge with it
     */
    i = sconf->conditionals->nelts - 1;
    icase = cmd->info == ICASE_MAGIC;
    if (i < 0
        || entries[i].name != fname
        || entries[i].icase != icase
        || strcmp(entries[i].regex, regex)) {

        /* no match, create a new entry */
        new = apr_array_push(sconf->conditionals);
        new->name = fname;
        new->regex = regex;
        new->icase = icase;
        if ((simple_pattern = non_regex_pattern(cmd->pool, regex))) {
            new->pattern = apr_strmatch_precompile(cmd->pool,
                                                   simple_pattern, !icase);
            if (new->pattern == NULL) {
                return apr_pstrcat(cmd->pool, cmd->cmd->name,
                                   " pattern could not be compiled.", NULL);
            }
            new->preg = NULL;
        }
        else {
            new->preg = ap_pregcomp(cmd->pool, regex,
                                    (AP_REG_EXTENDED | (icase ? AP_REG_ICASE : 0)));
            if (new->preg == NULL) {
                return apr_pstrcat(cmd->pool, cmd->cmd->name,
                                   " regex could not be compiled.", NULL);
            }
            new->pattern = NULL;
        }
        new->features = apr_table_make(cmd->pool, 2);

        if (!strcasecmp(fname, "remote_addr")) {
            new->special_type = SPECIAL_REMOTE_ADDR;
        }
        else if (!strcasecmp(fname, "remote_host")) {
            new->special_type = SPECIAL_REMOTE_HOST;
        }
        else if (!strcasecmp(fname, "request_uri")) {
            new->special_type = SPECIAL_REQUEST_URI;
        }
        else if (!strcasecmp(fname, "request_method")) {
            new->special_type = SPECIAL_REQUEST_METHOD;
        }
        else if (!strcasecmp(fname, "request_protocol")) {
            new->special_type = SPECIAL_REQUEST_PROTOCOL;
        }
        else if (!strcasecmp(fname, "server_addr")) {
            new->special_type = SPECIAL_SERVER_ADDR;
        }
        else {
            new->special_type = SPECIAL_NOT;
            /* Handle fname as a regular expression.
             * If fname a simple header string, identify as such
             * (new->pnamereg = NULL) to avoid the overhead of searching
             * through headers_in for a regex match.
             */
            if (is_header_regex(cmd->temp_pool, fname)) {
                new->pnamereg = ap_pregcomp(cmd->pool, fname,
                                            (AP_REG_EXTENDED | AP_REG_NOSUB
                                             | (icase ? AP_REG_ICASE : 0)));
                if (new->pnamereg == NULL)
                    return apr_pstrcat(cmd->pool, cmd->cmd->name,
                                       "Header name regex could not be "
                                       "compiled.", NULL);
            }
            else {
                new->pnamereg = NULL;
            }
        }
    }
    else {
        new = &entries[i];
    }

    return add_envvars(cmd, args, new);
}

static const char *add_setenvif(cmd_parms *cmd, void *mconfig,
                                const char *args)
{
    char *fname;

    /* get header name */
    fname = ap_getword_conf(cmd->pool, &args);
    if (!*fname) {
        return apr_pstrcat(cmd->pool, "Missing header-field name for ",
                           cmd->cmd->name, NULL);
    }
    return add_setenvif_core(cmd, mconfig, fname, args);
}

static const char *add_setenvifexpr(cmd_parms *cmd, void *mconfig,
                                    const char *args)
{
    char *expr;
    sei_cfg_rec *sconf;
    sei_entry *new;
    const char *err;

    /*
     * Determine from our context into which record to put the entry.
     * cmd->path == NULL means we're in server-wide context; otherwise,
     * we're dealing with a per-directory setting.
     */
    sconf = (cmd->path != NULL)
      ? (sei_cfg_rec *) mconfig
      : (sei_cfg_rec *) ap_get_module_config(cmd->server->module_config,
                                               &setenvif_module);
    /* get expr */
    expr = ap_getword_conf(cmd->pool, &args);
    if (!*expr) {
        return apr_pstrcat(cmd->pool, "Missing expression for ",
                           cmd->cmd->name, NULL);
    }

    new = apr_array_push(sconf->conditionals);
    new->features = apr_table_make(cmd->pool, 2);
    new->name = NULL;
    new->regex = NULL;
    new->pattern = NULL;
    new->preg = NULL;
    new->expr = ap_expr_parse_cmd(cmd, expr, 0, &err, NULL);
    if (err)
        return apr_psprintf(cmd->pool, "Could not parse expression \"%s\": %s",
                            expr, err);

    return add_envvars(cmd, args, new);
}

/*
 * This routine handles the BrowserMatch* directives.  It simply turns around
 * and feeds them, with the appropriate embellishments, to the general-purpose
 * command handler.
 */
static const char *add_browser(cmd_parms *cmd, void *mconfig, const char *args)
{
    return add_setenvif_core(cmd, mconfig, "User-Agent", args);
}

static const command_rec setenvif_module_cmds[] =
{
    AP_INIT_RAW_ARGS("SetEnvIf", add_setenvif, NULL, OR_FILEINFO,
                     "A header-name, regex and a list of variables."),
    AP_INIT_RAW_ARGS("SetEnvIfNoCase", add_setenvif, ICASE_MAGIC, OR_FILEINFO,
                     "a header-name, regex and a list of variables."),
    AP_INIT_RAW_ARGS("SetEnvIfExpr", add_setenvifexpr, NULL, OR_FILEINFO,
                     "an expression and a list of variables."),
    AP_INIT_RAW_ARGS("BrowserMatch", add_browser, NULL, OR_FILEINFO,
                     "A browser regex and a list of variables."),
    AP_INIT_RAW_ARGS("BrowserMatchNoCase", add_browser, ICASE_MAGIC,
                     OR_FILEINFO,
                     "A browser regex and a list of variables."),
    { NULL },
};

/*
 * This routine gets called at two different points in request processing:
 * once before the URI has been translated (during the post-read-request
 * phase) and once after (during the header-parse phase).  We use different
 * config records for the two different calls to reduce overhead (by not
 * re-doing the server-wide settings during directory processing), and
 * signal which call it is by having the earlier one pass a flag to the
 * later one.
 */
static int match_headers(request_rec *r)
{
    sei_cfg_rec *sconf;
    sei_entry *entries;
    const apr_table_entry_t *elts;
    const char *val, *err;
    apr_size_t val_len = 0;
    int i, j;
    char *last_name;
    ap_regmatch_t regm[AP_MAX_REG_MATCH];

    if (!ap_get_module_config(r->request_config, &setenvif_module)) {
        ap_set_module_config(r->request_config, &setenvif_module,
                             SEI_MAGIC_HEIRLOOM);
        sconf  = (sei_cfg_rec *) ap_get_module_config(r->server->module_config,
                                                      &setenvif_module);
    }
    else {
        sconf = (sei_cfg_rec *) ap_get_module_config(r->per_dir_config,
                                                     &setenvif_module);
    }
    entries = (sei_entry *) sconf->conditionals->elts;
    last_name = NULL;
    val = NULL;
    for (i = 0; i < sconf->conditionals->nelts; ++i) {
        sei_entry *b = &entries[i];

        if (!b->expr) {
            /* Optimize the case where a bunch of directives in a row use the
             * same header.  Remember we don't need to strcmp the two header
             * names because we made sure the pointers were equal during
             * configuration.
             */
            if (b->name != last_name) {
                last_name = b->name;
                switch (b->special_type) {
                case SPECIAL_REMOTE_ADDR:
                    val = r->useragent_ip;
                    break;
                case SPECIAL_SERVER_ADDR:
                    val = r->connection->local_ip;
                    break;
                case SPECIAL_REMOTE_HOST:
                    val =  ap_get_remote_host(r->connection, r->per_dir_config,
                                              REMOTE_NAME, NULL);
                    break;
                case SPECIAL_REQUEST_URI:
                    val = r->uri;
                    break;
                case SPECIAL_REQUEST_METHOD:
                    val = r->method;
                    break;
                case SPECIAL_REQUEST_PROTOCOL:
                    val = r->protocol;
                    break;
                case SPECIAL_NOT:
                    if (b->pnamereg) {
                        /* Matching headers_in against a regex. Iterate through
                         * the headers_in until we find a match or run out of
                         * headers.
                         */
                        const apr_array_header_t
                            *arr = apr_table_elts(r->headers_in);

                        elts = (const apr_table_entry_t *) arr->elts;
                        val = NULL;
                        for (j = 0; j < arr->nelts; ++j) {
                            if (!ap_regexec(b->pnamereg, elts[j].key, 0, NULL, 0)) {
                                val = elts[j].val;
                            }
                        }
                    }
                    else {
                        /* Not matching against a regex */
                        val = apr_table_get(r->headers_in, b->name);
                        if (val == NULL) {
                            val = apr_table_get(r->subprocess_env, b->name);
                        }
                    }
                }
                val_len = val ? strlen(val) : 0;
            }

        }

        /*
         * A NULL value indicates that the header field or special entity
         * wasn't present or is undefined.  Represent that as an empty string
         * so that REs like "^$" will work and allow envariable setting
         * based on missing or empty field. This is also necessary to make
         * ap_pregsub work after evaluating an ap_expr_t which does set the
         * regexp backref data.
         */
        if (val == NULL) {
            val = "";
            val_len = 0;
        }

        if ((b->pattern && apr_strmatch(b->pattern, val, val_len)) ||
            (b->preg && !ap_regexec(b->preg, val, AP_MAX_REG_MATCH, regm, 0)) ||
            (b->expr && ap_expr_exec_re(r, b->expr, AP_MAX_REG_MATCH, regm, &val, &err) > 0))
        {
            const apr_array_header_t *arr = apr_table_elts(b->features);
            elts = (const apr_table_entry_t *) arr->elts;

            for (j = 0; j < arr->nelts; ++j) {
                if (*(elts[j].val) == '!') {
                    apr_table_unset(r->subprocess_env, elts[j].key);
                }
                else {
                    if (!b->pattern) {
                        char *replaced = ap_pregsub(r->pool, elts[j].val, val,
                                                    AP_MAX_REG_MATCH, regm);
                        if (replaced) {
                            apr_table_setn(r->subprocess_env, elts[j].key,
                                           replaced);
                        }
                        else {
                            ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0, r, APLOGNO(01505)
                                          "Regular expression replacement "
                                          "failed for '%s', value too long?",
                                          elts[j].key);
                            return HTTP_INTERNAL_SERVER_ERROR;
                        }
                    }
                    else {
                        apr_table_setn(r->subprocess_env, elts[j].key,
                                       elts[j].val);
                    }
                }
                ap_log_rerror(APLOG_MARK, APLOG_TRACE2, 0, r, "Setting %s",
                              elts[j].key);
            }
        }
    }

    return DECLINED;
}

static void register_hooks(apr_pool_t *p)
{
    ap_hook_header_parser(match_headers, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_post_read_request(match_headers, NULL, NULL, APR_HOOK_MIDDLE);

    is_header_regex_regex = ap_pregcomp(p, "^[-A-Za-z0-9_]*$",
                                        (AP_REG_EXTENDED | AP_REG_NOSUB ));
    ap_assert(is_header_regex_regex != NULL);
}

AP_DECLARE_MODULE(setenvif) =
{
    STANDARD20_MODULE_STUFF,
    create_setenvif_config_dir, /* dir config creater */
    merge_setenvif_config,      /* dir merger --- default is to override */
    create_setenvif_config_svr, /* server config */
    merge_setenvif_config,      /* merge server configs */
    setenvif_module_cmds,       /* command apr_table_t */
    register_hooks              /* register hooks */
};
