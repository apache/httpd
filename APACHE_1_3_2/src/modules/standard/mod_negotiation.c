/* ====================================================================
 * Copyright (c) 1995-1998 The Apache Group.  All rights reserved.
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
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the Apache Group
 *    for use in the Apache HTTP server project (http://www.apache.org/)."
 *
 * 4. The names "Apache Server" and "Apache Group" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    apache@apache.org.
 *
 * 5. Products derived from this software may not be called "Apache"
 *    nor may "Apache" appear in their names without prior written
 *    permission of the Apache Group.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the Apache Group
 *    for use in the Apache HTTP server project (http://www.apache.org/)."
 *
 * THIS SOFTWARE IS PROVIDED BY THE APACHE GROUP ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE APACHE GROUP OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Group and was originally based
 * on public domain software written at the National Center for
 * Supercomputing Applications, University of Illinois, Urbana-Champaign.
 * For more information on the Apache Group and the Apache HTTP server
 * project, please see <http://www.apache.org/>.
 *
 */

/*
 * mod_negotiation.c: keeps track of MIME types the client is willing to
 * accept, and contains code to handle type arbitration.
 *
 * rst
 */

#include "httpd.h"
#include "http_config.h"
#include "http_request.h"
#include "http_core.h"
#include "http_log.h"
#include "util_script.h"

/* define TCN_02 to allow for Holtman I-D transparent negotiation.
 * This file currently implements the draft-02, except for
 * anything to do with features and cache-control (max-age etc)
 *
 * Since the draft is just that, and we don't yet implement
 * everything, regard the transparent negotiation stuff as experimental.
 */
/*#define TCN_02 */

/* Commands --- configuring document caching on a per (virtual?)
 * server basis... 
 */

typedef struct {
    array_header *language_priority;
} neg_dir_config;

module MODULE_VAR_EXPORT negotiation_module;

static char *merge_string_array(pool *p, array_header *arr, char *sep)
{
    int i;
    char *t = "";

    for (i = 0; i < arr->nelts; i++) {
        t = ap_pstrcat(p, t, (i ? sep : ""), ((char **) arr->elts)[i], NULL);
    }
    return t;
}

static void *create_neg_dir_config(pool *p, char *dummy)
{
    neg_dir_config *new = (neg_dir_config *) ap_palloc(p, sizeof(neg_dir_config));

    new->language_priority = ap_make_array(p, 4, sizeof(char *));
    return new;
}

static void *merge_neg_dir_configs(pool *p, void *basev, void *addv)
{
    neg_dir_config *base = (neg_dir_config *) basev;
    neg_dir_config *add = (neg_dir_config *) addv;
    neg_dir_config *new = (neg_dir_config *) ap_palloc(p, sizeof(neg_dir_config));

    /* give priority to the config in the subdirectory */
    new->language_priority = ap_append_arrays(p, add->language_priority,
                                           base->language_priority);
    return new;
}

static const char *set_language_priority(cmd_parms *cmd, void *n, char *lang)
{
    array_header *arr = ((neg_dir_config *) n)->language_priority;
    char **langp = (char **) ap_push_array(arr);

    *langp = lang;
    return NULL;
}

static const char *cache_negotiated_docs(cmd_parms *cmd, void *dummy,
                                         char *dummy2)
{
    void *server_conf = cmd->server->module_config;

    ap_set_module_config(server_conf, &negotiation_module, "Cache");
    return NULL;
}

static int do_cache_negotiated_docs(server_rec *s)
{
    return (ap_get_module_config(s->module_config, &negotiation_module) != NULL);
}

static const command_rec negotiation_cmds[] =
{
    {"CacheNegotiatedDocs", cache_negotiated_docs, NULL, RSRC_CONF, NO_ARGS,
     "no arguments (either present or absent)"},
    {"LanguagePriority", set_language_priority, NULL, OR_FILEINFO, ITERATE,
     "space-delimited list of MIME language abbreviations"},
    {NULL}
};

/*
 * Record of available info on a media type specified by the client
 * (we also use 'em for encodings and languages)
 */

typedef struct accept_rec {
    char *type_name;		/* MUST be lowercase */
    float quality;
    float max_bytes;
    float level;
    char *charset;              /* for content-type only */
} accept_rec;

/*
 * Record of available info on a particular variant
 *
 * Note that a few of these fields are updated by the actual negotiation
 * code.  These are:
 *
 * level_matched --- initialized to zero.  Set to the value of level
 *             if the client actually accepts this media type at that
 *             level (and *not* if it got in on a wildcard).  See level_cmp
 *             below.
 */

typedef struct var_rec {
    request_rec *sub_req;       /* May be NULL (is, for map files) */
    char *type_name;		/* MUST be lowercase */
    char *file_name;
    const char *content_encoding;
    array_header *content_languages;    /* list of languages for this variant */
    char *content_charset;
    char *description;

    /* The next five items give the quality values for the dimensions
     * of negotiation for this variant. They are obtained from the
     * appropriate header lines, except for accept_type_quality, which
     * is obtained from the variant itself (the 'qs' parameter value
     * from the variant's mime-type). Apart from type_quality,
     * these values are set when we find the quality for each variant
     * (see best_match()). type_quality is set from the 'qs' parameter
     * of the variant description or mime type: see set_mime_fields().
     */
    float lang_quality;         /* quality of this variant's language */
    int encoding_quality;       /* ditto encoding (1 or 0 only) */
    float charset_quality;      /* ditto charset */
    float accept_type_quality;  /* ditto media type */
    float type_quality;         /* quality of source for this type */

    /* Now some special values */
    float level;                /* Auxiliary to content-type... */
    float bytes;                /* content length, if known */
    int lang_index;             /* pre HTTP/1.1 language priority stuff */
    int is_pseudo_html;         /* text/html, *or* the INCLUDES_MAGIC_TYPEs */

    /* Above are all written-once properties of the variant.  The
     * three fields below are changed during negotiation:
     */

    float level_matched;
    int mime_stars;
    int definite;
} var_rec;

/* Something to carry around the state of negotiation (and to keep
 * all of this thread-safe)...
 */

typedef struct {
    pool *pool;
    request_rec *r;
    char *dir_name;
    int accept_q;               /* 1 if an Accept item has a q= param */
    float default_lang_quality; /* fiddle lang q for variants with no lang */


    array_header *accepts;      /* accept_recs */
    int have_accept_header;     /* 1 if Accept-Header present */
    array_header *accept_encodings;     /* accept_recs */
    array_header *accept_charsets;      /* accept_recs */
    array_header *accept_langs; /* accept_recs */
    array_header *avail_vars;   /* available variants */

    int count_multiviews_variants;      /* number of variants found on disk */

    int ua_can_negotiate;       /* 1 if ua can do transparent negotiate */
    int use_transparent_neg;    /* 1 if we are using transparent neg */
    int short_accept_headers;   /* 1 if ua does trans neg & sent short accpt */
} negotiation_state;

/* A few functions to manipulate var_recs.
 * Cleaning out the fields...
 */

static void clean_var_rec(var_rec *mime_info)
{
    mime_info->sub_req = NULL;
    mime_info->type_name = "";
    mime_info->file_name = "";
    mime_info->content_encoding = NULL;
    mime_info->content_languages = NULL;
    mime_info->content_charset = "";
    mime_info->description = "";

    mime_info->is_pseudo_html = 0;
    mime_info->level = 0.0f;
    mime_info->level_matched = 0.0f;
    mime_info->bytes = 0.0f;
    mime_info->lang_index = -1;
    mime_info->mime_stars = 0;
    mime_info->definite = 1;

    mime_info->charset_quality = 1.0f;
    mime_info->type_quality = 0.0f;
    mime_info->encoding_quality = 1;
    mime_info->lang_quality = 1.0f;
    mime_info->accept_type_quality = 1.0f;
}

/* Initializing the relevant fields of a variant record from the
 * accept_info read out of its content-type, one way or another.
 */

static void set_mime_fields(var_rec *var, accept_rec *mime_info)
{
    var->type_name = mime_info->type_name;
    var->type_quality = mime_info->quality;
    var->level = mime_info->level;
    var->content_charset = mime_info->charset;

    var->is_pseudo_html = (!strcmp(var->type_name, "text/html")
                           || !strcmp(var->type_name, INCLUDES_MAGIC_TYPE)
                           || !strcmp(var->type_name, INCLUDES_MAGIC_TYPE3));
}

/*****************************************************************
 *
 * Parsing (lists of) media types and their parameters, as seen in
 * HTTPD header lines and elsewhere.
 */

/*
 * Get a single mime type entry --- one media type and parameters;
 * enter the values we recognize into the argument accept_rec
 */

static const char *get_entry(pool *p, accept_rec *result, const char *accept_line)
{
    result->quality = 1.0f;
    result->max_bytes = 0.0f;
    result->level = 0.0f;
    result->charset = "";

    /*
     * Note that this handles what I gather is the "old format",
     *
     *    Accept: text/html text/plain moo/zot
     *
     * without any compatibility kludges --- if the token after the
     * MIME type begins with a semicolon, we know we're looking at parms,
     * otherwise, we know we aren't.  (So why all the pissing and moaning
     * in the CERN server code?  I must be missing something).
     */

    result->type_name = ap_get_token(p, &accept_line, 0);
    ap_str_tolower(result->type_name);     /* You want case-insensitive,
                                         * you'll *get* case-insensitive.
                                         */

    /* KLUDGE!!! Default HTML to level 2.0 unless the browser
     * *explicitly* says something else.
     */

    if (!strcmp(result->type_name, "text/html") && (result->level == 0.0)) {
        result->level = 2.0f;
    }
    else if (!strcmp(result->type_name, INCLUDES_MAGIC_TYPE)) {
        result->level = 2.0f;
    }
    else if (!strcmp(result->type_name, INCLUDES_MAGIC_TYPE3)) {
        result->level = 3.0f;
    }

    while (*accept_line == ';') {
        /* Parameters ... */

        char *parm;
        char *cp;
        char *end;

        ++accept_line;
        parm = ap_get_token(p, &accept_line, 1);

        /* Look for 'var = value' --- and make sure the var is in lcase. */

        for (cp = parm; (*cp && !ap_isspace(*cp) && *cp != '='); ++cp) {
            *cp = ap_tolower(*cp);
        }

        if (!*cp) {
            continue;           /* No '='; just ignore it. */
        }

        *cp++ = '\0';           /* Delimit var */
        while (*cp && (ap_isspace(*cp) || *cp == '=')) {
            ++cp;
        }

        if (*cp == '"') {
            ++cp;
            for (end = cp;
                 (*end && *end != '\n' && *end != '\r' && *end != '\"');
                 end++);
        }
        else {
            for (end = cp; (*end && !ap_isspace(*end)); end++);
        }
        if (*end) {
            *end = '\0';        /* strip ending quote or return */
        }
        ap_str_tolower(cp);

        if (parm[0] == 'q'
            && (parm[1] == '\0' || (parm[1] == 's' && parm[2] == '\0'))) {
            result->quality = atof(cp);
        }
        else if (parm[0] == 'm' && parm[1] == 'x' &&
                 parm[2] == 'b' && parm[3] == '\0') {
            result->max_bytes = atof(cp);
        }
        else if (parm[0] == 'l' && !strcmp(&parm[1], "evel")) {
            result->level = atof(cp);
        }
        else if (!strcmp(parm, "charset")) {
            result->charset = cp;
        }
    }

    if (*accept_line == ',') {
        ++accept_line;
    }

    return accept_line;
}

/*****************************************************************
 *
 * Dealing with header lines ...
 *
 * Accept, Accept-Charset, Accept-Language and Accept-Encoding
 * are handled by do_header_line() - they all have the same
 * basic structure of a list of items of the format
 *    name; q=N; charset=TEXT
 *
 * where q is only valid in Accept, Accept-Charset and Accept-Languages,
 * and charset is only valid in Accept.
 */

static array_header *do_header_line(pool *p, const char *accept_line)
{
    array_header *accept_recs = ap_make_array(p, 40, sizeof(accept_rec));

    if (!accept_line) {
        return accept_recs;
    }

    while (*accept_line) {
        accept_rec *new = (accept_rec *) ap_push_array(accept_recs);
        accept_line = get_entry(p, new, accept_line);
    }

    return accept_recs;
}

/* Given the text of the Content-Languages: line from the var map file,
 * return an array containing the languages of this variant
 */

static array_header *do_languages_line(pool *p, const char **lang_line)
{
    array_header *lang_recs = ap_make_array(p, 2, sizeof(char *));

    if (!lang_line) {
        return lang_recs;
    }

    while (**lang_line) {
        char **new = (char **) ap_push_array(lang_recs);
        *new = ap_get_token(p, lang_line, 0);
        ap_str_tolower(*new);
        if (**lang_line == ',' || **lang_line == ';') {
            ++(*lang_line);
        }
    }

    return lang_recs;
}

/*****************************************************************
 *
 * Handling header lines from clients...
 */

static negotiation_state *parse_accept_headers(request_rec *r)
{
    negotiation_state *new = (negotiation_state *) ap_pcalloc(r->pool,
                                                 sizeof(negotiation_state));
    accept_rec *elts;
    table *hdrs = r->headers_in;
    int i;
    const char *hdr;

    new->pool = r->pool;
    new->r = r;
    new->dir_name = ap_make_dirstr_parent(r->pool, r->filename);

    new->accepts = do_header_line(r->pool, ap_table_get(hdrs, "Accept"));

    hdr = ap_table_get(hdrs, "Accept-encoding");
    if (hdr) {
        new->have_accept_header = 1;
    }
    new->accept_encodings = do_header_line(r->pool, hdr);

    new->accept_langs = do_header_line(r->pool,
                                       ap_table_get(hdrs, "Accept-language"));
    new->accept_charsets = do_header_line(r->pool,
                                          ap_table_get(hdrs, "Accept-charset"));
    new->avail_vars = ap_make_array(r->pool, 40, sizeof(var_rec));

#ifdef TCN_02
    if (ap_table_get(r->headers_in, "Negotiate")) {
        /* Negotiate: header tells us UA does transparent negotiation
         * We have to decide whether we want to ... for now, yes,
         * we do */

        new->ua_can_negotiate = 1;
        if (r->method_number == M_GET) {
            new->use_transparent_neg = 1;       /* should be configurable */
        }

        /* Check for 'Short Accept', ie either no Accept: header,
         * or just "Accept: * / *" */
        if (new->accepts->nelts == 0 ||
            (new->accepts->nelts == 1 &&
             (!strcmp(((accept_rec *) new->accepts->elts)[0].type_name,
                      "*/*")))) {
            /* Using short accept header */
            new->short_accept_headers = 1;
        }
    }
#endif

    if (!new->use_transparent_neg) {
        /* Now we check for q-values. If they're all 1.0, we assume the
         * client is "broken", and we are allowed to fiddle with the
         * values later. Otherwise, we leave them alone.
         */

        elts = (accept_rec *) new->accepts->elts;

        for (i = 0; i < new->accepts->nelts; ++i) {
            if (elts[i].quality < 1.0) {
                new->accept_q = 1;
            }
        }
    }
    else {
        new->accept_q = 1;
    }

    return new;
}

/* Sometimes clients will give us no Accept info at all; this routine sets
 * up the standard default for that case, and also arranges for us to be
 * willing to run a CGI script if we find one.  (In fact, we set up to
 * dramatically prefer CGI scripts in cases where that's appropriate,
 * e.g., POST).
 */

static void maybe_add_default_encodings(negotiation_state *neg, int prefer_scripts)
{
    accept_rec *new_accept = (accept_rec *) ap_push_array(neg->accepts);

    new_accept->type_name = CGI_MAGIC_TYPE;
    new_accept->quality = prefer_scripts ? 1e-20f : 1e20f;
    new_accept->level = 0.0f;
    new_accept->max_bytes = 0.0f;

    if (neg->accepts->nelts > 1) {
        return;
    }

    new_accept = (accept_rec *) ap_push_array(neg->accepts);

    new_accept->type_name = "*/*";
    new_accept->quality = 1.0f;
    new_accept->level = 0.0f;
    new_accept->max_bytes = 0.0f;
}

/*****************************************************************
 *
 * Parsing type-map files, in Roy's meta/http format augmented with
 * #-comments.
 */

/* Reading RFC822-style header lines, ignoring #-comments and
 * handling continuations.
 */

enum header_state {
    header_eof, header_seen, header_sep
};

static enum header_state get_header_line(char *buffer, int len, FILE *map)
{
    char *buf_end = buffer + len;
    char *cp;
    int c;

    /* Get a noncommented line */

    do {
        if (fgets(buffer, MAX_STRING_LEN, map) == NULL) {
            return header_eof;
        }
    } while (buffer[0] == '#');

    /* If blank, just return it --- this ends information on this variant */

    for (cp = buffer; (*cp && ap_isspace(*cp)); ++cp) {
        continue;
    }

    if (*cp == '\0') {
        return header_sep;
    }

    /* If non-blank, go looking for header lines, but note that we still
     * have to treat comments specially...
     */

    cp += strlen(cp);

    while ((c = getc(map)) != EOF) {
        if (c == '#') {
            /* Comment line */
            while ((c = getc(map)) != EOF && c != '\n') {
                continue;
            }
        }
        else if (ap_isspace(c)) {
            /* Leading whitespace.  POSSIBLE continuation line
             * Also, possibly blank --- if so, we ungetc() the final newline
             * so that we will pick up the blank line the next time 'round.
             */

            while (c != EOF && c != '\n' && ap_isspace(c)) {
                c = getc(map);
            }

            ungetc(c, map);

            if (c == '\n') {
                return header_seen;     /* Blank line */
            }

            /* Continuation */

            while (cp < buf_end - 2 && (c = getc(map)) != EOF && c != '\n') {
                *cp++ = c;
            }

            *cp++ = '\n';
            *cp = '\0';
        }
        else {

            /* Line beginning with something other than whitespace */

            ungetc(c, map);
            return header_seen;
        }
    }

    return header_seen;
}

/* Stripping out RFC822 comments */

static void strip_paren_comments(char *hdr)
{
    /* Hmmm... is this correct?  In Roy's latest draft, (comments) can nest! */

    while (*hdr) {
        if (*hdr == '"') {
	    hdr = strchr(hdr, '"');
	    if (hdr == NULL) {
		return;
	    }
	    ++hdr;
        }
        else if (*hdr == '(') {
            while (*hdr && *hdr != ')') {
                *hdr++ = ' ';
            }

            if (*hdr) {
                *hdr++ = ' ';
            }
        }
        else {
            ++hdr;
        }
    }
}

/* Getting to a header body from the header */

static char *lcase_header_name_return_body(char *header, request_rec *r)
{
    char *cp = header;

    for ( ; *cp && *cp != ':' ; ++cp) {
        *cp = ap_tolower(*cp);
    }

    if (!*cp) {
        ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
                    "Syntax error in type map --- no ':': %s", r->filename);
        return NULL;
    }

    do {
        ++cp;
    } while (*cp && ap_isspace(*cp));

    if (!*cp) {
        ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
                    "Syntax error in type map --- no header body: %s",
                    r->filename);
        return NULL;
    }

    return cp;
}

static int read_type_map(negotiation_state *neg, request_rec *rr)
{
    request_rec *r = neg->r;
    FILE *map;
    char buffer[MAX_STRING_LEN];
    enum header_state hstate;
    struct var_rec mime_info;

    /* We are not using multiviews */
    neg->count_multiviews_variants = 0;

    map = ap_pfopen(neg->pool, rr->filename, "r");
    if (map == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, r,
                    "cannot access type map file: %s", rr->filename);
        return HTTP_FORBIDDEN;
    }

    clean_var_rec(&mime_info);

    do {
        hstate = get_header_line(buffer, MAX_STRING_LEN, map);

        if (hstate == header_seen) {
            char *body1 = lcase_header_name_return_body(buffer, neg->r);
	    const char *body;

            if (body1 == NULL) {
                return SERVER_ERROR;
            }

            strip_paren_comments(body1);
	    body=body1;

            if (!strncmp(buffer, "uri:", 4)) {
                mime_info.file_name = ap_get_token(neg->pool, &body, 0);
            }
            else if (!strncmp(buffer, "content-type:", 13)) {
                struct accept_rec accept_info;

                get_entry(neg->pool, &accept_info, body);
                set_mime_fields(&mime_info, &accept_info);
            }
            else if (!strncmp(buffer, "content-length:", 15)) {
                mime_info.bytes = atof(body);
            }
            else if (!strncmp(buffer, "content-language:", 17)) {
                mime_info.content_languages = do_languages_line(neg->pool,
                                                                &body);
            }
            else if (!strncmp(buffer, "content-encoding:", 17)) {
                mime_info.content_encoding = ap_get_token(neg->pool, &body, 0);
            }
            else if (!strncmp(buffer, "description:", 12)) {
                mime_info.description = ap_get_token(neg->pool, &body, 0);
            }
        }
        else {
            if (mime_info.type_quality > 0 && *mime_info.file_name) {
                void *new_var = ap_push_array(neg->avail_vars);

                memcpy(new_var, (void *) &mime_info, sizeof(var_rec));
            }

            clean_var_rec(&mime_info);
        }
    } while (hstate != header_eof);

    ap_pfclose(neg->pool, map);
    return OK;
}

/*****************************************************************
 *
 * Same, except we use a filtered directory listing as the map...
 */

static int read_types_multi(negotiation_state *neg)
{
    request_rec *r = neg->r;

    char *filp;
    int prefix_len;
    DIR *dirp;
    struct DIR_TYPE *dir_entry;
    struct var_rec mime_info;
    struct accept_rec accept_info;
    void *new_var;

    clean_var_rec(&mime_info);

    if (!(filp = strrchr(r->filename, '/'))) {
        return DECLINED;        /* Weird... */
    }

    if (strncmp(r->filename, "proxy:", 6) == 0) {
        return DECLINED;
    }

    ++filp;
    prefix_len = strlen(filp);

    dirp = ap_popendir(neg->pool, neg->dir_name);

    if (dirp == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, r,
                    "cannot read directory for multi: %s", neg->dir_name);
        return HTTP_FORBIDDEN;
    }

    while ((dir_entry = readdir(dirp))) {
        request_rec *sub_req;

        /* Do we have a match? */

        if (strncmp(dir_entry->d_name, filp, prefix_len)) {
            continue;
        }
        if (dir_entry->d_name[prefix_len] != '.') {
            continue;
        }

        /* Yep.  See if it's something which we have access to, and 
         * which has a known type and encoding (as opposed to something
         * which we'll be slapping default_type on later).
         */

        sub_req = ap_sub_req_lookup_file(dir_entry->d_name, r);

        /* If it has a handler, we'll pretend it's a CGI script,
         * since that's a good indication of the sort of thing it
         * might be doing.
         */
        if (sub_req->handler && !sub_req->content_type) {
            sub_req->content_type = CGI_MAGIC_TYPE;
        }

        if (sub_req->status != HTTP_OK || !sub_req->content_type) {
            ap_destroy_sub_req(sub_req);
            continue;
        }

        /* If it's a map file, we use that instead of the map
         * we're building...
         */

        if (((sub_req->content_type) &&
             !strcmp(sub_req->content_type, MAP_FILE_MAGIC_TYPE)) ||
            ((sub_req->handler) &&
             !strcmp(sub_req->handler, "type-map"))) {

            ap_pclosedir(neg->pool, dirp);
            neg->avail_vars->nelts = 0;
	    if (sub_req->status != HTTP_OK) {
		return sub_req->status;
	    }
            return read_type_map(neg, sub_req);
        }

        /* Have reasonable variant --- gather notes.
         */

        mime_info.sub_req = sub_req;
        mime_info.file_name = ap_pstrdup(neg->pool, dir_entry->d_name);
        if (sub_req->content_encoding) {
            mime_info.content_encoding = sub_req->content_encoding;
        }
        if (sub_req->content_languages) {
            mime_info.content_languages = sub_req->content_languages;
        }

        get_entry(neg->pool, &accept_info, sub_req->content_type);
        set_mime_fields(&mime_info, &accept_info);

        new_var = ap_push_array(neg->avail_vars);
        memcpy(new_var, (void *) &mime_info, sizeof(var_rec));

        neg->count_multiviews_variants++;

        clean_var_rec(&mime_info);
    }

    ap_pclosedir(neg->pool, dirp);
    return OK;
}


/*****************************************************************
 * And now for the code you've been waiting for... actually
 * finding a match to the client's requirements.
 */

/* Matching MIME types ... the star/star and foo/star commenting conventions
 * are implemented here.  (You know what I mean by star/star, but just
 * try mentioning those three characters in a C comment).  Using strcmp()
 * is legit, because everything has already been smashed to lowercase.
 *
 * Note also that if we get an exact match on the media type, we update
 * level_matched for use in level_cmp below...
 * 
 * We also give a value for mime_stars, which is used later. It should
 * be 1 for star/star, 2 for type/star and 3 for type/subtype.
 */

static int mime_match(accept_rec *accept_r, var_rec *avail)
{
    char *accept_type = accept_r->type_name;
    char *avail_type = avail->type_name;
    int len = strlen(accept_type);

    if (accept_type[0] == '*') {        /* Anything matches star/star */
        if (avail->mime_stars < 1) {
            avail->mime_stars = 1;
        }
        return 1;
    }
    else if ((accept_type[len - 1] == '*') &&
             !strncmp(accept_type, avail_type, len - 2)) {
        if (avail->mime_stars < 2) {
            avail->mime_stars = 2;
        }
        return 1;
    }
    else if (!strcmp(accept_type, avail_type)
             || (!strcmp(accept_type, "text/html")
                 && (!strcmp(avail_type, INCLUDES_MAGIC_TYPE)
                     || !strcmp(avail_type, INCLUDES_MAGIC_TYPE3)))) {
        if (accept_r->level >= avail->level) {
            avail->level_matched = avail->level;
            avail->mime_stars = 3;
            return 1;
        }
    }

    return OK;
}

/* This code implements a piece of the tie-breaking algorithm between
 * variants of equal quality.  This piece is the treatment of variants
 * of the same base media type, but different levels.  What we want to
 * return is the variant at the highest level that the client explicitly
 * claimed to accept.
 *
 * If all the variants available are at a higher level than that, or if
 * the client didn't say anything specific about this media type at all
 * and these variants just got in on a wildcard, we prefer the lowest
 * level, on grounds that that's the one that the client is least likely
 * to choke on.
 *
 * (This is all motivated by treatment of levels in HTML --- we only
 * want to give level 3 to browsers that explicitly ask for it; browsers
 * that don't, including HTTP/0.9 browsers that only get the implicit
 * "Accept: * / *" [space added to avoid confusing cpp --- no, that
 * syntax doesn't really work] should get HTML2 if available).
 *
 * (Note that this code only comes into play when we are choosing among
 * variants of equal quality, where the draft standard gives us a fair
 * bit of leeway about what to do.  It ain't specified by the standard;
 * rather, it is a choice made by this server about what to do in cases
 * where the standard does not specify a unique course of action).
 */

static int level_cmp(var_rec *var1, var_rec *var2)
{
    /* Levels are only comparable between matching media types */

    if (var1->is_pseudo_html && !var2->is_pseudo_html) {
        return 0;
    }

    if (!var1->is_pseudo_html && strcmp(var1->type_name, var2->type_name)) {
        return 0;
    }

    /* Take highest level that matched, if either did match. */

    if (var1->level_matched > var2->level_matched) {
        return 1;
    }
    if (var1->level_matched < var2->level_matched) {
        return -1;
    }

    /* Neither matched.  Take lowest level, if there's a difference. */

    if (var1->level < var2->level) {
        return 1;
    }
    if (var1->level > var2->level) {
        return -1;
    }

    /* Tied */

    return 0;
}

/* Finding languages.  The main entry point is set_language_quality()
 * which is called for each variant. It sets two elements in the
 * variant record:
 *    language_quality  - the 'q' value of the 'best' matching language
 *                        from Accept-Language: header (HTTP/1.1)
 *    lang_index    -     Pre HTTP/1.1 language priority, using
 *                        position of language on the Accept-Language:
 *                        header, if present, else LanguagePriority
 *                        directive order.
 *
 * When we do the variant checking for best variant, we use language
 * quality first, and if a tie, language_index next (this only
 * applies when _not_ using the network algorithm). If using
 * network algorithm, lang_index is never used.
 *
 * set_language_quality() calls find_lang_index() and find_default_index()
 * to set lang_index.
 */

static int find_lang_index(array_header *accept_langs, char *lang)
{
    accept_rec *accs;
    int i;

    if (!lang) {
        return -1;
    }

    accs = (accept_rec *) accept_langs->elts;

    for (i = 0; i < accept_langs->nelts; ++i) {
        if (!strncmp(lang, accs[i].type_name, strlen(accs[i].type_name))) {
            return i;
        }
    }

    return -1;
}

/* This function returns the priority of a given language
 * according to LanguagePriority.  It is used in case of a tie
 * between several languages.
 */

static int find_default_index(neg_dir_config *conf, char *lang)
{
    array_header *arr;
    int nelts;
    char **elts;
    int i;

    if (!lang) {
        return -1;
    }

    arr = conf->language_priority;
    nelts = arr->nelts;
    elts = (char **) arr->elts;

    for (i = 0; i < nelts; ++i) {
        if (!strcasecmp(elts[i], lang)) {
            return i;
        }
    }

    return -1;
}

/* set_default_lang_quality() sets the quality we apply to variants
 * which have no language assigned to them. If none of the variants
 * have a language, we are not negotiating on language, so all are
 * acceptable, and we set the default q value to 1.0. However if
 * some of the variants have languages, we set this default to 0.001.
 * The value of this default will be applied to all variants with
 * no explicit language -- which will have the effect of making them
 * acceptable, but only if no variants with an explicit language
 * are acceptable. The default q value set here is assigned to variants
 * with no language type in set_language_quality().
 *
 * Note that if using the transparent negotiation network algorythm,
 * we don't use this fiddle.
 */

static void set_default_lang_quality(negotiation_state *neg)
{
    var_rec *avail_recs = (var_rec *) neg->avail_vars->elts;
    int j;

    if (!neg->use_transparent_neg) {
        for (j = 0; j < neg->avail_vars->nelts; ++j) {
            var_rec *variant = &avail_recs[j];
            if (variant->content_languages &&
                variant->content_languages->nelts) {
                neg->default_lang_quality = 0.001f;
                return;
            }
        }
    }

    neg->default_lang_quality = 1.0f;
}

/* Set the language_quality value in the variant record. Also
 * assigns lang_index for back-compat. 
 *
 * To find the language_quality value, we look for the 'q' value
 * of the 'best' matching language on the Accept-Language:
 * header. The'best' match is the language on Accept-Language:
 * header which matches the language of this variant either fully,
 * or as far as the prefix marker (-). If two or more languages
 * match, use the longest string from the Accept-Language: header
 * (see HTTP/1.1 [14.4])
 *
 * When a variant has multiple languages, we find the 'best'
 * match for each variant language tag as above, then select the
 * one with the highest q value. Because both the accept-header
 * and variant can have multiple languages, we now have a hairy
 * loop-within-a-loop here.
 *
 * If the variant has no language and we have no Accept-Language
 * items, leave the quality at 1.0 and return.
 *
 * If the variant has no language, we use the default as set by
 * set_default_lang_quality() (1.0 if we are not negotiating on
 * language, 0.001 if we are).
 *
 * Following the setting of the language quality, we drop through to
 * set the old 'lang_index'. This is set based on either the order
 * of the languages on the Accept-Language header, or the
 * order on the LanguagePriority directive. This is only used
 * in the negotiation if the language qualities tie.
 */

static void set_language_quality(negotiation_state *neg, var_rec *variant)
{
    int i;
    int naccept = neg->accept_langs->nelts;
    int idx;
    neg_dir_config *conf = NULL;
    char *firstlang;

    if (naccept == 0) {
        conf = (neg_dir_config *) ap_get_module_config(neg->r->per_dir_config,
                                                    &negotiation_module);
    }

    if (naccept == 0 && (!variant->content_languages ||
                         !variant->content_languages->nelts)) {
        return;                 /* no accept-language and no variant lang */
    }

    if (!variant->content_languages || !variant->content_languages->nelts) {
        /* This variant has no content-language, so use the default
         * quality factor for variants with no content-language
         * (previously set by set_default_lang_quality()). */
        variant->lang_quality = neg->default_lang_quality;

        if (naccept == 0) {
            return;             /* no accept-language items */
        }

    }
    else if (naccept) {
        /* Variant has one (or more) languages, and we have one (or more)
         * language ranges on the Accept-Language header. Look for
         * the best match. We do this by going through each language
         * on the variant description looking for a match on the
         * Accept-Language header. The best match is the longest matching
         * language on the header. The final result is the best q value
         * from all the languages on the variant description.
         */
        int j;
        float fiddle_q = 0.0f;
        accept_rec *accs = (accept_rec *) neg->accept_langs->elts;
        accept_rec *best = NULL, *star = NULL;
        char *p;

        for (j = 0; j < variant->content_languages->nelts; ++j) {
            char *lang;         /* language from variant description */
            accept_rec *bestthistag = NULL;
            int prefixlen = 0;
            int longest_lang_range_len = 0;
            int len;

            /* lang is the variant's language-tag, which is the one
             * we are allowed to use the prefix of in HTTP/1.1
             */
            lang = ((char **) (variant->content_languages->elts))[j];
            p = strchr(lang, '-');      /* find prefix part (if any) */
            if (p) {
                prefixlen = p - lang;
            }

            /* now find the best (i.e. longest) matching Accept-Language
             * header language. We put the best match for this tag in 
             * bestthistag. We cannot update the overall best (based on
             * q value) because the best match for this tag is the longest
             * language item on the accept header, not necessarily the
             * highest q.
             */
            for (i = 0; i < neg->accept_langs->nelts; ++i) {
                if (!strcmp(accs[i].type_name, "*")) {
                    if (!star) {
                        star = &accs[i];
                    }
                    continue;
                }

                /* Find language. We match if either the variant language
                 * tag exactly matches, or the prefix of the tag up to the
                 * '-' character matches the whole of the language in the
                 * Accept-Language header. We only use this accept-language
                 * item as the best match for the current tag if it
                 * is longer than the previous best match */
                if ((!strcmp(lang, accs[i].type_name) ||
                     (prefixlen &&
                      !strncmp(lang, accs[i].type_name, prefixlen) &&
                      (accs[i].type_name[prefixlen] == '\0'))) &&
                    ((len = strlen(accs[i].type_name)) >
                     longest_lang_range_len)) {
                    longest_lang_range_len = len;
                    bestthistag = &accs[i];
                }

                if (!bestthistag) {
                    /* The next bit is a fiddle. Some browsers might be
                     * configured to send more specific language ranges
                     * than desirable. For example, an Accept-Language of
                     * en-US should never match variants with languages en
                     * or en-GB. But US English speakers might pick en-US
                     * as their language choice.  So this fiddle checks if
                     * the language range has a prefix, and if so, it
                     * matches variants which match that prefix with a
                     * priority of 0.001. So a request for en-US would
                     * match variants of types en and en-GB, but at much
                     * lower priority than matches of en-US directly, or
                     * of any other language listed on the Accept-Language
                     * header
                     */
                    if ((p = strchr(accs[i].type_name, '-'))) {
                        int plen = p - accs[i].type_name;
                        if (!strncmp(lang, accs[i].type_name, plen)) {
                            fiddle_q = 0.001f;
                        }
                    }
                }
            }
            /* Finished looking at Accept-Language headers, the best
             * (longest) match is in bestthistag, or NULL if no match
             */
            if (!best ||
                (bestthistag && bestthistag->quality > best->quality)) {
                best = bestthistag;
            }
        }

        variant->lang_quality = best
            ? best->quality
            : (star ? star->quality : fiddle_q);
    }

    /* Now set the old lang_index field. Since this is old 
     * stuff anyway, don't both with handling multiple languages
     * per variant, just use the first one assigned to it
     */
    idx = 0;
    if (variant->content_languages && variant->content_languages->nelts) {
        firstlang = ((char **) variant->content_languages->elts)[0];
    }
    else {
        firstlang = "";
    }
    if (naccept == 0) {         /* Client doesn't care */
        idx = find_default_index(conf, firstlang);
    }
    else {                      /* Client has Accept-Language */
        idx = find_lang_index(neg->accept_langs, firstlang);
    }
    variant->lang_index = idx;

    return;
}

/* Determining the content length --- if the map didn't tell us,
 * we have to do a stat() and remember for next time.
 *
 * Grump.  For Apache, even the first stat here may well be
 * redundant (for multiviews) with a stat() done by the sub_req
 * machinery.  At some point, that ought to be fixed.
 */

static float find_content_length(negotiation_state *neg, var_rec *variant)
{
    struct stat statb;

    if (variant->bytes == 0) {
        char *fullname = ap_make_full_path(neg->pool, neg->dir_name,
                                        variant->file_name);

        if (stat(fullname, &statb) >= 0) {
            /* Note, precision may be lost */
            variant->bytes = (float) statb.st_size;
        }
    }

    return variant->bytes;
}

/* For a given variant, find the best matching Accept: header
 * and assign the Accept: header's quality value to the
 * accept_type_quality field of the variant, for later use in
 * determining the best matching variant.
 */

static void set_accept_quality(negotiation_state *neg, var_rec *variant)
{
    int i;
    accept_rec *accept_recs = (accept_rec *) neg->accepts->elts;
    float q = 0.0f;
    int q_definite = 1;

    /* if no Accept: header, leave quality alone (will
     * remain at the default value of 1) */
    if (!neg->accepts || neg->accepts->nelts == 0) {
        return;
    }

    /*
     * Go through each of the ranges on the Accept: header,
     * looking for the 'best' match with this variant's
     * content-type. We use the best match's quality
     * value (from the Accept: header) for this variant's
     * accept_type_quality field.
     *
     * The best match is determined like this:
     *    type/type is better than type/ * is better than * / *
     *    if match is type/type, use the level mime param if available
     */
    for (i = 0; i < neg->accepts->nelts; ++i) {

        accept_rec *type = &accept_recs[i];
        int prev_mime_stars;

        prev_mime_stars = variant->mime_stars;

        if (!mime_match(type, variant)) {
            continue;           /* didn't match the content type at all */
        }
        else {
            /* did match - see if there were less or more stars than
             * in previous match
             */
            if (prev_mime_stars == variant->mime_stars) {
                continue;       /* more stars => not as good a match */
            }
        }

        /* Check maxbytes -- not in HTTP/1.1 or Holtman */

        if (type->max_bytes > 0
            && (find_content_length(neg, variant) > type->max_bytes)) {
            continue;
        }

        /* If we are allowed to mess with the q-values,
         * make wildcards very low, so we have a low chance
         * of ending up with them if there's something better.
         */

        if (!neg->accept_q && variant->mime_stars == 1) {
            q = 0.01f;
        }
        else if (!neg->accept_q && variant->mime_stars == 2) {
            q = 0.02f;
        }
        else {
            q = type->quality;
        }

        q_definite = (variant->mime_stars == 3);
    }
    variant->accept_type_quality = q;
    variant->definite = variant->definite && q_definite;

    /* if the _best_ quality we got for this variant was 0.0,
     * eliminate it now */
}

/* For a given variant, find the 'q' value of the charset given
 * on the Accept-Charset line. If not charsets are listed,
 * assume value of '1'.
 */

static void set_charset_quality(negotiation_state *neg, var_rec *variant)
{
    int i;
    accept_rec *accept_recs = (accept_rec *) neg->accept_charsets->elts;
    char *charset = variant->content_charset;
    accept_rec *star = NULL;

    /* if no Accept-Charset: header, leave quality alone (will
     * remain at the default value of 1) */
    if (!neg->accept_charsets || neg->accept_charsets->nelts == 0) {
        return;
    }

    if (charset == NULL || !*charset) {
        charset = "iso-8859-1";
    }

    /*
     * Go through each of the items on the Accept-Charset: header,
     * looking for a match with this variant's charset. If none
     * match, charset is unacceptable, so set quality to 0.
     */
    for (i = 0; i < neg->accept_charsets->nelts; ++i) {

        accept_rec *type = &accept_recs[i];

        if (!strcmp(type->type_name, charset)) {
            variant->charset_quality = type->quality;
            return;
        }
        else if (strcmp(type->type_name, "*") == 0) {
            star = type;
        }
    }
    /* No explicit match */
    if (star) {
        variant->charset_quality = star->quality;
        return;
    }
    /* If this variant is in charset iso-8859-1, the default is 1.0 */
    if (strcmp(charset, "iso-8859-1") == 0) {
        variant->charset_quality = 1.0f;
    }
    else {
        variant->charset_quality = 0.0f;
    }
}

/* For a given variant, find the best matching Accept: header
 * and assign the Accept: header's quality value to the
 * accept_type_quality field of the variant, for later use in
 * determining the best matching variant.
 */

/* is_identity_encoding is included for back-compat, but does anyone
 * use 7bit, 8bin or binary in their var files??
 */

static int is_identity_encoding(const char *enc)
{
    return (!enc || !enc[0] || !strcmp(enc, "7bit") || !strcmp(enc, "8bit")
            || !strcmp(enc, "binary"));
}

static void set_encoding_quality(negotiation_state *neg, var_rec *variant)
{
    int i;
    accept_rec *accept_recs = (accept_rec *) neg->accept_encodings->elts;
    const char *enc = variant->content_encoding;

    if (!enc || is_identity_encoding(enc)) {
        return;
    }

    /* if no Accept: header, leave quality alone (will
     * remain at the default value of 1) */
    if (neg->accept_encodings->nelts == 0) {
        /* If we had an empty Accept-Encoding header, assume that
         * no encodings are acceptable, else all encodings are ok */
        variant->encoding_quality = neg->have_accept_header ? 0 : 1;
        return;
    }

    /* Go through each of the encodings on the Accept-Encoding: header,
     * looking for a match with our encoding. x- prefixes are ignored.
     */
    if (enc[0] == 'x' && enc[1] == '-') {
        enc += 2;
    }
    for (i = 0; i < neg->accept_encodings->nelts; ++i) {
        char *name = accept_recs[i].type_name;

        if (name[0] == 'x' && name[1] == '-') {
            name += 2;
        }

        if (!strcmp(name, enc)) {
            variant->encoding_quality = 1;
            return;
        }
    }

    /* Encoding not found on Accept-Encoding: header, so it is
     * _not_ acceptable */
    variant->encoding_quality = 0;
}

/* Possible results of the network algorithm */
enum algorithm_results {
    na_not_applied = -1,        /* net algorithm not used */
    na_choice = 1,              /* choose variant */
    na_list                     /* list variants */
};

/*
 * This is a heavily-rewritten 'best_match' function. For a start, it
 * now returns an int, which has one of the three values: na_not_applied,
 * na_choice or na_list, which give the result of the network algorithm
 * (if it was not applied, the return value is na_not_applied).
 * The best variable is returned in *pbest. It also has two possible
 * algorithms for determining the best match: the network algorithm,
 * and the standard Apache algorithm. These are split out into
 * separate functions (is_variant_better_na() and is_variant_better()).
 *
 * Previously, best_match iterated first through the content_types
 * in the Accept: header, then checked each variant, and eliminated
 * those that didn't match the variant's type. We cannot do this because
 * we need full information, including language, charset, etc
 * quality for _every_ variant, for the Alternates: header,
 * and (possibly) the human-readable choice responses or 406 errors.
 *
 * After the 'best' (if any) is determined, the overall result of
 * the negotiation is obtained. If the network algorithm was not
 * in use, the result is na_not_applied. Else the result is
 * na_list if 'short accept header' is in use, else na_list
 * if _no_ best match was found, or na_choice if a best match
 * was found.
 */

/* Firstly, the negotiation 'network algorithm' from Holtman.
 */

static int is_variant_better_na(negotiation_state *neg, var_rec *variant,
                                var_rec *best, float *p_bestq)
{
    float bestq = *p_bestq, q;

    /* Note: Encoding is not negotiated in the Holtman
     * transparent neg draft, so we ignored it here. But
     * it does mean we could return encodings the UA
     * or proxy cannot handle. Eek. */

    q = variant->accept_type_quality *
        variant->type_quality *
        variant->charset_quality *
        variant->lang_quality;

#ifdef NEG_DEBUG
    fprintf(stderr, "Variant: file=%s type=%s lang=%s acceptq=%1.3f "
            "langq=%1.3f typeq=%1.3f q=%1.3f definite=%d\n",
            (variant->file_name ? variant->file_name : ""),
            (variant->type_name ? variant->type_name : ""),
            (variant->content_languages
             ? merge_string_array(neg->pool, variant->content_languages, ",")
             : ""),
            variant->accept_type_quality,
            variant->lang_quality,
            variant->type_quality,
            q,
            variant->definite);
#endif

    if (q > bestq) {
        *p_bestq = q;
        return 1;
    }
    if (q == bestq) {
        /* If the best variant's charset is ISO-8859-1 and this variant has
         * the same charset quality, then we prefer this variant
         */
        if (variant->charset_quality == best->charset_quality &&
            (variant->content_charset != NULL &&
             *variant->content_charset != '\0' &&
             strcmp(variant->content_charset, "iso-8859-1") != 0) &&
            (best->content_charset == NULL ||
             *best->content_charset == '\0' ||
             strcmp(best->content_charset, "iso-8859-1") == 0)) {
            *p_bestq = q;
            return 1;
        }
    }
    return 0;
}

/* Negotiation algorithm as used by previous versions of Apache
 * (just about). 
 */

static int is_variant_better(negotiation_state *neg, var_rec *variant, var_rec *best, float *p_bestq)
{
    float bestq = *p_bestq, q;
    int levcmp;

    /*
     * For non-transparent negotiation, server can choose how
     * to handle the negotiation. We'll use the following in
     * order: content-type, language, content-type level, charset,
     * content length.
     *
     * For each check, we have three possible outcomes:
     *   This variant is worse than current best: return 0
     *   This variant is better than the current best:
     *          assign this variant's q to *p_bestq, and return 1
     *   This variant is just as desirable as the current best:
     *          drop through to the next test.
     *
     * This code is written in this long-winded way to allow future
     * customisation, either by the addition of additional
     * checks, or to allow the order of the checks to be determined
     * by configuration options (e.g. we might prefer to check
     * language quality _before_ content type).
     */

    /* First though, eliminate this variant if it is not
     * acceptable by type, charset, encoding or language.
     */

    if (variant->encoding_quality == 0 ||
        variant->lang_quality == 0 ||
        variant->type_quality == 0 ||
        variant->charset_quality == 0 ||
        variant->accept_type_quality == 0) {
        return 0;               /* don't consider unacceptables */
    }

    q = variant->accept_type_quality * variant->type_quality;
    if (q == 0.0 || q < bestq) {
        return 0;
    }
    if (q > bestq || !best) {
        *p_bestq = q;
        return 1;
    }

    /* language */
    if (variant->lang_quality < best->lang_quality) {
        return 0;
    }
    if (variant->lang_quality > best->lang_quality) {
        *p_bestq = q;
        return 1;
    }

    /* if language qualities were equal, try the LanguagePriority
     * stuff */
    if (best->lang_index != -1 && variant->lang_index > best->lang_index) {
        return 0;
    }
    if (variant->lang_index != -1 &&
        (variant->lang_index < best->lang_index || best->lang_index == -1)) {
        *p_bestq = q;
        return 1;
    }

    /* content-type level (text/html only?) */
    levcmp = level_cmp(variant, best);
    if (levcmp == -1) {
        return 0;
    }
    if (levcmp == 1) {
        *p_bestq = q;
        return 1;
    }

    /* encoding -- can only be 1 or 0, and if 0 we eliminated this
     * variant at the start of this function. However we 
     * prefer variants with no encoding over those with encoding */
    if (best->content_encoding == NULL && variant->content_encoding) {
        return 0;
    }
    if (best->content_encoding && variant->content_encoding == NULL) {
        *p_bestq = q;
        return 1;
    }

    /* charset */
    if (variant->charset_quality < best->charset_quality) {
        return 0;
    }
    /* If the best variant's charset is ISO-8859-1 and this variant has
     * the same charset quality, then we prefer this variant
     */
    if (variant->charset_quality > best->charset_quality ||
        ((variant->content_charset != NULL &&
          *variant->content_charset != '\0' &&
          strcmp(variant->content_charset, "iso-8859-1") != 0) &&
         (best->content_charset == NULL ||
          *best->content_charset == '\0' ||
          strcmp(best->content_charset, "iso-8859-1") == 0))) {
        *p_bestq = q;
        return 1;
    }


    /* content length if all else equal */
    if (find_content_length(neg, variant) >= find_content_length(neg, best)) {
        return 0;
    }

    /* ok, to get here means every thing turned out equal, except
     * we have a shorter content length, so use this variant */
    *p_bestq = q;
    return 1;
}

static int best_match(negotiation_state *neg, var_rec **pbest)
{
    int j;
    var_rec *best = NULL;
    float bestq = 0.0f;
    enum algorithm_results algorithm_result = na_not_applied;

    var_rec *avail_recs = (var_rec *) neg->avail_vars->elts;

    set_default_lang_quality(neg);

    /*
     * Find the 'best' variant
     */

    for (j = 0; j < neg->avail_vars->nelts; ++j) {
        var_rec *variant = &avail_recs[j];

        /* Find all the relevant 'quality' values from the
         * Accept... headers, and store in the variant
         */
        set_accept_quality(neg, variant);
        set_language_quality(neg, variant);
        set_encoding_quality(neg, variant);
        set_charset_quality(neg, variant);

        /* Now find out if this variant is better than the current
         * best, either using the network algorithm, or Apache's
         * internal server-driven algorithm. Presumably other
         * server-driven algorithms are possible, and could be
         * implemented here.
         */

        if (neg->use_transparent_neg) {
            if (is_variant_better_na(neg, variant, best, &bestq)) {
                best = variant;
            }
        }
        else {
            if (is_variant_better(neg, variant, best, &bestq)) {
                best = variant;
            }
        }
    }

    /* We now either have a best variant, or no best variant 
     */
    if (neg->use_transparent_neg) {
        if (neg->short_accept_headers) {
            algorithm_result = na_list;
        }
        else {
            /* From Holtman, result is:
             *   If variant & URI are not neigbors, list_ua or list_os
             *   Else
             *     If UA can do trans neg
             *        IF best is definite && best q > 0, choice_ua 
             *        ELSE                               list_ua
             *     ELSE
             *        IF best q > 0, choose_os
             *        ELSE           list_os (or forward_os on proxy)
             */

            /* assume variant and URI are neigbors (since URI in
             * var map must be in same directory) */

            if (neg->use_transparent_neg) {
                algorithm_result = (best && best->definite) && (bestq > 0)
                    ? na_choice : na_list;
            }
            else {
                algorithm_result = bestq > 0 ? na_choice : na_list;
            }
        }
    }

    *pbest = best;
    return algorithm_result;
}

/*
 * Sets the Alternates and Vary headers, used if we are going to
 * return 406 Not Acceptable status, a 300 Multiple Choice status,
 * or a Choice response.
 *
 * 'type' is the result of the network algorithm, if applied.
 * We do different things if the network algorithm was not applied
 * (type == na_not_applied): no Alternates header, and Vary:
 * does not include 'negotiate'.
 *
 * We should also add a max-age lifetime for the Alternates header,
 * but how long we we give it? Presumably this should be
 * configurable in the map file.
 */

static void set_neg_headers(request_rec *r, negotiation_state *neg,
                            int na_result)
{
    int j;
    var_rec *avail_recs = (var_rec *) neg->avail_vars->elts;
    char *sample_type = NULL;
    char *sample_language = NULL;
    const char *sample_encoding = NULL;
    char *sample_charset = NULL;
    int vary_by_type = 0;
    int vary_by_language = 0;
    int vary_by_charset = 0;
    int vary_by_encoding = 0;
    table *hdrs;

    /* Put headers into err_headers_out, new send_http_header()
     * outputs both headers_out and err_headers_out */
    hdrs = r->err_headers_out;

    for (j = 0; j < neg->avail_vars->nelts; ++j) {
        var_rec *variant = &avail_recs[j];
        char *rec;
        char qstr[6];
        long len;
        char lenstr[22];        /* enough for 2^64 */

        ap_snprintf(qstr, sizeof(qstr), "%1.3f", variant->type_quality);

        /* Strip trailing zeros (saves those valuable network bytes) */
        if (qstr[4] == '0') {
            qstr[4] = '\0';
            if (qstr[3] == '0') {
                qstr[3] = '\0';
                if (qstr[2] == '0') {
                    qstr[1] = '\0';
                }
            }
        }

        rec = ap_pstrcat(r->pool, "{\"", variant->file_name, "\" ", qstr, NULL);
        if (variant->type_name) {
            if (*variant->type_name) {
                rec = ap_pstrcat(r->pool, rec, " {type ",
                              variant->type_name, "}", NULL);
            }
            if (!sample_type) {
                sample_type = variant->type_name;
            }
            else if (strcmp(sample_type, variant->type_name)) {
                vary_by_type = 1;
            }
        }
        if (variant->content_languages && variant->content_languages->nelts) {
            char *langs = merge_string_array(r->pool,
                                           variant->content_languages, ",");
            rec = ap_pstrcat(r->pool, rec, " {language ", langs, "}", NULL);
            if (!sample_language) {
                sample_language = langs;
            }
            else if (strcmp(sample_language, langs)) {
                vary_by_language = 1;
            }
        }
        if (variant->content_encoding) {
            if (!sample_encoding) {
                sample_encoding = variant->content_encoding;
            }
            else if (strcmp(sample_encoding, variant->content_encoding)) {
                vary_by_encoding = 1;
            }
        }
        if (variant->content_charset) {
            if (*variant->content_charset) {
                rec = ap_pstrcat(r->pool, rec, " {charset ",
                              variant->content_charset, "}", NULL);
            }
            if (!sample_charset) {
                sample_charset = variant->content_charset;
            }
            else if (strcmp(sample_charset, variant->content_charset)) {
                vary_by_charset = 1;
            }
        }
        if ((len = find_content_length(neg, variant)) != 0) {
            ap_snprintf(lenstr, sizeof(lenstr), "%ld", len);
            rec = ap_pstrcat(r->pool, rec, " {length ", lenstr, "}", NULL);
        }

        rec = ap_pstrcat(r->pool, rec, "}", NULL);

        if (na_result != na_not_applied) {
            ap_table_mergen(hdrs, "Alternates", rec);
        }
    }

    if (na_result != na_not_applied) {
        ap_table_mergen(hdrs, "Vary", "negotiate");
    }
    if (vary_by_type) {
        ap_table_mergen(hdrs, "Vary", "accept");
    }
    if (vary_by_language) {
        ap_table_mergen(hdrs, "Vary", "accept-language");
    }
    if (vary_by_charset) {
        ap_table_mergen(hdrs, "Vary", "accept-charset");
    }
    if (vary_by_encoding && na_result == na_not_applied) {
        ap_table_mergen(hdrs, "Vary", "accept-encoding");
    }
}

/**********************************************************************
 *
 * Return an HTML list of variants. This is output as part of the
 * 300 or 406 status body.
 */

/* XXX: this is disgusting, this has O(n^2) behaviour! -djg */
static char *make_variant_list(request_rec *r, negotiation_state *neg)
{
    int i;
    char *t;

    t = ap_pstrdup(r->pool, "Available variants:\n<ul>\n");
    for (i = 0; i < neg->avail_vars->nelts; ++i) {
        var_rec *variant = &((var_rec *) neg->avail_vars->elts)[i];
        char *filename = variant->file_name ? variant->file_name : "";
        array_header *languages = variant->content_languages;
        char *description = variant->description ? variant->description : "";

        /* The format isn't very neat, and it would be nice to make
         * the tags human readable (eg replace 'language en' with
         * 'English'). */
        t = ap_pstrcat(r->pool, t, "<li><a href=\"", filename, "\">",
                    filename, "</a> ", description, NULL);
        if (variant->type_name && *variant->type_name) {
            t = ap_pstrcat(r->pool, t, ", type ", variant->type_name, NULL);
        }
        if (languages && languages->nelts) {
            t = ap_pstrcat(r->pool, t, ", language ",
                        merge_string_array(r->pool, languages, ", "),
                        NULL);
        }
        if (variant->content_charset && *variant->content_charset) {
            t = ap_pstrcat(r->pool, t, ", charset ", variant->content_charset,
                        NULL);
        }
        t = ap_pstrcat(r->pool, t, "\n", NULL);
    }
    t = ap_pstrcat(r->pool, t, "</ul>\n", NULL);

    return t;
}

static void store_variant_list(request_rec *r, negotiation_state *neg)
{
    if (r->main == NULL) {
        ap_table_setn(r->notes, "variant-list", make_variant_list(r, neg));
    }
    else {
        ap_table_setn(r->main->notes, "variant-list",
                  make_variant_list(r->main, neg));
    }
}

/* Called if we got a "Choice" response from the network algorithm.
 * It checks the result of the chosen variant to see if it
 * is itself negotiated (if so, return error VARIANT_ALSO_VARIES).
 * Otherwise, add the appropriate headers to the current response.
 */

static int setup_choice_response(request_rec *r, negotiation_state *neg, var_rec *variant)
{
    request_rec *sub_req;
    const char *sub_vary;

    if (!variant->sub_req) {
        int status;

        sub_req = ap_sub_req_lookup_file(variant->file_name, r);
        status = sub_req->status;
        if (status != HTTP_OK && status != HTTP_MULTIPLE_CHOICES) {
            ap_destroy_sub_req(sub_req);
            return status;
        }
        variant->sub_req = sub_req;
    }
    else {
        sub_req = variant->sub_req;
    }

    /* The network algorithm told us to return a "Choice"
     * response. This is the normal variant response, with
     * some extra headers. First, ensure that the chosen
     * variant did not itself return a "List" or "Choice" response.
     * If not, set the appropriate headers, and fall through to
     * the normal variant handling 
     */

    if ((sub_req->status == HTTP_MULTIPLE_CHOICES) ||
        (ap_table_get(sub_req->err_headers_out, "Alternates")) ||
        (ap_table_get(sub_req->err_headers_out, "Content-Location"))) {
        return VARIANT_ALSO_VARIES;
    }

    if ((sub_vary = ap_table_get(sub_req->err_headers_out, "Vary")) != NULL) {
        ap_table_setn(r->err_headers_out, "Variant-Vary", sub_vary);
    }
    ap_table_setn(r->err_headers_out, "Content-Location",
		ap_pstrdup(r->pool, variant->file_name));
    set_neg_headers(r, neg, na_choice);         /* add Alternates and Vary */
    /* to do: add Expires */

    return 0;
}

/****************************************************************
 *
 * Executive...
 */

static int handle_map_file(request_rec *r)
{
    negotiation_state *neg = parse_accept_headers(r);
    var_rec *best;
    int res;
    int na_result;

    char *udir;

    if ((res = read_type_map(neg, r))) {
        return res;
    }

    maybe_add_default_encodings(neg, 0);

    na_result = best_match(neg, &best);

    /* na_result is one of
     *   na_not_applied: we didn't use the network algorithm
     *   na_choice: return a "Choice" response
     *   na_list: return a "List" response (no variant chosen)
     */

    if (na_result == na_list) {
        set_neg_headers(r, neg, na_list);
        store_variant_list(r, neg);
        return MULTIPLE_CHOICES;
    }

    if (!best) {
        ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
                    "no acceptable variant: %s", r->filename);

        set_neg_headers(r, neg, na_result);
        store_variant_list(r, neg);
        return NOT_ACCEPTABLE;
    }

    if (na_result == na_choice) {
        if ((res = setup_choice_response(r, neg, best)) != 0) {
            return res;
        }
    }

    /* Make sure caching works - Vary should handle HTTP/1.1, but for
     * HTTP/1.0, we can't allow caching at all. NB that we merge the
     * header in case some other module negotiates on something else.
     */
    if (!do_cache_negotiated_docs(r->server) && (r->proto_num < HTTP_VERSION(1,1))) {
        r->no_cache = 1;
    }

    if (na_result == na_not_applied) {
        set_neg_headers(r, neg, na_not_applied);
    }

    if (r->path_info && *r->path_info) {
        r->uri[ap_find_path_info(r->uri, r->path_info)] = '\0';
    }
    udir = ap_make_dirstr_parent(r->pool, r->uri);
    udir = escape_uri(r->pool, udir);
    ap_internal_redirect(ap_pstrcat(r->pool, udir, best->file_name, r->path_info,
                              NULL), r);
    return OK;
}

static int handle_multi(request_rec *r)
{
    negotiation_state *neg;
    var_rec *best, *avail_recs;
    request_rec *sub_req;
    int res;
    int j;
    int na_result;              /* result of network algorithm */

    if (r->finfo.st_mode != 0 || !(ap_allow_options(r) & OPT_MULTI)) {
        return DECLINED;
    }

    neg = parse_accept_headers(r);

    if ((res = read_types_multi(neg))) {
      return_from_multi:
        /* free all allocated memory from subrequests */
        avail_recs = (var_rec *) neg->avail_vars->elts;
        for (j = 0; j < neg->avail_vars->nelts; ++j) {
            var_rec *variant = &avail_recs[j];
            if (variant->sub_req) {
                ap_destroy_sub_req(variant->sub_req);
            }
        }
        return res;
    }
    if (neg->avail_vars->nelts == 0) {
        return DECLINED;
    }

    maybe_add_default_encodings(neg,
                                (r->method_number != M_GET) ||
                                r->args || r->path_info);

    na_result = best_match(neg, &best);
    if (na_result == na_list) {
        /*
         * Network algorithm tols us to output a "List" response.
         * This is output at a 300 status code, which we will
         * return. The list of variants will be stored in r->notes
         * under the name "variants-list".
         */
        set_neg_headers(r, neg, na_list);       /* set Alternates: and Vary: */

        store_variant_list(r, neg);
        res = MULTIPLE_CHOICES;
        goto return_from_multi;
    }

    if (!best) {
        ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
                    "no acceptable variant: %s", r->filename);

        set_neg_headers(r, neg, na_result);
        store_variant_list(r, neg);
        res = NOT_ACCEPTABLE;
        goto return_from_multi;
    }

    if (na_result == na_choice) {
        if ((res = setup_choice_response(r, neg, best)) != 0) {
            goto return_from_multi;
        }
    }

    if (!(sub_req = best->sub_req)) {
        /* We got this out of a map file, so we don't actually have
         * a sub_req structure yet.  Get one now.
         */

        sub_req = ap_sub_req_lookup_file(best->file_name, r);
        if (sub_req->status != HTTP_OK) {
            res = sub_req->status;
            ap_destroy_sub_req(sub_req);
            goto return_from_multi;
        }
    }

    /* BLETCH --- don't multi-resolve non-ordinary files */

    if (!S_ISREG(sub_req->finfo.st_mode)) {
        res = NOT_FOUND;
        goto return_from_multi;
    }

    /* Otherwise, use it. */

    if ((!do_cache_negotiated_docs(r->server) && (r->proto_num < HTTP_VERSION(1,1)))
        && neg->count_multiviews_variants != 1) {
        r->no_cache = 1;
    }

    if (na_result == na_not_applied) {
        set_neg_headers(r, neg, na_not_applied);
    }

    /* now do a "fast redirect" ... promote the sub_req into the main req */
    /* We need to tell POOL_DEBUG that we're guaranteeing that sub_req->pool
     * will exist as long as r->pool.  Otherwise we run into troubles because
     * some values in this request will be allocated in r->pool, and others in
     * sub_req->pool.
     */
    ap_pool_join(r->pool, sub_req->pool);
    r->filename = sub_req->filename;
    r->handler = sub_req->handler;
    r->content_type = sub_req->content_type;
    r->content_encoding = sub_req->content_encoding;
    r->content_languages = sub_req->content_languages;
    r->content_language = sub_req->content_language;
    r->finfo = sub_req->finfo;
    r->per_dir_config = sub_req->per_dir_config;
    /* copy output headers from subrequest, but leave negotiation headers */
    r->notes = ap_overlay_tables(r->pool, sub_req->notes, r->notes);
    r->headers_out = ap_overlay_tables(r->pool, sub_req->headers_out,
                                    r->headers_out);
    r->err_headers_out = ap_overlay_tables(r->pool, sub_req->err_headers_out,
                                        r->err_headers_out);
    r->subprocess_env = ap_overlay_tables(r->pool, sub_req->subprocess_env,
                                       r->subprocess_env);
    avail_recs = (var_rec *) neg->avail_vars->elts;
    for (j = 0; j < neg->avail_vars->nelts; ++j) {
        var_rec *variant = &avail_recs[j];
        if (variant != best && variant->sub_req) {
            ap_destroy_sub_req(variant->sub_req);
        }
    }
    return OK;
}

/* There is a problem with content-encoding, as some clients send and
 * expect an x- token (e.g. x-gzip) while others expect the plain token
 * (i.e. gzip). To try and deal with this as best as possible we do
 * the following: if the client sent an Accept-Encoding header and it
 * contains a plain token corresponding to the content encoding of the
 * response, then set content encoding using the plain token. Else if
 * the A-E header contains the x- token use the x- token in the C-E
 * header. Else don't do anything.
 *
 * Note that if no A-E header was sent, or it does not contain a token
 * compatible with the final content encoding, then the token in the
 * C-E header will be whatever was specified in the AddEncoding
 * directive.
 */
static int fix_encoding(request_rec *r)
{
    const char *enc = r->content_encoding;
    char *x_enc = NULL;
    array_header *accept_encodings;
    accept_rec *accept_recs;
    int i;

    if (!enc || !*enc) {
        return DECLINED;
    }

    if (enc[0] == 'x' && enc[1] == '-') {
        enc += 2;
    }

    accept_encodings = do_header_line(r->pool,
                                ap_table_get(r->headers_in, "Accept-encoding"));
    accept_recs = (accept_rec *) accept_encodings->elts;

    for (i = 0; i < accept_encodings->nelts; ++i) {
        char *name = accept_recs[i].type_name;

        if (!strcmp(name, enc)) {
            r->content_encoding = name;
            return OK;
        }

        if (name[0] == 'x' && name[1] == '-' && !strcmp(name+2, enc)) {
            x_enc = name;
        }
    }

    if (x_enc) {
        r->content_encoding = x_enc;
        return OK;
    }

    return DECLINED;
}

static const handler_rec negotiation_handlers[] =
{
    {MAP_FILE_MAGIC_TYPE, handle_map_file},
    {"type-map", handle_map_file},
    {NULL}
};

module MODULE_VAR_EXPORT negotiation_module =
{
    STANDARD_MODULE_STUFF,
    NULL,                       /* initializer */
    create_neg_dir_config,      /* dir config creater */
    merge_neg_dir_configs,      /* dir merger --- default is to override */
    NULL,                       /* server config */
    NULL,                       /* merge server config */
    negotiation_cmds,           /* command table */
    negotiation_handlers,       /* handlers */
    NULL,                       /* filename translation */
    NULL,                       /* check_user_id */
    NULL,                       /* check auth */
    NULL,                       /* check access */
    handle_multi,               /* type_checker */
    fix_encoding,               /* fixups */
    NULL,                       /* logger */
    NULL,                       /* header parser */
    NULL,                       /* child_init */
    NULL,                       /* child_exit */
    NULL                        /* post read-request */
};
