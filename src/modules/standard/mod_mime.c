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
 * http_mime.c: Sends/gets MIME headers for requests
 * 
 * Rob McCool
 * 
 */

#define MIME_PRIVATE

#include "httpd.h"
#include "http_config.h"
#include "http_log.h"

typedef struct {
    table *forced_types;        /* Additional AddTyped stuff */
    table *encoding_types;      /* Added with AddEncoding... */
    table *language_types;      /* Added with AddLanguage... */
    table *handlers;            /* Added with AddHandler...  */

    char *type;                 /* Type forced with ForceType  */
    char *handler;              /* Handler forced with SetHandler */
} mime_dir_config;

module MODULE_VAR_EXPORT mime_module;

static void *create_mime_dir_config(pool *p, char *dummy)
{
    mime_dir_config *new =
    (mime_dir_config *) ap_palloc(p, sizeof(mime_dir_config));

    new->forced_types = ap_make_table(p, 4);
    new->encoding_types = ap_make_table(p, 4);
    new->language_types = ap_make_table(p, 4);
    new->handlers = ap_make_table(p, 4);

    new->type = NULL;
    new->handler = NULL;

    return new;
}

static void *merge_mime_dir_configs(pool *p, void *basev, void *addv)
{
    mime_dir_config *base = (mime_dir_config *) basev;
    mime_dir_config *add = (mime_dir_config *) addv;
    mime_dir_config *new =
    (mime_dir_config *) ap_palloc(p, sizeof(mime_dir_config));

    new->forced_types = ap_overlay_tables(p, add->forced_types,
                                       base->forced_types);
    new->encoding_types = ap_overlay_tables(p, add->encoding_types,
                                         base->encoding_types);
    new->language_types = ap_overlay_tables(p, add->language_types,
                                         base->language_types);
    new->handlers = ap_overlay_tables(p, add->handlers,
                                   base->handlers);

    new->type = add->type ? add->type : base->type;
    new->handler = add->handler ? add->handler : base->handler;

    return new;
}

static const char *add_type(cmd_parms *cmd, mime_dir_config * m, char *ct,
                            char *ext)
{
    if (*ext == '.')
        ++ext;
    ap_str_tolower(ct);
    ap_table_setn(m->forced_types, ext, ct);
    return NULL;
}

static const char *add_encoding(cmd_parms *cmd, mime_dir_config * m, char *enc,
                                char *ext)
{
    if (*ext == '.')
        ++ext;
    ap_str_tolower(enc);
    ap_table_setn(m->encoding_types, ext, enc);
    return NULL;
}

static const char *add_language(cmd_parms *cmd, mime_dir_config * m, char *lang,
                                char *ext)
{
    if (*ext == '.')
        ++ext;
    ap_str_tolower(lang);
    ap_table_setn(m->language_types, ext, lang);
    return NULL;
}

static const char *add_handler(cmd_parms *cmd, mime_dir_config * m, char *hdlr,
                               char *ext)
{
    if (*ext == '.')
        ++ext;
    ap_str_tolower(hdlr);
    ap_table_setn(m->handlers, ext, hdlr);
    return NULL;
}

/* The sole bit of server configuration that the MIME module has is
 * the name of its config file, so...
 */

static const char *set_types_config(cmd_parms *cmd, void *dummy, char *arg)
{
    ap_set_module_config(cmd->server->module_config, &mime_module, arg);
    return NULL;
}

static const command_rec mime_cmds[] =
{
    {"AddType", add_type, NULL, OR_FILEINFO, ITERATE2,
     "a mime type followed by one or more file extensions"},
    {"AddEncoding", add_encoding, NULL, OR_FILEINFO, ITERATE2,
     "an encoding (e.g., gzip), followed by one or more file extensions"},
    {"AddLanguage", add_language, NULL, OR_FILEINFO, ITERATE2,
     "a language (e.g., fr), followed by one or more file extensions"},
    {"AddHandler", add_handler, NULL, OR_FILEINFO, ITERATE2,
     "a handler name followed by one or more file extensions"},
    {"ForceType", ap_set_string_slot_lower, 
     (void *)XtOffsetOf(mime_dir_config, type), OR_FILEINFO, TAKE1, 
     "a media type"},
    {"SetHandler", ap_set_string_slot_lower, 
     (void *)XtOffsetOf(mime_dir_config, handler), OR_FILEINFO, TAKE1, 
     "a handler name"},
    {"TypesConfig", set_types_config, NULL, RSRC_CONF, TAKE1,
     "the MIME types config file"},
    {NULL}
};

/* Hash table  --- only one of these per daemon; virtual hosts can
 * get private versions through AddType...
 */

/* MIME_HASHSIZE used to be 27 (26 chars and one "non-alpha" slot), but
 * with character sets like EBCDIC, this is insufficient because the
 * range 'a'...'z' is not contigous. Defining it as ('z'-'a'+2) is
 * equivalent to 27 in ASCII, and makes it work in EBCDIC.
 */
#define MIME_HASHSIZE ('z'-'a'+2)
#define hash(i) (ap_isalpha(i) ? (ap_tolower(i)) - 'a' : (MIME_HASHSIZE-1))

static table *hash_buckets[MIME_HASHSIZE];

static void init_mime(server_rec *s, pool *p)
{
    configfile_t *f;
    char l[MAX_STRING_LEN];
    int x;
    char *types_confname = ap_get_module_config(s->module_config, &mime_module);

    if (!types_confname)
        types_confname = TYPES_CONFIG_FILE;

    types_confname = ap_server_root_relative(p, types_confname);

    if (!(f = ap_pcfg_openfile(p, types_confname))) {
        ap_log_error(APLOG_MARK, APLOG_ERR, s,
		     "httpd: could not open mime types log file %s.", types_confname);
        exit(1);
    }

    for (x = 0; x < MIME_HASHSIZE; x++)
        hash_buckets[x] = ap_make_table(p, 10);

    while (!(ap_cfg_getline(l, MAX_STRING_LEN, f))) {
        const char *ll = l, *ct;

        if (l[0] == '#')
            continue;
        ct = ap_getword_conf(p, &ll);

        while (ll[0]) {
            char *ext = ap_getword_conf(p, &ll);
            ap_str_tolower(ext);   /* ??? */
            ap_table_setn(hash_buckets[hash(ext[0])], ext, ct);
        }
    }
    ap_cfg_closefile(f);
}

static int find_ct(request_rec *r)
{
    const char *fn = strrchr(r->filename, '/');
    mime_dir_config *conf =
    (mime_dir_config *) ap_get_module_config(r->per_dir_config, &mime_module);
    char *ext;
    const char *orighandler = r->handler;
    const char *type;

    if (S_ISDIR(r->finfo.st_mode)) {
        r->content_type = DIR_MAGIC_TYPE;
        return OK;
    }

    /* TM -- FIXME
     * if r->filename does not contain a '/', the following passes a null
     * pointer to getword, causing a SEGV ..
     */

    if (fn == NULL)
        fn = r->filename;

    /* Parse filename extensions, which can be in any order */
    while ((ext = ap_getword(r->pool, &fn, '.')) && *ext) {
        int found = 0;

        /* Check for Content-Type */
        if ((type = ap_table_get(conf->forced_types, ext))
            || (type = ap_table_get(hash_buckets[hash(*ext)], ext))) {
            r->content_type = type;
            found = 1;
        }

        /* Check for Content-Language */
        if ((type = ap_table_get(conf->language_types, ext))) {
            const char **new;

            r->content_language = type;         /* back compat. only */
            if (!r->content_languages)
                r->content_languages = ap_make_array(r->pool, 2, sizeof(char *));
            new = (const char **) ap_push_array(r->content_languages);
            *new = type;
            found = 1;
        }

        /* Check for Content-Encoding */
        if ((type = ap_table_get(conf->encoding_types, ext))) {
            if (!r->content_encoding)
                r->content_encoding = type;
            else
                r->content_encoding = ap_pstrcat(r->pool, r->content_encoding,
                                              ", ", type, NULL);
            found = 1;
        }

        /* Check for a special handler, but not for proxy request */
        if ((type = ap_table_get(conf->handlers, ext)) && !r->proxyreq) {
            r->handler = type;
            found = 1;
        }

        /* This is to deal with cases such as foo.gif.bak, which we want
         * to not have a type. So if we find an unknown extension, we
         * zap the type/language/encoding and reset the handler
         */

        if (!found) {
            r->content_type = NULL;
            r->content_language = NULL;
            r->content_languages = NULL;
            r->content_encoding = NULL;
            r->handler = orighandler;
        }

    }

    /* Check for overrides with ForceType/SetHandler */

    if (conf->type && strcmp(conf->type, "none"))
        r->content_type = conf->type;
    if (conf->handler && strcmp(conf->handler, "none"))
        r->handler = conf->handler;

    if (!r->content_type)
        return DECLINED;

    return OK;
}

module MODULE_VAR_EXPORT mime_module =
{
    STANDARD_MODULE_STUFF,
    init_mime,                  /* initializer */
    create_mime_dir_config,     /* dir config creator */
    merge_mime_dir_configs,     /* dir config merger */
    NULL,                       /* server config */
    NULL,                       /* merge server config */
    mime_cmds,                  /* command table */
    NULL,                       /* handlers */
    NULL,                       /* filename translation */
    NULL,                       /* check_user_id */
    NULL,                       /* check auth */
    NULL,                       /* check access */
    find_ct,                    /* type_checker */
    NULL,                       /* fixups */
    NULL,                       /* logger */
    NULL,                       /* header parser */
    NULL,                       /* child_init */
    NULL,                       /* child_exit */
    NULL                        /* post read-request */
};
