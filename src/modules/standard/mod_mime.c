/* ====================================================================
 * Copyright (c) 1995-1999 The Apache Group.  All rights reserved.
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

/*
 * isascii(c) isn't universal, and even those places where it is
 * defined it's not always right for our needs.  Roll our own that
 * we can rely on.
 */
#define ap_isascii(c) ((OS_ASC(c) & 0x80) == 0)

typedef struct handlers_info {
    char *name;
} handlers_info;

typedef struct {
    table *forced_types;        /* Additional AddTyped stuff */
    table *encoding_types;      /* Added with AddEncoding... */
    table *charset_types;	/* Added with AddCharset... */
    table *language_types;      /* Added with AddLanguage... */
    table *handlers;            /* Added with AddHandler...  */
    array_header *handlers_remove;     /* List of handlers to remove */

    char *type;                 /* Type forced with ForceType  */
    char *handler;              /* Handler forced with SetHandler */
    char *default_language;     /* Language if no AddLanguage ext found */
} mime_dir_config;

typedef struct param_s {
    char *attr;
    char *val;
    struct param_s *next;
} param;

typedef struct {
    char *type;
    char *subtype;
    param *param;
} content_type;

static char tspecial[] = {
    '(', ')', '<', '>', '@', ',', ';', ':',
    '\\', '"', '/', '[', ']', '?', '=',
    '\0'
};

module MODULE_VAR_EXPORT mime_module;

static void *create_mime_dir_config(pool *p, char *dummy)
{
    mime_dir_config *new =
    (mime_dir_config *) ap_palloc(p, sizeof(mime_dir_config));

    new->forced_types = ap_make_table(p, 4);
    new->encoding_types = ap_make_table(p, 4);
    new->charset_types = ap_make_table(p, 4);
    new->language_types = ap_make_table(p, 4);
    new->handlers = ap_make_table(p, 4);
    new->handlers_remove = ap_make_array(p, 4, sizeof(handlers_info));

    new->type = NULL;
    new->handler = NULL;
    new->default_language = NULL;

    return new;
}

static void *merge_mime_dir_configs(pool *p, void *basev, void *addv)
{
    mime_dir_config *base = (mime_dir_config *) basev;
    mime_dir_config *add = (mime_dir_config *) addv;
    mime_dir_config *new =
        (mime_dir_config *) ap_palloc(p, sizeof(mime_dir_config));
    int i;
    handlers_info *hand;

    hand = (handlers_info *) add->handlers_remove->elts;
    for (i = 0; i < add->handlers_remove->nelts; i++) {
        ap_table_unset(base->handlers, hand[i].name);
    }

    new->forced_types = ap_overlay_tables(p, add->forced_types,
					 base->forced_types);
    new->encoding_types = ap_overlay_tables(p, add->encoding_types,
                                         base->encoding_types);
    new->charset_types = ap_overlay_tables(p, add->charset_types,
					   base->charset_types);
    new->language_types = ap_overlay_tables(p, add->language_types,
                                         base->language_types);
    new->handlers = ap_overlay_tables(p, add->handlers,
                                   base->handlers);

    new->type = add->type ? add->type : base->type;
    new->handler = add->handler ? add->handler : base->handler;
    new->default_language = add->default_language ?
        add->default_language : base->default_language;

    return new;
}

static const char *add_type(cmd_parms *cmd, mime_dir_config *m, char *ct,
                            char *ext)
{
    if (*ext == '.')
	++ext;
	
    ap_str_tolower(ct);
    ap_table_setn(m->forced_types, ext, ct);
    return NULL;
}

static const char *add_encoding(cmd_parms *cmd, mime_dir_config *m, char *enc,
                                char *ext)
{
    if (*ext == '.')
        ++ext;
    ap_str_tolower(enc);
    ap_table_setn(m->encoding_types, ext, enc);
    return NULL;
}

static const char *add_charset(cmd_parms *cmd, mime_dir_config *m,
			       char *charset, char *ext)
{
    if (*ext == '.') {
	++ext;
    }
    ap_str_tolower(charset);
    ap_table_setn(m->charset_types, ext, charset);
    return NULL;
}

static const char *add_language(cmd_parms *cmd, mime_dir_config *m, char *lang,
                                char *ext)
{
    if (*ext == '.') {
	++ext;
    }
    ap_str_tolower(lang);
    ap_table_setn(m->language_types, ext, lang);
    return NULL;
}

static const char *add_handler(cmd_parms *cmd, mime_dir_config *m, char *hdlr,
                               char *ext)
{
    if (*ext == '.')
        ++ext;
    ap_str_tolower(hdlr);
    ap_table_setn(m->handlers, ext, hdlr);
    return NULL;
}

/*
 * Note handler names that should be un-added for this location.  This
 * will keep the association from being inherited, as well, but not
 * from being re-added at a subordinate level.
 */
static const char *remove_handler(cmd_parms *cmd, void *m, char *ext)
{
    mime_dir_config *mcfg = (mime_dir_config *) m;
    handlers_info *hand;

    if (*ext == '.') {
        ++ext;
    }
    hand = (handlers_info *) ap_push_array(mcfg->handlers_remove);
    hand->name = ap_pstrdup(cmd->pool, ext);
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
    {"AddCharset", add_charset, NULL, OR_FILEINFO, ITERATE2,
     "a charset (e.g., iso-2022-jp), followed by one or more file extensions"},
    {"AddLanguage", add_language, NULL, OR_FILEINFO, ITERATE2,
     "a language (e.g., fr), followed by one or more file extensions"},
    {"AddHandler", add_handler, NULL, OR_FILEINFO, ITERATE2,
     "a handler name followed by one or more file extensions"},
    {"ForceType", ap_set_string_slot_lower, 
     (void *)XtOffsetOf(mime_dir_config, type), OR_FILEINFO, TAKE1, 
     "a media type"},
    {"RemoveHandler", remove_handler, NULL, OR_FILEINFO, ITERATE,
     "one or more file extensions"},
    {"SetHandler", ap_set_string_slot_lower, 
     (void *)XtOffsetOf(mime_dir_config, handler), OR_FILEINFO, TAKE1, 
     "a handler name"},
    {"TypesConfig", set_types_config, NULL, RSRC_CONF, TAKE1,
     "the MIME types config file"},
    {"DefaultLanguage", ap_set_string_slot,
     (void*)XtOffsetOf(mime_dir_config, default_language), OR_FILEINFO, TAKE1,
     "language to use for documents with no other language file extension" },
    {NULL}
};

/* Hash table  --- only one of these per daemon; virtual hosts can
 * get private versions through AddType...
 */

#define MIME_HASHSIZE (32)
#define hash(i) (ap_tolower(i) % MIME_HASHSIZE)

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
		     "could not open mime types log file %s.", types_confname);
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

static char *zap_sp(char *s)
{
    char *tp;

    if (s == NULL) {
	return (NULL);
    }
    if (*s == '\0') {
	return (s);
    }

    /* delete prefixed white space */
    for (; *s == ' ' || *s == '\t' || *s == '\n'; s++);

    /* delete postfixed white space */
    for (tp = s; *tp != '\0'; tp++);
    for (tp--; tp != s && (*tp == ' ' || *tp == '\t' || *tp == '\n'); tp--) {
	*tp = '\0';
    }
    return (s);
}

static int is_token(char c)
{
    int res;

    res = (ap_isascii(c) && isgraph(c)
	   && (strchr(tspecial, c) == NULL)) ? 1 : -1;
    return res;
}

static int is_qtext(char c)
{
    int res;

    res = (ap_isascii(c) && (c != '"') && (c != '\\') && (c != '\n'))
	? 1 : -1;
    return res;
}

static int is_quoted_pair(char *s)
{
    int res = -1;
    int c;

    if (((s + 1) != NULL) && (*s == '\\')) {
	c = (int) *(s + 1);
	if (ap_isascii(c)) {
	    res = 1;
	}
    }
    return (res);
}

static content_type *analyze_ct(pool *p, char *s)
{
    char *tp, *mp, *cp;
    char *attribute, *value;
    int quoted = 0;

    content_type *ctp;
    param *pp, *npp;

    /* initialize ctp */
    ctp = (content_type *) ap_palloc(p, sizeof(content_type));
    ctp->type = NULL;
    ctp->subtype = NULL;
    ctp->param = NULL;

    tp = ap_pstrdup(p, s);

    mp = tp;
    cp = mp;

    /* getting a type */
    if (!(cp = strchr(mp, '/'))) {
	ap_log_error(APLOG_MARK, APLOG_WARNING, NULL,
		     "mod_mime: analyze_ct: cannot get media type from '%s'",
		     mp);
	return (NULL);
    }
    ctp->type = ap_pstrndup(p, mp, cp - mp);
    ctp->type = zap_sp(ctp->type);
    if (ctp->type == NULL || *(ctp->type) == '\0' ||
	strchr(ctp->type, ';') || strchr(ctp->type, ' ') ||
	strchr(ctp->type, '\t')) {
	ap_log_error(APLOG_MARK, APLOG_WARNING, NULL,
		     "Cannot get media subtype.");
	return (NULL);
    }

    /* getting a subtype */
    cp++;
    mp = cp;

    for (; *cp != ';' && *cp != '\0'; cp++);
    ctp->subtype = ap_pstrndup(p, mp, cp - mp);
    ctp->subtype = zap_sp(ctp->subtype);
    if ((ctp->subtype == NULL) || (*(ctp->subtype) == '\0') ||
	strchr(ctp->subtype, ' ') || strchr(ctp->subtype, '\t')) {
	ap_log_error(APLOG_MARK, APLOG_WARNING, NULL,
		     "Cannot get media subtype.");
	return (NULL);
    }
    cp = zap_sp(cp);
    if (cp == NULL || *cp == '\0') {
	return (ctp);
    }

    /* getting parameters */
    cp++;
    cp = zap_sp(cp);
    if (cp == NULL || *cp == '\0') {
	ap_log_error(APLOG_MARK, APLOG_WARNING, NULL,
		     "Cannot get media parameter.");
	return (NULL);
    }
    mp = cp;
    attribute = NULL;
    value = NULL;

    while (cp != NULL && *cp != '\0') {
	if (attribute == NULL) {
	    if (is_token((int) *cp) > 0) {
		cp++;
		continue;
	    }
	    else if (*cp == ' ' || *cp == '\t' || *cp == '\n') {
		cp++;
		continue;
	    }
	    else if (*cp == '=') {
		attribute = ap_pstrndup(p, mp, cp - mp);
		attribute = zap_sp(attribute);
		if (attribute == NULL || *attribute == '\0') {
		    ap_log_error(APLOG_MARK, APLOG_WARNING, NULL,
				 "Cannot get media parameter.");
		    return (NULL);
		}
		cp++;
		cp = zap_sp(cp);
		if (cp == NULL || *cp == '\0') {
		    ap_log_error(APLOG_MARK, APLOG_WARNING, NULL,
				 "Cannot get media parameter.");
		    return (NULL);
		}
		mp = cp;
		continue;
	    }
	    else {
		ap_log_error(APLOG_MARK, APLOG_WARNING, NULL,
			     "Cannot get media parameter.");
		return (NULL);
	    }
	}
	else {
	    if (mp == cp) {
		if (*cp == '"') {
		    quoted = 1;
		    cp++;
		}
		else {
		    quoted = 0;
		}
	    }
	    if (quoted > 0) {
		while (quoted && *cp != '\0') {
		    if (is_qtext((int) *cp) > 0) {
			cp++;
		    }
		    else if (is_quoted_pair(cp) > 0) {
			cp += 2;
		    }
		    else if (*cp == '"') {
			cp++;
			while (*cp == ' ' || *cp == '\t' || *cp == '\n') {
			    cp++;
			}
			if (*cp != ';' && *cp != '\0') {
			    ap_log_error(APLOG_MARK, APLOG_WARNING, NULL,
					 "Cannot get media parameter.");
			    return(NULL);
			}
			quoted = 0;
		    }
		    else {
			ap_log_error(APLOG_MARK, APLOG_WARNING, NULL,
				     "Cannot get media parameter.");
			return (NULL);
		    }
		}
	    }
	    else {
		while (1) {
		    if (is_token((int) *cp) > 0) {
			cp++;
		    }
		    else if (*cp == '\0' || *cp == ';') {
			break;
		    }
		    else {
			ap_log_error(APLOG_MARK, APLOG_WARNING, NULL,
				     "Cannot get media parameter.");
			return (NULL);
		    }
		}
	    }
	    value = ap_pstrndup(p, mp, cp - mp);
	    value = zap_sp(value);
	    if (value == NULL || *value == '\0') {
		ap_log_error(APLOG_MARK, APLOG_WARNING, NULL,
			     "Cannot get media parameter.");
		return (NULL);
	    }

	    pp = ap_palloc(p, sizeof(param));
	    pp->attr = attribute;
	    pp->val = value;
	    pp->next = NULL;

	    if (ctp->param == NULL) {
		ctp->param = pp;
	    }
	    else {
		npp = ctp->param;
		while (npp->next) {
		    npp = npp->next;
		}
		npp->next = pp;
	    }
	    quoted = 0;
	    attribute = NULL;
	    value = NULL;
	    if (*cp == '\0') {
		break;
	    }
	    cp++;
	    mp = cp;
	}
    }
    return (ctp);
}

static int find_ct(request_rec *r)
{
    const char *fn = strrchr(r->filename, '/');
    mime_dir_config *conf =
    (mime_dir_config *) ap_get_module_config(r->per_dir_config, &mime_module);
    char *ext;
    const char *orighandler = r->handler;
    const char *type;
    const char *charset = NULL;

    if (S_ISDIR(r->finfo.st_mode)) {
        r->content_type = DIR_MAGIC_TYPE;
        return OK;
    }

    /* TM -- FIXME
     * if r->filename does not contain a '/', the following passes a null
     * pointer to getword, causing a SEGV ..
     */

    if (fn == NULL) {
	fn = r->filename;
    }

    /* Parse filename extensions, which can be in any order */
    while ((ext = ap_getword(r->pool, &fn, '.')) && *ext) {
        int found = 0;

        /* Check for Content-Type */
        if ((type = ap_table_get(conf->forced_types, ext))
            || (type = ap_table_get(hash_buckets[hash(*ext)], ext))) {
            r->content_type = type;
            found = 1;
        }

	/* Add charset to Content-Type */
	if ((type = ap_table_get(conf->charset_types, ext))) {
	    charset = type;
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
        if ((type = ap_table_get(conf->handlers, ext))
	    && r->proxyreq == NOT_PROXY) {
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
	    charset = NULL;
	}
    }

    if (r->content_type) {
	content_type *ctp;
	char *ct;
	int override = 0;

	ct = (char *) ap_palloc(r->pool,
				sizeof(char) * (strlen(r->content_type) + 1));
	strcpy(ct, r->content_type);

	if ((ctp = analyze_ct(r->pool, ct))) {
	    param *pp = ctp->param;
	    r->content_type = ap_pstrcat(r->pool, ctp->type, "/",
					 ctp->subtype, NULL);
	    while (pp != NULL) {
		if (charset && !strcmp(pp->attr, "charset")) {
		    if (!override) {
			r->content_type = ap_pstrcat(r->pool, r->content_type,
						     "; charset=", charset,
						     NULL);
			override = 1;
		    }
		}
		else {
		    r->content_type = ap_pstrcat(r->pool, r->content_type,
						 "; ", pp->attr,
						 "=", pp->val,
						 NULL);
		}
		pp = pp->next;
	    }
	    if (charset && !override) {
		r->content_type = ap_pstrcat(r->pool, r->content_type,
					     "; charset=", charset,
					     NULL);
	    }
	}
    }

    /* Set default language, if none was specified by the extensions
     * and we have a DefaultLanguage setting in force
     */

    if (!r->content_languages && conf->default_language) {
        const char **new;

        r->content_language = conf->default_language; /* back compat. only */
        if (!r->content_languages)
            r->content_languages = ap_make_array(r->pool, 2, sizeof(char *));
        new = (const char **) ap_push_array(r->content_languages);
        *new = conf->default_language;
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
