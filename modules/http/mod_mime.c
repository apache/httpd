/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000-2001 The Apache Software Foundation.  All rights
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
 * http_mime.c: Sends/gets MIME headers for requests
 * 
 * Rob McCool
 * 
 */

#include "apr.h"
#include "apr_strings.h"
#include "apr_lib.h"
#include "apr_hash.h"

#define APR_WANT_STRFUNC
#include "apr_want.h"

#include "ap_config.h"
#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "http_request.h"


/* XXXX - fix me / EBCDIC
 *        there was a cludge here which would use its
 *	  own version apr_isascii(). Indicating that
 *	  on some platforms that might be needed. 
 *
 *	  #define OS_ASC(c) (c)		    -- for mere mortals 
 *     or
 *        #define OS_ASC(c) (ebcdic2ascii[c]) -- for dino's
 *
 *        #define apr_isascii(c) ((OS_ASC(c) & 0x80) == 0)
 */

/* XXXXX - fix me - See note with NOT_PROXY 
 */

typedef struct attrib_info {
    char *name;
    int   offset;
} attrib_info;

/* Information to which an extension can be mapped
 */
typedef struct extension_info {
    char *forced_type;                /* Additional AddTyped stuff */
    char *encoding_type;              /* Added with AddEncoding... */
    char *language_type;              /* Added with AddLanguage... */
    char *handler;                    /* Added with AddHandler... */
    char *charset_type;               /* Added with AddCharset... */
    char *input_filters;              /* Added with AddInputFilter... */
    char *output_filters;             /* Added with AddOutputFilter... */
} extension_info;

typedef struct {
    apr_hash_t  *extension_mappings;  /* Map from extension name to
                                       * extension_info structure */

    apr_array_header_t *remove_mappings; /* A simple list, walked once */

    char *default_language;     /* Language if no AddLanguage ext found */
	                        /* Due to the FUD about JS and charsets 
                                 * default_charset is actually in src/main */
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

module AP_MODULE_DECLARE_DATA mime_module;

static void *create_mime_dir_config(apr_pool_t *p, char *dummy)
{
    mime_dir_config *new =
    (mime_dir_config *) apr_palloc(p, sizeof(mime_dir_config));

    new->extension_mappings = NULL;
    new->remove_mappings = NULL;

    new->default_language = NULL;

    return new;
}
/*
 * Overlay one hash table of extension_mappings onto another
 */
static void overlay_extension_mappings(apr_pool_t *p,
                                       apr_hash_t *overlay, apr_hash_t *base)
{
    apr_hash_index_t *index;
    for (index = apr_hash_first(p, overlay); index;
         index = apr_hash_next(index)) {
        char *key;
        apr_ssize_t klen;
        extension_info *overlay_info, *base_info;
        
        apr_hash_this(index, (const void**)&key, &klen, (void**)&overlay_info);

        base_info = (extension_info*)apr_hash_get(base, key, klen);

        if (base_info) {
            extension_info *copyinfo = base_info;
            base_info = (extension_info*)apr_palloc(p, sizeof(*base_info));
            apr_hash_set(base, key, klen, base_info);
            memcpy(base_info, copyinfo, sizeof(*base_info));

            if (overlay_info->forced_type) {
                base_info->forced_type = overlay_info->forced_type;
            }
            if (overlay_info->encoding_type) {
                base_info->encoding_type = overlay_info->encoding_type;
            }
            if (overlay_info->language_type) {
                base_info->language_type = overlay_info->language_type;
            }
            if (overlay_info->handler) {
                base_info->handler = overlay_info->handler;
            }
            if (overlay_info->charset_type) {
                base_info->charset_type = overlay_info->charset_type;
            }
            if (overlay_info->input_filters) {
                base_info->input_filters = overlay_info->input_filters;
            }
            if (overlay_info->output_filters) {
                base_info->output_filters = overlay_info->output_filters;
            }
        }
        else {
            apr_hash_set(base, key, klen, overlay_info);
        }
    }
}

/* Member is the offset within an extension_info of the pointer to reset 
 */
static void remove_items(apr_pool_t *p, apr_array_header_t *remove, 
                         apr_hash_t *mappings)
{
    attrib_info *suffix = (attrib_info *) remove->elts;
    int i;
    for (i = 0; i < remove->nelts; i++) {
        extension_info *exinfo =
            (extension_info*)apr_hash_get(mappings,
                                          suffix[i].name,
                                          APR_HASH_KEY_STRING);
        if (exinfo && *(const char**)((char *)exinfo + suffix[i].offset)) {
            extension_info *copyinfo = exinfo;
            exinfo = (extension_info*)apr_palloc(p, sizeof(*exinfo));
            apr_hash_set(mappings, suffix[i].name, 
                         APR_HASH_KEY_STRING, exinfo);
            memcpy(exinfo, copyinfo, sizeof(*exinfo));
            *(const char**)((char *)exinfo + suffix[i].offset) = NULL;
        }
    }
}

static void *merge_mime_dir_configs(apr_pool_t *p, void *basev, void *addv)
{
    mime_dir_config *base = (mime_dir_config *) basev;
    mime_dir_config *add = (mime_dir_config *) addv;
    mime_dir_config *new = apr_palloc(p, sizeof(mime_dir_config));

    if (base->extension_mappings && add->extension_mappings) {
        new->extension_mappings = apr_hash_make(p);
        overlay_extension_mappings(p, base->extension_mappings,
                                   new->extension_mappings);
        overlay_extension_mappings(p, add->extension_mappings,
                                   new->extension_mappings);
    }
    else {
        if (base->extension_mappings == NULL) {
            new->extension_mappings = add->extension_mappings;
        }
        else {
            new->extension_mappings = base->extension_mappings;
        }
        /* We may not be merging the tables, but if we potentially will change
         * an exinfo member, then we are about to trounce it anyways.
         * We must have a copy for safety.
         */
        if (new->extension_mappings && add->remove_mappings) {
            apr_hash_t *copyhash = new->extension_mappings;
            new->extension_mappings = apr_hash_make(p);
            overlay_extension_mappings(p, copyhash, new->extension_mappings);
        }
    }

    if (new->extension_mappings) {
        if (add->remove_mappings)
            remove_items(p, add->remove_mappings, new->extension_mappings);
    }
    new->remove_mappings = NULL;

    new->default_language = add->default_language ?
        add->default_language : base->default_language;

    return new;
}

static const char *add_extension_info(cmd_parms *cmd, void *m_, 
                                      const char *value_, const char* ext)
{
    mime_dir_config *m=m_;
    extension_info *exinfo;
    int offset = (int) (long) cmd->info;
    char *key = apr_pstrdup(cmd->temp_pool, ext);
    char *value = apr_pstrdup(cmd->pool, value_);
    ap_str_tolower(value);
#ifdef CASE_BLIND_FILESYSTEM
    ap_str_tolower(key);
#endif
    if (*key == '.')
	++key;
    if (!m->extension_mappings) {
        m->extension_mappings = apr_hash_make(cmd->pool);
        exinfo = NULL;
    }
    else
        exinfo = (extension_info*)apr_hash_get(m->extension_mappings, key,
                                               APR_HASH_KEY_STRING);
    if (!exinfo) {
        exinfo = apr_pcalloc(cmd->pool, sizeof(extension_info));
        key = apr_pstrdup(cmd->pool, key);
        apr_hash_set(m->extension_mappings, key,
                     APR_HASH_KEY_STRING, exinfo);
    }
    *(const char**)((char *)exinfo + offset) = value;
    return NULL;
}

/*
 * Note handler names are un-added with each per_dir_config merge.
 * This keeps the association from being inherited, but not
 * from being re-added at a subordinate level.
 */
static const char *remove_extension_info(cmd_parms *cmd, void *m_, 
                                         const char *ext)
{
    mime_dir_config *m = (mime_dir_config *) m_;
    attrib_info *suffix;
    if (*ext == '.')
        ++ext;
    if (!m->remove_mappings) {
        m->remove_mappings = apr_array_make(cmd->pool, 4, sizeof(*suffix));
    }
    suffix = (attrib_info *) apr_array_push(m->remove_mappings);
    suffix->name = apr_pstrdup(cmd->pool, ext);
#ifdef CASE_BLIND_FILESYSTEM
    ap_str_tolower(suffix->name);
#endif
    suffix->offset = (int) (long) cmd->info;
    return NULL;
}

/* The sole bit of server configuration that the MIME module has is
 * the name of its config file, so...
 */

static const char *set_types_config(cmd_parms *cmd, void *dummy,
				    const char *arg)
{
    ap_set_module_config(cmd->server->module_config, &mime_module,
			 (void *)arg);
    return NULL;
}

static const command_rec mime_cmds[] =
{
AP_INIT_ITERATE2("AddCharset", add_extension_info, 
         (void *)APR_XtOffsetOf(extension_info, charset_type), OR_FILEINFO,
     "a charset (e.g., iso-2022-jp), followed by one or more file extensions"),
AP_INIT_ITERATE2("AddEncoding", add_extension_info, 
         (void *)APR_XtOffsetOf(extension_info, encoding_type), OR_FILEINFO,
     "an encoding (e.g., gzip), followed by one or more file extensions"),
AP_INIT_ITERATE2("AddHandler", add_extension_info, 
         (void *)APR_XtOffsetOf(extension_info, handler), OR_FILEINFO,
     "a handler name followed by one or more file extensions"),
AP_INIT_ITERATE2("AddInputFilter", add_extension_info, 
         (void *)APR_XtOffsetOf(extension_info, input_filters), OR_FILEINFO,
     "input filter name (or ; delimited names) followed by one or more file extensions"),
AP_INIT_ITERATE2("AddLanguage", add_extension_info, 
         (void *)APR_XtOffsetOf(extension_info, language_type), OR_FILEINFO,
     "a language (e.g., fr), followed by one or more file extensions"),
AP_INIT_ITERATE2("AddOutputFilter", add_extension_info, 
         (void *)APR_XtOffsetOf(extension_info, output_filters), OR_FILEINFO, 
     "output filter name (or ; delimited names) followed by one or more file extensions"),
AP_INIT_ITERATE2("AddType", add_extension_info, 
         (void *)APR_XtOffsetOf(extension_info, forced_type), OR_FILEINFO, 
     "a mime type followed by one or more file extensions"),
AP_INIT_TAKE1("DefaultLanguage", ap_set_string_slot,
       (void*)APR_XtOffsetOf(mime_dir_config, default_language), OR_FILEINFO,
     "language to use for documents with no other language file extension"),
AP_INIT_ITERATE("RemoveCharset", remove_extension_info, 
        (void *)APR_XtOffsetOf(extension_info, charset_type), OR_FILEINFO,
     "one or more file extensions"),
AP_INIT_ITERATE("RemoveEncoding", remove_extension_info, 
        (void *)APR_XtOffsetOf(extension_info, encoding_type), OR_FILEINFO,
     "one or more file extensions"),
AP_INIT_ITERATE("RemoveHandler", remove_extension_info, 
        (void *)APR_XtOffsetOf(extension_info, handler), OR_FILEINFO,
     "one or more file extensions"),
AP_INIT_ITERATE("RemoveInputFilter", remove_extension_info, 
        (void *)APR_XtOffsetOf(extension_info, input_filters), OR_FILEINFO,
     "one or more file extensions"),
AP_INIT_ITERATE("RemoveLanguage", remove_extension_info, 
        (void *)APR_XtOffsetOf(extension_info, language_type), OR_FILEINFO,
     "one or more file extensions"),
AP_INIT_ITERATE("RemoveOutputFilter", remove_extension_info, 
        (void *)APR_XtOffsetOf(extension_info, output_filters), OR_FILEINFO,
     "one or more file extensions"),
AP_INIT_ITERATE("RemoveType", remove_extension_info, 
        (void *)APR_XtOffsetOf(extension_info, forced_type), OR_FILEINFO,
     "one or more file extensions"),
AP_INIT_TAKE1("TypesConfig", set_types_config, NULL, RSRC_CONF,
     "the MIME types config file"),
    {NULL}
};

static apr_hash_t *mime_type_extensions;

static void mime_post_config(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s)
{
    ap_configfile_t *f;
    char l[MAX_STRING_LEN];
    const char *types_confname = ap_get_module_config(s->module_config, &mime_module);
    apr_status_t status;

    if (!types_confname)
        types_confname = AP_TYPES_CONFIG_FILE;

    types_confname = ap_server_root_relative(p, types_confname);

    if ((status = ap_pcfg_openfile(&f, ptemp, types_confname)) != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, status, s,
		     "could not open mime types config file %s.", types_confname);
        exit(1);
    }

    mime_type_extensions = apr_hash_make(p);

    while (!(ap_cfg_getline(l, MAX_STRING_LEN, f))) {
        const char *ll = l, *ct;

        if (l[0] == '#')
            continue;
        ct = ap_getword_conf(p, &ll);

        while (ll[0]) {
            char *ext = ap_getword_conf(p, &ll);
            ap_str_tolower(ext);   /* ??? */
            apr_hash_set(mime_type_extensions, ext, APR_HASH_KEY_STRING, ct);
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

    res = (apr_isascii(c) && apr_isgraph(c)
	   && (strchr(tspecial, c) == NULL)) ? 1 : -1;
    return res;
}

static int is_qtext(char c)
{
    int res;

    res = (apr_isascii(c) && (c != '"') && (c != '\\') && (c != '\n'))
	? 1 : -1;
    return res;
}

static int is_quoted_pair(char *s)
{
    int res = -1;
    int c;

    if (((s + 1) != NULL) && (*s == '\\')) {
	c = (int) *(s + 1);
	if (apr_isascii(c)) {
	    res = 1;
	}
    }
    return (res);
}

static content_type *analyze_ct(request_rec *r, char *s)
{
    char *tp, *mp, *cp;
    char *attribute, *value;
    int quoted = 0;
    server_rec * ss = r->server;
    apr_pool_t  * p = r->pool;

    content_type *ctp;
    param *pp, *npp;

    /* initialize ctp */
    ctp = (content_type *) apr_palloc(p, sizeof(content_type));
    ctp->type = NULL;
    ctp->subtype = NULL;
    ctp->param = NULL;

    tp = apr_pstrdup(p, s);

    mp = tp;
    cp = mp;

    /* getting a type */
    if (!(cp = strchr(mp, '/'))) {
	ap_log_error(APLOG_MARK, APLOG_WARNING, 0, ss,
		     "mod_mime: analyze_ct: cannot get media type from '%s'",
		     (const char *) mp);
	return (NULL);
    }
    ctp->type = apr_pstrndup(p, mp, cp - mp);
    ctp->type = zap_sp(ctp->type);
    if (ctp->type == NULL || *(ctp->type) == '\0' ||
	strchr(ctp->type, ';') || strchr(ctp->type, ' ') ||
	strchr(ctp->type, '\t')) {
	ap_log_error(APLOG_MARK, APLOG_WARNING, 0, ss,
		     "Cannot get media subtype.");
	return (NULL);
    }

    /* getting a subtype */
    cp++;
    mp = cp;

    for (; *cp != ';' && *cp != '\0'; cp++)
        continue;
    ctp->subtype = apr_pstrndup(p, mp, cp - mp);
    ctp->subtype = zap_sp(ctp->subtype);
    if ((ctp->subtype == NULL) || (*(ctp->subtype) == '\0') ||
	strchr(ctp->subtype, ' ') || strchr(ctp->subtype, '\t')) {
	ap_log_error(APLOG_MARK, APLOG_WARNING, 0, ss,
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
	ap_log_error(APLOG_MARK, APLOG_WARNING, 0, ss,
		     "Cannot get media parameter.");
	return (NULL);
    }
    mp = cp;
    attribute = NULL;
    value = NULL;

    while (cp != NULL && *cp != '\0') {
	if (attribute == NULL) {
	    if (is_token(*cp) > 0) {
		cp++;
		continue;
	    }
	    else if (*cp == ' ' || *cp == '\t' || *cp == '\n') {
		cp++;
		continue;
	    }
	    else if (*cp == '=') {
		attribute = apr_pstrndup(p, mp, cp - mp);
		attribute = zap_sp(attribute);
		if (attribute == NULL || *attribute == '\0') {
		    ap_log_error(APLOG_MARK, APLOG_WARNING, 0, ss,
				 "Cannot get media parameter.");
		    return (NULL);
		}
		cp++;
		cp = zap_sp(cp);
		if (cp == NULL || *cp == '\0') {
		    ap_log_error(APLOG_MARK, APLOG_WARNING, 0, ss,
				 "Cannot get media parameter.");
		    return (NULL);
		}
		mp = cp;
		continue;
	    }
	    else {
		ap_log_error(APLOG_MARK, APLOG_WARNING, 0, ss,
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
		    if (is_qtext(*cp) > 0) {
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
			    ap_log_error(APLOG_MARK, APLOG_WARNING, 0, ss,
					 "Cannot get media parameter.");
			    return(NULL);
			}
			quoted = 0;
		    }
		    else {
			ap_log_error(APLOG_MARK, APLOG_WARNING, 0, ss,
				     "Cannot get media parameter.");
			return (NULL);
		    }
		}
	    }
	    else {
		while (1) {
		    if (is_token(*cp) > 0) {
			cp++;
		    }
		    else if (*cp == '\0' || *cp == ';') {
			break;
		    }
		    else {
			ap_log_error(APLOG_MARK, APLOG_WARNING, 0, ss,
				     "Cannot get media parameter.");
			return (NULL);
		    }
		}
	    }
	    value = apr_pstrndup(p, mp, cp - mp);
	    value = zap_sp(value);
	    if (value == NULL || *value == '\0') {
		ap_log_error(APLOG_MARK, APLOG_WARNING, 0, ss,
			     "Cannot get media parameter.");
		return (NULL);
	    }

	    pp = apr_palloc(p, sizeof(param));
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

/*
 * find_ct is the hook routine for determining content-type and other
 * MIME-related metadata.  It assumes that r->filename has already been
 * set and stat has been called for r->finfo.  It also assumes that the
 * non-path base file name is not the empty string unless it is a dir.
 */
static int find_ct(request_rec *r)
{
    mime_dir_config *conf;
    apr_array_header_t *exception_list;
    char *ext;
    const char *fn, *type, *charset = NULL;
    int found_metadata = 0;

    if (r->finfo.filetype == APR_DIR) {
        r->content_type = DIR_MAGIC_TYPE;
        return OK;
    }

    conf = (mime_dir_config *) ap_get_module_config(r->per_dir_config,
                                                    &mime_module);
    exception_list = apr_array_make(r->pool, 2, sizeof(char *));

    /* Always drop the path leading up to the file name.
     */
    if ((fn = strrchr(r->filename, '/')) == NULL)
        fn = r->filename;
    else
        ++fn;

    /* The exception list keeps track of those filename components that
     * are not associated with extensions indicating metadata.
     * The base name is always the first exception (i.e., "txt.html" has
     * a basename of "txt" even though it might look like an extension).
     */
    ext = ap_getword(r->pool, &fn, '.');
    *((const char **) apr_array_push(exception_list)) = ext;

    /* Parse filename extensions which can be in any order 
     */
    while (*fn && (ext = ap_getword(r->pool, &fn, '.'))) {
        extension_info *exinfo = NULL;
        int found;

        if (*ext == '\0')  /* ignore empty extensions "bad..html" */
            continue;

        found = 0;

#ifdef CASE_BLIND_FILESYSTEM
        /* We have a basic problem that folks on case-crippled systems
         * expect anything and everything to succeed
         */
        ap_str_tolower(ext);
#endif

        if (conf->extension_mappings != NULL) {
            exinfo = (extension_info*)apr_hash_get(conf->extension_mappings,
                                                   ext, APR_HASH_KEY_STRING);
        }

        if (exinfo == NULL || !exinfo->forced_type) {
            if ((type = apr_hash_get(mime_type_extensions, ext,
                                     APR_HASH_KEY_STRING)) != NULL) {
                r->content_type = type;
                found = 1;
            }
        }

        if (exinfo != NULL) {

            if (exinfo->forced_type) {
                r->content_type = exinfo->forced_type;
                found = 1;
            }

            if (exinfo->charset_type) {
                charset = exinfo->charset_type;
                found = 1;
            }
            if (exinfo->language_type) {
                if (!r->content_languages)
                    r->content_languages = apr_array_make(r->pool, 2,
                                                          sizeof(char *));
                    *((const char **) apr_array_push(r->content_languages))
                                          = exinfo->language_type;
                found = 1;
            }
            if (exinfo->encoding_type) {
                if (!r->content_encoding)
                    r->content_encoding = exinfo->encoding_type;
                else {
                    /* XXX should eliminate duplicate entities */
                    r->content_encoding = apr_pstrcat(r->pool,
                                                      r->content_encoding,
                                                      ", ",
                                                      exinfo->encoding_type,
                                                      NULL);
                }
                found = 1;
            }
            /* The following extensions are not 'Found'.  That is, they don't
             * make any contribution to metadata negotation, so they must have
             * been explicitly requested by name. 
             */
            if (exinfo->handler && r->proxyreq == PROXYREQ_NONE) {
                r->handler = exinfo->handler;
                found = 1;
            }
            /* XXX Two significant problems; 1, we don't check to see if we are
             * setting redundant filters.    2, we insert these in the types config
             * hook, which may be too early (dunno.)
             */
            if (exinfo->input_filters && r->proxyreq == PROXYREQ_NONE) {
                const char *filter, *filters = exinfo->input_filters;
                while (*filters 
                    && (filter = ap_getword(r->pool, &filters, ';'))) {
                    ap_add_input_filter(filter, NULL, r, r->connection);
                }
                found = 1;
            }
            if (exinfo->output_filters && r->proxyreq == PROXYREQ_NONE) {
                const char *filter, *filters = exinfo->output_filters;
                while (*filters 
                    && (filter = ap_getword(r->pool, &filters, ';'))) {
                    ap_add_output_filter(filter, NULL, r, r->connection);
                }
                found = 1;
            }
        }

        if (found)
            found_metadata = 1;
        else
            *((const char **) apr_array_push(exception_list)) = ext;
    }

    /*
     * Need to set a notes entry on r for unrecognized elements.
     * Somebody better claim them!  If we did absolutely nothing,
     * skip the notes to alert mod_negotiation we are clueless.
     */
    if (found_metadata) {
        apr_table_setn(r->notes, "ap-mime-exceptions-list", 
                       (void *)exception_list);
    }

    if (r->content_type) {
	content_type *ctp;
	char *ct;
	int override = 0;

	ct = (char *) apr_palloc(r->pool,
				sizeof(char) * (strlen(r->content_type) + 1));
	strcpy(ct, r->content_type);

	if ((ctp = analyze_ct(r, ct))) {
	    param *pp = ctp->param;
	    r->content_type = apr_pstrcat(r->pool, ctp->type, "/",
					 ctp->subtype, NULL);
	    while (pp != NULL) {
		if (charset && !strcmp(pp->attr, "charset")) {
		    if (!override) {
			r->content_type = apr_pstrcat(r->pool, r->content_type,
						     "; charset=", charset,
						     NULL);
			override = 1;
		    }
		}
		else {
		    r->content_type = apr_pstrcat(r->pool, r->content_type,
						 "; ", pp->attr,
						 "=", pp->val,
						 NULL);
		}
		pp = pp->next;
	    }
	    if (charset && !override) {
		r->content_type = apr_pstrcat(r->pool, r->content_type,
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

        if (!r->content_languages)
            r->content_languages = apr_array_make(r->pool, 2, sizeof(char *));
        new = (const char **) apr_array_push(r->content_languages);
        *new = conf->default_language;
    }

    if (!r->content_type)
        return DECLINED;

    return OK;
}

static void register_hooks(apr_pool_t *p)
{
    ap_hook_post_config(mime_post_config,NULL,NULL,APR_HOOK_MIDDLE);
    ap_hook_type_checker(find_ct,NULL,NULL,APR_HOOK_MIDDLE);
 /* 
  * this hook seems redundant ... is there any reason a type checker isn't
  * allowed to do this already?  I'd think that fixups in general would be
  * the last opportunity to get the filters right.
  * ap_hook_insert_filter(mime_insert_filters,NULL,NULL,APR_HOOK_MIDDLE);
  */
}

module AP_MODULE_DECLARE_DATA mime_module = {
    STANDARD20_MODULE_STUFF,
    create_mime_dir_config,	/* create per-directory config structure */
    merge_mime_dir_configs,	/* merge per-directory config structures */
    NULL,			/* create per-server config structure */
    NULL,			/* merge per-server config structures */
    mime_cmds,			/* command apr_table_t */
    register_hooks		/* register hooks */
};
