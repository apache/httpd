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
#include "http_protocol.h"

/* XXXX - fix me / EBCDIC
 *        there was a cludge here which would use its
 *        own version apr_isascii(). Indicating that
 *        on some platforms that might be needed.
 *
 *        #define OS_ASC(c) (c)             -- for mere mortals
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

#define MULTIMATCH_UNSET      0
#define MULTIMATCH_ANY        1
#define MULTIMATCH_NEGOTIATED 2
#define MULTIMATCH_HANDLERS   4
#define MULTIMATCH_FILTERS    8

typedef struct {
    apr_hash_t *extension_mappings;  /* Map from extension name to
                                      * extension_info structure */

    apr_array_header_t *remove_mappings; /* A simple list, walked once */

    char *default_language;     /* Language if no AddLanguage ext found */

    int multimatch;       /* Extensions to include in multiview matching
                           * for filenames, e.g. Filters and Handlers
                           */
    int use_path_info;    /* If set to 0, only use filename.
                           * If set to 1, append PATH_INFO to filename for
                           *   lookups.
                           * If set to 2, this value is unset and is
                           *   effectively 0.
                           */
} mime_dir_config;

typedef struct param_s {
    char *attr;
    char *val;
    struct param_s *next;
} param;

typedef struct {
    const char *type;
    apr_size_t type_len;
    const char *subtype;
    apr_size_t subtype_len;
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
    mime_dir_config *new = apr_palloc(p, sizeof(mime_dir_config));

    new->extension_mappings = NULL;
    new->remove_mappings = NULL;

    new->default_language = NULL;

    new->multimatch = MULTIMATCH_UNSET;

    new->use_path_info = 2;

    return new;
}
/*
 * Overlay one hash table of extension_mappings onto another
 */
static void *overlay_extension_mappings(apr_pool_t *p,
                                        const void *key,
                                        apr_ssize_t klen,
                                        const void *overlay_val,
                                        const void *base_val,
                                        const void *data)
{
    const extension_info *overlay_info = (const extension_info *)overlay_val;
    const extension_info *base_info = (const extension_info *)base_val;
    extension_info *new_info = apr_pmemdup(p, base_info, sizeof(extension_info));

    if (overlay_info->forced_type) {
        new_info->forced_type = overlay_info->forced_type;
    }
    if (overlay_info->encoding_type) {
        new_info->encoding_type = overlay_info->encoding_type;
    }
    if (overlay_info->language_type) {
        new_info->language_type = overlay_info->language_type;
    }
    if (overlay_info->handler) {
        new_info->handler = overlay_info->handler;
    }
    if (overlay_info->charset_type) {
        new_info->charset_type = overlay_info->charset_type;
    }
    if (overlay_info->input_filters) {
        new_info->input_filters = overlay_info->input_filters;
    }
    if (overlay_info->output_filters) {
        new_info->output_filters = overlay_info->output_filters;
    }

    return new_info;
}

/* Member is the offset within an extension_info of the pointer to reset
 */
static void remove_items(apr_pool_t *p, apr_array_header_t *remove,
                         apr_hash_t *mappings)
{
    attrib_info *suffix = (attrib_info *) remove->elts;
    int i;
    for (i = 0; i < remove->nelts; i++) {
        extension_info *exinfo = apr_hash_get(mappings,
                                              suffix[i].name,
                                              APR_HASH_KEY_STRING);
        if (exinfo && *(const char**)((char *)exinfo + suffix[i].offset)) {
            extension_info *copyinfo = exinfo;
            exinfo = apr_pmemdup(p, copyinfo, sizeof(*exinfo));
            apr_hash_set(mappings, suffix[i].name,
                         APR_HASH_KEY_STRING, exinfo);

            *(const char**)((char *)exinfo + suffix[i].offset) = NULL;
        }
    }
}

static void *merge_mime_dir_configs(apr_pool_t *p, void *basev, void *addv)
{
    mime_dir_config *base = (mime_dir_config *)basev;
    mime_dir_config *add = (mime_dir_config *)addv;
    mime_dir_config *new = apr_palloc(p, sizeof(mime_dir_config));

    if (base->extension_mappings && add->extension_mappings) {
        new->extension_mappings = apr_hash_merge(p, add->extension_mappings,
                                                 base->extension_mappings,
                                                 overlay_extension_mappings,
                                                 NULL);
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
            new->extension_mappings =
                apr_hash_copy(p, new->extension_mappings);
        }
    }

    if (new->extension_mappings) {
        if (add->remove_mappings)
            remove_items(p, add->remove_mappings, new->extension_mappings);
    }
    new->remove_mappings = NULL;

    new->default_language = add->default_language ?
        add->default_language : base->default_language;

    new->multimatch = (add->multimatch != MULTIMATCH_UNSET) ?
        add->multimatch : base->multimatch;

    if ((add->use_path_info & 2) == 0) {
        new->use_path_info = add->use_path_info;
    }
    else {
        new->use_path_info = base->use_path_info;
    }

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
    ap_str_tolower(key);

    if (*key == '.') {
        ++key;
    }
    if (!m->extension_mappings) {
        m->extension_mappings = apr_hash_make(cmd->pool);
        exinfo = NULL;
    }
    else {
        exinfo = (extension_info*)apr_hash_get(m->extension_mappings, key,
                                               APR_HASH_KEY_STRING);
    }
    if (!exinfo) {
        exinfo = apr_pcalloc(cmd->pool, sizeof(extension_info));
        key = apr_pstrdup(cmd->pool, key);
        apr_hash_set(m->extension_mappings, key, APR_HASH_KEY_STRING, exinfo);
    }
    *(const char**)((char *)exinfo + offset) = value;
    return NULL;
}

/*
 * As RemoveType should also override the info from TypesConfig, we add an
 * empty string as type instead of actually removing the type.
 */
static const char *remove_extension_type(cmd_parms *cmd, void *m_,
                                         const char *ext)
{
    return add_extension_info(cmd, m_, "", ext);
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
    if (*ext == '.') {
        ++ext;
    }
    if (!m->remove_mappings) {
        m->remove_mappings = apr_array_make(cmd->pool, 4, sizeof(*suffix));
    }
    suffix = (attrib_info *)apr_array_push(m->remove_mappings);
    suffix->name = apr_pstrdup(cmd->pool, ext);
    ap_str_tolower(suffix->name);
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

static const char *multiviews_match(cmd_parms *cmd, void *m_,
                                    const char *include)
{
    mime_dir_config *m = (mime_dir_config *) m_;
    const char *errmsg;

    errmsg = ap_check_cmd_context(cmd, NOT_IN_LOCATION);
    if (errmsg != NULL) {
        return errmsg;
    }

    if (strcasecmp(include, "Any") == 0) {
        if (m->multimatch && (m->multimatch & ~MULTIMATCH_ANY)) {
            return "Any is incompatible with NegotiatedOnly, "
                   "Filters and Handlers";
        }
        m->multimatch |= MULTIMATCH_ANY;
    }
    else if (strcasecmp(include, "NegotiatedOnly") == 0) {
        if (m->multimatch && (m->multimatch & ~MULTIMATCH_NEGOTIATED)) {
            return "NegotiatedOnly is incompatible with Any, "
                   "Filters and Handlers";
        }
        m->multimatch |= MULTIMATCH_NEGOTIATED;
    }
    else if (strcasecmp(include, "Filters") == 0) {
        if (m->multimatch && (m->multimatch & (MULTIMATCH_NEGOTIATED
                                             | MULTIMATCH_ANY))) {
            return "Filters is incompatible with Any and NegotiatedOnly";
        }
        m->multimatch |= MULTIMATCH_FILTERS;
    }
    else if (strcasecmp(include, "Handlers") == 0) {
        if (m->multimatch && (m->multimatch & (MULTIMATCH_NEGOTIATED
                                             | MULTIMATCH_ANY))) {
            return "Handlers is incompatible with Any and NegotiatedOnly";
        }
        m->multimatch |= MULTIMATCH_HANDLERS;
    }
    else {
        return apr_psprintf(cmd->pool, "Unrecognized option '%s'", include);
    }

    return NULL;
}

static const command_rec mime_cmds[] =
{
    AP_INIT_ITERATE2("AddCharset", add_extension_info,
        (void *)APR_OFFSETOF(extension_info, charset_type), OR_FILEINFO,
        "a charset (e.g., iso-2022-jp), followed by one or more "
        "file extensions"),
    AP_INIT_ITERATE2("AddEncoding", add_extension_info,
        (void *)APR_OFFSETOF(extension_info, encoding_type), OR_FILEINFO,
        "an encoding (e.g., gzip), followed by one or more file extensions"),
    AP_INIT_ITERATE2("AddHandler", add_extension_info,
        (void *)APR_OFFSETOF(extension_info, handler), OR_FILEINFO,
        "a handler name followed by one or more file extensions"),
    AP_INIT_ITERATE2("AddInputFilter", add_extension_info,
        (void *)APR_OFFSETOF(extension_info, input_filters), OR_FILEINFO,
        "input filter name (or ; delimited names) followed by one or "
        "more file extensions"),
    AP_INIT_ITERATE2("AddLanguage", add_extension_info,
        (void *)APR_OFFSETOF(extension_info, language_type), OR_FILEINFO,
        "a language (e.g., fr), followed by one or more file extensions"),
    AP_INIT_ITERATE2("AddOutputFilter", add_extension_info,
        (void *)APR_OFFSETOF(extension_info, output_filters), OR_FILEINFO,
        "output filter name (or ; delimited names) followed by one or "
        "more file extensions"),
    AP_INIT_ITERATE2("AddType", add_extension_info,
        (void *)APR_OFFSETOF(extension_info, forced_type), OR_FILEINFO,
        "a mime type followed by one or more file extensions"),
    AP_INIT_TAKE1("DefaultLanguage", ap_set_string_slot,
        (void*)APR_OFFSETOF(mime_dir_config, default_language), OR_FILEINFO,
        "language to use for documents with no other language file extension"),
    AP_INIT_ITERATE("MultiviewsMatch", multiviews_match, NULL, OR_FILEINFO,
        "NegotiatedOnly (default), Handlers and/or Filters, or Any"),
    AP_INIT_ITERATE("RemoveCharset", remove_extension_info,
        (void *)APR_OFFSETOF(extension_info, charset_type), OR_FILEINFO,
        "one or more file extensions"),
    AP_INIT_ITERATE("RemoveEncoding", remove_extension_info,
        (void *)APR_OFFSETOF(extension_info, encoding_type), OR_FILEINFO,
        "one or more file extensions"),
    AP_INIT_ITERATE("RemoveHandler", remove_extension_info,
        (void *)APR_OFFSETOF(extension_info, handler), OR_FILEINFO,
        "one or more file extensions"),
    AP_INIT_ITERATE("RemoveInputFilter", remove_extension_info,
        (void *)APR_OFFSETOF(extension_info, input_filters), OR_FILEINFO,
        "one or more file extensions"),
    AP_INIT_ITERATE("RemoveLanguage", remove_extension_info,
        (void *)APR_OFFSETOF(extension_info, language_type), OR_FILEINFO,
        "one or more file extensions"),
    AP_INIT_ITERATE("RemoveOutputFilter", remove_extension_info,
        (void *)APR_OFFSETOF(extension_info, output_filters), OR_FILEINFO,
        "one or more file extensions"),
    AP_INIT_ITERATE("RemoveType", remove_extension_type,
        (void *)APR_OFFSETOF(extension_info, forced_type), OR_FILEINFO,
        "one or more file extensions"),
    AP_INIT_TAKE1("TypesConfig", set_types_config, NULL, RSRC_CONF,
        "the MIME types config file"),
    AP_INIT_FLAG("ModMimeUsePathInfo", ap_set_flag_slot,
        (void *)APR_OFFSETOF(mime_dir_config, use_path_info), ACCESS_CONF,
        "Set to 'yes' to allow mod_mime to use path info for type checking"),
    {NULL}
};

static apr_hash_t *mime_type_extensions;

static int mime_post_config(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s)
{
    ap_configfile_t *f;
    char l[MAX_STRING_LEN];
    const char *types_confname = ap_get_module_config(s->module_config,
                                                      &mime_module);
    apr_status_t status;

    if (!types_confname) {
        types_confname = AP_TYPES_CONFIG_FILE;
    }

    types_confname = ap_server_root_relative(p, types_confname);
    if (!types_confname) {
        ap_log_error(APLOG_MARK, APLOG_ERR, APR_EBADPATH, s, APLOGNO(01596)
                     "Invalid mime types config path %s",
                     (const char *)ap_get_module_config(s->module_config,
                                                        &mime_module));
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    if ((status = ap_pcfg_openfile(&f, ptemp, types_confname))
                != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, status, s, APLOGNO(01597)
                     "could not open mime types config file %s.",
                     types_confname);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    mime_type_extensions = apr_hash_make(p);

    while (!(ap_cfg_getline(l, MAX_STRING_LEN, f))) {
        const char *ll = l, *ct;

        if (l[0] == '#') {
            continue;
        }
        ct = ap_getword_conf(p, &ll);

        while (ll[0]) {
            char *ext = ap_getword_conf(p, &ll);
            ap_str_tolower(ext);
            apr_hash_set(mime_type_extensions, ext, APR_HASH_KEY_STRING, ct);
        }
    }
    ap_cfg_closefile(f);
    return OK;
}

static const char *zap_sp(const char *s)
{
    if (s == NULL) {
        return (NULL);
    }
    if (*s == '\0') {
        return (s);
    }

    /* skip prefixed white space */
    for (; *s == ' ' || *s == '\t' || *s == '\n'; s++)
        ;

    return (s);
}

static char *zap_sp_and_dup(apr_pool_t *p, const char *start,
                            const char *end, apr_size_t *len)
{
    while ((start < end) && apr_isspace(*start)) {
        start++;
    }
    while ((end > start) && apr_isspace(*(end - 1))) {
        end--;
    }
    if (len) {
        *len = end - start;
    }
    return apr_pstrmemdup(p, start, end - start);
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

static int is_quoted_pair(const char *s)
{
    int res = -1;
    int c;

    if (*s == '\\') {
        c = (int) *(s + 1);
        if (c && apr_isascii(c)) {
            res = 1;
        }
    }
    return (res);
}

static content_type *analyze_ct(request_rec *r, const char *s)
{
    const char *cp, *mp;
    char *attribute, *value;
    int quoted = 0;
    server_rec * ss = r->server;
    apr_pool_t * p = r->pool;

    content_type *ctp;
    param *pp, *npp;

    /* initialize ctp */
    ctp = (content_type *)apr_palloc(p, sizeof(content_type));
    ctp->type = NULL;
    ctp->subtype = NULL;
    ctp->param = NULL;

    mp = s;

    /* getting a type */
    cp = mp;
    while (apr_isspace(*cp)) {
        cp++;
    }
    if (!*cp) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, ss, APLOGNO(01598)
                     "mod_mime: analyze_ct: cannot get media type from '%s'",
                     (const char *) mp);
        return (NULL);
    }
    ctp->type = cp;
    do {
        cp++;
    } while (*cp && (*cp != '/') && !apr_isspace(*cp) && (*cp != ';'));
    if (!*cp || (*cp == ';')) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, ss, APLOGNO(01599)
                     "Cannot get media type from '%s'",
                     (const char *) mp);
        return (NULL);
    }
    while (apr_isspace(*cp)) {
        cp++;
    }
    if (*cp != '/') {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, ss, APLOGNO(01600)
                     "mod_mime: analyze_ct: cannot get media type from '%s'",
                     (const char *) mp);
        return (NULL);
    }
    ctp->type_len = cp - ctp->type;

    cp++; /* skip the '/' */

    /* getting a subtype */
    while (apr_isspace(*cp)) {
        cp++;
    }
    if (!*cp) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, ss, APLOGNO(01601)
                     "Cannot get media subtype.");
        return (NULL);
    }
    ctp->subtype = cp;
    do {
        cp++;
    } while (*cp && !apr_isspace(*cp) && (*cp != ';'));
    ctp->subtype_len = cp - ctp->subtype;
    while (apr_isspace(*cp)) {
        cp++;
    }

    if (*cp == '\0') {
        return (ctp);
    }

    /* getting parameters */
    cp++; /* skip the ';' */
    cp = zap_sp(cp);
    if (cp == NULL || *cp == '\0') {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, ss, APLOGNO(01602)
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
                attribute = zap_sp_and_dup(p, mp, cp, NULL);
                if (attribute == NULL || *attribute == '\0') {
                    ap_log_error(APLOG_MARK, APLOG_WARNING, 0, ss, APLOGNO(01603)
                                 "Cannot get media parameter.");
                    return (NULL);
                }
                cp++;
                cp = zap_sp(cp);
                if (cp == NULL || *cp == '\0') {
                    ap_log_error(APLOG_MARK, APLOG_WARNING, 0, ss, APLOGNO(01604)
                                 "Cannot get media parameter.");
                    return (NULL);
                }
                mp = cp;
                continue;
            }
            else {
                ap_log_error(APLOG_MARK, APLOG_WARNING, 0, ss, APLOGNO(01605)
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
                            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, ss, APLOGNO(01606)
                                         "Cannot get media parameter.");
                            return(NULL);
                        }
                        quoted = 0;
                    }
                    else {
                        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, ss, APLOGNO(01607)
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
                        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, ss, APLOGNO(01608)
                                     "Cannot get media parameter.");
                        return (NULL);
                    }
                }
            }
            value = zap_sp_and_dup(p, mp, cp, NULL);
            if (value == NULL || *value == '\0') {
                ap_log_error(APLOG_MARK, APLOG_WARNING, 0, ss, APLOGNO(01609)
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
    const char *fn, *fntmp, *type, *charset = NULL, *resource_name, *qm;
    int found_metadata = 0;

    if (r->finfo.filetype == APR_DIR) {
        ap_set_content_type(r, DIR_MAGIC_TYPE);
        return OK;
    }

    if (!r->filename) {
        return DECLINED;
    }

    conf = (mime_dir_config *)ap_get_module_config(r->per_dir_config,
                                                   &mime_module);
    exception_list = apr_array_make(r->pool, 2, sizeof(char *));

    /* If use_path_info is explicitly set to on (value & 1 == 1), append. */
    if (conf->use_path_info & 1) {
        resource_name = apr_pstrcat(r->pool, r->filename, r->path_info, NULL);
    }
    /*
     * In the reverse proxy case r->filename might contain a query string if
     * the nocanon option was used with ProxyPass.
     * If this is the case cut off the query string as the last parameter in
     * this query string might end up on an extension we take care about, but
     * we only want to match against path components not against query
     * parameters.
     */
    else if ((r->proxyreq == PROXYREQ_REVERSE)
             && (apr_table_get(r->notes, "proxy-nocanon"))
             && ((qm = ap_strchr_c(r->filename, '?')) != NULL)) {
        resource_name = apr_pstrmemdup(r->pool, r->filename, qm - r->filename);
    }
    else {
        resource_name = r->filename;
    }

    /* Always drop the path leading up to the file name.
     */
    if ((fn = ap_strrchr_c(resource_name, '/')) == NULL) {
        fn = resource_name;
    }
    else {
        ++fn;
    }


    /* The exception list keeps track of those filename components that
     * are not associated with extensions indicating metadata.
     * The base name is always the first exception (i.e., "txt.html" has
     * a basename of "txt" even though it might look like an extension).
     * Leading dots are considered to be part of the base name (a file named
     * ".png" is likely not a png file but just a hidden file called png).
     */
    fntmp = fn;
    while (*fntmp == '.')
        fntmp++;
    fntmp = ap_strchr_c(fntmp, '.');
    if (fntmp) {
        ext = apr_pstrmemdup(r->pool, fn, fntmp - fn);
        fn = fntmp + 1;
    }
    else {
        ext = apr_pstrdup(r->pool, fn);
        fn += strlen(fn);
    }

    *((const char **)apr_array_push(exception_list)) = ext;

    /* Parse filename extensions which can be in any order
     */
    while (*fn && (ext = ap_getword(r->pool, &fn, '.'))) {
        const extension_info *exinfo = NULL;
        int found;
        char *extcase;

        if (*ext == '\0') {  /* ignore empty extensions "bad..html" */
            continue;
        }

        found = 0;

        /* Save the ext in extcase before converting it to lower case.
         */
        extcase = apr_pstrdup(r->pool, ext);
        ap_str_tolower(ext);

        if (conf->extension_mappings != NULL) {
            exinfo = (extension_info*)apr_hash_get(conf->extension_mappings,
                                                   ext, APR_HASH_KEY_STRING);
        }

        if (exinfo == NULL || !exinfo->forced_type) {
            if ((type = apr_hash_get(mime_type_extensions, ext,
                                     APR_HASH_KEY_STRING)) != NULL) {
                ap_set_content_type(r, (char*) type);
                found = 1;
            }
        }

        if (exinfo != NULL) {

            /* empty string is treated as special case for RemoveType */
            if (exinfo->forced_type && *exinfo->forced_type) {
                ap_set_content_type(r, exinfo->forced_type);
                found = 1;
            }

            if (exinfo->charset_type) {
                charset = exinfo->charset_type;
                found = 1;
            }
            if (exinfo->language_type) {
                if (!r->content_languages) {
                    r->content_languages = apr_array_make(r->pool, 2,
                                                          sizeof(char *));
                }
                *((const char **)apr_array_push(r->content_languages))
                    = exinfo->language_type;
                found = 1;
            }
            if (exinfo->encoding_type) {
                if (!r->content_encoding) {
                    r->content_encoding = exinfo->encoding_type;
                }
                else {
                    /* XXX should eliminate duplicate entities
                     *
                     * ah no. Order is important and double encoding is neither
                     * forbidden nor impossible. -- nd
                     */
                    r->content_encoding = apr_pstrcat(r->pool,
                                                      r->content_encoding,
                                                      ", ",
                                                      exinfo->encoding_type,
                                                      NULL);
                }
                found = 1;
            }
            /* The following extensions are not 'Found'.  That is, they don't
             * make any contribution to metadata negotiation, so they must have
             * been explicitly requested by name.
             */
            if (exinfo->handler && r->proxyreq == PROXYREQ_NONE) {
                r->handler = exinfo->handler;
                if (conf->multimatch & MULTIMATCH_HANDLERS) {
                    found = 1;
                }
            }
            /* XXX Two significant problems; 1, we don't check to see if we are
             * setting redundant filters.    2, we insert these in the types
             * config hook, which may be too early (dunno.)
             */
            if (exinfo->input_filters) {
                const char *filter, *filters = exinfo->input_filters;
                while (*filters
                    && (filter = ap_getword(r->pool, &filters, ';'))) {
                    ap_add_input_filter(filter, NULL, r, r->connection);
                }
                if (conf->multimatch & MULTIMATCH_FILTERS) {
                    found = 1;
                }
            }
            if (exinfo->output_filters) {
                const char *filter, *filters = exinfo->output_filters;
                while (*filters
                    && (filter = ap_getword(r->pool, &filters, ';'))) {
                    ap_add_output_filter(filter, NULL, r, r->connection);
                }
                if (conf->multimatch & MULTIMATCH_FILTERS) {
                    found = 1;
                }
            }
        }

        if (found || (conf->multimatch & MULTIMATCH_ANY)) {
            found_metadata = 1;
        }
        else {
            *((const char **) apr_array_push(exception_list)) = extcase;
        }
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
        int override = 0;

        if ((ctp = analyze_ct(r, r->content_type))) {
            param *pp = ctp->param;
            char *base_content_type = apr_palloc(r->pool, ctp->type_len +
                                                 ctp->subtype_len +
                                                 sizeof("/"));
            char *tmp = base_content_type;
            memcpy(tmp, ctp->type, ctp->type_len);
            tmp += ctp->type_len;
            *tmp++ = '/';
            memcpy(tmp, ctp->subtype, ctp->subtype_len);
            tmp += ctp->subtype_len;
            *tmp = 0;
            ap_set_content_type(r, base_content_type);
            while (pp != NULL) {
                if (charset && !strcmp(pp->attr, "charset")) {
                    if (!override) {
                        ap_set_content_type(r,
                                            apr_pstrcat(r->pool,
                                                        r->content_type,
                                                        "; charset=",
                                                        charset,
                                                        NULL));
                        override = 1;
                    }
                }
                else {
                    ap_set_content_type(r,
                                        apr_pstrcat(r->pool,
                                                    r->content_type,
                                                    "; ", pp->attr,
                                                    "=", pp->val,
                                                    NULL));
                }
                pp = pp->next;
            }
            if (charset && !override) {
                ap_set_content_type(r, apr_pstrcat(r->pool, r->content_type,
                                                   "; charset=", charset,
                                                   NULL));
            }
        }
    }

    /* Set default language, if none was specified by the extensions
     * and we have a DefaultLanguage setting in force
     */

    if (!r->content_languages && conf->default_language) {
        const char **new;

        r->content_languages = apr_array_make(r->pool, 2, sizeof(char *));
        new = (const char **)apr_array_push(r->content_languages);
        *new = conf->default_language;
    }

    if (!r->content_type) {
        return DECLINED;
    }

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

AP_DECLARE_MODULE(mime) = {
    STANDARD20_MODULE_STUFF,
    create_mime_dir_config,     /* create per-directory config structure */
    merge_mime_dir_configs,     /* merge per-directory config structures */
    NULL,                       /* create per-server config structure */
    NULL,                       /* merge per-server config structures */
    mime_cmds,                  /* command apr_table_t */
    register_hooks              /* register hooks */
};
