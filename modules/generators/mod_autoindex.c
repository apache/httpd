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
 * mod_autoindex.c: Handles the on-the-fly html index generation
 *
 * Rob McCool
 * 3/23/93
 *
 * Adapted to Apache by rst.
 *
 * Version sort added by Martin Pool <mbp@humbug.org.au>.
 */

#include "apr_strings.h"
#include "apr_fnmatch.h"
#include "apr_strings.h"
#include "apr_lib.h"

#define APR_WANT_STRFUNC
#include "apr_want.h"

#include "ap_config.h"
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_request.h"
#include "http_protocol.h"
#include "http_log.h"
#include "http_main.h"
#include "util_script.h"

#include "mod_core.h"

module AP_MODULE_DECLARE_DATA autoindex_module;

/****************************************************************
 *
 * Handling configuration directives...
 */

#define NO_OPTIONS          (1 <<  0)  /* Indexing options */
#define ICONS_ARE_LINKS     (1 <<  1)
#define SCAN_HTML_TITLES    (1 <<  2)
#define SUPPRESS_ICON       (1 <<  3)
#define SUPPRESS_LAST_MOD   (1 <<  4)
#define SUPPRESS_SIZE       (1 <<  5)
#define SUPPRESS_DESC       (1 <<  6)
#define SUPPRESS_PREAMBLE   (1 <<  7)
#define SUPPRESS_COLSORT    (1 <<  8)
#define SUPPRESS_RULES      (1 <<  9)
#define FOLDERS_FIRST       (1 << 10)
#define VERSION_SORT        (1 << 11)
#define TRACK_MODIFIED      (1 << 12)
#define FANCY_INDEXING      (1 << 13)
#define TABLE_INDEXING      (1 << 14)
#define IGNORE_CLIENT       (1 << 15)
#define IGNORE_CASE         (1 << 16)
#define EMIT_XHTML          (1 << 17)

#define K_NOADJUST 0
#define K_ADJUST 1
#define K_UNSET 2

/*
 * Define keys for sorting.
 */
#define K_NAME 'N'              /* Sort by file name (default) */
#define K_LAST_MOD 'M'          /* Last modification date */
#define K_SIZE 'S'              /* Size (absolute, not as displayed) */
#define K_DESC 'D'              /* Description */
#define K_VALID "NMSD"          /* String containing _all_ valid K_ opts */

#define D_ASCENDING 'A'
#define D_DESCENDING 'D'
#define D_VALID "AD"            /* String containing _all_ valid D_ opts */

/*
 * These are the dimensions of the default icons supplied with Apache.
 */
#define DEFAULT_ICON_WIDTH 20
#define DEFAULT_ICON_HEIGHT 22

/*
 * Other default dimensions.
 */
#define DEFAULT_NAME_WIDTH 23
#define DEFAULT_DESC_WIDTH 23

struct item {
    char *type;
    char *apply_to;
    char *apply_path;
    char *data;
};

typedef struct ai_desc_t {
    char *pattern;
    char *description;
    int full_path;
    int wildcards;
} ai_desc_t;

typedef struct autoindex_config_struct {

    char *default_icon;
    char *style_sheet;
    apr_int32_t opts;
    apr_int32_t incremented_opts;
    apr_int32_t decremented_opts;
    int name_width;
    int name_adjust;
    int desc_width;
    int desc_adjust;
    int icon_width;
    int icon_height;
    char default_keyid;
    char default_direction;

    apr_array_header_t *icon_list;
    apr_array_header_t *alt_list;
    apr_array_header_t *desc_list;
    apr_array_header_t *ign_list;
    apr_array_header_t *hdr_list;
    apr_array_header_t *rdme_list;

} autoindex_config_rec;

static char c_by_encoding, c_by_type, c_by_path;

#define BY_ENCODING &c_by_encoding
#define BY_TYPE &c_by_type
#define BY_PATH &c_by_path

/*
 * This routine puts the standard HTML header at the top of the index page.
 * We include the DOCTYPE because we may be using features therefrom (i.e.,
 * HEIGHT and WIDTH attributes on the icons if we're FancyIndexing).
 */
static void emit_preamble(request_rec *r, int xhtml, const char *title)
{
    autoindex_config_rec *d;

    d = (autoindex_config_rec *) ap_get_module_config(r->per_dir_config,
                                                      &autoindex_module);

    ap_rvputs(r, xhtml ? DOCTYPE_XHTML_1_0T : DOCTYPE_HTML_3_2,
              "<html>\n <head>\n  <title>Index of ", title,
              "</title>\n", NULL);
    if (d->style_sheet != NULL) {
        ap_rvputs(r, "  <link rel=\"stylesheet\" href=\"", d->style_sheet,
                "\" type=\"text/css\"", xhtml ? " />\n" : ">\n", NULL);
    }
    ap_rvputs(r, " </head>\n <body>\n", NULL);
}

static void push_item(apr_array_header_t *arr, char *type, const char *to,
                      const char *path, const char *data)
{
    struct item *p = (struct item *) apr_array_push(arr);

    if (!to) {
        to = "";
    }
    if (!path) {
        path = "";
    }

    p->type = type;
    p->data = data ? apr_pstrdup(arr->pool, data) : NULL;
    p->apply_path = apr_pstrcat(arr->pool, path, "*", NULL);

    if ((type == BY_PATH) && (!ap_is_matchexp(to))) {
        p->apply_to = apr_pstrcat(arr->pool, "*", to, NULL);
    }
    else if (to) {
        p->apply_to = apr_pstrdup(arr->pool, to);
    }
    else {
        p->apply_to = NULL;
    }
}

static const char *add_alt(cmd_parms *cmd, void *d, const char *alt,
                           const char *to)
{
    if (cmd->info == BY_PATH) {
        if (!strcmp(to, "**DIRECTORY**")) {
            to = "^^DIRECTORY^^";
        }
    }
    if (cmd->info == BY_ENCODING) {
        char *tmp = apr_pstrdup(cmd->pool, to);
        ap_str_tolower(tmp);
        to = tmp;
    }

    push_item(((autoindex_config_rec *) d)->alt_list, cmd->info, to,
              cmd->path, alt);
    return NULL;
}

static const char *add_icon(cmd_parms *cmd, void *d, const char *icon,
                            const char *to)
{
    char *iconbak = apr_pstrdup(cmd->pool, icon);

    if (icon[0] == '(') {
        char *alt;
        char *cl = strchr(iconbak, ')');

        if (cl == NULL) {
            return "missing closing paren";
        }
        alt = ap_getword_nc(cmd->pool, &iconbak, ',');
        *cl = '\0';                             /* Lose closing paren */
        add_alt(cmd, d, &alt[1], to);
    }
    if (cmd->info == BY_PATH) {
        if (!strcmp(to, "**DIRECTORY**")) {
            to = "^^DIRECTORY^^";
        }
    }
    if (cmd->info == BY_ENCODING) {
        char *tmp = apr_pstrdup(cmd->pool, to);
        ap_str_tolower(tmp);
        to = tmp;
    }

    push_item(((autoindex_config_rec *) d)->icon_list, cmd->info, to,
              cmd->path, iconbak);
    return NULL;
}

/*
 * Add description text for a filename pattern.  If the pattern has
 * wildcards already (or we need to add them), add leading and
 * trailing wildcards to it to ensure substring processing.  If the
 * pattern contains a '/' anywhere, force wildcard matching mode,
 * add a slash to the prefix so that "bar/bletch" won't be matched
 * by "foobar/bletch", and make a note that there's a delimiter;
 * the matching routine simplifies to just the actual filename
 * whenever it can.  This allows definitions in parent directories
 * to be made for files in subordinate ones using relative paths.
 */

/*
 * Absent a strcasestr() function, we have to force wildcards on
 * systems for which "AAA" and "aaa" mean the same file.
 */
#ifdef CASE_BLIND_FILESYSTEM
#define WILDCARDS_REQUIRED 1
#else
#define WILDCARDS_REQUIRED 0
#endif

static const char *add_desc(cmd_parms *cmd, void *d, const char *desc,
                            const char *to)
{
    autoindex_config_rec *dcfg = (autoindex_config_rec *) d;
    ai_desc_t *desc_entry;
    char *prefix = "";

    desc_entry = (ai_desc_t *) apr_array_push(dcfg->desc_list);
    desc_entry->full_path = (ap_strchr_c(to, '/') == NULL) ? 0 : 1;
    desc_entry->wildcards = (WILDCARDS_REQUIRED
                             || desc_entry->full_path
                             || apr_fnmatch_test(to));
    if (desc_entry->wildcards) {
        prefix = desc_entry->full_path ? "*/" : "*";
        desc_entry->pattern = apr_pstrcat(dcfg->desc_list->pool,
                                          prefix, to, "*", NULL);
    }
    else {
        desc_entry->pattern = apr_pstrdup(dcfg->desc_list->pool, to);
    }
    desc_entry->description = apr_pstrdup(dcfg->desc_list->pool, desc);
    return NULL;
}

static const char *add_ignore(cmd_parms *cmd, void *d, const char *ext)
{
    push_item(((autoindex_config_rec *) d)->ign_list, 0, ext, cmd->path, NULL);
    return NULL;
}

static const char *add_header(cmd_parms *cmd, void *d, const char *name)
{
    push_item(((autoindex_config_rec *) d)->hdr_list, 0, NULL, cmd->path,
              name);
    return NULL;
}

static const char *add_readme(cmd_parms *cmd, void *d, const char *name)
{
    push_item(((autoindex_config_rec *) d)->rdme_list, 0, NULL, cmd->path,
              name);
    return NULL;
}

static const char *add_opts(cmd_parms *cmd, void *d, const char *optstr)
{
    char *w;
    apr_int32_t opts;
    apr_int32_t opts_add;
    apr_int32_t opts_remove;
    char action;
    autoindex_config_rec *d_cfg = (autoindex_config_rec *) d;

    opts = d_cfg->opts;
    opts_add = d_cfg->incremented_opts;
    opts_remove = d_cfg->decremented_opts;
    while (optstr[0]) {
        int option = 0;

        w = ap_getword_conf(cmd->pool, &optstr);
        if ((*w == '+') || (*w == '-')) {
            action = *(w++);
        }
        else {
            action = '\0';
        }
        if (!strcasecmp(w, "FancyIndexing")) {
            option = FANCY_INDEXING;
        }
        else if (!strcasecmp(w, "FoldersFirst")) {
            option = FOLDERS_FIRST;
        }
        else if (!strcasecmp(w, "HTMLTable")) {
            option = TABLE_INDEXING;
        }
        else if (!strcasecmp(w, "IconsAreLinks")) {
            option = ICONS_ARE_LINKS;
        }
        else if (!strcasecmp(w, "IgnoreCase")) {
            option = IGNORE_CASE;
        }
        else if (!strcasecmp(w, "IgnoreClient")) {
            option = IGNORE_CLIENT;
        }
        else if (!strcasecmp(w, "ScanHTMLTitles")) {
            option = SCAN_HTML_TITLES;
        }
        else if (!strcasecmp(w, "SuppressColumnSorting")) {
            option = SUPPRESS_COLSORT;
        }
        else if (!strcasecmp(w, "SuppressDescription")) {
            option = SUPPRESS_DESC;
        }
        else if (!strcasecmp(w, "SuppressHTMLPreamble")) {
            option = SUPPRESS_PREAMBLE;
        }
        else if (!strcasecmp(w, "SuppressIcon")) {
            option = SUPPRESS_ICON;
        }
        else if (!strcasecmp(w, "SuppressLastModified")) {
            option = SUPPRESS_LAST_MOD;
        }
        else if (!strcasecmp(w, "SuppressSize")) {
            option = SUPPRESS_SIZE;
        }
        else if (!strcasecmp(w, "SuppressRules")) {
            option = SUPPRESS_RULES;
        }
        else if (!strcasecmp(w, "TrackModified")) {
            option = TRACK_MODIFIED;
        }
        else if (!strcasecmp(w, "VersionSort")) {
            option = VERSION_SORT;
        }
        else if (!strcasecmp(w, "XHTML")) {
            option = EMIT_XHTML;
        }
        else if (!strcasecmp(w, "None")) {
            if (action != '\0') {
                return "Cannot combine '+' or '-' with 'None' keyword";
            }
            opts = NO_OPTIONS;
            opts_add = 0;
            opts_remove = 0;
        }
        else if (!strcasecmp(w, "IconWidth")) {
            if (action != '-') {
                d_cfg->icon_width = DEFAULT_ICON_WIDTH;
            }
            else {
                d_cfg->icon_width = 0;
            }
        }
        else if (!strncasecmp(w, "IconWidth=", 10)) {
            if (action == '-') {
                return "Cannot combine '-' with IconWidth=n";
            }
            d_cfg->icon_width = atoi(&w[10]);
        }
        else if (!strcasecmp(w, "IconHeight")) {
            if (action != '-') {
                d_cfg->icon_height = DEFAULT_ICON_HEIGHT;
            }
            else {
                d_cfg->icon_height = 0;
            }
        }
        else if (!strncasecmp(w, "IconHeight=", 11)) {
            if (action == '-') {
                return "Cannot combine '-' with IconHeight=n";
            }
            d_cfg->icon_height = atoi(&w[11]);
        }
        else if (!strcasecmp(w, "NameWidth")) {
            if (action != '-') {
                return "NameWidth with no value may only appear as "
                       "'-NameWidth'";
            }
            d_cfg->name_width = DEFAULT_NAME_WIDTH;
            d_cfg->name_adjust = K_NOADJUST;
        }
        else if (!strncasecmp(w, "NameWidth=", 10)) {
            if (action == '-') {
                return "Cannot combine '-' with NameWidth=n";
            }
            if (w[10] == '*') {
                d_cfg->name_adjust = K_ADJUST;
            }
            else {
                int width = atoi(&w[10]);

                if (width && (width < 5)) {
                    return "NameWidth value must be greater than 5";
                }
                d_cfg->name_width = width;
                d_cfg->name_adjust = K_NOADJUST;
            }
        }
        else if (!strcasecmp(w, "DescriptionWidth")) {
            if (action != '-') {
                return "DescriptionWidth with no value may only appear as "
                       "'-DescriptionWidth'";
            }
            d_cfg->desc_width = DEFAULT_DESC_WIDTH;
            d_cfg->desc_adjust = K_NOADJUST;
        }
        else if (!strncasecmp(w, "DescriptionWidth=", 17)) {
            if (action == '-') {
                return "Cannot combine '-' with DescriptionWidth=n";
            }
            if (w[17] == '*') {
                d_cfg->desc_adjust = K_ADJUST;
            }
            else {
                int width = atoi(&w[17]);

                if (width && (width < 12)) {
                    return "DescriptionWidth value must be greater than 12";
                }
                d_cfg->desc_width = width;
                d_cfg->desc_adjust = K_NOADJUST;
            }
        }
        else {
            return "Invalid directory indexing option";
        }
        if (action == '\0') {
            opts |= option;
            opts_add = 0;
            opts_remove = 0;
        }
        else if (action == '+') {
            opts_add |= option;
            opts_remove &= ~option;
        }
        else {
            opts_remove |= option;
            opts_add &= ~option;
        }
    }
    if ((opts & NO_OPTIONS) && (opts & ~NO_OPTIONS)) {
        return "Cannot combine other IndexOptions keywords with 'None'";
    }
    d_cfg->incremented_opts = opts_add;
    d_cfg->decremented_opts = opts_remove;
    d_cfg->opts = opts;
    return NULL;
}

static const char *set_default_order(cmd_parms *cmd, void *m,
                                     const char *direction, const char *key)
{
    autoindex_config_rec *d_cfg = (autoindex_config_rec *) m;

    if (!strcasecmp(direction, "Ascending")) {
        d_cfg->default_direction = D_ASCENDING;
    }
    else if (!strcasecmp(direction, "Descending")) {
        d_cfg->default_direction = D_DESCENDING;
    }
    else {
        return "First keyword must be 'Ascending' or 'Descending'";
    }

    if (!strcasecmp(key, "Name")) {
        d_cfg->default_keyid = K_NAME;
    }
    else if (!strcasecmp(key, "Date")) {
        d_cfg->default_keyid = K_LAST_MOD;
    }
    else if (!strcasecmp(key, "Size")) {
        d_cfg->default_keyid = K_SIZE;
    }
    else if (!strcasecmp(key, "Description")) {
        d_cfg->default_keyid = K_DESC;
    }
    else {
        return "Second keyword must be 'Name', 'Date', 'Size', or "
               "'Description'";
    }

    return NULL;
}

#define DIR_CMD_PERMS OR_INDEXES

static const command_rec autoindex_cmds[] =
{
    AP_INIT_ITERATE2("AddIcon", add_icon, BY_PATH, DIR_CMD_PERMS,
                     "an icon URL followed by one or more filenames"),
    AP_INIT_ITERATE2("AddIconByType", add_icon, BY_TYPE, DIR_CMD_PERMS,
                     "an icon URL followed by one or more MIME types"),
    AP_INIT_ITERATE2("AddIconByEncoding", add_icon, BY_ENCODING, DIR_CMD_PERMS,
                     "an icon URL followed by one or more content encodings"),
    AP_INIT_ITERATE2("AddAlt", add_alt, BY_PATH, DIR_CMD_PERMS,
                     "alternate descriptive text followed by one or more "
                     "filenames"),
    AP_INIT_ITERATE2("AddAltByType", add_alt, BY_TYPE, DIR_CMD_PERMS,
                     "alternate descriptive text followed by one or more MIME "
                     "types"),
    AP_INIT_ITERATE2("AddAltByEncoding", add_alt, BY_ENCODING, DIR_CMD_PERMS,
                     "alternate descriptive text followed by one or more "
                     "content encodings"),
    AP_INIT_RAW_ARGS("IndexOptions", add_opts, NULL, DIR_CMD_PERMS,
                     "one or more index options [+|-][]"),
    AP_INIT_TAKE2("IndexOrderDefault", set_default_order, NULL, DIR_CMD_PERMS,
                  "{Ascending,Descending} {Name,Size,Description,Date}"),
    AP_INIT_ITERATE("IndexIgnore", add_ignore, NULL, DIR_CMD_PERMS,
                    "one or more file extensions"),
    AP_INIT_ITERATE2("AddDescription", add_desc, BY_PATH, DIR_CMD_PERMS,
                     "Descriptive text followed by one or more filenames"),
    AP_INIT_TAKE1("HeaderName", add_header, NULL, DIR_CMD_PERMS,
                  "a filename"),
    AP_INIT_TAKE1("ReadmeName", add_readme, NULL, DIR_CMD_PERMS,
                  "a filename"),
    AP_INIT_RAW_ARGS("FancyIndexing", ap_set_deprecated, NULL, OR_ALL,
                     "The FancyIndexing directive is no longer supported. "
                     "Use IndexOptions FancyIndexing."),
    AP_INIT_TAKE1("DefaultIcon", ap_set_string_slot,
                  (void *)APR_OFFSETOF(autoindex_config_rec, default_icon),
                  DIR_CMD_PERMS, "an icon URL"),
    AP_INIT_TAKE1("IndexStyleSheet", ap_set_string_slot,
                  (void *)APR_OFFSETOF(autoindex_config_rec, style_sheet),
                  DIR_CMD_PERMS, "URL to style sheet"),
    {NULL}
};

static void *create_autoindex_config(apr_pool_t *p, char *dummy)
{
    autoindex_config_rec *new =
    (autoindex_config_rec *) apr_pcalloc(p, sizeof(autoindex_config_rec));

    new->icon_width = 0;
    new->icon_height = 0;
    new->name_width = DEFAULT_NAME_WIDTH;
    new->name_adjust = K_UNSET;
    new->desc_width = DEFAULT_DESC_WIDTH;
    new->desc_adjust = K_UNSET;
    new->icon_list = apr_array_make(p, 4, sizeof(struct item));
    new->alt_list = apr_array_make(p, 4, sizeof(struct item));
    new->desc_list = apr_array_make(p, 4, sizeof(ai_desc_t));
    new->ign_list = apr_array_make(p, 4, sizeof(struct item));
    new->hdr_list = apr_array_make(p, 4, sizeof(struct item));
    new->rdme_list = apr_array_make(p, 4, sizeof(struct item));
    new->opts = 0;
    new->incremented_opts = 0;
    new->decremented_opts = 0;
    new->default_keyid = '\0';
    new->default_direction = '\0';

    return (void *) new;
}

static void *merge_autoindex_configs(apr_pool_t *p, void *basev, void *addv)
{
    autoindex_config_rec *new;
    autoindex_config_rec *base = (autoindex_config_rec *) basev;
    autoindex_config_rec *add = (autoindex_config_rec *) addv;

    new = (autoindex_config_rec *) apr_pcalloc(p, sizeof(autoindex_config_rec));
    new->default_icon = add->default_icon ? add->default_icon
                                          : base->default_icon;
    new->style_sheet = add->style_sheet ? add->style_sheet
                                          : base->style_sheet;
    new->icon_height = add->icon_height ? add->icon_height : base->icon_height;
    new->icon_width = add->icon_width ? add->icon_width : base->icon_width;

    new->alt_list = apr_array_append(p, add->alt_list, base->alt_list);
    new->ign_list = apr_array_append(p, add->ign_list, base->ign_list);
    new->hdr_list = apr_array_append(p, add->hdr_list, base->hdr_list);
    new->desc_list = apr_array_append(p, add->desc_list, base->desc_list);
    new->icon_list = apr_array_append(p, add->icon_list, base->icon_list);
    new->rdme_list = apr_array_append(p, add->rdme_list, base->rdme_list);
    if (add->opts & NO_OPTIONS) {
        /*
         * If the current directory says 'no options' then we also
         * clear any incremental mods from being inheritable further down.
         */
        new->opts = NO_OPTIONS;
        new->incremented_opts = 0;
        new->decremented_opts = 0;
    }
    else {
        /*
         * If there were any nonincremental options selected for
         * this directory, they dominate and we don't inherit *anything.*
         * Contrariwise, we *do* inherit if the only settings here are
         * incremental ones.
         */
        if (add->opts == 0) {
            new->incremented_opts = (base->incremented_opts
                                     | add->incremented_opts)
                                    & ~add->decremented_opts;
            new->decremented_opts = (base->decremented_opts
                                     | add->decremented_opts);
            /*
             * We may have incremental settings, so make sure we don't
             * inadvertently inherit an IndexOptions None from above.
             */
            new->opts = (base->opts & ~NO_OPTIONS);
        }
        else {
            /*
             * There are local nonincremental settings, which clear
             * all inheritance from above.  They *are* the new base settings.
             */
            new->opts = add->opts;;
        }
        /*
         * We're guaranteed that there'll be no overlap between
         * the add-options and the remove-options.
         */
        new->opts |= new->incremented_opts;
        new->opts &= ~new->decremented_opts;
    }
    /*
     * Inherit the NameWidth settings if there aren't any specific to
     * the new location; otherwise we'll end up using the defaults set in the
     * config-rec creation routine.
     */
    if (add->name_adjust == K_UNSET) {
        new->name_width = base->name_width;
        new->name_adjust = base->name_adjust;
    }
    else {
        new->name_width = add->name_width;
        new->name_adjust = add->name_adjust;
    }

    /*
     * Likewise for DescriptionWidth.
     */
    if (add->desc_adjust == K_UNSET) {
        new->desc_width = base->desc_width;
        new->desc_adjust = base->desc_adjust;
    }
    else {
        new->desc_width = add->desc_width;
        new->desc_adjust = add->desc_adjust;
    }

    new->default_keyid = add->default_keyid ? add->default_keyid
                                            : base->default_keyid;
    new->default_direction = add->default_direction ? add->default_direction
                                                    : base->default_direction;
    return new;
}

/****************************************************************
 *
 * Looking things up in config entries...
 */

/* Structure used to hold entries when we're actually building an index */

struct ent {
    char *name;
    char *icon;
    char *alt;
    char *desc;
    apr_off_t size;
    apr_time_t lm;
    struct ent *next;
    int ascending, ignore_case, version_sort;
    char key;
    int isdir;
};

static char *find_item(request_rec *r, apr_array_header_t *list, int path_only)
{
    const char *content_type = ap_field_noparam(r->pool, r->content_type);
    const char *content_encoding = r->content_encoding;
    char *path = r->filename;

    struct item *items = (struct item *) list->elts;
    int i;

    for (i = 0; i < list->nelts; ++i) {
        struct item *p = &items[i];

        /* Special cased for ^^DIRECTORY^^ and ^^BLANKICON^^ */
        if ((path[0] == '^') || (!ap_strcmp_match(path, p->apply_path))) {
            if (!*(p->apply_to)) {
                return p->data;
            }
            else if (p->type == BY_PATH || path[0] == '^') {
                if (!ap_strcmp_match(path, p->apply_to)) {
                    return p->data;
                }
            }
            else if (!path_only) {
                if (!content_encoding) {
                    if (p->type == BY_TYPE) {
                        if (content_type
                            && !ap_strcasecmp_match(content_type,
                                                    p->apply_to)) {
                            return p->data;
                        }
                    }
                }
                else {
                    if (p->type == BY_ENCODING) {
                        if (!ap_strcasecmp_match(content_encoding,
                                                 p->apply_to)) {
                            return p->data;
                        }
                    }
                }
            }
        }
    }
    return NULL;
}

#define find_icon(d,p,t) find_item(p,d->icon_list,t)
#define find_alt(d,p,t) find_item(p,d->alt_list,t)
#define find_header(d,p) find_item(p,d->hdr_list,0)
#define find_readme(d,p) find_item(p,d->rdme_list,0)

static char *find_default_item(char *bogus_name, apr_array_header_t *list)
{
    request_rec r;
    /* Bleah.  I tried to clean up find_item, and it lead to this bit
     * of ugliness.   Note that the fields initialized are precisely
     * those that find_item looks at...
     */
    r.filename = bogus_name;
    r.content_type = r.content_encoding = NULL;
    return find_item(&r, list, 1);
}

#define find_default_icon(d,n) find_default_item(n, d->icon_list)
#define find_default_alt(d,n) find_default_item(n, d->alt_list)

/*
 * Look through the list of pattern/description pairs and return the first one
 * if any) that matches the filename in the request.  If multiple patterns
 * match, only the first one is used; since the order in the array is the
 * same as the order in which directives were processed, earlier matching
 * directives will dominate.
 */

#ifdef CASE_BLIND_FILESYSTEM
#define MATCH_FLAGS APR_FNM_CASE_BLIND
#else
#define MATCH_FLAGS 0
#endif

static char *find_desc(autoindex_config_rec *dcfg, const char *filename_full)
{
    int i;
    ai_desc_t *list = (ai_desc_t *) dcfg->desc_list->elts;
    const char *filename_only;
    const char *filename;

    /*
     * If the filename includes a path, extract just the name itself
     * for the simple matches.
     */
    if ((filename_only = ap_strrchr_c(filename_full, '/')) == NULL) {
        filename_only = filename_full;
    }
    else {
        filename_only++;
    }
    for (i = 0; i < dcfg->desc_list->nelts; ++i) {
        ai_desc_t *tuple = &list[i];
        int found;

        /*
         * Only use the full-path filename if the pattern contains '/'s.
         */
        filename = (tuple->full_path) ? filename_full : filename_only;
        /*
         * Make the comparison using the cheapest method; only do
         * wildcard checking if we must.
         */
        if (tuple->wildcards) {
            found = (apr_fnmatch(tuple->pattern, filename, MATCH_FLAGS) == 0);
        }
        else {
            found = (ap_strstr_c(filename, tuple->pattern) != NULL);
        }
        if (found) {
            return tuple->description;
        }
    }
    return NULL;
}

static int ignore_entry(autoindex_config_rec *d, char *path)
{
    apr_array_header_t *list = d->ign_list;
    struct item *items = (struct item *) list->elts;
    char *tt;
    int i;

    if ((tt = strrchr(path, '/')) == NULL) {
        tt = path;
    }
    else {
        tt++;
    }

    for (i = 0; i < list->nelts; ++i) {
        struct item *p = &items[i];
        char *ap;

        if ((ap = strrchr(p->apply_to, '/')) == NULL) {
            ap = p->apply_to;
        }
        else {
            ap++;
        }

#ifndef CASE_BLIND_FILESYSTEM
        if (!ap_strcmp_match(path, p->apply_path)
            && !ap_strcmp_match(tt, ap)) {
            return 1;
        }
#else  /* !CASE_BLIND_FILESYSTEM */
        /*
         * On some platforms, the match must be case-blind.  This is really
         * a factor of the filesystem involved, but we can't detect that
         * reliably - so we have to granularise at the OS level.
         */
        if (!ap_strcasecmp_match(path, p->apply_path)
            && !ap_strcasecmp_match(tt, ap)) {
            return 1;
        }
#endif /* !CASE_BLIND_FILESYSTEM */
    }
    return 0;
}

/*****************************************************************
 *
 * Actually generating output
 */

/*
 * Elements of the emitted document:
 *      Preamble
 *              Emitted unless SUPPRESS_PREAMBLE is set AND ap_run_sub_req
 *              succeeds for the (content_type == text/html) header file.
 *      Header file
 *              Emitted if found (and able).
 *      H1 tag line
 *              Emitted if a header file is NOT emitted.
 *      Directory stuff
 *              Always emitted.
 *      HR
 *              Emitted if FANCY_INDEXING is set.
 *      Readme file
 *              Emitted if found (and able).
 *      ServerSig
 *              Emitted if ServerSignature is not Off AND a readme file
 *              is NOT emitted.
 *      Postamble
 *              Emitted unless SUPPRESS_PREAMBLE is set AND ap_run_sub_req
 *              succeeds for the (content_type == text/html) readme file.
 */


/*
 * emit a plain text file
 */
static void do_emit_plain(request_rec *r, apr_file_t *f)
{
    char buf[AP_IOBUFSIZE + 1];
    int ch;
    apr_size_t i, c, n;
    apr_status_t rv;

    ap_rputs("<pre>\n", r);
    while (!apr_file_eof(f)) {
        do {
            n = sizeof(char) * AP_IOBUFSIZE;
            rv = apr_file_read(f, buf, &n);
        } while (APR_STATUS_IS_EINTR(rv));
        if (n == 0 || rv != APR_SUCCESS) {
            /* ###: better error here? */
            break;
        }
        buf[n] = '\0';
        c = 0;
        while (c < n) {
            for (i = c; i < n; i++) {
                if (buf[i] == '<' || buf[i] == '>' || buf[i] == '&') {
                    break;
                }
            }
            ch = buf[i];
            buf[i] = '\0';
            ap_rputs(&buf[c], r);
            if (ch == '<') {
                ap_rputs("&lt;", r);
            }
            else if (ch == '>') {
                ap_rputs("&gt;", r);
            }
            else if (ch == '&') {
                ap_rputs("&amp;", r);
            }
            c = i + 1;
        }
    }
    ap_rputs("</pre>\n", r);
}

/*
 * Handle the preamble through the H1 tag line, inclusive.  Locate
 * the file with a subrequests.  Process text/html documents by actually
 * running the subrequest; text/xxx documents get copied verbatim,
 * and any other content type is ignored.  This means that a non-text
 * document (such as HEADER.gif) might get multiviewed as the result
 * instead of a text document, meaning nothing will be displayed, but
 * oh well.
 */
static void emit_head(request_rec *r, char *header_fname, int suppress_amble,
                      int emit_xhtml, char *title)
{
    apr_table_t *hdrs = r->headers_in;
    apr_file_t *f = NULL;
    request_rec *rr = NULL;
    int emit_amble = 1;
    int emit_H1 = 1;
    const char *r_accept;
    const char *r_accept_enc;

    /*
     * If there's a header file, send a subrequest to look for it.  If it's
     * found and html do the subrequest, otherwise handle it
     */
    r_accept = apr_table_get(hdrs, "Accept");
    r_accept_enc = apr_table_get(hdrs, "Accept-Encoding");
    apr_table_setn(hdrs, "Accept", "text/html, text/plain");
    apr_table_unset(hdrs, "Accept-Encoding");


    if ((header_fname != NULL) && r->args) {
        header_fname = apr_pstrcat(r->pool, header_fname, "?", r->args, NULL);
    }

    if ((header_fname != NULL)
        && (rr = ap_sub_req_lookup_uri(header_fname, r, r->output_filters))
        && (rr->status == HTTP_OK)
        && (rr->filename != NULL)
        && (rr->finfo.filetype == APR_REG)) {
        /*
         * Check for the two specific cases we allow: text/html and
         * text/anything-else.  The former is allowed to be processed for
         * SSIs.
         */
        if (rr->content_type != NULL) {
            if (!strcasecmp(ap_field_noparam(r->pool, rr->content_type),
                            "text/html")) {
                ap_filter_t *f;
               /* Hope everything will work... */
                emit_amble = 0;
                emit_H1 = 0;

                if (! suppress_amble) {
                    emit_preamble(r, emit_xhtml, title);
                }
                /* This is a hack, but I can't find any better way to do this.
                 * The problem is that we have already created the sub-request,
                 * but we just inserted the OLD_WRITE filter, and the
                 * sub-request needs to pass its data through the OLD_WRITE
                 * filter, or things go horribly wrong (missing data, data in
                 * the wrong order, etc).  To fix it, if you create a
                 * sub-request and then insert the OLD_WRITE filter before you
                 * run the request, you need to make sure that the sub-request
                 * data goes through the OLD_WRITE filter.  Just steal this
                 * code.  The long-term solution is to remove the ap_r*
                 * functions.
                 */
                for (f=rr->output_filters;
                     f->frec != ap_subreq_core_filter_handle; f = f->next);
                f->next = r->output_filters;

                /*
                 * If there's a problem running the subrequest, display the
                 * preamble if we didn't do it before -- the header file
                 * didn't get displayed.
                 */
                if (ap_run_sub_req(rr) != OK) {
                    /* It didn't work */
                    emit_amble = suppress_amble;
                    emit_H1 = 1;
                }
            }
            else if (!strncasecmp("text/", rr->content_type, 5)) {
                /*
                 * If we can open the file, prefix it with the preamble
                 * regardless; since we'll be sending a <pre> block around
                 * the file's contents, any HTML header it had won't end up
                 * where it belongs.
                 */
                if (apr_file_open(&f, rr->filename, APR_READ,
                                  APR_OS_DEFAULT, r->pool) == APR_SUCCESS) {
                    emit_preamble(r, emit_xhtml, title);
                    emit_amble = 0;
                    do_emit_plain(r, f);
                    apr_file_close(f);
                    emit_H1 = 0;
                }
            }
        }
    }

    if (r_accept) {
        apr_table_setn(hdrs, "Accept", r_accept);
    }
    else {
        apr_table_unset(hdrs, "Accept");
    }

    if (r_accept_enc) {
        apr_table_setn(hdrs, "Accept-Encoding", r_accept_enc);
    }

    if (emit_amble) {
        emit_preamble(r, emit_xhtml, title);
    }
    if (emit_H1) {
        ap_rvputs(r, "<h1>Index of ", title, "</h1>\n", NULL);
    }
    if (rr != NULL) {
        ap_destroy_sub_req(rr);
    }
}


/*
 * Handle the Readme file through the postamble, inclusive.  Locate
 * the file with a subrequests.  Process text/html documents by actually
 * running the subrequest; text/xxx documents get copied verbatim,
 * and any other content type is ignored.  This means that a non-text
 * document (such as FOOTER.gif) might get multiviewed as the result
 * instead of a text document, meaning nothing will be displayed, but
 * oh well.
 */
static void emit_tail(request_rec *r, char *readme_fname, int suppress_amble)
{
    apr_file_t *f = NULL;
    request_rec *rr = NULL;
    int suppress_post = 0;
    int suppress_sig = 0;

    /*
     * If there's a readme file, send a subrequest to look for it.  If it's
     * found and a text file, handle it -- otherwise fall through and
     * pretend there's nothing there.
     */
    if ((readme_fname != NULL)
        && (rr = ap_sub_req_lookup_uri(readme_fname, r, r->output_filters))
        && (rr->status == HTTP_OK)
        && (rr->filename != NULL)
        && rr->finfo.filetype == APR_REG) {
        /*
         * Check for the two specific cases we allow: text/html and
         * text/anything-else.  The former is allowed to be processed for
         * SSIs.
         */
        if (rr->content_type != NULL) {
            if (!strcasecmp(ap_field_noparam(r->pool, rr->content_type),
                            "text/html")) {
                ap_filter_t *f;
                for (f=rr->output_filters;
                     f->frec != ap_subreq_core_filter_handle; f = f->next);
                f->next = r->output_filters;


                if (ap_run_sub_req(rr) == OK) {
                    /* worked... */
                    suppress_sig = 1;
                    suppress_post = suppress_amble;
                }
            }
            else if (!strncasecmp("text/", rr->content_type, 5)) {
                /*
                 * If we can open the file, suppress the signature.
                 */
                if (apr_file_open(&f, rr->filename, APR_READ,
                                  APR_OS_DEFAULT, r->pool) == APR_SUCCESS) {
                    do_emit_plain(r, f);
                    apr_file_close(f);
                    suppress_sig = 1;
                }
            }
        }
    }

    if (!suppress_sig) {
        ap_rputs(ap_psignature("", r), r);
    }
    if (!suppress_post) {
        ap_rputs("</body></html>\n", r);
    }
    if (rr != NULL) {
        ap_destroy_sub_req(rr);
    }
}


static char *find_title(request_rec *r)
{
    char titlebuf[MAX_STRING_LEN], *find = "<title>";
    apr_file_t *thefile = NULL;
    int x, y, p;
    apr_size_t n;

    if (r->status != HTTP_OK) {
        return NULL;
    }
    if ((r->content_type != NULL)
        && (!strcasecmp(ap_field_noparam(r->pool, r->content_type),
                        "text/html")
            || !strcmp(r->content_type, INCLUDES_MAGIC_TYPE))
        && !r->content_encoding) {
        if (apr_file_open(&thefile, r->filename, APR_READ,
                          APR_OS_DEFAULT, r->pool) != APR_SUCCESS) {
            return NULL;
        }
        n = sizeof(char) * (MAX_STRING_LEN - 1);
        apr_file_read(thefile, titlebuf, &n);
        if (n <= 0) {
            apr_file_close(thefile);
            return NULL;
        }
        titlebuf[n] = '\0';
        for (x = 0, p = 0; titlebuf[x]; x++) {
            if (apr_tolower(titlebuf[x]) == find[p]) {
                if (!find[++p]) {
                    if ((p = ap_ind(&titlebuf[++x], '<')) != -1) {
                        titlebuf[x + p] = '\0';
                    }
                    /* Scan for line breaks for Tanmoy's secretary */
                    for (y = x; titlebuf[y]; y++) {
                        if ((titlebuf[y] == CR) || (titlebuf[y] == LF)) {
                            if (y == x) {
                                x++;
                            }
                            else {
                                titlebuf[y] = ' ';
                            }
                        }
                    }
                    apr_file_close(thefile);
                    return apr_pstrdup(r->pool, &titlebuf[x]);
                }
            }
            else {
                p = 0;
            }
        }
        apr_file_close(thefile);
    }
    return NULL;
}

static struct ent *make_parent_entry(apr_int32_t autoindex_opts,
                                     autoindex_config_rec *d,
                                     request_rec *r, char keyid,
                                     char direction)
{
    struct ent *p = (struct ent *) apr_pcalloc(r->pool, sizeof(struct ent));
    char *testpath;
    /*
     * p->name is now the true parent URI.
     * testpath is a crafted lie, so that the syntax '/some/..'
     * (or simply '..')be used to describe 'up' from '/some/'
     * when processeing IndexIgnore, and Icon|Alt|Desc configs.
     */

    /* The output has always been to the parent.  Don't make ourself
     * our own parent (worthless cyclical reference).
     */
    if (!(p->name = ap_make_full_path(r->pool, r->uri, "../"))) {
        return (NULL);
    }
    ap_getparents(p->name);
    if (!*p->name) {
        return (NULL);
    }

    /* IndexIgnore has always compared "/thispath/.." */
    testpath = ap_make_full_path(r->pool, r->filename, "..");
    if (ignore_entry(d, testpath)) {
        return (NULL);
    }

    p->size = -1;
    p->lm = -1;
    p->key = apr_toupper(keyid);
    p->ascending = (apr_toupper(direction) == D_ASCENDING);
    p->version_sort = autoindex_opts & VERSION_SORT;
    if (autoindex_opts & FANCY_INDEXING) {
        if (!(p->icon = find_default_icon(d, testpath))) {
            p->icon = find_default_icon(d, "^^DIRECTORY^^");
        }
        if (!(p->alt = find_default_alt(d, testpath))) {
            if (!(p->alt = find_default_alt(d, "^^DIRECTORY^^"))) {
                p->alt = "DIR";
            }
        }
        p->desc = find_desc(d, testpath);
    }
    return p;
}

static struct ent *make_autoindex_entry(const apr_finfo_t *dirent,
                                        int autoindex_opts,
                                        autoindex_config_rec *d,
                                        request_rec *r, char keyid,
                                        char direction,
                                        const char *pattern)
{
    request_rec *rr;
    struct ent *p;

    /* Dot is ignored, Parent is handled by make_parent_entry() */
    if ((dirent->name[0] == '.') && (!dirent->name[1]
        || ((dirent->name[1] == '.') && !dirent->name[2])))
        return (NULL);

    /*
     * On some platforms, the match must be case-blind.  This is really
     * a factor of the filesystem involved, but we can't detect that
     * reliably - so we have to granularise at the OS level.
     */
    if (pattern && (apr_fnmatch(pattern, dirent->name,
                                APR_FNM_NOESCAPE | APR_FNM_PERIOD
#ifdef CASE_BLIND_FILESYSTEM
                                | APR_FNM_CASE_BLIND
#endif
                                )
                    != APR_SUCCESS)) {
        return (NULL);
    }

    if (ignore_entry(d, ap_make_full_path(r->pool,
                                          r->filename, dirent->name))) {
        return (NULL);
    }

    if (!(rr = ap_sub_req_lookup_dirent(dirent, r, AP_SUBREQ_NO_ARGS, NULL))) {
        return (NULL);
    }

    if ((rr->finfo.filetype != APR_DIR && rr->finfo.filetype != APR_REG)
        || !(rr->status == OK || ap_is_HTTP_SUCCESS(rr->status)
                              || ap_is_HTTP_REDIRECT(rr->status))) {
        ap_destroy_sub_req(rr);
        return (NULL);
    }

    p = (struct ent *) apr_pcalloc(r->pool, sizeof(struct ent));
    if (dirent->filetype == APR_DIR) {
        p->name = apr_pstrcat(r->pool, dirent->name, "/", NULL);
    }
    else {
        p->name = apr_pstrdup(r->pool, dirent->name);
    }
    p->size = -1;
    p->icon = NULL;
    p->alt = NULL;
    p->desc = NULL;
    p->lm = -1;
    p->isdir = 0;
    p->key = apr_toupper(keyid);
    p->ascending = (apr_toupper(direction) == D_ASCENDING);
    p->version_sort = !!(autoindex_opts & VERSION_SORT);
    p->ignore_case = !!(autoindex_opts & IGNORE_CASE);

    if (autoindex_opts & (FANCY_INDEXING | TABLE_INDEXING)) {
        p->lm = rr->finfo.mtime;
        if (dirent->filetype == APR_DIR) {
            if (autoindex_opts & FOLDERS_FIRST) {
                p->isdir = 1;
            }
            rr->filename = ap_make_dirstr_parent (rr->pool, rr->filename);

            /* omit the trailing slash (1.3 compat) */
            rr->filename[strlen(rr->filename) - 1] = '\0';

            if (!(p->icon = find_icon(d, rr, 1))) {
                p->icon = find_default_icon(d, "^^DIRECTORY^^");
            }
            if (!(p->alt = find_alt(d, rr, 1))) {
                if (!(p->alt = find_default_alt(d, "^^DIRECTORY^^"))) {
                    p->alt = "DIR";
                }
            }
        }
        else {
            p->icon = find_icon(d, rr, 0);
            p->alt = find_alt(d, rr, 0);
            p->size = rr->finfo.size;
        }

        p->desc = find_desc(d, rr->filename);

        if ((!p->desc) && (autoindex_opts & SCAN_HTML_TITLES)) {
            p->desc = apr_pstrdup(r->pool, find_title(rr));
        }
    }
    ap_destroy_sub_req(rr);
    /*
     * We don't need to take any special action for the file size key.
     * If we did, it would go here.
     */
    if (keyid == K_LAST_MOD) {
        if (p->lm < 0) {
            p->lm = 0;
        }
    }
    return (p);
}

static char *terminate_description(autoindex_config_rec *d, char *desc,
                                   apr_int32_t autoindex_opts, int desc_width)
{
    int maxsize = desc_width;
    register int x;

    /*
     * If there's no DescriptionWidth in effect, default to the old
     * behaviour of adjusting the description size depending upon
     * what else is being displayed.  Otherwise, stick with the
     * setting.
     */
    if (d->desc_adjust == K_UNSET) {
        if (autoindex_opts & SUPPRESS_ICON) {
            maxsize += 6;
        }
        if (autoindex_opts & SUPPRESS_LAST_MOD) {
            maxsize += 19;
        }
        if (autoindex_opts & SUPPRESS_SIZE) {
            maxsize += 7;
        }
    }
    for (x = 0; desc[x] && ((maxsize > 0) || (desc[x] == '<')); x++) {
        if (desc[x] == '<') {
            while (desc[x] != '>') {
                if (!desc[x]) {
                    maxsize = 0;
                    break;
                }
                ++x;
            }
        }
        else if (desc[x] == '&') {
            /* entities like &auml; count as one character */
            --maxsize;
            for ( ; desc[x] != ';'; ++x) {
                if (desc[x] == '\0') {
                     maxsize = 0;
                     break;
                }
            }
        }
        else {
            --maxsize;
        }
    }
    if (!maxsize && desc[x] != '\0') {
        desc[x - 1] = '>';      /* Grump. */
        desc[x] = '\0';         /* Double Grump! */
    }
    return desc;
}

/*
 * Emit the anchor for the specified field.  If a field is the key for the
 * current request, the link changes its meaning to reverse the order when
 * selected again.  Non-active fields always start in ascending order.
 */
static void emit_link(request_rec *r, const char *anchor, char column,
                      char curkey, char curdirection,
                      const char *colargs, int nosort)
{
    if (!nosort) {
        char qvalue[9];

        qvalue[0] = '?';
        qvalue[1] = 'C';
        qvalue[2] = '=';
        qvalue[3] = column;
        qvalue[4] = ';';
        qvalue[5] = 'O';
        qvalue[6] = '=';
                    /* reverse? */
        qvalue[7] = ((curkey == column) && (curdirection == D_ASCENDING))
                      ? D_DESCENDING : D_ASCENDING;
        qvalue[8] = '\0';
        ap_rvputs(r, "<a href=\"", qvalue, colargs ? colargs : "",
                     "\">", anchor, "</a>", NULL);
    }
    else {
        ap_rputs(anchor, r);
    }
}

static void output_directories(struct ent **ar, int n,
                               autoindex_config_rec *d, request_rec *r,
                               apr_int32_t autoindex_opts, char keyid,
                               char direction, const char *colargs)
{
    int x;
    apr_size_t rv;
    char *name = r->uri;
    char *tp;
    int static_columns = !!(autoindex_opts & SUPPRESS_COLSORT);
    apr_pool_t *scratch;
    int name_width;
    int desc_width;
    char *name_scratch;
    char *pad_scratch;
    char *breakrow = "";

    apr_pool_create(&scratch, r->pool);
    if (name[0] == '\0') {
        name = "/";
    }

    name_width = d->name_width;
    desc_width = d->desc_width;

    if ((autoindex_opts & (FANCY_INDEXING | TABLE_INDEXING))
                        == FANCY_INDEXING) {
        if (d->name_adjust == K_ADJUST) {
            for (x = 0; x < n; x++) {
                int t = strlen(ar[x]->name);
                if (t > name_width) {
                    name_width = t;
                }
            }
        }

        if (d->desc_adjust == K_ADJUST) {
            for (x = 0; x < n; x++) {
                if (ar[x]->desc != NULL) {
                    int t = strlen(ar[x]->desc);
                    if (t > desc_width) {
                        desc_width = t;
                    }
                }
            }
        }
    }
    name_scratch = apr_palloc(r->pool, name_width + 1);
    pad_scratch = apr_palloc(r->pool, name_width + 1);
    memset(pad_scratch, ' ', name_width);
    pad_scratch[name_width] = '\0';

    if (autoindex_opts & TABLE_INDEXING) {
        int cols = 1;
        ap_rputs("<table><tr>", r);
        if (!(autoindex_opts & SUPPRESS_ICON)) {
            ap_rputs("<th>", r);
            if ((tp = find_default_icon(d, "^^BLANKICON^^"))) {
                ap_rvputs(r, "<img src=\"", ap_escape_html(scratch, tp),
                             "\" alt=\"[ICO]\"", NULL);
                if (d->icon_width) {
                    ap_rprintf(r, " width=\"%d\"", d->icon_width);
                }
                if (d->icon_height) {
                    ap_rprintf(r, " height=\"%d\"", d->icon_height);
                }

                if (autoindex_opts & EMIT_XHTML) {
                    ap_rputs(" /", r);
                }
                ap_rputs("></th>", r);
            }
            else {
                ap_rputs("&nbsp;</th>", r);
            }

            ++cols;
        }
        ap_rputs("<th>", r);
        emit_link(r, "Name", K_NAME, keyid, direction,
                  colargs, static_columns);
        if (!(autoindex_opts & SUPPRESS_LAST_MOD)) {
            ap_rputs("</th><th>", r);
            emit_link(r, "Last modified", K_LAST_MOD, keyid, direction,
                      colargs, static_columns);
            ++cols;
        }
        if (!(autoindex_opts & SUPPRESS_SIZE)) {
            ap_rputs("</th><th>", r);
            emit_link(r, "Size", K_SIZE, keyid, direction,
                      colargs, static_columns);
            ++cols;
        }
        if (!(autoindex_opts & SUPPRESS_DESC)) {
            ap_rputs("</th><th>", r);
            emit_link(r, "Description", K_DESC, keyid, direction,
                      colargs, static_columns);
            ++cols;
        }
        if (!(autoindex_opts & SUPPRESS_RULES)) {
            breakrow = apr_psprintf(r->pool,
                                    "<tr><th colspan=\"%d\">"
                                    "<hr%s></th></tr>\n", cols,
                                    (autoindex_opts & EMIT_XHTML) ? " /" : "");
        }
        ap_rvputs(r, "</th></tr>", breakrow, NULL);
    }
    else if (autoindex_opts & FANCY_INDEXING) {
        ap_rputs("<pre>", r);
        if (!(autoindex_opts & SUPPRESS_ICON)) {
            if ((tp = find_default_icon(d, "^^BLANKICON^^"))) {
                ap_rvputs(r, "<img src=\"", ap_escape_html(scratch, tp),
                             "\" alt=\"Icon \"", NULL);
                if (d->icon_width) {
                    ap_rprintf(r, " width=\"%d\"", d->icon_width);
                }
                if (d->icon_height) {
                    ap_rprintf(r, " height=\"%d\"", d->icon_height);
                }

                if (autoindex_opts & EMIT_XHTML) {
                    ap_rputs(" /", r);
                }
                ap_rputs("> ", r);
            }
            else {
                ap_rputs("      ", r);
            }
        }
        emit_link(r, "Name", K_NAME, keyid, direction,
                  colargs, static_columns);
        ap_rputs(pad_scratch + 4, r);
        /*
         * Emit the guaranteed-at-least-one-space-between-columns byte.
         */
        ap_rputs(" ", r);
        if (!(autoindex_opts & SUPPRESS_LAST_MOD)) {
            emit_link(r, "Last modified", K_LAST_MOD, keyid, direction,
                      colargs, static_columns);
            ap_rputs("      ", r);
        }
        if (!(autoindex_opts & SUPPRESS_SIZE)) {
            emit_link(r, "Size", K_SIZE, keyid, direction,
                      colargs, static_columns);
            ap_rputs("  ", r);
        }
        if (!(autoindex_opts & SUPPRESS_DESC)) {
            emit_link(r, "Description", K_DESC, keyid, direction,
                      colargs, static_columns);
        }
        if (!(autoindex_opts & SUPPRESS_RULES)) {
            ap_rputs("<hr", r);
            if (autoindex_opts & EMIT_XHTML) {
                ap_rputs(" /", r);
            }
            ap_rputs(">", r);
        }
        else {
            ap_rputc('\n', r);
        }
    }
    else {
        ap_rputs("<ul>", r);
    }

    for (x = 0; x < n; x++) {
        char *anchor, *t, *t2;
        int nwidth;

        apr_pool_clear(scratch);

        t = ar[x]->name;
        anchor = ap_escape_html(scratch, ap_os_escape_path(scratch, t, 0));

        if (!x && t[0] == '/') {
            t2 = "Parent Directory";
        }
        else {
            t2 = t;
        }

        if (autoindex_opts & TABLE_INDEXING) {
            ap_rputs("<tr>", r);
            if (!(autoindex_opts & SUPPRESS_ICON)) {
                ap_rputs("<td valign=\"top\">", r);
                if (autoindex_opts & ICONS_ARE_LINKS) {
                    ap_rvputs(r, "<a href=\"", anchor, "\">", NULL);
                }
                if ((ar[x]->icon) || d->default_icon) {
                    ap_rvputs(r, "<img src=\"",
                              ap_escape_html(scratch,
                                             ar[x]->icon ? ar[x]->icon
                                                         : d->default_icon),
                              "\" alt=\"[", (ar[x]->alt ? ar[x]->alt : "   "),
                              "]\"", NULL);
                    if (d->icon_width) {
                        ap_rprintf(r, " width=\"%d\"", d->icon_width);
                    }
                    if (d->icon_height) {
                        ap_rprintf(r, " height=\"%d\"", d->icon_height);
                    }

                    if (autoindex_opts & EMIT_XHTML) {
                        ap_rputs(" /", r);
                    }
                    ap_rputs(">", r);
                }
                else {
                    ap_rputs("&nbsp;", r);
                }
                if (autoindex_opts & ICONS_ARE_LINKS) {
                    ap_rputs("</a></td>", r);
                }
                else {
                    ap_rputs("</td>", r);
                }
            }
            if (d->name_adjust == K_ADJUST) {
                ap_rvputs(r, "<td><a href=\"", anchor, "\">",
                          ap_escape_html(scratch, t2), "</a>", NULL);
            }
            else {
                nwidth = strlen(t2);
                if (nwidth > name_width) {
                  memcpy(name_scratch, t2, name_width - 3);
                  name_scratch[name_width - 3] = '.';
                  name_scratch[name_width - 2] = '.';
                  name_scratch[name_width - 1] = '>';
                  name_scratch[name_width] = 0;
                  t2 = name_scratch;
                  nwidth = name_width;
                }
                ap_rvputs(r, "<td><a href=\"", anchor, "\">",
                          ap_escape_html(scratch, t2),
                          "</a>", pad_scratch + nwidth, NULL);
            }
            if (!(autoindex_opts & SUPPRESS_LAST_MOD)) {
                if (ar[x]->lm != -1) {
                    char time_str[MAX_STRING_LEN];
                    apr_time_exp_t ts;
                    apr_time_exp_lt(&ts, ar[x]->lm);
                    apr_strftime(time_str, &rv, MAX_STRING_LEN,
                                 "</td><td align=\"right\">%d-%b-%Y %H:%M  ",
                                 &ts);
                    ap_rputs(time_str, r);
                }
                else {
                    ap_rputs("</td><td>&nbsp;", r);
                }
            }
            if (!(autoindex_opts & SUPPRESS_SIZE)) {
                char buf[5];
                ap_rvputs(r, "</td><td align=\"right\">",
                          apr_strfsize(ar[x]->size, buf), NULL);
            }
            if (!(autoindex_opts & SUPPRESS_DESC)) {
                if (ar[x]->desc) {
                    if (d->desc_adjust == K_ADJUST) {
                        ap_rvputs(r, "</td><td>", ar[x]->desc, NULL);
                    }
                    else {
                        ap_rvputs(r, "</td><td>",
                                  terminate_description(d, ar[x]->desc,
                                                        autoindex_opts,
                                                        desc_width), NULL);
                    }
                }
            }
            else {
                ap_rputs("</td><td>&nbsp;", r);
            }
            ap_rputs("</td></tr>\n", r);
        }
        else if (autoindex_opts & FANCY_INDEXING) {
            if (!(autoindex_opts & SUPPRESS_ICON)) {
                if (autoindex_opts & ICONS_ARE_LINKS) {
                    ap_rvputs(r, "<a href=\"", anchor, "\">", NULL);
                }
                if ((ar[x]->icon) || d->default_icon) {
                    ap_rvputs(r, "<img src=\"",
                              ap_escape_html(scratch,
                                             ar[x]->icon ? ar[x]->icon
                                                         : d->default_icon),
                              "\" alt=\"[", (ar[x]->alt ? ar[x]->alt : "   "),
                              "]\"", NULL);
                    if (d->icon_width) {
                        ap_rprintf(r, " width=\"%d\"", d->icon_width);
                    }
                    if (d->icon_height) {
                        ap_rprintf(r, " height=\"%d\"", d->icon_height);
                    }

                    if (autoindex_opts & EMIT_XHTML) {
                        ap_rputs(" /", r);
                    }
                    ap_rputs(">", r);
                }
                else {
                    ap_rputs("     ", r);
                }
                if (autoindex_opts & ICONS_ARE_LINKS) {
                    ap_rputs("</a> ", r);
                }
                else {
                    ap_rputc(' ', r);
                }
            }
            nwidth = strlen(t2);
            if (nwidth > name_width) {
                memcpy(name_scratch, t2, name_width - 3);
                name_scratch[name_width - 3] = '.';
                name_scratch[name_width - 2] = '.';
                name_scratch[name_width - 1] = '>';
                name_scratch[name_width] = 0;
                t2 = name_scratch;
                nwidth = name_width;
            }
            ap_rvputs(r, "<a href=\"", anchor, "\">",
                      ap_escape_html(scratch, t2),
                      "</a>", pad_scratch + nwidth, NULL);
            /*
             * The blank before the storm.. er, before the next field.
             */
            ap_rputs(" ", r);
            if (!(autoindex_opts & SUPPRESS_LAST_MOD)) {
                if (ar[x]->lm != -1) {
                    char time_str[MAX_STRING_LEN];
                    apr_time_exp_t ts;
                    apr_time_exp_lt(&ts, ar[x]->lm);
                    apr_strftime(time_str, &rv, MAX_STRING_LEN,
                                "%d-%b-%Y %H:%M  ", &ts);
                    ap_rputs(time_str, r);
                }
                else {
                    /*Length="22-Feb-1998 23:42  " (see 4 lines above) */
                    ap_rputs("                   ", r);
                }
            }
            if (!(autoindex_opts & SUPPRESS_SIZE)) {
                char buf[5];
                ap_rputs(apr_strfsize(ar[x]->size, buf), r);
                ap_rputs("  ", r);
            }
            if (!(autoindex_opts & SUPPRESS_DESC)) {
                if (ar[x]->desc) {
                    ap_rputs(terminate_description(d, ar[x]->desc,
                                                   autoindex_opts,
                                                   desc_width), r);
                }
            }
            ap_rputc('\n', r);
        }
        else {
            ap_rvputs(r, "<li><a href=\"", anchor, "\"> ", t2,
                         "</a></li>\n", NULL);
        }
    }
    if (autoindex_opts & TABLE_INDEXING) {
        ap_rvputs(r, breakrow, "</table>\n", NULL);
    }
    else if (autoindex_opts & FANCY_INDEXING) {
        if (!(autoindex_opts & SUPPRESS_RULES)) {
            ap_rputs("<hr", r);
            if (autoindex_opts & EMIT_XHTML) {
                ap_rputs(" /", r);
            }
            ap_rputs("></pre>\n", r);
        }
        else {
            ap_rputs("</pre>\n", r);
        }
    }
    else {
        ap_rputs("</ul>\n", r);
    }
}

/*
 * Compare two file entries according to the sort criteria.  The return
 * is essentially a signum function value.
 */

static int dsortf(struct ent **e1, struct ent **e2)
{
    struct ent *c1;
    struct ent *c2;
    int result = 0;

    /*
     * First, see if either of the entries is for the parent directory.
     * If so, that *always* sorts lower than anything else.
     */
    if ((*e1)->name[0] == '/') {
        return -1;
    }
    if ((*e2)->name[0] == '/') {
        return 1;
    }
    /*
     * Now see if one's a directory and one isn't, if we're set
     * isdir for FOLDERS_FIRST.
     */
    if ((*e1)->isdir != (*e2)->isdir) {
        return (*e1)->isdir ? -1 : 1;
    }
    /*
     * All of our comparisons will be of the c1 entry against the c2 one,
     * so assign them appropriately to take care of the ordering.
     */
    if ((*e1)->ascending) {
        c1 = *e1;
        c2 = *e2;
    }
    else {
        c1 = *e2;
        c2 = *e1;
    }

    switch (c1->key) {
    case K_LAST_MOD:
        if (c1->lm > c2->lm) {
            return 1;
        }
        else if (c1->lm < c2->lm) {
            return -1;
        }
        break;
    case K_SIZE:
        if (c1->size > c2->size) {
            return 1;
        }
        else if (c1->size < c2->size) {
            return -1;
        }
        break;
    case K_DESC:
        if (c1->version_sort) {
            result = apr_strnatcmp(c1->desc ? c1->desc : "",
                                   c2->desc ? c2->desc : "");
        }
        else {
            result = strcmp(c1->desc ? c1->desc : "",
                            c2->desc ? c2->desc : "");
        }
        if (result) {
            return result;
        }
        break;
    }

    /* names may identical when treated case-insensitively,
     * so always fall back on strcmp() flavors to put entries
     * in deterministic order.  This means that 'ABC' and 'abc'
     * will always appear in the same order, rather than
     * variably between 'ABC abc' and 'abc ABC' order.
     */

    if (c1->version_sort) {
        if (c1->ignore_case) {
            result = apr_strnatcasecmp (c1->name, c2->name);
        }
        if (!result) {
            result = apr_strnatcmp(c1->name, c2->name);
        }
    }

    /* The names may be identical in respects other other than
     * filename case when strnatcmp is used above, so fall back
     * to strcmp on conflicts so that fn1.01.zzz and fn1.1.zzz
     * are also sorted in a deterministic order.
     */

    if (!result && c1->ignore_case) {
        result = strcasecmp (c1->name, c2->name);
    }

    if (!result) {
        result = strcmp (c1->name, c2->name);
    }

    return result;
}


static int index_directory(request_rec *r,
                           autoindex_config_rec *autoindex_conf)
{
    char *title_name = ap_escape_html(r->pool, r->uri);
    char *title_endp;
    char *name = r->filename;
    char *pstring = NULL;
    apr_finfo_t dirent;
    apr_dir_t *thedir;
    apr_status_t status;
    int num_ent = 0, x;
    struct ent *head, *p;
    struct ent **ar = NULL;
    const char *qstring;
    apr_int32_t autoindex_opts = autoindex_conf->opts;
    char keyid;
    char direction;
    char *colargs;
    char *fullpath;
    apr_size_t dirpathlen;

    if ((status = apr_dir_open(&thedir, name, r->pool)) != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, status, r,
                      "Can't open directory for index: %s", r->filename);
        return HTTP_FORBIDDEN;
    }

#if APR_HAS_UNICODE_FS
    ap_set_content_type(r, "text/html;charset=utf-8");
#else
    ap_set_content_type(r, "text/html");
#endif
    if (autoindex_opts & TRACK_MODIFIED) {
        ap_update_mtime(r, r->finfo.mtime);
        ap_set_last_modified(r);
        ap_set_etag(r);
    }
    if (r->header_only) {
        apr_dir_close(thedir);
        return 0;
    }

    /*
     * If there is no specific ordering defined for this directory,
     * default to ascending by filename.
     */
    keyid = autoindex_conf->default_keyid
                ? autoindex_conf->default_keyid : K_NAME;
    direction = autoindex_conf->default_direction
                ? autoindex_conf->default_direction : D_ASCENDING;

    /*
     * Figure out what sort of indexing (if any) we're supposed to use.
     *
     * If no QUERY_STRING was specified or client query strings have been
     * explicitly disabled.
     * If we are ignoring the client, suppress column sorting as well.
     */
    if (autoindex_opts & IGNORE_CLIENT) {
        qstring = NULL;
        autoindex_opts |= SUPPRESS_COLSORT;
        colargs = "";
    }
    else {
        char fval[5], vval[5], *ppre = "", *epattern = "";
        fval[0] = '\0'; vval[0] = '\0';
        qstring = r->args;

        while (qstring && *qstring) {

            /* C= First Sort key Column (N, M, S, D) */
            if (   qstring[0] == 'C' && qstring[1] == '='
                && qstring[2] && strchr(K_VALID, qstring[2])
                && (   qstring[3] == '&' || qstring[3] == ';'
                    || !qstring[3])) {
                keyid = qstring[2];
                qstring += qstring[3] ? 4 : 3;
            }

            /* O= Sort order (A, D) */
            else if (   qstring[0] == 'O' && qstring[1] == '='
                     && (   (qstring[2] == D_ASCENDING)
                         || (qstring[2] == D_DESCENDING))
                     && (   qstring[3] == '&' || qstring[3] == ';'
                         || !qstring[3])) {
                direction = qstring[2];
                qstring += qstring[3] ? 4 : 3;
            }

            /* F= Output Format (0 plain, 1 fancy (pre), 2 table) */
            else if (   qstring[0] == 'F' && qstring[1] == '='
                     && qstring[2] && strchr("012", qstring[2])
                     && (   qstring[3] == '&' || qstring[3] == ';'
                         || !qstring[3])) {
                if (qstring[2] == '0') {
                    autoindex_opts &= ~(FANCY_INDEXING | TABLE_INDEXING);
                }
                else if (qstring[2] == '1') {
                    autoindex_opts = (autoindex_opts | FANCY_INDEXING)
                        & ~TABLE_INDEXING;
                }
                else if (qstring[2] == '2') {
                    autoindex_opts |= FANCY_INDEXING | TABLE_INDEXING;
                }
                strcpy(fval, ";F= ");
                fval[3] = qstring[2];
                qstring += qstring[3] ? 4 : 3;
            }

            /* V= Version sort (0, 1) */
            else if (   qstring[0] == 'V' && qstring[1] == '='
                     && (qstring[2] == '0' || qstring[2] == '1')
                     && (   qstring[3] == '&' || qstring[3] == ';'
                         || !qstring[3])) {
                if (qstring[2] == '0') {
                    autoindex_opts &= ~VERSION_SORT;
                }
                else if (qstring[2] == '1') {
                    autoindex_opts |= VERSION_SORT;
                }
                strcpy(vval, ";V= "); 
                vval[3] = qstring[2];
                qstring += qstring[3] ? 4 : 3;
            }

            /* P= wildcard pattern (*.foo) */
            else if (qstring[0] == 'P' && qstring[1] == '=') {
                const char *eos = qstring += 2; /* for efficiency */

                while (*eos && *eos != '&' && *eos != ';') {
                    ++eos;
                }

                if (eos == qstring) {
                    pstring = NULL;
                }
                else {
                    pstring = apr_pstrndup(r->pool, qstring, eos - qstring);
                    if (ap_unescape_url(pstring) != OK) {
                        /* ignore the pattern, if it's bad. */
                        pstring = NULL;
                    }
                    else {
                        ppre = ";P=";
                        /* be correct */
                        epattern = ap_escape_uri(r->pool, pstring);
                    }
                }

                if (*eos && *++eos) {
                    qstring = eos;
                }
                else {
                    qstring = NULL;
                }
            }

            /* Syntax error?  Ignore the remainder! */
            else {
                qstring = NULL;
            }
        }
        colargs = apr_pstrcat(r->pool, fval, vval, ppre, epattern, NULL);
    }

    /* Spew HTML preamble */
    title_endp = title_name + strlen(title_name) - 1;

    while (title_endp > title_name && *title_endp == '/') {
        *title_endp-- = '\0';
    }

    emit_head(r, find_header(autoindex_conf, r),
              autoindex_opts & SUPPRESS_PREAMBLE,
              autoindex_opts & EMIT_XHTML, title_name);

    /*
     * Since we don't know how many dir. entries there are, put them into a
     * linked list and then arrayificate them so qsort can use them.
     */
    head = NULL;
    p = make_parent_entry(autoindex_opts, autoindex_conf, r, keyid, direction);
    if (p != NULL) {
        p->next = head;
        head = p;
        num_ent++;
    }
    fullpath = apr_palloc(r->pool, APR_PATH_MAX);
    dirpathlen = strlen(name);
    memcpy(fullpath, name, dirpathlen);
    while (apr_dir_read(&dirent, APR_FINFO_MIN | APR_FINFO_NAME,
                        thedir) == APR_SUCCESS) {
        /* We want to explode symlinks here. */
        if (dirent.filetype == APR_LNK) {
            const char *savename;
            apr_finfo_t fi;
            /* We *must* have FNAME. */
            savename = dirent.name;
            apr_cpystrn(fullpath + dirpathlen, dirent.name,
                        APR_PATH_MAX - dirpathlen);
            status = apr_stat(&fi, fullpath,
                              dirent.valid & ~(APR_FINFO_NAME), r->pool);
            if (status != APR_SUCCESS) {
                /* Something bad happened, skip this file. */
                continue;
            }
            memcpy(&dirent, &fi, sizeof(fi));
            dirent.name = savename;
            dirent.valid |= APR_FINFO_NAME;
        }
        p = make_autoindex_entry(&dirent, autoindex_opts, autoindex_conf, r,
                                 keyid, direction, pstring);
        if (p != NULL) {
            p->next = head;
            head = p;
            num_ent++;
        }
    }
    if (num_ent > 0) {
        ar = (struct ent **) apr_palloc(r->pool,
                                        num_ent * sizeof(struct ent *));
        p = head;
        x = 0;
        while (p) {
            ar[x++] = p;
            p = p->next;
        }

        qsort((void *) ar, num_ent, sizeof(struct ent *),
              (int (*)(const void *, const void *)) dsortf);
    }
    output_directories(ar, num_ent, autoindex_conf, r, autoindex_opts,
                       keyid, direction, colargs);
    apr_dir_close(thedir);

    emit_tail(r, find_readme(autoindex_conf, r),
              autoindex_opts & SUPPRESS_PREAMBLE);

    return 0;
}

/* The formal handler... */

static int handle_autoindex(request_rec *r)
{
    autoindex_config_rec *d;
    int allow_opts;

    if(strcmp(r->handler,DIR_MAGIC_TYPE)) {
        return DECLINED;
    }

    allow_opts = ap_allow_options(r);

    d = (autoindex_config_rec *) ap_get_module_config(r->per_dir_config,
                                                      &autoindex_module);

    r->allowed |= (AP_METHOD_BIT << M_GET);
    if (r->method_number != M_GET) {
        return DECLINED;
    }

    /* OK, nothing easy.  Trot out the heavy artillery... */

    if (allow_opts & OPT_INDEXES) {
        int errstatus;

        if ((errstatus = ap_discard_request_body(r)) != OK) {
            return errstatus;
        }

        /* KLUDGE --- make the sub_req lookups happen in the right directory.
         * Fixing this in the sub_req_lookup functions themselves is difficult,
         * and would probably break virtual includes...
         */

        if (r->filename[strlen(r->filename) - 1] != '/') {
            r->filename = apr_pstrcat(r->pool, r->filename, "/", NULL);
        }
        return index_directory(r, d);
    }
    else {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "Directory index forbidden by rule: %s", r->filename);
        return HTTP_FORBIDDEN;
    }
}

static void register_hooks(apr_pool_t *p)
{
    ap_hook_handler(handle_autoindex,NULL,NULL,APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA autoindex_module =
{
    STANDARD20_MODULE_STUFF,
    create_autoindex_config,    /* dir config creater */
    merge_autoindex_configs,    /* dir merger --- default is to override */
    NULL,                       /* server config */
    NULL,                       /* merge server config */
    autoindex_cmds,             /* command apr_table_t */
    register_hooks              /* register hooks */
};
