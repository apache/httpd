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
 * mod_autoindex.c: Handles the on-the-fly html index generation
 * 
 * Rob McCool
 * 3/23/93
 * 
 * Adapted to Apache by rst.
 */

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_request.h"
#include "http_protocol.h"
#include "http_log.h"
#include "http_main.h"
#include "util_script.h"

module MODULE_VAR_EXPORT autoindex_module;

/****************************************************************
 *
 * Handling configuration directives...
 */

#define HRULE 1
#define NO_HRULE 0
#define FRONT_MATTER 1
#define END_MATTER 0

#define FANCY_INDEXING 1	/* Indexing options */
#define ICONS_ARE_LINKS 2
#define SCAN_HTML_TITLES 4
#define SUPPRESS_LAST_MOD 8
#define SUPPRESS_SIZE 16
#define SUPPRESS_DESC 32
#define SUPPRESS_PREAMBLE 64
#define SUPPRESS_COLSORT 128

#define K_PAD 1
#define K_NOPAD 0

/*
 * Define keys for sorting.
 */
#define K_NAME 'N'		/* Sort by file name (default) */
#define K_LAST_MOD 'M'		/* Last modification date */
#define K_SIZE 'S'		/* Size (absolute, not as displayed) */
#define K_DESC 'D'		/* Description */

#define D_ASCENDING 'A'
#define D_DESCENDING 'D'

/*
 * These are the dimensions of the default icons supplied with Apache.
 */
#define DEFAULT_ICON_WIDTH 20
#define DEFAULT_ICON_HEIGHT 22

/*
 * Other default dimensions.
 */
#define DEFAULT_NAME_WIDTH 23

struct item {
    char *type;
    char *apply_to;
    char *apply_path;
    char *data;
};

typedef struct autoindex_config_struct {

    char *default_icon;
    int opts;
    int name_width;
    int name_adjust;
    int icon_width;
    int icon_height;

    array_header *icon_list, *alt_list, *desc_list, *ign_list;
    array_header *hdr_list, *rdme_list;

} autoindex_config_rec;

static char c_by_encoding, c_by_type, c_by_path;

#define BY_ENCODING &c_by_encoding
#define BY_TYPE &c_by_type
#define BY_PATH &c_by_path

/*
 * Return true if the specified string refers to the parent directory (i.e.,
 * matches ".." or "../").  Hopefully this one call is significantly less
 * expensive than multiple strcmp() calls.
 */
static ap_inline int is_parent(const char *name)
{
    /*
     * Now, IFF the first two bytes are dots, and the third byte is either
     * EOS (\0) or a slash followed by EOS, we have a match.
     */
    if (((name[0] == '.') && (name[1] == '.'))
	&& ((name[2] == '\0')
	    || ((name[2] == '/') && (name[3] == '\0')))) {
        return 1;
    }
    return 0;
}

/*
 * This routine puts the standard HTML header at the top of the index page.
 * We include the DOCTYPE because we may be using features therefrom (i.e.,
 * HEIGHT and WIDTH attributes on the icons if we're FancyIndexing).
 */
static void emit_preamble(request_rec *r, char *title)
{
    ap_rvputs(r, "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 3.2 Final//EN\">\n",
	      "<HTML>\n <HEAD>\n  <TITLE>Index of ", title,
	      "</TITLE>\n </HEAD>\n <BODY>\n", NULL);
}

static void push_item(array_header *arr, char *type, char *to, char *path,
		      char *data)
{
    struct item *p = (struct item *) ap_push_array(arr);

    if (!to) {
	to = "";
    }
    if (!path) {
	path = "";
    }

    p->type = type;
    p->data = data ? ap_pstrdup(arr->pool, data) : NULL;
    p->apply_path = ap_pstrcat(arr->pool, path, "*", NULL);

    if ((type == BY_PATH) && (!ap_is_matchexp(to))) {
	p->apply_to = ap_pstrcat(arr->pool, "*", to, NULL);
    }
    else if (to) {
	p->apply_to = ap_pstrdup(arr->pool, to);
    }
    else {
	p->apply_to = NULL;
    }
}

static const char *add_alt(cmd_parms *cmd, void *d, char *alt, char *to)
{
    if (cmd->info == BY_PATH) {
        if (!strcmp(to, "**DIRECTORY**")) {
	    to = "^^DIRECTORY^^";
	}
    }
    if (cmd->info == BY_ENCODING) {
	ap_str_tolower(to);
    }

    push_item(((autoindex_config_rec *) d)->alt_list, cmd->info, to,
	      cmd->path, alt);
    return NULL;
}

static const char *add_icon(cmd_parms *cmd, void *d, char *icon, char *to)
{
    char *iconbak = ap_pstrdup(cmd->pool, icon);

    if (icon[0] == '(') {
	char *alt;
	char *cl = strchr(iconbak, ')');

	if (cl == NULL) {
	    return "missing closing paren";
	}
	alt = ap_getword_nc(cmd->pool, &iconbak, ',');
	*cl = '\0';				/* Lose closing paren */
	add_alt(cmd, d, &alt[1], to);
    }
    if (cmd->info == BY_PATH) {
        if (!strcmp(to, "**DIRECTORY**")) {
	    to = "^^DIRECTORY^^";
	}
    }
    if (cmd->info == BY_ENCODING) {
	ap_str_tolower(to);
    }

    push_item(((autoindex_config_rec *) d)->icon_list, cmd->info, to,
	      cmd->path, iconbak);
    return NULL;
}

static const char *add_desc(cmd_parms *cmd, void *d, char *desc, char *to)
{
    push_item(((autoindex_config_rec *) d)->desc_list, cmd->info, to,
	      cmd->path, desc);
    return NULL;
}

static const char *add_ignore(cmd_parms *cmd, void *d, char *ext)
{
    push_item(((autoindex_config_rec *) d)->ign_list, 0, ext, cmd->path, NULL);
    return NULL;
}

static const char *add_header(cmd_parms *cmd, void *d, char *name)
{
    if (strchr(name, '/')) {
	return "HeaderName cannot contain a /";
    }
    push_item(((autoindex_config_rec *) d)->hdr_list, 0, NULL, cmd->path,
	      name);
    return NULL;
}

static const char *add_readme(cmd_parms *cmd, void *d, char *name)
{
    if (strchr(name, '/')) {
	return "ReadmeName cannot contain a /";
    }
    push_item(((autoindex_config_rec *) d)->rdme_list, 0, NULL, cmd->path,
	      name);
    return NULL;
}

/* A legacy directive, FancyIndexing is superseded by the IndexOptions
 * keyword.  But for compatibility..
 */
static const char *fancy_indexing(cmd_parms *cmd, void *d, int arg)
{
    int curopts;
    int newopts;
    autoindex_config_rec *cfg;

    cfg = (autoindex_config_rec *) d;
    curopts = cfg->opts;
    newopts = (arg ? (curopts | FANCY_INDEXING) : (curopts & !FANCY_INDEXING));
    cfg->opts = newopts;
    return NULL;
}

static const char *add_opts(cmd_parms *cmd, void *d, const char *optstr)
{
    char *w;
    int opts = 0;
    autoindex_config_rec *d_cfg = (autoindex_config_rec *) d;

    while (optstr[0]) {
	w = ap_getword_conf(cmd->pool, &optstr);
	if (!strcasecmp(w, "FancyIndexing")) {
	    opts |= FANCY_INDEXING;
	}
	else if (!strcasecmp(w, "IconsAreLinks")) {
	    opts |= ICONS_ARE_LINKS;
	}
	else if (!strcasecmp(w, "ScanHTMLTitles")) {
	    opts |= SCAN_HTML_TITLES;
	}
	else if (!strcasecmp(w, "SuppressLastModified")) {
	    opts |= SUPPRESS_LAST_MOD;
	}
	else if (!strcasecmp(w, "SuppressSize")) {
	    opts |= SUPPRESS_SIZE;
	}
	else if (!strcasecmp(w, "SuppressDescription")) {
	    opts |= SUPPRESS_DESC;
	}
	else if (!strcasecmp(w, "SuppressHTMLPreamble")) {
	    opts |= SUPPRESS_PREAMBLE;
	}
        else if (!strcasecmp(w, "SuppressColumnSorting")) {
            opts |= SUPPRESS_COLSORT;
	}
	else if (!strcasecmp(w, "None")) {
	    opts = 0;
	}
	else if (!strcasecmp(w, "IconWidth")) {
	    d_cfg->icon_width = DEFAULT_ICON_WIDTH;
	}
	else if (!strncasecmp(w, "IconWidth=", 10)) {
	    d_cfg->icon_width = atoi(&w[10]);
	}
	else if (!strcasecmp(w, "IconHeight")) {
	    d_cfg->icon_height = DEFAULT_ICON_HEIGHT;
	}
	else if (!strncasecmp(w, "IconHeight=", 11)) {
	    d_cfg->icon_height = atoi(&w[11]);
	}
	else if (!strncasecmp(w, "NameWidth=", 10)) {
	    if (w[10] == '*') {
		d_cfg->name_adjust = 1;
	    }
	    else {
		int width = atoi(&w[10]);

		if (width < 1) {
		    return "NameWidth value must be greater than 1";
		}
		d_cfg->name_width = width;
	    }
	}
	else {
	    return "Invalid directory indexing option";
	}
    }
    d_cfg->opts = opts;
    return NULL;
}

#define DIR_CMD_PERMS OR_INDEXES

static const command_rec autoindex_cmds[] =
{
    {"AddIcon", add_icon, BY_PATH, DIR_CMD_PERMS, ITERATE2,
     "an icon URL followed by one or more filenames"},
    {"AddIconByType", add_icon, BY_TYPE, DIR_CMD_PERMS, ITERATE2,
     "an icon URL followed by one or more MIME types"},
    {"AddIconByEncoding", add_icon, BY_ENCODING, DIR_CMD_PERMS, ITERATE2,
     "an icon URL followed by one or more content encodings"},
    {"AddAlt", add_alt, BY_PATH, DIR_CMD_PERMS, ITERATE2,
     "alternate descriptive text followed by one or more filenames"},
    {"AddAltByType", add_alt, BY_TYPE, DIR_CMD_PERMS, ITERATE2,
     "alternate descriptive text followed by one or more MIME types"},
    {"AddAltByEncoding", add_alt, BY_ENCODING, DIR_CMD_PERMS, ITERATE2,
     "alternate descriptive text followed by one or more content encodings"},
    {"IndexOptions", add_opts, NULL, DIR_CMD_PERMS, RAW_ARGS,
     "one or more index options"},
    {"IndexIgnore", add_ignore, NULL, DIR_CMD_PERMS, ITERATE,
     "one or more file extensions"},
    {"AddDescription", add_desc, BY_PATH, DIR_CMD_PERMS, ITERATE2,
     "Descriptive text followed by one or more filenames"},
    {"HeaderName", add_header, NULL, DIR_CMD_PERMS, TAKE1, "a filename"},
    {"ReadmeName", add_readme, NULL, DIR_CMD_PERMS, TAKE1, "a filename"},
    {"FancyIndexing", fancy_indexing, NULL, DIR_CMD_PERMS, FLAG,
     "Limited to 'on' or 'off' (superseded by IndexOptions FancyIndexing)"},
    {"DefaultIcon", ap_set_string_slot,
     (void *) XtOffsetOf(autoindex_config_rec, default_icon),
     DIR_CMD_PERMS, TAKE1, "an icon URL"},
    {NULL}
};

static void *create_autoindex_config(pool *p, char *dummy)
{
    autoindex_config_rec *new =
    (autoindex_config_rec *) ap_pcalloc(p, sizeof(autoindex_config_rec));

    new->icon_width = 0;
    new->icon_height = 0;
    new->name_width = DEFAULT_NAME_WIDTH;
    new->name_adjust = 0;
    new->icon_list = ap_make_array(p, 4, sizeof(struct item));
    new->alt_list = ap_make_array(p, 4, sizeof(struct item));
    new->desc_list = ap_make_array(p, 4, sizeof(struct item));
    new->ign_list = ap_make_array(p, 4, sizeof(struct item));
    new->hdr_list = ap_make_array(p, 4, sizeof(struct item));
    new->rdme_list = ap_make_array(p, 4, sizeof(struct item));
    new->opts = 0;

    return (void *) new;
}

static void *merge_autoindex_configs(pool *p, void *basev, void *addv)
{
    autoindex_config_rec *new;
    autoindex_config_rec *base = (autoindex_config_rec *) basev;
    autoindex_config_rec *add = (autoindex_config_rec *) addv;

    new = (autoindex_config_rec *) ap_pcalloc(p, sizeof(autoindex_config_rec));
    new->default_icon = add->default_icon ? add->default_icon
                                          : base->default_icon;
    new->icon_height = add->icon_height ? add->icon_height : base->icon_height;
    new->icon_width = add->icon_width ? add->icon_width : base->icon_width;

    new->alt_list = ap_append_arrays(p, add->alt_list, base->alt_list);
    new->ign_list = ap_append_arrays(p, add->ign_list, base->ign_list);
    new->hdr_list = ap_append_arrays(p, add->hdr_list, base->hdr_list);
    new->desc_list = ap_append_arrays(p, add->desc_list, base->desc_list);
    new->icon_list = ap_append_arrays(p, add->icon_list, base->icon_list);
    new->rdme_list = ap_append_arrays(p, add->rdme_list, base->rdme_list);
    new->opts = add->opts;
    new->name_width = add->name_width;
    new->name_adjust = add->name_adjust;

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
    size_t size;
    time_t lm;
    struct ent *next;
    int ascending;
    char key;
};

static char *find_item(request_rec *r, array_header *list, int path_only)
{
    const char *content_type = r->content_type;
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
#define find_desc(d,p) find_item(p,d->desc_list,0)
#define find_header(d,p) find_item(p,d->hdr_list,0)
#define find_readme(d,p) find_item(p,d->rdme_list,0)

static char *find_default_icon(autoindex_config_rec *d, char *bogus_name)
{
    request_rec r;

    /* Bleah.  I tried to clean up find_item, and it lead to this bit
     * of ugliness.   Note that the fields initialized are precisely
     * those that find_item looks at...
     */

    r.filename = bogus_name;
    r.content_type = r.content_encoding = NULL;

    return find_item(&r, d->icon_list, 1);
}

static int ignore_entry(autoindex_config_rec *d, char *path)
{
    array_header *list = d->ign_list;
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
 * Look for the specified file, and pump it into the response stream if we
 * find it.
 */
static int insert_readme(char *name, char *readme_fname, char *title,
			 int hrule, int whichend, request_rec *r)
{
    char *fn;
    FILE *f;
    struct stat finfo;
    int plaintext = 0;
    request_rec *rr;
    autoindex_config_rec *cfg;
    int autoindex_opts;

    cfg = (autoindex_config_rec *) ap_get_module_config(r->per_dir_config,
							&autoindex_module);
    autoindex_opts = cfg->opts;
    /* XXX: this is a load of crap, it needs to do a full sub_req_lookup_uri */
    fn = ap_make_full_path(r->pool, name, readme_fname);
    fn = ap_pstrcat(r->pool, fn, ".html", NULL);
    if (stat(fn, &finfo) == -1) {
	/* A brief fake multiviews search for README.html */
	fn[strlen(fn) - 5] = '\0';
	if (stat(fn, &finfo) == -1) {
	    return 0;
	}
	plaintext = 1;
	if (hrule) {
	    ap_rputs("<HR>\n", r);
	}
    }
    else if (hrule) {
	ap_rputs("<HR>\n", r);
    }
    /* XXX: when the above is rewritten properly, this necessary security
     * check will be redundant. -djg */
    rr = ap_sub_req_lookup_file(fn, r);
    if (rr->status != HTTP_OK) {
	ap_destroy_sub_req(rr);
	return 0;
    }
    ap_destroy_sub_req(rr);
    if (!(f = ap_pfopen(r->pool, fn, "r"))) {
        return 0;
    }
    if ((whichend == FRONT_MATTER)
	&& (!(autoindex_opts & SUPPRESS_PREAMBLE))) {
	emit_preamble(r, title);
    }
    if (!plaintext) {
	ap_send_fd(f, r);
    }
    else {
	char buf[IOBUFSIZE + 1];
	int i, n, c, ch;
	ap_rputs("<PRE>\n", r);
	while (!feof(f)) {
	    do {
		n = fread(buf, sizeof(char), IOBUFSIZE, f);
	    }
	    while (n == -1 && ferror(f) && errno == EINTR);
	    if (n == -1 || n == 0) {
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
    }
    ap_pfclose(r->pool, f);
    if (plaintext) {
	ap_rputs("</PRE>\n", r);
    }
    return 1;
}


static char *find_title(request_rec *r)
{
    char titlebuf[MAX_STRING_LEN], *find = "<TITLE>";
    FILE *thefile = NULL;
    int x, y, n, p;

    if (r->status != HTTP_OK) {
	return NULL;
    }
    if (r->content_type
	&& (!strcmp(r->content_type, "text/html")
	    || !strcmp(r->content_type, INCLUDES_MAGIC_TYPE))
	&& !r->content_encoding) {
        if (!(thefile = ap_pfopen(r->pool, r->filename, "r"))) {
	    return NULL;
	}
	n = fread(titlebuf, sizeof(char), MAX_STRING_LEN - 1, thefile);
	if (n <= 0) {
	    ap_pfclose(r->pool, thefile);
	    return NULL;
	}
	titlebuf[n] = '\0';
	for (x = 0, p = 0; titlebuf[x]; x++) {
	    if (ap_toupper(titlebuf[x]) == find[p]) {
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
		    ap_pfclose(r->pool, thefile);
		    return ap_pstrdup(r->pool, &titlebuf[x]);
		}
	    }
	    else {
		p = 0;
	    }
	}
	ap_pfclose(r->pool, thefile);
    }
    return NULL;
}

static struct ent *make_autoindex_entry(char *name, int autoindex_opts,
					autoindex_config_rec *d,
					request_rec *r, char keyid,
					char direction)
{
    struct ent *p;

    if ((name[0] == '.') && (!name[1])) {
	return (NULL);
    }

    if (ignore_entry(d, ap_make_full_path(r->pool, r->filename, name))) {
        return (NULL);
    }

    p = (struct ent *) ap_pcalloc(r->pool, sizeof(struct ent));
    p->name = ap_pstrdup(r->pool, name);
    p->size = 0;
    p->icon = NULL;
    p->alt = NULL;
    p->desc = NULL;
    p->lm = -1;
    p->key = ap_toupper(keyid);
    p->ascending = (ap_toupper(direction) == D_ASCENDING);

    if (autoindex_opts & FANCY_INDEXING) {
	request_rec *rr = ap_sub_req_lookup_file(name, r);

	if (rr->finfo.st_mode != 0) {
	    p->lm = rr->finfo.st_mtime;
	    if (S_ISDIR(rr->finfo.st_mode)) {
	        if (!(p->icon = find_icon(d, rr, 1))) {
		    p->icon = find_default_icon(d, "^^DIRECTORY^^");
		}
		if (!(p->alt = find_alt(d, rr, 1))) {
		    p->alt = "DIR";
		}
		p->size = 0;
		p->name = ap_pstrcat(r->pool, name, "/", NULL);
	    }
	    else {
		p->icon = find_icon(d, rr, 0);
		p->alt = find_alt(d, rr, 0);
		p->size = rr->finfo.st_size;
	    }
	}

	p->desc = find_desc(d, rr);

	if ((!p->desc) && (autoindex_opts & SCAN_HTML_TITLES)) {
	    p->desc = ap_pstrdup(r->pool, find_title(rr));
	}

	ap_destroy_sub_req(rr);
    }
    /*
     * We don't need to take any special action for the file size key.  If
     * we did, it would go here.
     */
    if (keyid == K_LAST_MOD) {
        if (p->lm < 0) {
	    p->lm = 0;
	}
    }
    return (p);
}

static char *terminate_description(autoindex_config_rec *d, char *desc,
				   int autoindex_opts)
{
    int maxsize = 23;
    register int x;

    if (autoindex_opts & SUPPRESS_LAST_MOD) {
	maxsize += 19;
    }
    if (autoindex_opts & SUPPRESS_SIZE) {
	maxsize += 7;
    }

    for (x = 0; desc[x] && (maxsize > 0 || desc[x]=='<'); x++) {
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
	desc[x - 1] = '>';	/* Grump. */
	desc[x] = '\0';		/* Double Grump! */
    }
    return desc;
}

/*
 * Emit the anchor for the specified field.  If a field is the key for the
 * current request, the link changes its meaning to reverse the order when
 * selected again.  Non-active fields always start in ascending order.
 */
static void emit_link(request_rec *r, char *anchor, char fname, char curkey,
                      char curdirection, int nosort)
{
    char qvalue[5];
    int reverse;

    if (!nosort) {
	qvalue[0] = '?';
	qvalue[1] = fname;
	qvalue[2] = '=';
	qvalue[4] = '\0';
	reverse = ((curkey == fname) && (curdirection == D_ASCENDING));
	qvalue[3] = reverse ? D_DESCENDING : D_ASCENDING;
	ap_rvputs(r, "<A HREF=\"", qvalue, "\">", anchor, "</A>", NULL);
    }
    else {
        ap_rputs(anchor, r);
    }
}

/*
 * Fit a string into a specified buffer width, marking any
 * truncation.  The size argument is the actual buffer size, including
 * the \0 termination byte.  The buffer will be prefilled with blanks.
 * If the pad argument is false, any extra spaces at the end of the
 * buffer are omitted.  (Used when constructing anchors.)
 */
static ap_inline char *widthify(const char *s, char *buff, int size, int pad)
{
    int s_len;

    memset(buff, ' ', size);
    buff[size - 1] = '\0';
    s_len = strlen(s);
    if (s_len > (size - 1)) {
	ap_cpystrn(buff, s, size);
	if (size > 1) {
	    buff[size - 2] = '>';
	}
	if (size > 2) {
	    buff[size - 3] = '.';
	}
	if (size > 3) {
	    buff[size - 4] = '.';
	}
    }
    else {
	ap_cpystrn(buff, s, s_len + 1);
	if (pad) {
	    buff[s_len] = ' ';
	}
    }
    return buff;
}

static void output_directories(struct ent **ar, int n,
			       autoindex_config_rec *d, request_rec *r,
			       int autoindex_opts, char keyid, char direction)
{
    int x;
    char *name = r->uri;
    char *tp;
    int static_columns = (autoindex_opts & SUPPRESS_COLSORT);
    pool *scratch = ap_make_sub_pool(r->pool);
    int name_width;
    char *name_scratch;

    if (name[0] == '\0') {
	name = "/";
    }

    name_width = d->name_width;
    if (d->name_adjust) {
	for (x = 0; x < n; x++) {
	    int t = strlen(ar[x]->name);
	    if (t > name_width) {
		name_width = t;
	    }
	}
    }
    ++name_width;
    name_scratch = ap_palloc(r->pool, name_width + 1);
    memset(name_scratch, ' ', name_width);
    name_scratch[name_width] = '\0';

    if (autoindex_opts & FANCY_INDEXING) {
	ap_rputs("<PRE>", r);
	if ((tp = find_default_icon(d, "^^BLANKICON^^"))) {
	    ap_rvputs(r, "<IMG SRC=\"", ap_escape_html(scratch, tp),
		   "\" ALT=\"     \"", NULL);
	    if (d->icon_width && d->icon_height) {
		ap_rprintf
		    (
			r,
			" HEIGHT=\"%d\" WIDTH=\"%d\"",
			d->icon_height,
			d->icon_width
		    );
	    }
	    ap_rputs("> ", r);
	}
        emit_link(r, widthify("Name", name_scratch,
			      (name_width > 5) ? 5 : name_width, K_NOPAD),
		  K_NAME, keyid, direction, static_columns);
	if (name_width > 5) {
	    memset(name_scratch, ' ', name_width);
	    name_scratch[name_width] = '\0';
	    ap_rputs(&name_scratch[5], r);
	}
	/*
	 * Emit the guaranteed-at-least-one-space-between-columns byte.
	 */
	ap_rputs(" ", r);
	if (!(autoindex_opts & SUPPRESS_LAST_MOD)) {
            emit_link(r, "Last modified", K_LAST_MOD, keyid, direction,
                      static_columns);
	    ap_rputs("       ", r);
	}
	if (!(autoindex_opts & SUPPRESS_SIZE)) {
            emit_link(r, "Size", K_SIZE, keyid, direction, static_columns);
	    ap_rputs("  ", r);
	}
	if (!(autoindex_opts & SUPPRESS_DESC)) {
            emit_link(r, "Description", K_DESC, keyid, direction,
                      static_columns);
	}
	ap_rputs("\n<HR>\n", r);
    }
    else {
	ap_rputs("<UL>", r);
    }

    for (x = 0; x < n; x++) {
	char *anchor, *t, *t2;
	char *pad;
	int nwidth;

	ap_clear_pool(scratch);

	if (is_parent(ar[x]->name)) {
	    t = ap_make_full_path(scratch, name, "../");
	    ap_getparents(t);
	    if (t[0] == '\0') {
		t = "/";
	    }
	       /* 1234567890123456 */
	    t2 = "Parent Directory";
	    pad = name_scratch + 16;
	    anchor = ap_escape_html(scratch, ap_os_escape_path(scratch, t, 0));
	}
	else {
	    t = ar[x]->name;
	    pad = name_scratch + strlen(t);
	    t2 = ap_escape_html(scratch, t);
	    anchor = ap_escape_html(scratch, ap_os_escape_path(scratch, t, 0));
	}

	if (autoindex_opts & FANCY_INDEXING) {
	    if (autoindex_opts & ICONS_ARE_LINKS) {
		ap_rvputs(r, "<A HREF=\"", anchor, "\">", NULL);
	    }
	    if ((ar[x]->icon) || d->default_icon) {
		ap_rvputs(r, "<IMG SRC=\"",
			  ap_escape_html(scratch,
					 ar[x]->icon ? ar[x]->icon
					             : d->default_icon),
			  "\" ALT=\"[", (ar[x]->alt ? ar[x]->alt : "   "),
			  "]\"", NULL);
		if (d->icon_width && d->icon_height) {
		    ap_rprintf(r, " HEIGHT=\"%d\" WIDTH=\"%d\"",
			       d->icon_height, d->icon_width);
		}
		ap_rputs(">", r);
	    }
	    if (autoindex_opts & ICONS_ARE_LINKS) {
		ap_rputs("</A>", r);
	    }

	    ap_rvputs(r, " <A HREF=\"", anchor, "\">",
		      widthify(t2, name_scratch, name_width, K_NOPAD),
		      "</A>", NULL);
	    /*
	     * We know that widthify() prefilled the buffer with spaces
	     * before doing its thing, so use them.
	     */
	    nwidth = strlen(t2);
	    if (nwidth < (name_width - 1)) {
		name_scratch[nwidth] = ' ';
		ap_rputs(&name_scratch[nwidth], r);
	    }
	    /*
	     * The blank before the storm.. er, before the next field.
	     */
	    ap_rputs(" ", r);
	    if (!(autoindex_opts & SUPPRESS_LAST_MOD)) {
		if (ar[x]->lm != -1) {
		    char time_str[MAX_STRING_LEN];
		    struct tm *ts = localtime(&ar[x]->lm);
		    strftime(time_str, MAX_STRING_LEN, "%d-%b-%Y %H:%M  ", ts);
		    ap_rputs(time_str, r);
		}
		else {
		    ap_rputs("                 ", r);
		}
	    }
	    if (!(autoindex_opts & SUPPRESS_SIZE)) {
		ap_send_size(ar[x]->size, r);
		ap_rputs("  ", r);
	    }
	    if (!(autoindex_opts & SUPPRESS_DESC)) {
		if (ar[x]->desc) {
		    ap_rputs(terminate_description(d, ar[x]->desc,
						   autoindex_opts), r);
		}
	    }
	}
	else {
	    ap_rvputs(r, "<LI><A HREF=\"", anchor, "\"> ", t2,
		      "</A>", pad, NULL);
	}
	ap_rputc('\n', r);
    }
    if (autoindex_opts & FANCY_INDEXING) {
	ap_rputs("</PRE>", r);
    }
    else {
	ap_rputs("</UL>", r);
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
    if (is_parent((*e1)->name)) {
        return -1;
    }
    if (is_parent((*e2)->name)) {
        return 1;
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
        result = strcmp(c1->desc ? c1->desc : "", c2->desc ? c2->desc : "");
        if (result) {
            return result;
        }
        break;
    }
    return strcmp(c1->name, c2->name);
}


static int index_directory(request_rec *r,
			   autoindex_config_rec *autoindex_conf)
{
    char *title_name = ap_escape_html(r->pool, r->uri);
    char *title_endp;
    char *name = r->filename;

    DIR *d;
    struct DIR_TYPE *dstruct;
    int num_ent = 0, x;
    struct ent *head, *p;
    struct ent **ar = NULL;
    char *tmp;
    const char *qstring;
    int autoindex_opts = autoindex_conf->opts;
    char keyid;
    char direction;

    if (!(d = ap_popendir(r->pool, name))) {
	ap_log_rerror(APLOG_MARK, APLOG_ERR, r,
		    "Can't open directory for index: %s", r->filename);
	return HTTP_FORBIDDEN;
    }

    r->content_type = "text/html";

    ap_send_http_header(r);

    if (r->header_only) {
	ap_pclosedir(r->pool, d);
	return 0;
    }
    ap_hard_timeout("send directory", r);

    /* Spew HTML preamble */

    title_endp = title_name + strlen(title_name) - 1;

    while (title_endp > title_name && *title_endp == '/') {
	*title_endp-- = '\0';
    }

    if ((!(tmp = find_header(autoindex_conf, r)))
	|| (!(insert_readme(name, tmp, title_name, NO_HRULE, FRONT_MATTER, r)))
	) {
	emit_preamble(r, title_name);
	ap_rvputs(r, "<H1>Index of ", title_name, "</H1>\n", NULL);
    }

    /*
     * Figure out what sort of indexing (if any) we're supposed to use.
     */
    if (autoindex_opts & SUPPRESS_COLSORT) {
	keyid = K_NAME;
	direction = D_ASCENDING;
    }
    else {
	qstring = r->args;

	/*
	 * If no QUERY_STRING was specified, we use the default: ascending
	 * by name.
	 */
	if ((qstring == NULL) || (*qstring == '\0')) {
	    keyid = K_NAME;
	    direction = D_ASCENDING;
	}
	else {
	    keyid = *qstring;
	    ap_getword(r->pool, &qstring, '=');
	    if (qstring != '\0') {
		direction = *qstring;
	    }
	    else {
		direction = D_ASCENDING;
	    }
	}
    }

    /* 
     * Since we don't know how many dir. entries there are, put them into a 
     * linked list and then arrayificate them so qsort can use them. 
     */
    head = NULL;
    while ((dstruct = readdir(d))) {
	p = make_autoindex_entry(dstruct->d_name, autoindex_opts,
				 autoindex_conf, r, keyid, direction);
	if (p != NULL) {
	    p->next = head;
	    head = p;
	    num_ent++;
	}
    }
    if (num_ent > 0) {
	ar = (struct ent **) ap_palloc(r->pool,
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
    output_directories(ar, num_ent, autoindex_conf, r, autoindex_opts, keyid,
		       direction);
    ap_pclosedir(r->pool, d);

    if ((tmp = find_readme(autoindex_conf, r))) {
	if (!insert_readme(name, tmp, "",
			   ((autoindex_opts & FANCY_INDEXING) ? HRULE
			                                      : NO_HRULE),
			   END_MATTER, r)) {
	    ap_rputs(ap_psignature("<HR>\n", r), r);
	}
    }
    ap_rputs("</BODY></HTML>\n", r);

    ap_kill_timeout(r);
    return 0;
}

/* The formal handler... */

static int handle_autoindex(request_rec *r)
{
    autoindex_config_rec *d;
    int allow_opts = ap_allow_options(r);

    d = (autoindex_config_rec *) ap_get_module_config(r->per_dir_config,
						      &autoindex_module);

    r->allowed |= (1 << M_GET);
    if (r->method_number != M_GET) {
	return DECLINED;
    }

    /* OK, nothing easy.  Trot out the heavy artillery... */

    if (allow_opts & OPT_INDEXES) {
	/* KLUDGE --- make the sub_req lookups happen in the right directory.
	 * Fixing this in the sub_req_lookup functions themselves is difficult,
	 * and would probably break virtual includes...
	 */

	if (r->filename[strlen(r->filename) - 1] != '/') {
	    r->filename = ap_pstrcat(r->pool, r->filename, "/", NULL);
	}
	return index_directory(r, d);
    }
    else {
	ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
		     "Directory index forbidden by rule: %s", r->filename);
	return HTTP_FORBIDDEN;
    }
}


static const handler_rec autoindex_handlers[] =
{
    {DIR_MAGIC_TYPE, handle_autoindex},
    {NULL}
};

module MODULE_VAR_EXPORT autoindex_module =
{
    STANDARD_MODULE_STUFF,
    NULL,			/* initializer */
    create_autoindex_config,	/* dir config creater */
    merge_autoindex_configs,	/* dir merger --- default is to override */
    NULL,			/* server config */
    NULL,			/* merge server config */
    autoindex_cmds,		/* command table */
    autoindex_handlers,		/* handlers */
    NULL,			/* filename translation */
    NULL,			/* check_user_id */
    NULL,			/* check auth */
    NULL,			/* check access */
    NULL,			/* type_checker */
    NULL,			/* fixups */
    NULL,			/* logger */
    NULL,			/* header parser */
    NULL,			/* child_init */
    NULL,			/* child_exit */
    NULL			/* post read-request */
};
