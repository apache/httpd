/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000-2004 The Apache Software Foundation.  All rights
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
 * This imagemap module started as a port of the original imagemap.c
 * written by Rob McCool (11/13/93 robm@ncsa.uiuc.edu).
 * This version includes the mapping algorithms found in version 1.3
 * of imagemap.c.
 *
 * Contributors to this code include:
 *
 * Kevin Hughes, kevinh@pulua.hcc.hawaii.edu
 *
 * Eric Haines, erich@eye.com
 * "macmartinized" polygon code copyright 1992 by Eric Haines, erich@eye.com
 *
 * Randy Terbush, randy@zyzzyva.com
 * port to Apache module format, "base_uri" and support for relative URLs
 * 
 * James H. Cloos, Jr., cloos@jhcloos.com
 * Added point datatype, using code in NCSA's version 1.8 imagemap.c
 * program, as distributed with version 1.4.1 of their server.
 * The point code is originally added by Craig Milo Rogers, Rogers@ISI.Edu
 *
 * Nathan Kurz, nate@tripod.com
 * Rewrite/reorganization.  New handling of default, base and relative URLs.  
 * New Configuration directives:
 *    ImapMenu {none, formatted, semiformatted, unformatted}
 *    ImapDefault {error, nocontent, referer, menu, URL}
 *    ImapBase {map, referer, URL}
 * Support for creating non-graphical menu added.  (backwards compatible):
 *    Old:  directive URL [x,y ...]
 *    New:  directive URL "Menu text" [x,y ...]
 *     or:  directive URL x,y ... "Menu text"
 * Map format and menu concept courtesy Joshua Bell, jsbell@acs.ucalgary.ca.
 *
 * Mark Cox, mark@ukweb.com, Allow relative URLs even when no base specified
 */

#include "httpd.h"
#include "http_config.h"
#include "http_request.h"
#include "http_core.h"
#include "http_protocol.h"
#include "http_main.h"
#include "http_log.h"
#include "util_script.h"

#define IMAP_MAGIC_TYPE "application/x-httpd-imap"
#define MAXVERTS 100
#define X 0
#define Y 1

#define IMAP_MENU_DEFAULT "formatted"
#define IMAP_DEFAULT_DEFAULT "nocontent"
#define IMAP_BASE_DEFAULT "map"

#ifdef SUNOS4
double strtod();                /* SunOS needed this */
#endif

module MODULE_VAR_EXPORT imap_module;

typedef struct {
    char *imap_menu;
    char *imap_default;
    char *imap_base;
} imap_conf_rec;

static void *create_imap_dir_config(pool *p, char *dummy)
{
    imap_conf_rec *icr =
    (imap_conf_rec *) ap_palloc(p, sizeof(imap_conf_rec));

    icr->imap_menu = NULL;
    icr->imap_default = NULL;
    icr->imap_base = NULL;

    return icr;
}

static void *merge_imap_dir_configs(pool *p, void *basev, void *addv)
{
    imap_conf_rec *new = (imap_conf_rec *) ap_pcalloc(p, sizeof(imap_conf_rec));
    imap_conf_rec *base = (imap_conf_rec *) basev;
    imap_conf_rec *add = (imap_conf_rec *) addv;

    new->imap_menu = add->imap_menu ? add->imap_menu : base->imap_menu;
    new->imap_default = add->imap_default ? add->imap_default
                                          : base->imap_default;
    new->imap_base = add->imap_base ? add->imap_base : base->imap_base;

    return new;
}


static const command_rec imap_cmds[] =
{
    {"ImapMenu", ap_set_string_slot,
     (void *) XtOffsetOf(imap_conf_rec, imap_menu), OR_INDEXES, TAKE1,
 "the type of menu generated: none, formatted, semiformatted, unformatted"},
    {"ImapDefault", ap_set_string_slot,
     (void *) XtOffsetOf(imap_conf_rec, imap_default), OR_INDEXES, TAKE1,
     "the action taken if no match: error, nocontent, referer, menu, URL"},
    {"ImapBase", ap_set_string_slot,
     (void *) XtOffsetOf(imap_conf_rec, imap_base), OR_INDEXES, TAKE1,
     "the base for all URL's: map, referer, URL (or start of)"},
    {NULL}
};

static int pointinrect(const double point[2], double coords[MAXVERTS][2])
{
    double max[2], min[2];
    if (coords[0][X] > coords[1][X]) {
        max[0] = coords[0][X];
        min[0] = coords[1][X];
    }
    else {
        max[0] = coords[1][X];
        min[0] = coords[0][X];
    }

    if (coords[0][Y] > coords[1][Y]) {
        max[1] = coords[0][Y];
        min[1] = coords[1][Y];
    }
    else {
        max[1] = coords[1][Y];
        min[1] = coords[0][Y];
    }

    return ((point[X] >= min[0] && point[X] <= max[0]) &&
            (point[Y] >= min[1] && point[Y] <= max[1]));
}

static int pointincircle(const double point[2], double coords[MAXVERTS][2])
{
    double radius1, radius2;

    radius1 = ((coords[0][Y] - coords[1][Y]) * (coords[0][Y] - coords[1][Y]))
        + ((coords[0][X] - coords[1][X]) * (coords[0][X] - coords[1][X]));

    radius2 = ((coords[0][Y] - point[Y]) * (coords[0][Y] - point[Y]))
        + ((coords[0][X] - point[X]) * (coords[0][X] - point[X]));

    return (radius2 <= radius1);
}

#define fmin(a,b) (((a)>(b))?(b):(a))
#define fmax(a,b) (((a)>(b))?(a):(b))

static int pointinpoly(const double point[2], double pgon[MAXVERTS][2])
{
    int i, numverts, crossings = 0;
    double x = point[X], y = point[Y];

    for (numverts = 0; pgon[numverts][X] != -1 && numverts < MAXVERTS;
	numverts++) {
	/* just counting the vertexes */
    }

    for (i = 0; i < numverts; i++) {
        double x1=pgon[i][X];
        double y1=pgon[i][Y];
        double x2=pgon[(i + 1) % numverts][X];
        double y2=pgon[(i + 1) % numverts][Y];
        double d=(y - y1) * (x2 - x1) - (x - x1) * (y2 - y1);

        if ((y1 >= y) != (y2 >= y)) {
	    crossings +=y2 - y1 >= 0 ? d >= 0 : d <= 0;
	}
        if (!d && fmin(x1,x2) <= x && x <= fmax(x1,x2)
	    && fmin(y1,y2) <= y && y <= fmax(y1,y2)) {
	    return 1;
	}
    }
    return crossings & 0x01;
}


static int is_closer(const double point[2], double coords[MAXVERTS][2],
                     double *closest)
{
    double dist_squared = ((point[X] - coords[0][X])
                           * (point[X] - coords[0][X]))
                          + ((point[Y] - coords[0][Y])
                             * (point[Y] - coords[0][Y]));

    if (point[X] < 0 || point[Y] < 0) {
        return (0);          /* don't mess around with negative coordinates */
    }

    if (*closest < 0 || dist_squared < *closest) {
        *closest = dist_squared;
        return (1);          /* if this is the first point or is the closest yet
                                set 'closest' equal to this distance^2 */
    }

    return (0);              /* if it's not the first or closest */

}

static double get_x_coord(const char *args)
{
    char *endptr;               /* we want it non-null */
    double x_coord = -1;        /* -1 is returned if no coordinate is given */

    if (args == NULL) {
        return (-1);            /* in case we aren't passed anything */
    }

    while (*args && !ap_isdigit(*args) && *args != ',') {
        args++;                 /* jump to the first digit, but not past
                                   a comma or end */
    }

    x_coord = strtod(args, &endptr);

    if (endptr > args) {        /* if a conversion was made */
        return (x_coord);
    }

    return (-1);                /* else if no conversion was made,
                                   or if no args was given */
}

static double get_y_coord(const char *args)
{
    char *endptr;               /* we want it non-null */
    char *start_of_y = NULL;
    double y_coord = -1;        /* -1 is returned on error */

    if (args == NULL) {
        return (-1);            /* in case we aren't passed anything */
    }

    start_of_y = strchr(args, ',');     /* the comma */

    if (start_of_y) {

        start_of_y++;           /* start looking at the character after
                                   the comma */

        while (*start_of_y && !ap_isdigit(*start_of_y)) {
            start_of_y++;       /* jump to the first digit, but not
                                   past the end */
	}

        y_coord = strtod(start_of_y, &endptr);

        if (endptr > start_of_y) {
            return (y_coord);
	}
    }

    return (-1);                /* if no conversion was made, or
                                   no comma was found in args */
}


/* See if string has a "quoted part", and if so set *quoted_part to
 * the first character of the quoted part, then hammer a \0 onto the
 * trailing quote, and set *string to point at the first character
 * past the second quote.
 *
 * Otherwise set *quoted_part to NULL, and leave *string alone.
 */
static void read_quoted(char **string, char **quoted_part)
{
    char *strp = *string;

    /* assume there's no quoted part */
    *quoted_part = NULL;

    while (ap_isspace(*strp)) {
        strp++;               	/* go along string until non-whitespace */
    }

    if (*strp == '"') {       	/* if that character is a double quote */
        strp++;               	/* step over it */
	*quoted_part = strp;  	/* note where the quoted part begins */

        while (*strp && *strp != '"') {
	    ++strp;		/* skip the quoted portion */
        }

        *strp = '\0';    	/* end the string with a NUL */

        strp++;               	/* step over the last double quote */
	*string = strp;
    }
}

/*
 * returns the mapped URL or NULL.
 */
static char *imap_url(request_rec *r, const char *base, const char *value)
{
/* translates a value into a URL. */
    int slen, clen;
    char *string_pos = NULL;
    const char *string_pos_const = NULL;
    char *directory = NULL;
    const char *referer = NULL;
    char *my_base;

    if (!strcasecmp(value, "map") || !strcasecmp(value, "menu")) {
	return ap_construct_url(r->pool, r->uri, r);
    }

    if (!strcasecmp(value, "nocontent") || !strcasecmp(value, "error")) {
        return ap_pstrdup(r->pool, value);      /* these are handled elsewhere,
                                                so just copy them */
    }

    if (!strcasecmp(value, "referer")) {
        referer = ap_table_get(r->headers_in, "Referer");
        if (referer && *referer) {
	    return ap_pstrdup(r->pool, referer);
        }
        else {
	    /* XXX:  This used to do *value = '\0'; ... which is totally bogus
	     * because it hammers the passed in value, which can be a string
             * constant, or part of a config, or whatever.  Total garbage.
             * This works around that without changing the rest of this
             * code much
             */
            value = "";      /* if 'referer' but no referring page,
                                null the value */
        }
    }

    string_pos_const = value;
    while (ap_isalpha(*string_pos_const)) {
	string_pos_const++;           /* go along the URL from the map
                                         until a non-letter */
    }
    if (*string_pos_const == ':') {
	/* if letters and then a colon (like http:) */
	/* it's an absolute URL, so use it! */
	return ap_pstrdup(r->pool, value);
    }

    if (!base || !*base) {
        if (value && *value) {
	    return ap_pstrdup(r->pool, value); /* no base: use what is given */
        }
	/* no base, no value: pick a simple default */
	return ap_construct_url(r->pool, "/", r);
    }

    /* must be a relative URL to be combined with base */
    if (strchr(base, '/') == NULL && (!strncmp(value, "../", 3)
        || !strcmp(value, ".."))) {
        ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
                    "invalid base directive in map file: %s", r->uri);
        return NULL;
    }
    my_base = ap_pstrdup(r->pool, base);
    string_pos = my_base;
    while (*string_pos) {
        if (*string_pos == '/' && *(string_pos + 1) == '/') {
            string_pos += 2;    /* if there are two slashes, jump over them */
            continue;
        }
        if (*string_pos == '/') {       /* the first single slash */
            if (value[0] == '/') {
                *string_pos = '\0';
            }                   /* if the URL from the map starts from root,
                                   end the base URL string at the first single
                                   slash */
            else {
                directory = string_pos;         /* save the start of
                                                   the directory portion */

                string_pos = strrchr(string_pos, '/');  /* now reuse
                                                           string_pos */
                string_pos++;   /* step over that last slash */
                *string_pos = '\0';
            }                   /* but if the map url is relative, leave the
                                   slash on the base (if there is one) */
            break;
        }
        string_pos++;           /* until we get to the end of my_base without
                                   finding a slash by itself */
    }

    while (!strncmp(value, "../", 3) || !strcmp(value, "..")) {

        if (directory && (slen = strlen(directory))) {

            /* for each '..',  knock a directory off the end 
               by ending the string right at the last slash.
               But only consider the directory portion: don't eat
               into the server name.  And only try if a directory
               portion was found */

            clen = slen - 1;

            while ((slen - clen) == 1) {

                if ((string_pos = strrchr(directory, '/'))) {
                    *string_pos = '\0';
		}
                clen = strlen(directory);
                if (clen == 0) {
                    break;
		}
            }

            value += 2;         /* jump over the '..' that we found in the
                                   value */
        }
        else if (directory) {
            ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
                        "invalid directory name in map file: %s", r->uri);
            return NULL;
        }

        if (!strncmp(value, "/../", 4) || !strcmp(value, "/..")) {
            value++;            /* step over the '/' if there are more '..'
                                   to do.  This way, we leave the starting
                                   '/' on value after the last '..', but get
                                   rid of it otherwise */
	}

    }                           /* by this point, value does not start
                                   with '..' */

    if (value && *value) {
	return ap_pstrcat(r->pool, my_base, value, NULL);
    }
    return my_base;
}

static int imap_reply(request_rec *r, char *redirect)
{
    if (!strcasecmp(redirect, "error")) {
        return SERVER_ERROR;    /* they actually requested an error! */
    }
    if (!strcasecmp(redirect, "nocontent")) {
        return HTTP_NO_CONTENT; /* tell the client to keep the page it has */
    }
    if (redirect && *redirect) {
        ap_table_setn(r->headers_out, "Location", redirect);
        return REDIRECT;        /* must be a URL, so redirect to it */
    }
    return SERVER_ERROR;
}

static void menu_header(request_rec *r, char *menu)
{
    r->content_type = "text/html";
    ap_send_http_header(r);
#ifdef CHARSET_EBCDIC
    /* Server-generated response, converted */
    ap_bsetflag(r->connection->client, B_EBCDIC2ASCII, r->ebcdic.conv_out = 1);
#endif
    ap_hard_timeout("send menu", r);       /* killed in menu_footer */

    ap_rvputs(r, DOCTYPE_HTML_3_2, "<html><head>\n<title>Menu for ", r->uri,
           "</title>\n</head><body>\n", NULL);

    if (!strcasecmp(menu, "formatted")) {
        ap_rvputs(r, "<h1>Menu for ", r->uri, "</h1>\n<hr>\n\n", NULL);
    }

    return;
}

static void menu_blank(request_rec *r, char *menu)
{
    if (!strcasecmp(menu, "formatted")) {
        ap_rputs("\n", r);
    }
    if (!strcasecmp(menu, "semiformatted")) {
        ap_rputs("<br>\n", r);
    }
    if (!strcasecmp(menu, "unformatted")) {
        ap_rputs("\n", r);
    }
    return;
}

static void menu_comment(request_rec *r, char *menu, char *comment)
{
    if (!strcasecmp(menu, "formatted")) {
        ap_rputs("\n", r);         /* print just a newline if 'formatted' */
    }
    if (!strcasecmp(menu, "semiformatted") && *comment) {
        ap_rvputs(r, comment, "\n", NULL);
    }
    if (!strcasecmp(menu, "unformatted") && *comment) {
        ap_rvputs(r, comment, "\n", NULL);
    }
    return;                     /* comments are ignored in the
                                   'formatted' form */
}

static void menu_default(request_rec *r, char *menu, char *href, char *text)
{
    if (!strcasecmp(href, "error") || !strcasecmp(href, "nocontent")) {
        return;                 /* don't print such lines, these aren't
                                   really href's */
    }
    if (!strcasecmp(menu, "formatted")) {
        ap_rvputs(r, "<pre>(Default) <a href=\"", href, "\">", text,
               "</a></pre>\n", NULL);
    }
    if (!strcasecmp(menu, "semiformatted")) {
        ap_rvputs(r, "<pre>(Default) <a href=\"", href, "\">", text,
               "</a></pre>\n", NULL);
    }
    if (!strcasecmp(menu, "unformatted")) {
        ap_rvputs(r, "<a href=\"", href, "\">", text, "</a>", NULL);
    }
    return;
}

static void menu_directive(request_rec *r, char *menu, char *href, char *text)
{
    if (!strcasecmp(href, "error") || !strcasecmp(href, "nocontent")) {
        return;                 /* don't print such lines, as this isn't
                                   really an href */
    }
    if (!strcasecmp(menu, "formatted")) {
        ap_rvputs(r, "<pre>          <a href=\"", href, "\">", text,
               "</a></pre>\n", NULL);
    }
    if (!strcasecmp(menu, "semiformatted")) {
        ap_rvputs(r, "<pre>          <a href=\"", href, "\">", text,
               "</a></pre>\n", NULL);
    }
    if (!strcasecmp(menu, "unformatted")) {
        ap_rvputs(r, "<a href=\"", href, "\">", text, "</a>", NULL);
    }
    return;
}

static void menu_footer(request_rec *r)
{
    ap_rputs("\n\n</body>\n</html>\n", r);         /* finish the menu */
    ap_kill_timeout(r);
}

static int imap_handler(request_rec *r)
{
    char input[MAX_STRING_LEN];
    char *directive;
    char *value;
    char *href_text;
    char *base;
    char *redirect;
    char *mapdflt;
    char *closest = NULL;
    double closest_yet = -1;

    double testpoint[2];
    double pointarray[MAXVERTS + 1][2];
    int vertex;

    char *string_pos;
    int showmenu = 0;

    imap_conf_rec *icr = ap_get_module_config(r->per_dir_config, &imap_module);

    char *imap_menu = icr->imap_menu ? icr->imap_menu : IMAP_MENU_DEFAULT;
    char *imap_default = icr->imap_default
			    ?  icr->imap_default : IMAP_DEFAULT_DEFAULT;
    char *imap_base = icr->imap_base ? icr->imap_base : IMAP_BASE_DEFAULT;

    configfile_t *imap; 

    if (r->method_number != M_GET) {
	return DECLINED;
    }

    imap = ap_pcfg_openfile(r->pool, r->filename);

    if (!imap) {
        return NOT_FOUND;
    }

    base = imap_url(r, NULL, imap_base);         /* set base according
                                                    to default */
    if (!base) {
	return HTTP_INTERNAL_SERVER_ERROR;
    }
    mapdflt = imap_url(r, NULL, imap_default);   /* and default to
                                                    global default */
    if (!mapdflt) {
	return HTTP_INTERNAL_SERVER_ERROR;
    }

    testpoint[X] = get_x_coord(r->args);
    testpoint[Y] = get_y_coord(r->args);

    if ((testpoint[X] == -1 || testpoint[Y] == -1) ||
        (testpoint[X] == 0 && testpoint[Y] == 0)) {
        /* if either is -1 or if both are zero (new Lynx) */
        /* we don't have valid coordinates */
        testpoint[X] = -1;
        testpoint[Y] = -1;
        if (strncasecmp(imap_menu, "none", 2)) {
            showmenu = 1;       /* show the menu _unless_ ImapMenu is
                                   'none' or 'no' */
	}
    }

    if (showmenu) {             /* send start of imagemap menu if
                                   we're going to */
        menu_header(r, imap_menu);
    }

    while (!ap_cfg_getline(input, sizeof(input), imap)) {
        if (!input[0]) {
            if (showmenu) {
                menu_blank(r, imap_menu);
            }
            continue;
        }

        if (input[0] == '#') {
            if (showmenu) {
                menu_comment(r, imap_menu, input + 1);
            }
            continue;
        }                       /* blank lines and comments are ignored
                                   if we aren't printing a menu */

	/* find the first two space delimited fields, recall that
	 * ap_cfg_getline has removed leading/trailing whitespace.
	 *
	 * note that we're tokenizing as we go... if we were to use the
	 * ap_getword() class of functions we would end up allocating extra
	 * memory for every line of the map file
	 */
        string_pos = input;
	if (!*string_pos) {		/* need at least two fields */
	    goto need_2_fields;
	}

	directive = string_pos;
	while (*string_pos && !ap_isspace(*string_pos)) {	/* past directive */
	    ++string_pos;
	}
	if (!*string_pos) {		/* need at least two fields */
	    goto need_2_fields;
	}
	*string_pos++ = '\0';

	if (!*string_pos) {		/* need at least two fields */
	    goto need_2_fields;
	}
	while(*string_pos && ap_isspace(*string_pos)) { /* past whitespace */
	    ++string_pos;
	}

	value = string_pos;
	while (*string_pos && !ap_isspace(*string_pos)) {	/* past value */
	    ++string_pos;
	}
	if (ap_isspace(*string_pos)) {
	    *string_pos++ = '\0';
	}
	else {
	    /* end of input, don't advance past it */
	    *string_pos = '\0';
	}

        if (!strncasecmp(directive, "base", 4)) {       /* base, base_uri */
            base = imap_url(r, NULL, value);
	    if (!base) {
		goto menu_bail;
	    }
            continue;           /* base is never printed to a menu */
        }

        read_quoted(&string_pos, &href_text);

        if (!strcasecmp(directive, "default")) {        /* default */
            mapdflt = imap_url(r, NULL, value);
	    if (!mapdflt) {
		goto menu_bail;
	    }
            if (showmenu) {     /* print the default if there's a menu */
                redirect = imap_url(r, base, mapdflt);
		if (!redirect) {
		    goto menu_bail;
		}
                menu_default(r, imap_menu, redirect,
                             href_text ? href_text : mapdflt);
            }
            continue;
        }

        vertex = 0;
        while (vertex < MAXVERTS &&
               sscanf(string_pos, "%lf%*[, ]%lf",
                      &pointarray[vertex][X], &pointarray[vertex][Y]) == 2) {
            /* Now skip what we just read... we can't use ANSIism %n */
            while (ap_isspace(*string_pos)) {      /* past whitespace */
                string_pos++;
	    }
            while (ap_isdigit(*string_pos)) {      /* and the 1st number */
                string_pos++;
	    }
            string_pos++;       /* skip the ',' */
            while (ap_isspace(*string_pos)) {      /* past any more whitespace */
                string_pos++;
	    }
            while (ap_isdigit(*string_pos)) {      /* 2nd number */
                string_pos++;
	    }
            vertex++;
        }                       /* so long as there are more vertices to
                                   read, and we have room, read them in.
                                   We start where we left off of the last
                                   sscanf, not at the beginning. */

        pointarray[vertex][X] = -1;     /* signals the end of vertices */

        if (showmenu) {
	    if (!href_text) {
		read_quoted(&string_pos, &href_text);     /* href text could
                                                             be here instead */
	    }
            redirect = imap_url(r, base, value);
	    if (!redirect) {
		goto menu_bail;
	    }
            menu_directive(r, imap_menu, redirect,
                           href_text ? href_text : value);
            continue;
        }
        /* note that we don't make it past here if we are making a menu */

        if (testpoint[X] == -1 || pointarray[0][X] == -1) {
            continue;           /* don't try the following tests if testpoints
                                   are invalid, or if there are no
                                   coordinates */
	}

        if (!strcasecmp(directive, "poly")) {   /* poly */

            if (pointinpoly(testpoint, pointarray)) {
		ap_cfg_closefile(imap);
                redirect = imap_url(r, base, value);
		if (!redirect) {
		    return HTTP_INTERNAL_SERVER_ERROR;
		}
                return (imap_reply(r, redirect));
            }
            continue;
        }

        if (!strcasecmp(directive, "circle")) {         /* circle */

            if (pointincircle(testpoint, pointarray)) {
		ap_cfg_closefile(imap);
                redirect = imap_url(r, base, value);
		if (!redirect) {
		    return HTTP_INTERNAL_SERVER_ERROR;
		}
                return (imap_reply(r, redirect));
            }
            continue;
        }

        if (!strcasecmp(directive, "rect")) {   /* rect */

            if (pointinrect(testpoint, pointarray)) {
		ap_cfg_closefile(imap);
                redirect = imap_url(r, base, value);
		if (!redirect) {
		    return HTTP_INTERNAL_SERVER_ERROR;
		}
                return (imap_reply(r, redirect));
            }
            continue;
        }

        if (!strcasecmp(directive, "point")) {  /* point */

            if (is_closer(testpoint, pointarray, &closest_yet)) {
		closest = ap_pstrdup(r->pool, value);
            }

            continue;
        }                       /* move on to next line whether it's
                                   closest or not */

    }                           /* nothing matched, so we get another line! */

    ap_cfg_closefile(imap);        /* we are done with the map file; close it */

    if (showmenu) {
        menu_footer(r);         /* finish the menu and we are done */
        return OK;
    }

    if (closest) {             /* if a 'point' directive has been seen */
        redirect = imap_url(r, base, closest);
	if (!redirect) {
	    return HTTP_INTERNAL_SERVER_ERROR;
	}
        return (imap_reply(r, redirect));
    }

    if (mapdflt) {             /* a default should be defined, even if
                                  only 'nocontent' */
        redirect = imap_url(r, base, mapdflt);
	if (!redirect) {
	    return HTTP_INTERNAL_SERVER_ERROR;
	}
        return (imap_reply(r, redirect));
    }

    return HTTP_INTERNAL_SERVER_ERROR;        /* If we make it this far,
                                                 we failed. They lose! */

need_2_fields:
    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
		"map file %s, line %d syntax error: requires at "
                "least two fields", r->uri, imap->line_number);
    /* fall through */
menu_bail:
    ap_cfg_closefile(imap);
    if (showmenu) {
	/* There's not much else we can do ... we've already sent the headers
	 * to the client.
	 */
	ap_rputs("\n\n[an internal server error occured]\n", r);
	menu_footer(r);
	return OK;
    }
    return HTTP_INTERNAL_SERVER_ERROR;
}


static const handler_rec imap_handlers[] =
{
    {IMAP_MAGIC_TYPE, imap_handler},
    {"imap-file", imap_handler},
    {NULL}
};

module MODULE_VAR_EXPORT imap_module =
{
    STANDARD_MODULE_STUFF,
    NULL,                       /* initializer */
    create_imap_dir_config,     /* dir config creater */
    merge_imap_dir_configs,     /* dir merger --- default is to override */
    NULL,                       /* server config */
    NULL,                       /* merge server config */
    imap_cmds,                  /* command table */
    imap_handlers,              /* handlers */
    NULL,                       /* filename translation */
    NULL,                       /* check_user_id */
    NULL,                       /* check auth */
    NULL,                       /* check access */
    NULL,                       /* type_checker */
    NULL,                       /* fixups */
    NULL,                       /* logger */
    NULL,                       /* header parser */
    NULL,                       /* child_init */
    NULL,                       /* child_exit */
    NULL                        /* post read-request */
};
