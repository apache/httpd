
/* ====================================================================
 * Copyright (c) 1995 The Apache Group.  All rights reserved.
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
 *    prior written permission.
 *
 * 5. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the Apache Group
 *    for use in the Apache HTTP server project (http://www.apache.org/)."
 *
 * THIS SOFTWARE IS PROVIDED BY THE APACHE GROUP ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE APACHE GROUP OR
 * IT'S CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
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
#define LARGEBUF 500
#define SMALLBUF 100
#define MAXVERTS 100
#define X 0
#define Y 1

#define IMAP_MENU_DEFAULT "formatted"
#define IMAP_DEFAULT_DEFAULT "nocontent"
#define IMAP_BASE_DEFAULT "map"

#ifdef SUNOS4
double strtod();   /* SunOS needed this */
#endif

module imap_module;

typedef struct { 
  char *imap_menu;
  char *imap_default;
  char *imap_base;
} imap_conf_rec;

void *create_imap_dir_config (pool *p, char *dummy) { 
  imap_conf_rec *icr = 
    (imap_conf_rec *)palloc(p, sizeof(imap_conf_rec));

  icr->imap_menu = NULL;
  icr->imap_default = NULL;
  icr->imap_base = NULL;

  return icr;
}

void *merge_imap_dir_configs (pool *p, void *basev, void *addv)
{
  imap_conf_rec *new=(imap_conf_rec *)pcalloc (p, sizeof(imap_conf_rec));
  imap_conf_rec *base = (imap_conf_rec *)basev;
  imap_conf_rec *add = (imap_conf_rec *)addv;
 
  new->imap_menu = add->imap_menu ? add->imap_menu : base->imap_menu;
  new->imap_default=add->imap_default ? add->imap_default : base->imap_default;
  new->imap_base =add-> imap_base ? add->imap_base : base->imap_base;

  return new;
}


command_rec imap_cmds[] = {
{ "ImapMenu", set_string_slot, 
    (void*)XtOffsetOf(imap_conf_rec, imap_menu), OR_INDEXES, TAKE1,
    "the type of menu generated: none, formatted, semiformatted, unformatted"},
{ "ImapDefault", set_string_slot, 
    (void*)XtOffsetOf(imap_conf_rec, imap_default), OR_INDEXES, TAKE1,
    "the action taken if no match: error, nocontent, referer, menu, URL" },
{ "ImapBase", set_string_slot, 
    (void*)XtOffsetOf(imap_conf_rec, imap_base), OR_INDEXES, TAKE1,
    "the base for all URL's: map, referer, URL (or start of)" },
{ NULL }
};

int pointinrect(double point[2], double coords[MAXVERTS][2])
{
    double max[2], min[2];
    if (coords[0][X] > coords[1][X]) {
        max[0] = coords[0][X];
        min[0] = coords[1][X];
    } else {
        max[0] = coords[1][X];
        min[0] = coords[0][X];
    }

    if (coords[0][Y] > coords[1][Y]) {
        max[1] = coords[0][Y];
        min[1] = coords[1][Y];
    } else {
        max[1] = coords[1][Y];
        min[1] = coords[0][Y];
    }

    return ((point[X] >= min[0] && point[X] <= max[0]) &&
	    (point[Y] >= min[1] && point[Y] <= max[1]));
}

int pointincircle(double point[2], double coords[MAXVERTS][2])
{
    int radius1, radius2;

    radius1 = ((coords[0][Y] - coords[1][Y]) * (coords[0][Y] - coords[1][Y]))
	+ ((coords[0][X] - coords[1][X]) * (coords[0][X] - coords[1][X]));
    
    radius2 = ((coords[0][Y] - point[Y]) * (coords[0][Y] - point[Y]))
	+ ((coords[0][X] - point[X]) * (coords[0][X] - point[X]));

    return (radius2 <= radius1);
}

int pointinpoly(double point[2], double pgon[MAXVERTS][2])
{
    int i, numverts, inside_flag, xflag0;
    int crossings;
    double *p, *stop;
    double tx, ty, y;

    for (i = 0; pgon[i][X] != -1 && i < MAXVERTS; i++);

    numverts = i;
    crossings = 0;

    tx = point[X];
    ty = point[Y];
    y = pgon[numverts - 1][Y];

    p = (double *) pgon + 1;
    if ((y >= ty) != (*p >= ty)) {

	if ((xflag0 = (pgon[numverts - 1][X] >= tx)) == (*(double *) pgon >= tx)) {
	    if (xflag0)
		crossings++;
	}
	else {
	    crossings += (pgon[numverts - 1][X] - (y - ty) *
			  (*(double *) pgon - pgon[numverts - 1][X]) /
			  (*p - y)) >= tx;
	}
    }

    stop = pgon[numverts];

    for (y = *p, p += 2; p < stop; y = *p, p += 2) {
	
	if (y >= ty) {
        
	    while ((p < stop) && (*p >= ty))
		p += 2;
	    
	    if (p >= stop)
		break;
	    if ((xflag0 = (*(p - 3) >= tx)) == (*(p - 1) >= tx)) {
		
		if (xflag0)
		    crossings++;
	    }
	    else {
		crossings += (*(p - 3) - (*(p - 2) - ty) *
			      (*(p - 1) - *(p - 3)) / (*p - *(p - 2))) >= tx;
	    }
	}
	else {
	    while ((p < stop) && (*p < ty))
		p += 2;

	    if (p >= stop)
		break;

	    if ((xflag0 = (*(p - 3) >= tx)) == (*(p - 1) >= tx)) {
		if (xflag0)
		    crossings++;
	    }
	    else {
		crossings += (*(p - 3) - (*(p - 2) - ty) *
			      (*(p - 1) - *(p - 3)) / (*p - *(p - 2))) >= tx;
	    }
	}
    }

    inside_flag = crossings & 0x01;
    return (inside_flag);
}


int is_closer(double point[2], double coords[MAXVERTS][2], double *closest)
{
  double dist_squared =((point[X] - coords[0][X]) * (point[X] - coords[0][X]))
	     + ((point[Y] - coords[0][Y]) * (point[Y] - coords[0][Y]));

  if (point[X] < 0 || point[Y] < 0 ) 
    return(0);          /* don't mess around with negative coordinates */

  if ( *closest < 0 || dist_squared < *closest ) {
    *closest = dist_squared;
    return(1);         /* if this is the first point or is the closest yet
			  set 'closest' equal to this distance^2 */
  }
  
  return(0);           /* if it's not the first or closest */

}

double get_x_coord(char *args) 
{
  char *endptr;           /* we want it non-null */
  double x_coord = -1;    /* -1 is returned if no coordinate is given */

  if (args == NULL)
    return(-1);           /* in case we aren't passed anything */

  while( *args && !isdigit(*args) && *args != ',') 
    args++;   /* jump to the first digit, but not past a comma or end */

  x_coord = strtod(args, &endptr);

  if (endptr > args)   /* if a conversion was made */
    return(x_coord); 

  return(-1);  /* else if no conversion was made, or if no args was given */
}

double get_y_coord(char *args) 
{
  char *endptr;        /* we want it non-null */
  char *start_of_y = NULL;
  double y_coord = -1;    /* -1 is returned on error */

  if (args == NULL)
    return(-1);           /* in case we aren't passed anything */

  start_of_y = strchr(args, ',');  /* the comma */

  if (start_of_y) {
    
    start_of_y++;    /* start looking at the character after the comma */

    while( *start_of_y && !isdigit(*start_of_y))  
      start_of_y++;  /* jump to the first digit, but not past the end */

    y_coord = strtod(start_of_y, &endptr);

    if (endptr > start_of_y) 
      return(y_coord); 
  }
  
  return(-1);   /* if no conversion was made, or no comma was found in args */
}
  

int read_quoted(char *string, char *quoted_part)
{ 
  char *starting_pos = string;
  
  while ( isspace(*string) )
    string++;    /* go along string until non-whitespace */

  if ( *string == '"' ) { /* if that character is a double quote */

    string++;  /* step over it */

    while ( *string && *string != '"' ) {
      *quoted_part++ = *string++;  /* copy the quoted portion */
    }

    *quoted_part = '\0';  /* end the string with a SNUL */
	
    string++;  /* step over the last double quote */
  }

  return(string - starting_pos); /* return the total characters read */
}


void imap_url(request_rec *r, char *base, char *value, char *url) 
{
/* translates a value into a URL. */
  int slen, clen;
  char *string_pos = NULL;
  char *directory = NULL;
  char *referer = NULL;
  char my_base[SMALLBUF] = {'\0'};

  if ( ! strcasecmp(value, "map" ) || ! strcasecmp(value, "menu") ) {
    if (r->server->port == 80 ) { 
      sprintf(url, "http://%s%s", r->server->server_hostname, r->uri);
    }
    else {
      sprintf(url, "http://%s:%d%s", r->server->server_hostname,
	      r->server->port, r->uri);      
    }
    return;  
  }

  if ( ! strcasecmp(value, "nocontent") || ! strcasecmp(value, "error") ) {
    strcpy(url, value);
    return;    /* these are handled elsewhere, so just copy them */
  }

  if ( ! strcasecmp(value, "referer" ) ) {
    referer = table_get(r->headers_in, "Referer");
    if ( referer && *referer ) {
      strcpy(url, referer);
      return;
    }
    else {
      *value = '\0';  /* if 'referer' but no referring page, null the value */
    }                 
  }         

  string_pos = value;
  while ( isalpha(*string_pos) )
    string_pos++;    /* go along the URL from the map until a non-letter */
  if ( *string_pos == ':' ) { 
    strcpy(url, value);        /* if letters and then a colon (like http:) */
    return;                    /* it's an absolute URL, so use it! */
  }

  if ( ! base || ! *base ) {
    if ( value && *value ) {  
      strcpy(url, value);   /* no base: use what is given */
    }         
    else {                  
      if (r->server->port == 80 ) {  
	sprintf(url, "http://%s/", r->server->server_hostname);
      }            
      if (r->server->port != 80 ) {
	sprintf(url, "http://%s:%d/", r->server->server_hostname, 
		r->server->port);
      }                     /* no base, no value: pick a simple default */
    }
    return;  
  }

  strcpy(my_base, base);  /* must be a relative URL to be combined with base */
  string_pos = my_base; 
  while (*string_pos) {  
    if (*string_pos == '/' && *(string_pos+1) == '/') {
      string_pos += 2;  /* if there are two slashes, jump over them */
      continue;
    }
    if (*string_pos == '/') {  /* the first single slash */
	if ( value[0] == '/' ) {
	  *string_pos = '\0';  
	}              /* if the URL from the map starts from root, end the
			  base URL string at the first single slash */
	else {
	  directory = string_pos; /* save the start of the directory portion */

	  string_pos = strrchr(string_pos, '/');  /* now reuse string_pos */
	  string_pos++;  /* step over that last slash */
	  *string_pos = '\0';
	}              /* but if the map url is relative, leave the
			slash on the base (if there is one) */
	break;
      }
    string_pos++;   /* until we get to the end of my_base without finding
		       a slash by itself */
  }

  while ( ! strncmp(value, "../", 3) || ! strcmp(value, "..") ) { 

      if (directory && (slen = strlen (directory))) {

	  /* for each '..',  knock a directory off the end 
	     by ending the string right at the last slash.
	     But only consider the directory portion: don't eat
	     into the server name.  And only try if a directory
	     portion was found */    
	  
	  clen = slen - 1;
	
	  while ((slen - clen) == 1) {
	
	      if ((string_pos = strrchr(directory, '/')))
		  *string_pos = '\0';
	      clen = strlen (directory);
	      if (clen == 0) break;
	  }

	  value += 2;      /* jump over the '..' that we found in the value */
      }
      
      if (! strncmp(value, "/../", 4) || ! strcmp(value, "/..") )

	  value++;       /* step over the '/' if there are more '..' to do.
			   this way, we leave the starting '/' on value after
			   the last '..', but get rid of it otherwise */ 
     
  }                   /* by this point, value does not start with '..' */

  if ( value && *value ) {
    sprintf(url, "%s%s", my_base, value);   
  }
  else {
    sprintf(url, "%s", my_base);   
  }
  return;
}

int imap_reply(request_rec *r, char *redirect)
{ 
  if ( ! strcasecmp(redirect, "error") ) {
    return SERVER_ERROR;  /* they actually requested an error! */
  }
  if ( ! strcasecmp(redirect, "nocontent") ) {
    r->status_line = pstrdup(r->pool, "204 No Content");
    soft_timeout ("send no content", r);
    send_http_header(r);
    return OK;            /* tell the client to keep the page it has */
  }
  if (redirect && *redirect ) { 
    table_set(r->headers_out, "Location", redirect);
    return REDIRECT;      /* must be a URL, so redirect to it */
  }    
  return SERVER_ERROR;
}

void menu_header(request_rec *r, char *menu)
{
  if (! strcasecmp(menu, "formatted")) {
    r->content_type = "text/html";
    soft_timeout ("send menu", r);
    send_http_header(r);
    rvputs(r, "<html>\n<head><title>Menu for ", r->uri,
	   "</title></head>\n\n<body>\n", NULL);
    rvputs(r, "<h1>Menu for ", r->uri, "</h1>\n<hr>\n\n", NULL);
  } 
  if (! strcasecmp(menu, "semiformatted")) {
    r->content_type = "text/html";
    soft_timeout ("send menu", r);
    send_http_header(r);
    rvputs(r, "<html>\n<head><title>Menu for ", r->uri,
	   "</title></head>\n\n<body>\n", NULL);
  } 
  if (! strcasecmp(menu, "unformatted")) {
    r->content_type = "text/html";
    soft_timeout ("send menu", r);
    send_http_header(r);
    rvputs(r, "<html>\n<head><title>Menu for ", r->uri,
	   "</title></head>\n\n<body>\n", NULL);
  }
  return;
}

void menu_blank(request_rec *r, char *menu)
{
  if (! strcasecmp(menu, "formatted") ) {
    rputs("\n", r);
  }
  if (! strcasecmp(menu, "semiformatted") ) {
    rputs("<br>\n", r);
  }
  if (! strcasecmp(menu, "unformatted") ) {
    rputs("\n", r);  
  }
  return;  
}

void menu_comment(request_rec *r, char *menu, char *comment)
{
  if (! strcasecmp(menu, "formatted") ) {
    rputs("\n", r);  /* print just a newline if 'formatted' */
  }
  if (! strcasecmp(menu, "semiformatted") && *comment ) {
    rvputs(r, comment, "\n", NULL);
  }             
  if (! strcasecmp(menu, "unformatted") && *comment ) {
    rvputs(r, comment, "\n", NULL);
  }             
  return;    /* comments are ignored in the 'formatted' form */
}

void menu_default(request_rec *r, char *menu, char *href, char *text)
{
  if ( ! strcasecmp(href, "error") || ! strcasecmp(href, "nocontent") ) {
    return;   /* don't print such lines, these aren'te really href's */
  }
  if ( ! strcasecmp(menu, "formatted" ) ) {
    rvputs(r, "<pre>(Default) <a href=\"", href, "\">", text, "</a></pre>\n",
	   NULL);
  }
  if ( ! strcasecmp(menu, "semiformatted" ) ) {
    rvputs(r, "<pre>(Default) <a href=\"", href, "\">", text, "</a></pre>\n",
	   NULL);
  }
  if ( ! strcasecmp(menu, "unformatted" ) ) {
    rvputs(r, "<a href=\"", href, "\">", text, "</a>", NULL);
  }
  return;
}

void menu_directive(request_rec *r, char *menu, char *href, char *text)
{
  if ( ! strcasecmp(href, "error") || ! strcasecmp(href, "nocontent") ) {
    return;   /* don't print such lines, as this isn't really an href */
  }
  if ( ! strcasecmp(menu, "formatted" ) ) {
    rvputs(r, "<pre>          <a href=\"", href, "\">", text, "</a></pre>\n",
	   NULL);
  }
  if ( ! strcasecmp(menu, "semiformatted" ) ) {
    rvputs(r, "<pre>          <a href=\"", href, "\">", text, "</a></pre>\n",
	   NULL);
  }
  if ( ! strcasecmp(menu, "unformatted" ) ) {
    rvputs(r, "<a href=\"", href, "\">", text, "</a>", NULL);
  }
  return;
}

void menu_footer(request_rec *r)
{
  rputs("\n\n</body>\n</html>\n", r);  /* finish the menu */
}

int imap_handler(request_rec *r)
{
  char input[LARGEBUF] = {'\0'};
  char href_text[SMALLBUF] = {'\0'};
  char base[SMALLBUF] = {'\0'};
  char redirect[SMALLBUF] = {'\0'};
  char directive[SMALLBUF] = {'\0'};
  char value[SMALLBUF] = {'\0'};
  char mapdflt[SMALLBUF] = {'\0'};
  char closest[SMALLBUF] = {'\0'};
  double closest_yet = -1;

  double testpoint[2] = { -1,-1 }; 
  double pointarray[MAXVERTS + 1][2] = { {-1,-1} };
  int vertex = 0;

  char *string_pos = NULL;
  int chars_read = 0;
  int showmenu = 0;

  imap_conf_rec *icr = get_module_config(r->per_dir_config, &imap_module);

  char *imap_menu = icr->imap_menu ? 
    icr->imap_menu : IMAP_MENU_DEFAULT;
  char *imap_default = icr->imap_default ? 
    icr->imap_default : IMAP_DEFAULT_DEFAULT;
  char *imap_base = icr->imap_base ?
    icr->imap_base : IMAP_BASE_DEFAULT;

  FILE *imap = pfopen(r->pool, r->filename, "r"); 

  if ( ! imap ) 
    return NOT_FOUND;

  imap_url(r, NULL, imap_base, base);       /* set base according to default */
  imap_url(r, NULL, imap_default, mapdflt); /* and default to global default */

  testpoint[X] = get_x_coord(r->args);
  testpoint[Y] = get_y_coord(r->args);

  if ((testpoint[X] == -1 || testpoint[Y] == -1) ||
      (testpoint[X] == 0  && testpoint[Y] == 0) ) {
              /* if either is -1 or if both are zero (new Lynx) */
              /* we don't have valid coordinates */
    testpoint[X] = -1;
    testpoint[Y] = -1;
    if ( strncasecmp(imap_menu, "none", 2) )
      showmenu = 1;    /* show the menu _unless_ ImapMenu is 'none' or 'no' */
  }

  if (showmenu) {        /* send start of imagemap menu if we're going to */
    menu_header(r, imap_menu);
  }

  while (!cfg_getline(input, LARGEBUF, imap)) {
    string_pos = input;   /* always start at the beginning of line */

    directive[0] = '\0';
    value[0] = '\0';  
    href_text[0] = '\0';
    redirect[0] = '\0';
    chars_read = 0; /* clear these before using */

    if ( ! input[0] ) {     
      if (showmenu) {
	menu_blank(r, imap_menu);
      }
      continue;                           
    }

    if ( input[0] == '#' ) {
      if (showmenu) {
	menu_comment(r, imap_menu, input + 1); 
      }           
      continue;
    } /* blank lines and comments are ignored if we aren't printing a menu */


    if (sscanf(input, "%s %s", directive, value) != 2) {
      continue;                           /* make sure we read two fields */
    }
    /* Now skip what we just read... we can't use ANSIism %n */
    while (!(isspace(*string_pos)))	/* past directive */
	string_pos++;
    while (isspace(*string_pos))	/* and whitespace */
	string_pos++;
    while (!(isspace(*string_pos)))	/* and value... have to watch it */
	string_pos++;			/* can have punctuation and stuff */
    
    if ( ! strncasecmp(directive, "base", 4 ) ) {       /* base, base_uri */
      imap_url(r, NULL, value, base);
      continue; /* base is never printed to a menu */
    }	

    chars_read = read_quoted(string_pos, href_text);
    string_pos += chars_read;      /* read the quoted href text if present */

    if ( ! strcasecmp(directive, "default" ) ) {        /* default */
      imap_url(r, NULL, value, mapdflt);
      if (showmenu) {              /* print the default if there's a menu */
	if (! *href_text) {           /* if we didn't find a "href text" */
	  strcpy(href_text, mapdflt); /* use the href itself as text */
	}
	imap_url(r, base, mapdflt, redirect); 
	menu_default(r, imap_menu, redirect, href_text);
      }
      continue;
    }

    vertex = 0;
    while ( vertex < MAXVERTS &&  
     sscanf(string_pos, "%lf,%lf",
     &pointarray[vertex][X], &pointarray[vertex][Y])   == 2)
    {
	/* Now skip what we just read... we can't use ANSIism %n */
	while(isspace(*string_pos))	/* past whitespace */
	    string_pos++;
	while(isdigit(*string_pos))	/* and the 1st number */
	    string_pos++;
	string_pos++;			/* skip the ',' */
	while(isdigit(*string_pos))	/* 2nd number */
	    string_pos++;
	vertex++;
    }                /* so long as there are more vertices to read, and
			we have room, read them in.  We start where we left
			off of the last sscanf, not at the beginning.*/
                  
    pointarray[vertex][X] = -1;  /* signals the end of vertices */

    if (showmenu) {
      read_quoted(string_pos, href_text); /* href text could be here instead */
      if (! *href_text) {           /* if we didn't find a "href text" */
	strcpy(href_text, value);  /* use the href itself in the menu */
      }
      imap_url(r, base, value, redirect); 
      menu_directive(r, imap_menu, redirect, href_text);
      continue;
    }
    /* note that we don't make it past here if we are making a menu */

    if (testpoint[X] == -1 || pointarray[0][X] == -1 )
      continue;    /* don't try the following tests if testpoints
		    are invalid, or if there are no coordinates */

    if ( ! strcasecmp(directive, "poly" ) ) {        /* poly */

      if (pointinpoly (testpoint, pointarray) ) {
	pfclose(r->pool, imap); 
	imap_url(r, base, value, redirect);     
	return (imap_reply(r, redirect));
      }
      continue;
    }

    if ( ! strcasecmp(directive, "circle" ) ) {        /* circle */
	
      if (pointincircle (testpoint, pointarray) ) {
	pfclose(r->pool, imap); 
	imap_url(r, base, value, redirect);     
	return (imap_reply(r, redirect));
      }
      continue;
    }
    
    if ( ! strcasecmp(directive, "rect" ) ) {        /* rect */
      
      if (pointinrect (testpoint, pointarray) ) {
	pfclose(r->pool, imap); 
	imap_url(r, base, value, redirect);     
	return (imap_reply(r, redirect));
      }
      continue;
    }
    
    if ( ! strcasecmp(directive, "point" ) ) {         /* point */
      
      if (is_closer(testpoint, pointarray, &closest_yet) ) {
	strcpy(closest, value);  /* if the closest point yet save it */
      }
      
      continue;    
    }     /* move on to next line whether it's closest or not */
    
  }       /* nothing matched, so we get another line! */

  pfclose(r->pool, imap);   /* we are done with the map file, so close it */

  if (showmenu) {
    menu_footer(r);   /* finish the menu and we are done */
    return OK;                
  }

  if (*closest) {    /* if a 'point' directive has been seen */
    imap_url(r, base, closest, redirect);     
    return (imap_reply(r, redirect));
  }    

  if (*mapdflt ) {   /* a default should be defined, even if only 'nocontent'*/
    imap_url(r, base, mapdflt, redirect);
    return(imap_reply(r, redirect));
  }    

  return SERVER_ERROR;   /* If we make it this far, we failed. They lose! */
}


handler_rec imap_handlers[] = {
{ IMAP_MAGIC_TYPE, imap_handler },
{ "imap-file", imap_handler },
{ NULL }
};

module imap_module = {
   STANDARD_MODULE_STUFF,
   NULL,			/* initializer */
   create_imap_dir_config,	/* dir config creater */
   merge_imap_dir_configs,	/* dir merger --- default is to override */
   NULL,			/* server config */
   NULL,			/* merge server config */
   imap_cmds,			/* command table */
   imap_handlers,		/* handlers */
   NULL,			/* filename translation */
   NULL,			/* check_user_id */
   NULL,			/* check auth */
   NULL,			/* check access */
   NULL,			/* type_checker */
   NULL,			/* fixups */
   NULL				/* logger */
};
