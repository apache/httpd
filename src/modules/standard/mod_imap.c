
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
 * This imagemap module is essentially a port of the original imagemap.c
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
#define MAXLINE 500
#define MAXVERTS 100
#define X 0
#define Y 1

char *getline(char *, int, FILE *);

module imap_module;

int pointinrect(double point[2], double coords[MAXVERTS][2])
{
    return ((point[X] >= coords[0][X] && point[X] <= coords[1][X]) &&
	    (point[Y] >= coords[0][Y] && point[Y] <= coords[1][Y]));
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


void set_redirect (request_rec *r, char *base_uri, char *mapurl) {

    char redirect[MAXLINE];
    char rooturl[80];
    char port[40];
    char *basedir;
    char *u,*b,*q;
    int k;

    server_rec *s = r->server;

    if (s->port != 80) {

	sprintf (port, "%d", s->port);
	sprintf (rooturl, "http://%s:%s", s->server_hostname, port);
    }
    else {

	sprintf (rooturl, "http://%s", s->server_hostname);
    }

    if ((!strncmp (mapurl, "http:", 5 )) ||
	!strncmp (mapurl, "mailto:", 7) ||
	!strncmp (mapurl, "ftp:", 4) ||
	!strncmp (mapurl, "telnet:", 7) ||
	!strncmp (mapurl, "news:", 5)) {

	strcpy (redirect, mapurl);
    }
    else if (*base_uri)  {

	while ((u = strstr (mapurl, "..")) != NULL) {
	    
	    if ((k = strlen(u)) > 3) {
		mapurl = u + 3;
	    }
	    else {
		mapurl = u + k;
	    }
	    
	    b = strrchr (base_uri, '/');
	    *b = '\0';
	}
	
	b = strrchr (base_uri, '/'); b++;
	*b = '\0';

	sprintf (redirect, "%s%s", base_uri, mapurl);
    }
    else if (mapurl[0] == '/') {
	
	sprintf (redirect, "%s%s", rooturl, mapurl);
    }
    else {

	basedir = r->uri;

	q = strrchr (basedir, '/'); q++;
	*q = '\0';

	sprintf (redirect, "%s%s%s", rooturl, basedir, mapurl);
    }
    
    table_set (r->headers_out, "Location", redirect);
}


int imap_handler (request_rec *r)
{

    char input[MAXLINE];
    char mapdflt[MAXLINE];
    char maptype[MAXLINE];
    char mapurl[MAXLINE];
    char base_uri[MAXLINE];
    char num[10];
    double testpoint[2], pointarray[MAXVERTS][2];
    int i, j, k;
    FILE *imap;
    char *ycoord;
    char *referer;
    double dist = 0;
    double mindist = 0;
    int sawpoint = 0;


    if (r->args == NULL) { /* Client doesn't support Imagemaps, */
      testpoint[X] = -1;   /* so fake some co-ordinates so that */
      testpoint[Y] = -1;   /* the default is picked.  MJC 02Nov95 */
    } else {
        if (!(ycoord = strchr (r->args, ',')))
          return BAD_REQUEST;
        *ycoord++ = '\0';
        testpoint[X] = (double) atoi (r->args);
        testpoint[Y] = (double) atoi (ycoord);
    }
      
    if (!(imap = fopen (r->filename,"r")))
        return SERVER_ERROR;
    
    referer = table_get (r->headers_in, "Referer");
    base_uri[0] = '\0';

    while ((getline(input, MAXLINE, imap))) {

	if ((input[0] == '#') || (!input[0]) )
	    continue;

	maptype[0] = '\0';
	mapurl[0] = '\0';

	for (i = 0; (isalpha(input[i]) || input[i] == '_') && input[i]; i++ )
	    maptype[i] = input[i];
	maptype[i] = '\0';

	while (isspace(input[i])) ++i;

	for (j = 0; input[i] && !isspace(input[i]); ++i,++j)
	    mapurl[j] = input[i];
	mapurl[j] = '\0';

	if (!strcmp (maptype, "base_uri")) {
	
	    if (!strcmp (mapurl, "map")) {
	    
		strcpy (base_uri, r->uri);
	    }
	    else if (!strcmp (mapurl, "referer")) {

		if (referer != NULL) {

		    strcpy (base_uri, referer);
		}
		else {
		    strcpy (base_uri, r->uri);
		}
	    }
	    else if ((mapurl[0] == '/') || (!strstr (mapurl, "://")))  {
	    
		strcpy (base_uri, mapurl);
	    }

	    k = strlen (base_uri);
	    base_uri[k] = '\0';
	    continue;
	}

        if (!strcmp (maptype, "default")) {

            strcpy (mapdflt, mapurl);
            continue;
        }

        k = 0;
        while (input[i]) {

            while (isspace(input[i]) || input[i] == ',') i++;

            j = 0;

            while (isdigit(input[i]))
                num[j++] = input[i++];

            num[j] = '\0';

            if (num[0] != '\0') {

		pointarray[k][X] = (double) atoi(num);
	    }
            else
                break;

            while (isspace(input[i]) || input[i] == ',') i++;

            j = 0;

            while (isdigit(input[i]))
                num[j++] = input[i++];

            num[j] = '\0';

            if (num[0] != '\0') {
                pointarray[k++][Y] = (double) atoi (num);
	    }
            else {
                fclose (imap);
                return SERVER_ERROR;
            }
        }

        pointarray[k][X] = -1;
        
	if (!strcmp (maptype,"poly")) {
            
	    if (pointinpoly (testpoint,pointarray)) {
		set_redirect (r, base_uri, mapurl);
	        fclose (imap);
		return REDIRECT;
	    }
	}

        if (!strcmp (maptype,"circle")) {

            if(pointincircle (testpoint,pointarray)) {
		set_redirect (r, base_uri, mapurl);
	        fclose (imap);
		return REDIRECT;
	    }
	}

        if (!strcmp (maptype,"rect")) {

            if (pointinrect (testpoint,pointarray)) {
		set_redirect (r, base_uri, mapurl);
    		fclose (imap);
		return REDIRECT;
	    }
	}
	if (!strcmp (maptype,"point")) {
	    /* Don't need to take sqaure root */
	    dist = ((testpoint[X] - pointarray[0][X])
		 *  (testpoint[X] - pointarray[0][X]))
	         + ((testpoint[Y] - pointarray[0][Y])
		 *  (testpoint[Y] - pointarray[0][Y]));
	    /* If this is the first point, or the nearest, set the default. */
	    if ((! sawpoint) || (dist < mindist)) {
	         mindist = dist;
	         strcpy(mapdflt,mapurl);
	    }
	    sawpoint++;
	}
    }

    if (mapdflt[0]) {

	set_redirect (r, base_uri, mapdflt);
        fclose(imap);
	return REDIRECT;
    }

    fclose (imap);
    return SERVER_ERROR;
}

handler_rec imap_handlers[] = {
{ IMAP_MAGIC_TYPE, imap_handler },
{ NULL }
};

module imap_module = {
   STANDARD_MODULE_STUFF,
   NULL,			/* initializer */
   NULL,			/* dir config creater */
   NULL,			/* dir merger --- default is to override */
   NULL,			/* server config */
   NULL,			/* merge server config */
   NULL,			/* command table */
   imap_handlers,		/* handlers */
   NULL,			/* filename translation */
   NULL,			/* check_user_id */
   NULL,			/* check auth */
   NULL,			/* check access */
   NULL,			/* type_checker */
   NULL,			/* fixups */
   NULL				/* logger */
};
