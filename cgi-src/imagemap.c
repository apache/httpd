/*
** mapper 1.2
** 7/26/93 Kevin Hughes, kevinh@pulua.hcc.hawaii.edu
** "macmartinized" polygon code copyright 1992 by Eric Haines, erich@eye.com
** All suggestions, help, etc. gratefully accepted!
**
** 1.1 : Better formatting, added better polygon code.
** 1.2 : Changed isname(), added config file specification.
**
** 11/13/93: Rob McCool, robm@ncsa.uiuc.edu
**
** 1.3 : Rewrote configuration stuff for NCSA /htbin script
**
** 12/05/93: Rob McCool, robm@ncsa.uiuc.edu
** 
** 1.4 : Made CGI/1.0 compliant.
**
** 06/27/94: Chris Hyams, cgh@rice.edu
**          Based on an idea by Rick Troth (troth@rice.edu)
** 
** 1.5 : Imagemap configuration file in PATH_INFO.  Backwards compatible.
**
**  Old-style lookup in imagemap table:
**    <a href="http://foo.edu/cgi-bin/imagemap/oldmap">
**
**  New-style specification of mapfile relative to DocumentRoot:
**    <a href="http://foo.edu/cgi-bin/imagemap/path/for/new.map">
**
**  New-style specification of mapfile in user's public HTML directory:
**    <a href="http://foo.edu/cgi-bin/imagemap/~username/path/for/new.map">
**
** 07/11/94: Craig Milo Rogers, Rogers@ISI.Edu
**
** 1.6 : Added "point" datatype: the nearest point wins.  Overrides "default".
**
** 08/28/94: Carlos Varela, cvarela@ncsa.uiuc.edu
**
** 1.7 : Fixed bug:  virtual URLs are now understood.
**       Better error reporting when not able to open configuration file.
**
** 03/07/95: Carlos Varela, cvarela@ncsa.uiuc.edu
**
** 1.8 : Fixed bug (strcat->sprintf) when reporting error.
**       Included getline() function from util.c in NCSA httpd distribution.
**
** 11/08/95: Brandon Long, blong@ncsa.uiuc.edu
**
** 1.9 : Fixed bug:  If you requested a new style conf file in DOCUMENT_ROOT,
**       and didn't have an old style conf file, it would fail
** 1.9a: Most other imagemap programs seem to allow a non-full path as the url,
**	 so we'll switch to that.  Any url not starting with / goes to the
**	 same path as the map file.
*/

#include <stdio.h>
#include <string.h>
#if !defined(pyr) && !defined(NO_STDLIB_H)
#include <stdlib.h>
#else
#include <sys/types.h>
#include <ctype.h>
char *getenv();
#include <ctype.h>
#endif
#include <sys/types.h>
#include "util.h"
#include <sys/stat.h>

#define CONF_FILE "/usr/local/etc/httpd/conf/imagemap.conf"

#define MAXLINE 500
#define MAXVERTS 100
#define X 0
#define Y 1
#define LF 10
#define CR 13


static void servererr(char *msg);
static void sendmesg(char *url);
static int pointinpoly(double point[2], double pgon[MAXVERTS][2]);
static int pointincircle(double point[2], double coords[MAXVERTS][2]);
static int pointinrect(double point[2], double coords[MAXVERTS][2]);

int isname(char);

int main(int argc, char **argv)
{
    char input[MAXLINE], *mapname, def[MAXLINE], conf[MAXLINE], errstr[MAXLINE];
    double testpoint[2], pointarray[MAXVERTS][2];
    int i, j, k;
    FILE *fp;
    char *t;
    double dist, mindist;
    int sawpoint = 0;
    
    if (argc != 2)
        servererr("Wrong number of arguments, client may not support ISMAP.");
    mapname=getenv("PATH_INFO");

    if((!mapname) || (!mapname[0]))
        servererr("No map name given. Please read the <A HREF=\"http://hoohoo.ncsa.uiuc.edu/docs/tutorials/imagemapping.html\">instructions</A>.<P>");


    mapname++;
    if(!(t = strchr(argv[1],',')))
        servererr("Your client doesn't support image mapping properly.");
    *t++ = '\0';
    testpoint[X] = (double) atoi(argv[1]);
    testpoint[Y] = (double) atoi(t);

    /*
     * if the mapname contains a '/', it represents a unix path -
     * we get the translated path, and skip reading the configuration file.
     */
    if (strchr(mapname,'/')) {
      strcpy(conf,getenv("PATH_TRANSLATED"));
      goto openconf;
    }
    
    if ((fp = fopen(CONF_FILE, "r")) == NULL){
      /* Assume new style request if CONF_FILE doesn't exist
       */
       goto openconf;
    }

    while(!(getline(input,MAXLINE,fp))) {
        char confname[MAXLINE];
        if((input[0] == '#') || (!input[0]))
            continue;
        for(i=0;isname(input[i]) && (input[i] != ':');i++)
            confname[i] = input[i];
        confname[i] = '\0';
        if(!strcmp(confname,mapname))
            goto found;
    }
    /*
     * if mapname was not found in the configuration file, it still
     * might represent a file in the server root directory -
     * we get the translated path, and check to see if a file of that
     * name exists, jumping to the opening of the map file if it does.
     */
    if(feof(fp)) {
      struct stat sbuf;
      strcpy(conf,getenv("PATH_TRANSLATED"));
      if (!stat(conf,&sbuf) && ((sbuf.st_mode & S_IFMT) == S_IFREG))
	goto openconf;
      else
	servererr("Map not found in configuration file.");
    }
    
  found:
    fclose(fp);
    while(isspace(input[i]) || input[i] == ':') ++i;

    for(j=0;input[i] && isname(input[i]);++i,++j)
        conf[j] = input[i];
    conf[j] = '\0';

  openconf:
    if(!(fp=fopen(conf,"r"))){
	sprintf(errstr, "Couldn't open configuration file: %s", conf);
        servererr(errstr);
    }

    while(!(getline(input,MAXLINE,fp))) {
        char type[MAXLINE];
        char url[MAXLINE];
        char num[10];

        if((input[0] == '#') || (!input[0]))
            continue;

        type[0] = '\0';url[0] = '\0';

        for(i=0;isname(input[i]) && (input[i]);i++)
            type[i] = input[i];
        type[i] = '\0';

        while(isspace(input[i])) ++i;
        for(j=0;input[i] && isname(input[i]);++i,++j)
            url[j] = input[i];
        url[j] = '\0';

        if(!strcmp(type,"default") && !sawpoint) {
            strcpy(def,url);
            continue;
        }

        k=0;
        while (input[i]) {
            while (isspace(input[i]) || input[i] == ',')
                i++;
            j = 0;
            while (isdigit(input[i]))
                num[j++] = input[i++];
            num[j] = '\0';
            if (num[0] != '\0')
                pointarray[k][X] = (double) atoi(num);
            else
                break;
            while (isspace(input[i]) || input[i] == ',')
                i++;
            j = 0;
            while (isdigit(input[i]))
                num[j++] = input[i++];
            num[j] = '\0';
            if (num[0] != '\0')
                pointarray[k++][Y] = (double) atoi(num);
            else {
                fclose(fp);
                servererr("Missing y value.");
            }
        }
        pointarray[k][X] = -1;
        if(!strcmp(type,"poly"))
            if(pointinpoly(testpoint,pointarray))
                sendmesg(url);
        if(!strcmp(type,"circle"))
            if(pointincircle(testpoint,pointarray))
                sendmesg(url);
        if(!strcmp(type,"rect"))
            if(pointinrect(testpoint,pointarray))
                sendmesg(url);
        if(!strcmp(type,"point")) {
	    /* Don't need to take square root. */
	    dist = ((testpoint[X] - pointarray[0][X])
		    * (testpoint[X] - pointarray[0][X]))
		   + ((testpoint[Y] - pointarray[0][Y])
		      * (testpoint[Y] - pointarray[0][Y]));
	    /* If this is the first point, or the nearest, set the default. */
	    if ((! sawpoint) || (dist < mindist)) {
		mindist = dist;
	        strcpy(def,url);
	    }
	    sawpoint++;
	}
    }
    if(def[0])
        sendmesg(def);
    servererr("No default specified.");
}

static void sendmesg(char *url)
{
  char *port;
  char *path_info;
  char path[MAXLINE];

  if (strchr(url, ':'))   /*** It is a full URL ***/
    printf("Location: %s%c%c",url,LF,LF);
  else {                   /*** It is a virtual URL ***/
    printf("Location: http://%s", getenv("SERVER_NAME"));

      /* only add port if it's not the default */
     if ((port = getenv("SERVER_PORT")) && strcmp(port,"80"))
      printf(":%s",port);
    
    /* if its a full path, just use it, else add path from PATH_INFO */
    if (url[0] == '/') {
      printf("%s%c%c",url,LF,LF);
    } else { 
      if ((path_info = getenv("PATH_INFO"))) {
	char *last = strrchr(path_info,'/');
	int x = 0;
	while (((path_info+x) <= last) && (x < MAXLINE)) {
	  path[x] = *(path_info+x);
	  x++;
        }
	path[x] = '\0';
      }	else { 
	strcpy(path,"/");
      }
      printf("%s%s%c%c",path,url,LF,LF);
    }
  }
  printf("This document has moved <A HREF=\"%s\">here</A>%c",url,LF);
  exit(1);
}

static int pointinrect(double point[2], double coords[MAXVERTS][2])
{
        return ((point[X] >= coords[0][X] && point[X] <= coords[1][X]) &&
        (point[Y] >= coords[0][Y] && point[Y] <= coords[1][Y]));
}

static int pointincircle(double point[2], double coords[MAXVERTS][2])
{
        int radius1, radius2;

        radius1 = ((coords[0][Y] - coords[1][Y]) * (coords[0][Y] -
        coords[1][Y])) + ((coords[0][X] - coords[1][X]) * (coords[0][X] -
        coords[1][X]));
        radius2 = ((coords[0][Y] - point[Y]) * (coords[0][Y] - point[Y])) +
        ((coords[0][X] - point[X]) * (coords[0][X] - point[X]));
        return (radius2 <= radius1);
}

static int pointinpoly(double point[2], double pgon[MAXVERTS][2])
{
        int i, numverts, inside_flag, xflag0;
        int crossings;
        double *p, *stop;
        double tx, ty, y;

        for (i = 0; pgon[i][X] != -1 && i < MAXVERTS; i++)
                ;
        numverts = i;
        crossings = 0;

        tx = point[X];
        ty = point[Y];
        y = pgon[numverts - 1][Y];

        p = (double *) pgon + 1;
        if ((y >= ty) != (*p >= ty)) {
                if ((xflag0 = (pgon[numverts - 1][X] >= tx)) ==
                (*(double *) pgon >= tx)) {
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

static void servererr(char *msg)
{
    printf("Content-type: text/html%c%c",LF,LF);
    printf("<title>Mapping Server Error</title>");
    printf("<h1>Mapping Server Error</h1>");
    printf("This server encountered an error:<p>");
    printf("%s", msg);
    exit(-1);
}

int isname(char c)
{
        return (!isspace(c));
}

int getline(char *s, int n, FILE *f) {
    register int i=0;

    while(1) {
        s[i] = (char)fgetc(f);

        if(s[i] == CR)
            s[i] = fgetc(f);

        if((s[i] == 0x4) || (s[i] == LF) || (i == (n-1))) {
            s[i] = '\0';
            return (feof(f) ? 1 : 0);
        }
        ++i;
    }
}

