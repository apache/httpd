
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
 * str.c: string utility things
 * 
 * 3/21/93 Rob McCool
 * 
 */


#include "httpd.h"
#include "http_conf_globals.h"	/* for user_id & group_id */
#ifdef QNX
#include <time.h>
#endif

#ifdef NOTDEF
extern char** environ;

/* taken from bdflush-1.5 for Linux source code */
void inststr(char *dst[], int argc, char *src)
{
    if (strlen(src) <= strlen(dst[0]))
    {
        char *ptr;

        for (ptr = dst[0]; *ptr; *(ptr++) = '\0');

        strcpy(dst[0], src);
    } else
    {
        /* stolen from the source to perl 4.036 (assigning to $0) */
        char *ptr, *ptr2;
        int count;
        ptr = dst[0] + strlen(dst[0]);
        for (count = 1; count < argc; count++) {
            if (dst[count] == ptr + 1)
                ptr += strlen(++ptr);
        }
        if (environ[0] == ptr + 1) {
            for (count = 0; environ[count]; count++)
                if (environ[count] == ptr + 1)
                    ptr += strlen(++ptr);
        }
        count = 0;
        for (ptr2 = dst[0]; ptr2 <= ptr; ptr2++) {
            *ptr2 = '\0';
            count++;
        }
        strncpy(dst[0], src, count);
    }
}
#endif

char *get_time() {
    time_t t;
    char *time_string;

    t=time(NULL);
    time_string = ctime(&t);
    time_string[strlen(time_string) - 1] = '\0';
    return (time_string);
}

char *ht_time(pool *p, time_t t, char *fmt, int gmt) {
    char ts[MAX_STRING_LEN];
    struct tm *tms;

    tms = (gmt ? gmtime(&t) : localtime(&t));

    /* check return code? */
    strftime(ts,MAX_STRING_LEN,fmt,tms);
    return pstrdup (p, ts);
}

char *gm_timestr_822(pool *p, time_t sec) {
    static const char *const days[7]=
       {"Sun","Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
    char ts[50];
    struct tm *tms;

    tms = gmtime(&sec);

/* RFC date format; as strftime '%a, %d %b %Y %T GMT' */
    sprintf(ts, "%s, %.2d %s %d %.2d:%.2d:%.2d GMT", days[tms->tm_wday],
	    tms->tm_mday, month_snames[tms->tm_mon], tms->tm_year + 1900,
	    tms->tm_hour, tms->tm_min, tms->tm_sec);

    return pstrdup (p, ts);
}

/* What a pain in the ass. */
struct tm *get_gmtoff(long *tz) {
    time_t tt;
    struct tm *t;

    tt = time(NULL);
    t = localtime(&tt);
#if defined(HAS_GMTOFF)
    *tz = t->tm_gmtoff;
#elif !defined(NO_TIMEZONE)
    *tz = - timezone;
    if(t->tm_isdst)
        *tz += 3600;
#else
  {
    static struct tm loc_t;

    loc_t = *t;   /* save it */
    t = gmtime(&tt);
    *tz = mktime(&loc_t) - mktime(t);
    t = &loc_t; /* return pointer to saved time */
  }
#endif
    return t;
}


/* Match = 0, NoMatch = 1, Abort = -1 */
/* Based loosely on sections of wildmat.c by Rich Salz
 * Hmmm... shouldn't this really go component by component?
 */
int strcmp_match(char *str, char *exp) {
    int x,y;

    for(x=0,y=0;exp[y];++y,++x) {
        if((!str[x]) && (exp[y] != '*'))
            return -1;
        if(exp[y] == '*') {
            while(exp[++y] == '*');
            if(!exp[y])
                return 0;
            while(str[x]) {
                int ret;
                if((ret = strcmp_match(&str[x++],&exp[y])) != 1)
                    return ret;
            }
            return -1;
        } else 
            if((exp[y] != '?') && (str[x] != exp[y]))
                return 1;
    }
    return (str[x] != '\0');
}

int strcasecmp_match(char *str, char *exp) {
    int x,y;

    for(x=0,y=0;exp[y];++y,++x) {
        if((!str[x]) && (exp[y] != '*'))
            return -1;
        if(exp[y] == '*') {
            while(exp[++y] == '*');
            if(!exp[y])
                return 0;
            while(str[x]) {
                int ret;
                if((ret = strcasecmp_match(&str[x++],&exp[y])) != 1)
                    return ret;
            }
            return -1;
        } else 
            if((exp[y] != '?') && (tolower(str[x]) != tolower(exp[y])))
                return 1;
    }
    return (str[x] != '\0');
}

int is_matchexp(char *str) {
    register int x;

    for(x=0;str[x];x++)
        if((str[x] == '*') || (str[x] == '?'))
            return 1;
    return 0;
}

/*
 * Parse .. so we don't compromise security
 */
void getparents(char *name)
{
    int l, w;

    /* Four paseses, as per RFC 1808 */
    /* a) remove ./ path segments */

    for (l=0, w=0; name[l] != '\0';)
    {
	if (name[l] == '.' && name[l+1] == '/' && (l == 0 || name[l-1] == '/'))
	    l += 2;
	else
	    name[w++] = name[l++];
    }

    /* b) remove trailing . path, segment */
    if (w == 1 && name[0] == '.') w--;
    else if (w > 1 && name[w-1] == '.' && name[w-2] == '/') w--;
    name[w] = '\0';

    /* c) remove all xx/../ segments. (including leading ../ and /../) */
    l = 0;

    while(name[l]!='\0') {
        if(name[l] == '.' && name[l+1] == '.' && name[l+2] == '/' &&
	    (l == 0 || name[l-1] == '/')) {
		register int m=l+3,n;

		l=l-2;
		if(l>=0) {
		    while(l >= 0 && name[l] != '/') l--;
		    l++;
		}
		else l=0;
		n=l;
		while((name[n]=name[m])) (++n,++m);
            }
	else ++l;
    }

    /* d) remove trailing xx/.. segment. */
    if (l == 2 && name[0] == '.' && name[1] == '.') name[0] = '\0';
    else if (l > 2 && name[l-1] == '.' && name[l-2] == '.' && name[l-3] == '/')
    {
	l = l - 4;
	if (l >= 0)
	{
	    while (l >= 0 && name[l] != '/') l--;
	    l++;
	}
	else l = 0;
	name[l] = '\0';
    }
} 

void no2slash(char *name) {
    register int x,y;

    for(x=0; name[x];)
        if(x && (name[x-1] == '/') && (name[x] == '/'))
            for(y=x+1;name[y-1];y++)
                name[y-1] = name[y];
	else x++;
}

char *make_dirstr(pool *p, char *s, int n) {
    register int x,f;
    char *res;

    for(x=0,f=0;s[x];x++) {
        if(s[x] == '/')
            if((++f) == n) {
		res = palloc(p, x + 2);
		strncpy (res, s, x);
		res[x] = '/';
		res[x+1] = '\0';
                return res;
            }
    }

    if (s[strlen(s) - 1] == '/')
        return pstrdup (p, s);
    else
        return pstrcat (p, s, "/", NULL);
}

int count_dirs(char *path) {
    register int x,n;

    for(x=0,n=0;path[x];x++)
        if(path[x] == '/') n++;
    return n;
}


void chdir_file(char *file) {
    int i;

    if((i = rind(file,'/')) == -1)
        return;
    file[i] = '\0';
    chdir(file);
    file[i] = '/';
}

char *getword(pool* atrans, char **line, char stop) {
    int pos = ind(*line, stop);
    char *res;

    if (pos == -1) {
        res = pstrdup (atrans, *line);
	*line += strlen (*line);
	return res;
    }
  
    res = palloc(atrans, pos + 1);
    strncpy (res, *line, pos);
    res[pos] = '\0';
    
    while ((*line)[pos] == stop) ++pos;
    
    *line += pos;
    
    return res;
}
char *getword_nulls(pool* atrans, char **line, char stop) {
    int pos = ind(*line, stop);
    char *res;

    if (pos == -1) {
        res = pstrdup (atrans, *line);
	*line += strlen (*line);
	return res;
    }
  
    res = palloc(atrans, pos + 1);
    strncpy (res, *line, pos);
    res[pos] = '\0';
    
    ++pos;
    
    *line += pos;
    
    return res;
}

/* Get a word, (new) config-file style --- quoted strings and backslashes
 * all honored
 */

char *substring_conf (pool *p, char *start, int len)
{
    char *result = palloc (p, len + 2);
    char *resp = result;
    int i;

    for (i = 0; i < len; ++i) {
        if (start[i] == '\\') 
	    *resp++ = start[++i];
	else
	    *resp++ = start[i];
    }

    *resp++ = '\0';
    return result;
}

char *getword_conf(pool* p, char **line) {
    char *str = *line, *strend, *res;
    char quote;

    while (*str && isspace (*str))
        ++str;

    if (!*str) {
        *line = str;
        return "";
    }

    if ((quote = *str) == '"' || quote == '\'') {
        strend = str + 1;
	while (*strend && *strend != quote) {
	    if (*strend == '\\' && strend[1]) strend += 2;
	    else ++strend;
	}
	res = substring_conf (p, str + 1, strend - str - 1);

	if (*strend == quote) ++strend;
    } else {
        strend = str;
	while (*strend && !isspace (*strend))
	    if (*strend == '\\' && strend[1]) strend += 2;
	    else ++strend;

	res = substring_conf (p, str, strend - str);
    }

    while (*strend && isspace(*strend)) ++ strend;
    *line = strend;
    return res;
}

void cfg_getword(char *word, char *line) {
    int x=0,y;
    
    for(x=0;line[x] && isspace(line[x]);x++);
    y=0;
    while(1) {
        if(!(word[y] = line[x]))
            break;
        if(isspace(line[x]))
            if((!x) || (line[x-1] != '\\'))
                break;
        if(line[x] != '\\') ++y;
        ++x;
    }
    word[y] = '\0';
    while(line[x] && isspace(line[x])) ++x;
    for(y=0;(line[y] = line[x]);++x,++y);
}

int
cfg_getline(char *s, int n, FILE *f) {
    register int i=0, c;

    s[0] = '\0';
    /* skip leading whitespace */
    do {
        c = getc(f);
    } while (c == '\t' || c == ' ');

    while(1) {
        if((c == '\t') || (c == ' ')) {
            s[i++] = ' ';
            while((c == '\t') || (c == ' ')) 
                c = getc(f);
        }
        if(c == CR) {
            c = getc(f);
        }
        if(c == EOF || c == 0x4 || c == LF || i == (n-1)) {
            /* blast trailing whitespace */
            while(i && (s[i-1] == ' ')) --i;
            s[i] = '\0';
            return (feof(f) ? 1 : 0);
        }
        s[i] = c;
        ++i;
        c = getc(f);
    }
}

/* Retrieve a token, spacing over it and returning a pointer to
 * the first non-white byte afterwards.  Note that these tokens
 * are delimited by semis and commas; and can also be delimited
 * by whitespace at the caller's option.
 */

char *get_token (pool *p, char **accept_line, int accept_white)
{
    char *ptr = *accept_line;
    char *tok_start;
    char *token;
    int tok_len;
  
    /* Find first non-white byte */
    
    while (*ptr && isspace(*ptr))
      ++ptr;

    tok_start = ptr;
    
    /* find token end, skipping over quoted strings.
     * (comments are already gone).
     */
    
    while (*ptr && (accept_white || !isspace(*ptr))
	   && *ptr != ';' && *ptr != ',')
    {
	if (*ptr++ == '"')
	    while (*ptr)
	        if (*ptr++ == '"') break;
    }
	  
    tok_len = ptr - tok_start;
    token = palloc (p, tok_len + 1);
    strncpy (token, tok_start, tok_len);
    token[tok_len] = '\0';
    
    /* Advance accept_line pointer to the next non-white byte */

    while (*ptr && isspace(*ptr))
      ++ptr;

    *accept_line = ptr;
    return token;
}

char *escape_shell_cmd(pool *p, char *s) {
    register int x,y,l;
    char *cmd;

    l=strlen(s);
    cmd = palloc (p, 2 * l + 1); /* Be safe */
    strcpy (cmd, s);
    
    for(x=0;cmd[x];x++) {
    
#ifdef __EMX__
        /* Don't allow '&' in parameters under OS/2. */
        /* This can be used to send commands to the shell. */
        if (cmd[x] == '&') {
            cmd[x] = ' ';
        }
#endif

        if(ind("&;`'\"|*?~<>^()[]{}$\\\n",cmd[x]) != -1){
            for(y=l+1;y>x;y--)
                cmd[y] = cmd[y-1];
            l++; /* length has been increased */
            cmd[x] = '\\';
            x++; /* skip the character */
        }
    }

    return cmd;
}

void plustospace(char *str) {
    register int x;

    for(x=0;str[x];x++) if(str[x] == '+') str[x] = ' ';
}

void spacetoplus(char *str) {
    register int x;

    for(x=0;str[x];x++) if(str[x] == ' ') str[x] = '+';
}

char x2c(char *what) {
    register char digit;

    digit = ((what[0] >= 'A') ? ((what[0] & 0xdf) - 'A')+10 : (what[0] - '0'));
    digit *= 16;
    digit += (what[1] >= 'A' ? ((what[1] & 0xdf) - 'A')+10 : (what[1] - '0'));
    return(digit);
}

/*
 * Unescapes a URL.
 * Returns 0 on success, non-zero on error
 * Failure is due to
 *   bad % escape       returns BAD_REQUEST
 *
 *   decoding %00 -> \0
 *   decoding %2f -> /   (a special character)
 *                      returns NOT_FOUND
 */
int
unescape_url(char *url) {
    register int x,y, badesc, badpath;

    badesc = 0;
    badpath = 0;
    for(x=0,y=0;url[y];++x,++y) {
	if (url[y] != '%') url[x] = url[y];
	else
	{
	    if (!isxdigit(url[y+1]) || !isxdigit(url[y+2]))
	    {
		badesc = 1;
		url[x] = '%';
	    } else
	    {
		url[x] = x2c(&url[y+1]);
		y += 2;
		if (url[x] == '/' || url[x] == '\0') badpath = 1;
	    }
        }
    }
    url[x] = '\0';
    if (badesc) return BAD_REQUEST;
    else if (badpath) return NOT_FOUND;
    else return OK;
}

char *construct_url(pool *p, char *uri, server_rec *s) {
    char portnum[10];		/* Long enough.  Really! */
  
    if (s->port == 80) {
        return pstrcat (p, "http://", s->server_hostname, uri, NULL);
    } else {
        sprintf (portnum, "%d", s->port);
	return pstrcat (p, "http://", s->server_hostname, ":", portnum, uri,
			NULL);
    }
}

#define c2x(what,where) sprintf(where,"%%%02x",what)

/*
escape_path_segment() escapes a path segment, as defined in RFC 1808. This
routine is (should be) OS independent.

os_escape_path() converts an OS path to a URL, in an OS dependent way. In all
cases if a ':' occurs before the first '/' in the URL, the URL should be
prefixed with "./" (or the ':' escaped). In the case of Unix, this means
leaving '/' alone, but otherwise doing what escape_path_segment() does. For
efficiency reasons, we don't use escape_path_segment(), which is provided for
reference. Again, RFC 1808 is where this stuff is defined.

If partial is set, os_escape_path() assumes that the path will be appended to
something with a '/' in it (and thus does not prefix "./").
*/

char *escape_path_segment(pool *p, const char *segment) {
    register int x,y;
    char *copy = palloc (p, 3 * strlen (segment) + 1);
            
    for(x=0,y=0; segment[x]; x++,y++) {
      char c=segment[x];
      if((c < 'A' || c > 'Z') && (c < 'a' || c > 'z') && (c < '0' || c >'9')
	 && ind("$-_.+!*'(),:@&=~",c) == -1)
	{
	  c2x(c,&copy[y]);
	  y+=2;
	}
      else
	copy[y]=c;
    }
    copy[y] = '\0';
    return copy;
}

char *os_escape_path(pool *p,const char *path,int partial) {
  char *copy=palloc(p,3*strlen(path)+3);
  char *s=copy;

  if(!partial)
    {
      int colon=ind(path,':');
      int slash=ind(path,'/');

      if(colon >= 0 && (colon < slash || slash < 0))
	{
	  *s++='.';
	  *s++='/';
	}
    }
  for( ; *path ; ++path)
    {
      char c=*path;
      if((c < 'A' || c > 'Z') && (c < 'a' || c > 'z') && (c < '0' || c >'9')
	 && ind("$-_.+!*'(),:@&=/~",c) == -1)
	{
	  c2x(c,s);
	  s+=3;
	}
      else
	*s++=c;
    }
  *s='\0';
  return copy;
}

char *escape_uri(pool *p, char *uri) {
    register int x,y;
    char *copy = palloc (p, 3 * strlen (uri) + 1);
            
    for(x=0,y=0; uri[x]; x++,y++) {
        if (ind (":% ?+&",(copy[y] = uri[x])) != -1) {
            c2x(uri[x],&copy[y]);
            y+=2;
        }
    }
    copy[y] = '\0';
    return copy;
}

char *
escape_html(pool *p, const char *s)
{
    int i, j;
    char *x;

/* first, count the number of extra characters */
    for (i=0, j=0; s[i] != '\0'; i++)
	if (s[i] == '<' || s[i] == '>') j += 3;
	else if (s[i] == '&') j += 4;

    if (j == 0) return pstrdup(p, s);
    x = palloc(p, i + j + 1);
    for (i=0, j=0; s[i] != '\0'; i++, j++)
	if (s[i] == '<')
	{
	    memcpy(&x[j], "&lt;", 4);
	    j += 3;
	} else if (s[i] == '>')
	{
	    memcpy(&x[j], "&gt;", 4);
	    j += 3;
	} else if (s[i] == '&')
	{
	    memcpy(&x[j], "&amp;", 5);
	    j += 4;
	} else
            x[j] = s[i];

    x[j] = '\0';
    return x;
}

#ifdef NOTDEF

void escape_url(char *url) {
    register int x,y;
    register char digit;
    char *copy;

    copy = strdup(url);
            
    for(x=0,y=0;copy[x];x++,y++) {
        if(ind("% ?+&",url[y] = copy[x]) != -1) {
            c2x(copy[x],&url[y]);
            y+=2;
        }
    }
    url[y] = '\0';
    free(copy);
}

#endif

int is_directory(char *path) {
    struct stat finfo;

    if(stat(path,&finfo) == -1)
        return 0; /* in error condition, just return no */

    return(S_ISDIR(finfo.st_mode));
}

char *make_full_path(pool *a, char *src1,char *src2) {
    register int x;

    x = strlen(src1);
    if (x == 0) return pstrcat (a, "/", src2, NULL);

    if (src1[x - 1] != '/') return pstrcat (a, src1, "/", src2, NULL);
    else return pstrcat (a, src1, src2, NULL);
}

int is_url(char *u) {
    register int x;

    for(x=0;u[x] != ':';x++)
        if((!u[x]) || (!isalpha(u[x])))
            return 0;

    if((u[x+1] == '/') && (u[x+2] == '/'))
        return 1;
    else return 0;
}

int can_exec(struct stat *finfo) {
#ifdef __EMX__
    /* OS/2 dosen't have Users and Groups */
    return (finfo->st_mode & S_IEXEC);
#else    
    if(user_id == finfo->st_uid)
        if(finfo->st_mode & S_IXUSR)
            return 1;
    if(group_id == finfo->st_gid)
        if(finfo->st_mode & S_IXGRP)
            return 1;
    return (finfo->st_mode & S_IXOTH);
#endif    
}

#ifdef NEED_STRDUP
char *strdup (char *str)
{
  char *dup;

  if(!(dup = (char *)malloc (strlen (str) + 1)))
      return NULL;
  dup = strcpy (dup, str);

  return dup;
}
#endif

/* The following two routines were donated for SVR4 by Andreas Vogel */
#ifdef NEED_STRCASECMP
int strcasecmp (const char *a, const char *b)
{
    const char *p = a;
    const char *q = b;
    for (p = a, q = b; *p && *q; p++, q++)
    {
      int diff = tolower(*p) - tolower(*q);
      if (diff) return diff;
    }
    if (*p) return 1;       /* p was longer than q */
    if (*q) return -1;      /* p was shorter than q */
    return 0;               /* Exact match */
}

#endif

#ifdef NEED_STRNCASECMP
int strncasecmp (const char *a, const char *b, int n)
{
    const char *p = a;
    const char *q = b;

    for (p = a, q = b; /*NOTHING*/; p++, q++)
    {
      int diff;
      if (p == a + n) return 0;     /*   Match up to n characters */
      if (!(*p && *q)) return *p - *q;
      diff = tolower(*p) - tolower(*q);
      if (diff) return diff;
    }
    /*NOTREACHED*/
}
#endif



#ifdef NEED_INITGROUPS
int initgroups(const char *name, gid_t basegid)
{
#ifdef QNX
/* QNX does not appear to support supplementary groups.
Ben <ben@algroup.co.uk> */
	return 0;
#else /* ndef QNX */
  gid_t groups[NGROUPS_MAX];
  struct group *g;
  int index = 0;

  setgrent();

  groups[index++] = basegid;

  while (index < NGROUPS_MAX && ((g = getgrent()) != NULL))
    if (g->gr_gid != basegid)
    {
      char **names;

      for (names = g->gr_mem; *names != NULL; ++names)
        if (!strcmp(*names, name))
          groups[index++] = g->gr_gid;
    }

  endgrent();

  return setgroups(index, groups);
#endif /* def QNX */
}
#endif /* def NEED_INITGROUPS */

#ifdef NEED_WAITPID
/* From ikluft@amdahl.com */
/* this is not ideal but it works for SVR3 variants */
/* httpd does not use the options so this doesn't implement them */
int waitpid(pid_t pid, int *statusp, int options)
{
    int tmp_pid;
    if ( kill ( pid,0 ) == -1) {
        errno=ECHILD;
        return -1;
    }
    while ((( tmp_pid = wait(statusp)) != pid) && ( tmp_pid != -1 ));
    return tmp_pid;
}
#endif

int ind(const char *s, char c) {
    register int x;

    for(x=0;s[x];x++)
        if(s[x] == c) return x;

    return -1;
}

int rind(const char *s, char c) {
    register int x;

    for(x=strlen(s)-1;x != -1;x--)
        if(s[x] == c) return x;

    return -1;
}

void str_tolower(char *str) {
    while(*str) {
        *str = tolower(*str);
        ++str;
    }
}
        
uid_t uname2id(char *name) {
    struct passwd *ent;

    if(name[0] == '#') 
        return(atoi(&name[1]));

    if(!(ent = getpwnam(name))) {
        fprintf(stderr,"httpd: bad user name %s\n",name);
        exit(1);
    }
    else return(ent->pw_uid);
}

gid_t gname2id(char *name) {
    struct group *ent;

    if(name[0] == '#') 
        return(atoi(&name[1]));

    if(!(ent = getgrnam(name))) {
        fprintf(stderr,"httpd: bad group name %s\n",name);
        exit(1);
    }
    else return(ent->gr_gid);
}

#if 0
int get_portnum(int sd) {
    struct sockaddr addr;
    int len;

    len = sizeof(struct sockaddr);
    if(getsockname(sd,&addr,&len) < 0)
        return -1;
    return ntohs(((struct sockaddr_in *)&addr)->sin_port);
}

struct in_addr get_local_addr(int sd) {
    struct sockaddr addr;
    int len;

    len = sizeof(struct sockaddr);
    if(getsockname(sd,&addr,&len) < 0) {
        fprintf (stderr, "Can't get local host address!\n");
	perror ("getsockname");
	exit(1);
    }
         
    return ((struct sockaddr_in *)&addr)->sin_addr;
}
#endif

/*
 * Parses a host of the form <address>[:port]
 * :port is permitted if 'port' is not NULL
 */
unsigned long get_virthost_addr (char *w, short int *ports) {
    struct hostent *hep;
    unsigned long my_addr;
    char *p;

    p = strchr(w, ':');
    if (ports != NULL)
    {
	*ports = 0;
	if (p != NULL && strcmp(p+1, "*") != 0) *ports = atoi(p+1);
    }

    if (p != NULL) *p = '\0';
    if (strcmp(w, "*") == 0)
    {
	if (p != NULL) *p = ':';
	return htonl(INADDR_ANY);
    }
	
#ifdef DGUX
    my_addr = inet_network(w);
#else
    my_addr = inet_addr(w);
#endif
    if (my_addr != ((unsigned long) 0xffffffff))
    {
	if (p != NULL) *p = ':';
	return my_addr;
    }

    hep = gethostbyname(w);
	    
    if ((!hep) || (hep->h_addrtype != AF_INET || !hep->h_addr_list[0])) {
	fprintf (stderr, "Cannot resolve host name %s --- exiting!\n", w);
	exit(1);
    }
	    
    if (hep->h_addr_list[1]) {
	fprintf(stderr, "Host %s has multiple addresses ---\n", w);
	fprintf(stderr, "you must choose one explicitly for use as\n");
	fprintf(stderr, "a virtual host.  Exiting!!!\n");
	exit(1);
    }
	    
    if (p != NULL) *p = ':';

    return ((struct in_addr *)(hep->h_addr))->s_addr;
}


#ifdef NOTDEF    
    
char *get_remote_logname(FILE *fd) {
    int len;
    char *result;
#if defined(NEXT) || defined(BSD4_4) || defined(SOLARIS2) || defined(LINUX) || defined(__EMX__)
    struct sockaddr sa_server, sa_client;
#else
    struct sockaddr_in sa_server,sa_client;
#endif

    len = sizeof(sa_client);
    if(getpeername(fileno(stdout),&sa_client,&len) != -1) {
        len = sizeof(sa_server);
        if(getsockname(fileno(stdout),&sa_server,&len) == -1)
            result = "unknown";
        else
            result = rfc931((struct sockaddr_in *) & sa_client,
                                    (struct sockaddr_in *) & sa_server);
    }
    else result = "unknown";

    return result; /* robm=pinhead */
}
#endif    

static char *find_fqdn(pool *a, struct hostent *p) {
    int x;

    if(ind(p->h_name,'.') == -1) {
        for(x=0;p->h_aliases[x];++x) {
            if((ind(p->h_aliases[x],'.') != -1) && 
               (!strncmp(p->h_aliases[x],p->h_name,strlen(p->h_name))))
                return pstrdup(a, p->h_aliases[x]);
        }
        return NULL;
    } else return pstrdup(a, (void *)p->h_name);
}

char *get_local_host(pool *a)
{
    char str[128];
    int len = 128;
    char *server_hostname;

    struct hostent *p;
    gethostname(str, len);
    if((!(p=gethostbyname(str))) || (!(server_hostname = find_fqdn(a, p)))) {
        fprintf(stderr,"httpd: cannot determine local host name.\n");
	fprintf(stderr,"Use ServerName to set it manually.\n");
	exit(1);
    }

    return server_hostname;
}

/* aaaack but it's fast and const should make it shared text page. */
const int pr2six[256]={
    64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
    64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,62,64,64,64,63,
    52,53,54,55,56,57,58,59,60,61,64,64,64,64,64,64,64,0,1,2,3,4,5,6,7,8,9,
    10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,64,64,64,64,64,64,26,27,
    28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,
    64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
    64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
    64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
    64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
    64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
    64,64,64,64,64,64,64,64,64,64,64,64,64
};

char *uudecode(pool *p, char *bufcoded) {
    int nbytesdecoded;
    register unsigned char *bufin;
    register char *bufplain;
    register unsigned char *bufout;
    register int nprbytes;
    
    /* Strip leading whitespace. */
    
    while(*bufcoded==' ' || *bufcoded == '\t') bufcoded++;
    
    /* Figure out how many characters are in the input buffer.
     * Allocate this many from the per-transaction pool for the result.
     */
    bufin = (unsigned char *)bufcoded;
    while(pr2six[*(bufin++)] <= 63);
    nprbytes = (char *)bufin - bufcoded - 1;
    nbytesdecoded = ((nprbytes+3)/4) * 3;

    bufplain = palloc(p, nbytesdecoded + 1);
    bufout = (unsigned char *)bufplain;
    
    bufin = (unsigned char *)bufcoded;
    
    while (nprbytes > 0) {
        *(bufout++) = 
            (unsigned char) (pr2six[*bufin] << 2 | pr2six[bufin[1]] >> 4);
        *(bufout++) = 
            (unsigned char) (pr2six[bufin[1]] << 4 | pr2six[bufin[2]] >> 2);
        *(bufout++) = 
            (unsigned char) (pr2six[bufin[2]] << 6 | pr2six[bufin[3]]);
        bufin += 4;
        nprbytes -= 4;
    }
    
    if(nprbytes & 03) {
        if(pr2six[bufin[-2]] > 63)
            nbytesdecoded -= 2;
        else
            nbytesdecoded -= 1;
    }
    bufplain[nbytesdecoded] = '\0';
    return bufplain;
}

#ifdef __EMX__
void os2pathname(char *path) {
    char newpath[MAX_STRING_LEN];
    int loop;
    int offset;

    offset = 0;
    for (loop=0; loop < (strlen(path) + 1); loop++) {
        if (path[loop] == '/') {
            newpath[offset] = '\\';
            /*
            offset = offset + 1;
            newpath[offset] = '\\';
            */
        } else
            newpath[offset] = path[loop];
        offset = offset + 1;
    };
    /* Debugging code */
    /* fprintf(stderr, "%s \n", newpath); */

    strcpy(path, newpath);
};
#endif


#ifdef NEED_STRERROR
char *
strerror (int err) {

    char *p;
    extern char *const sys_errlist[];

    p = sys_errlist[err];
    return (p);
}
#endif
