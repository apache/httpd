
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
 * http_include.c: Handles the server-parsed HTML documents
 * 
 * Original by Rob McCool; substantial fixups by David Robinson;
 * incorporated into the Shambhala module framework by rst.
 * 
 */

#include "httpd.h"
#include "http_config.h"
#include "http_request.h"
#include "http_core.h"
#include "http_protocol.h"
#include "http_log.h"
#include "http_main.h"
#include "util_script.h"

#define STARTING_SEQUENCE "<!--#"
#define ENDING_SEQUENCE "-->"
#define DEFAULT_ERROR_MSG "[an error occurred while processing this directive]"
#define DEFAULT_TIME_FORMAT "%A, %d-%b-%y %T %Z"
#define SIZEFMT_BYTES 0
#define SIZEFMT_KMG 1

static void decodehtml(char *s);
static char *get_tag(pool *p, FILE *in, char *tag, int tag_len, int dodecode);
static int get_directive(FILE *in, char *d, pool *p);

/* ------------------------ Environment function -------------------------- */

void add_include_vars(request_rec *r, char *timefmt)
{
    struct passwd *pw;
    table *e = r->subprocess_env;
    char *t;
    time_t date = time(NULL);

    table_set(e, "DATE_LOCAL", ht_time(r->pool, date, timefmt, 0));
    table_set(e, "DATE_GMT", ht_time(r->pool, date, timefmt, 1));
    table_set(e, "LAST_MODIFIED",ht_time(r->pool,r->finfo.st_mtime,timefmt,0));
    table_set(e, "DOCUMENT_URI", r->uri);
    table_set(e, "DOCUMENT_PATH_INFO", r->path_info);
    pw = getpwuid(r->finfo.st_uid);
    if (pw) {
      table_set(e, "USER_NAME", pw->pw_name);
    } else {
      char uid[16];
      sprintf(uid, "user#%ld", (unsigned long)r->finfo.st_uid);
      table_set(e, "USER_NAME", uid);
    }

    if((t = strrchr(r->filename, '/')))
        table_set (e, "DOCUMENT_NAME", ++t);
    else
        table_set (e, "DOCUMENT_NAME", r->uri);
    if (r->args) {
        unescape_url (r->args);
	  table_set (e, "QUERY_STRING_UNESCAPED",
		   escape_shell_cmd (r->pool, r->args));
    }
}

#define GET_CHAR(f,c,r,p) \
 { \
   int i = getc(f); \
   if(feof(f) || ferror(f) || (i == -1)) { \
        pfclose(p, f); \
        return r; \
   } \
   c = (char)i; \
 }

/* --------------------------- Parser functions --------------------------- */

/* Grrrr... rputc makes this slow as all-get-out.  Elsewhere, it doesn't
 * matter much, but this is an inner loop...
 */

int find_string(FILE *in,char *str, request_rec *r) {
    int x,l=strlen(str),p;
    char c;

    p=0;
    while(1) {
        GET_CHAR(in,c,1,r->pool);
        if(c == str[p]) {
            if((++p) == l)
                return 0;
        }
        else {
            if(r) {
                if(p) {
                    for(x=0;x<p;x++) {
                        rputc(str[x],r);
                    }
                }
                rputc(c,r);
            }
            p=0;
        }
    }
}

/*
 * decodes a string containing html entities or numeric character references.
 * 's' is overwritten with the decoded string.
 * If 's' is syntatically incorrect, then the followed fixups will be made:
 *   unknown entities will be left undecoded;
 *   references to unused numeric characters will be deleted.
 *   In particular, &#00; will not be decoded, but will be deleted.
 *
 * drtr
 */

/* maximum length of any ISO-LATIN-1 HTML entity name. */
#define MAXENTLEN (6)

/* The following is a shrinking transformation, therefore safe. */

static void
decodehtml(char *s)
{
    int val, i, j;
    char *p=s;
    char *ents;
    static char *entlist[MAXENTLEN+1]={
	NULL,  /* 0 */
	NULL,  /* 1 */
	"lt\074gt\076", /* 2 */
	"amp\046ETH\320eth\360", /* 3 */
	"quot\042Auml\304Euml\313Iuml\317Ouml\326Uuml\334auml\344euml\353\
iuml\357ouml\366uuml\374yuml\377", /* 4 */
	"Acirc\302Aring\305AElig\306Ecirc\312Icirc\316Ocirc\324Ucirc\333\
THORN\336szlig\337acirc\342aring\345aelig\346ecirc\352icirc\356ocirc\364\
ucirc\373thorn\376", /* 5 */
	"Agrave\300Aacute\301Atilde\303Ccedil\307Egrave\310Eacute\311\
Igrave\314Iacute\315Ntilde\321Ograve\322Oacute\323Otilde\325Oslash\330\
Ugrave\331Uacute\332Yacute\335agrave\340aacute\341atilde\343ccedil\347\
egrave\350eacute\351igrave\354iacute\355ntilde\361ograve\362oacute\363\
otilde\365oslash\370ugrave\371uacute\372yacute\375" /* 6 */
    };

    for (; *s != '\0'; s++, p++) {
	if (*s != '&') {
	    *p = *s;
	    continue;
	}
	/* find end of entity */
	for (i=1; s[i] != ';' && s[i] != '\0'; i++)
	    continue;

	if (s[i] == '\0') {	/* treat as normal data */
	    *p = *s;
	    continue;
	}

	/* is it numeric ? */
	if (s[1] == '#') {
	    for (j=2, val=0; j < i && isdigit(s[j]); j++)
		val = val * 10 + s[j] - '0';
	    s += i;
	    if (j < i || val <= 8 || (val >= 11 && val <= 31) ||
		(val >= 127 && val <= 160) || val >= 256)
		p--;  /* no data to output */
	    else
		*p = val;
	} else{
	    j = i-1;
	    if (i-1 > MAXENTLEN || entlist[i-1] == NULL) { /* wrong length */
		*p = '&';
		continue;  /* skip it */
	    }
	    for (ents=entlist[i-1]; *ents != '\0'; ents += i)
		if (strncmp(s+1, ents, i-1) == 0) break;

	    if (*ents == '\0')
		*p = '&';  /* unknown */
	    else {
		*p = ((const unsigned char *)ents)[i-1];
		s += i;
	    }
	}
    }

    *p = '\0';
}

/*
 * extract the next tag name and value.
 * if there are no more tags, set the tag name to 'done'
 * the tag value is html decoded if dodecode is non-zero
 */

static char *
get_tag(pool *p, FILE *in, char *tag, int tagbuf_len, int dodecode) {
    char *t = tag, *tag_val, c, term;
    int n;

    n = 0;

    do { /* skip whitespace */
	GET_CHAR(in,c,NULL,p);
    } while (isspace(c));

    /* tags can't start with - */
    if(c == '-') {
        GET_CHAR(in,c,NULL,p);
        if(c == '-') {
            do {
		GET_CHAR(in,c,NULL,p);
	    } while (isspace(c));
            if(c == '>') {
                strcpy(tag,"done");
                return tag;
            }
        }
	return NULL; /* failed */
    }

    /* find end of tag name */
    while(1) {
        if(++n == tagbuf_len) {
            t[tagbuf_len - 1] = '\0';
            return NULL;
        }
	if(c == '=' || isspace(c)) break;
	*(t++) = tolower(c);
        GET_CHAR(in,c,NULL,p);
    }

    *t++ = '\0';
    tag_val = t;

    while (isspace(c)) GET_CHAR(in, c, NULL,p); /* space before = */
    if (c != '=') return NULL;

    do {
	GET_CHAR(in,c,NULL,p);  /* space after = */
    } while (isspace(c));

    /* we should allow a 'name' as a value */
    
    if (c != '"' && c != '\'') return NULL;
    term = c;
    while(1) {
	GET_CHAR(in,c,NULL,p);
	if(++n == tagbuf_len) {
	    t[tagbuf_len - 1] = '\0';
	    return NULL;
	}
	if (c == term) break;
	*(t++) = c;
    }
    *t = '\0';
    if (dodecode) decodehtml(tag_val);
    return pstrdup (p, tag_val);
}

/* the pool is required to allow GET_CHAR to call pfclose */
static int
get_directive(FILE *in, char *d, pool *p) {
    char c;

    /* skip initial whitespace */
    while(1) {
        GET_CHAR(in,c,1,p);
        if(!isspace(c))
            break;
    }
    /* now get directive */
    while(1) {
        *d++ = tolower(c);
        GET_CHAR(in,c,1,p);
        if(isspace(c))
            break;
    }
    *d = '\0';
    return 0;
}

/* --------------------------- Action handlers ---------------------------- */

int include_cgi(char *s, request_rec *r)
{
    request_rec *rr = sub_req_lookup_uri (s, r);
    
    if (rr->status != 200) return -1;
    
    /* No hardwired path info or query allowed */
    
    if ((rr->path_info && rr->path_info[0]) || rr->args) return -1;
    if (rr->finfo.st_mode == 0) return -1;

    /* Script gets parameters of the *document*, for back compatibility */
    
    rr->path_info = r->path_info; /* painful to get right; see mod_cgi.c */
    rr->args = r->args;
    
    /* Force sub_req to be treated as a CGI request, even if ordinary
     * typing rules would have called it something else.
     */

    rr->content_type = CGI_MAGIC_TYPE;

    /* Run it. */
    
    if (run_sub_req (rr) == REDIRECT) {
        char *location = table_get (rr->headers_out, "Location");
	location = escape_html(rr->pool, location);
	rvputs(r,"<A HREF=\"", location, "\">", location, "</A>", NULL);
    }
    
    destroy_sub_req (rr);
    
    return 0;
}

int handle_include(FILE *in, request_rec *r, char *error, int noexec) {
    char tag[MAX_STRING_LEN];
    char *tag_val;

    while(1) {
        if(!(tag_val = get_tag(r->pool, in, tag, MAX_STRING_LEN, 1)))
            return 1;
        if(!strcmp(tag,"file") || !strcmp (tag, "virtual")) {
	    request_rec *rr=NULL;
	    char *error_fmt = NULL;

	    if (tag[0] == 'f')
	    { /* be safe; only files in this directory or below allowed */
		char tmp[MAX_STRING_LEN+2];
		sprintf(tmp, "/%s/", tag_val);
		if (tag_val[0] == '/' || strstr(tmp, "/../") != NULL)
		    error_fmt = "unable to include file %s in parsed file %s";
		else
		    rr = sub_req_lookup_file (tag_val, r);
	    } else
		rr = sub_req_lookup_uri (tag_val, r);
	    
	    if (!error_fmt && rr->status != 200)
	        error_fmt = "unable to include %s in parsed file %s";

	    if (!error_fmt && noexec && rr->content_type
		&& (strncmp (rr->content_type, "text/", 5)))
	        error_fmt =
		  "unable to include potential exec %s in parsed file %s";

	    if (error_fmt == NULL)
	    {
		request_rec *p;

		for (p=r; p != NULL; p=p->main)
		    if (strcmp(p->filename, rr->filename) == 0) break;
		if (p != NULL)
		    error_fmt = "Recursive include of %s in parsed file %s";
	    }
	    
	    if (!error_fmt && run_sub_req (rr))
	        error_fmt = "unable to include %s in parsed file %s";
		    
            if (error_fmt) {
                log_printf(r->server, error_fmt, tag_val, r->filename);
                rputs(error, r);
            }            

	    if (rr != NULL) destroy_sub_req (rr);
        } 
        else if(!strcmp(tag,"done"))
            return 0;
        else {
            log_printf(r->server, "unknown parameter %s to tag include in %s",
		       tag, r->filename);
            rputs(error, r);
        }
    }
}

typedef struct {
    request_rec *r;
    char *s;
} include_cmd_arg;

void include_cmd_child (void *arg)
{
    request_rec *r =  ((include_cmd_arg *)arg)->r;
    char *s = ((include_cmd_arg *)arg)->s;
    table *env = r->subprocess_env;
#ifdef DEBUG_INCLUDE_CMD    
#ifdef __EMX__
    /* under OS/2 /dev/tty is referenced as con */
    FILE *dbg = fopen ("con", "w");
#else
        FILE *dbg = fopen ("/dev/tty", "w");
#endif    
#endif    
    char err_string [MAX_STRING_LEN];

#ifdef DEBUG_INCLUDE_CMD    
    fprintf (dbg, "Attempting to include command '%s'\n", s);
#endif    

    if (r->path_info && r->path_info[0] != '\0')
    {
	request_rec *pa_req;

	table_set (env, "PATH_INFO", escape_shell_cmd (r->pool, r->path_info));
	
	pa_req = sub_req_lookup_uri(escape_uri(r->pool, r->path_info), r);
	if (pa_req->filename)
	    table_set(env, "PATH_TRANSLATED",
		      pstrcat(r->pool, pa_req->filename, pa_req->path_info,
			      NULL));
    }

    if (r->args) {
        table_set (env, "QUERY_STRING", r->args);
	unescape_url (r->args);
	table_set (env, "QUERY_STRING_UNESCAPED",
		   escape_shell_cmd (r->pool, r->args));
    }
    
    error_log2stderr (r->server);
    
#ifdef DEBUG_INCLUDE_CMD    
    fprintf (dbg, "Attempting to exec '%s'\n", s);
#endif    
    cleanup_for_exec();
    execle(SHELL_PATH, SHELL_PATH, "-c", s, NULL,
	   create_environment (r->pool, env));
    
    /* Oh, drat.  We're still here.  The log file descriptors are closed,
     * so we have to whimper a complaint onto stderr...
     */
    
#ifdef DEBUG_INCLUDE_CMD    
    fprintf (dbg, "Exec failed\n");
#endif    
    sprintf(err_string, "httpd: exec of %s failed, errno is %d\n",
	    SHELL_PATH,errno);
    write (2, err_string, strlen(err_string));
    exit(0);
}

int include_cmd(char *s, request_rec *r) {
    include_cmd_arg arg;
    FILE *f;

    arg.r = r; arg.s = s;

    if (!spawn_child (r->connection->pool, include_cmd_child, &arg,
		      kill_after_timeout, NULL, &f))
        return -1;
    
    send_fd(f,r);
    pfclose(r->pool, f);	/* will wait for zombie when
				 * r->pool is cleared
				 */
    return 0;
}


int handle_exec(FILE *in, request_rec *r, char *error)
{
    char tag[MAX_STRING_LEN];
    char *tag_val;
    char *file = r->filename;

    while(1) {
        if(!(tag_val = get_tag (r->pool, in, tag, MAX_STRING_LEN, 1)))
            return 1;
        if(!strcmp(tag,"cmd")) {
            if(include_cmd(tag_val, r) == -1) {
                log_printf(r->server, "failed command exec %s in %s",
			   tag_val, file);
                rputs(error, r);
            }
            /* just in case some stooge changed directories */
            chdir_file(r->filename);
        } 
        else if(!strcmp(tag,"cgi")) {
            if(include_cgi(tag_val, r) == -1) {
                log_printf(r->server, "invalid CGI ref %s in %s",tag_val,file);
                rputs(error, r);
            }
            /* grumble groan */
            chdir_file(r->filename);
        }
        else if(!strcmp(tag,"done"))
            return 0;
        else {
            log_printf(r->server, "unknown parameter %s to tag exec in %s",
		       tag, file);
            rputs(error, r);
        }
    }

}

int handle_echo (FILE *in, request_rec *r, char *error) {
    char tag[MAX_STRING_LEN];
    char *tag_val;

    while(1) {
        if(!(tag_val = get_tag (r->pool, in, tag, MAX_STRING_LEN, 1)))
            return 1;
        if(!strcmp(tag,"var")) {
	    char *val = table_get (r->subprocess_env, tag_val);

	    if (val) rputs(val, r);
	    else rputs("(none)", r);
        } else if(!strcmp(tag,"done"))
            return 0;
        else {
            log_printf(r->server, "unknown parameter %s to tag echo in %s",
		    tag, r->filename);
            rputs(error, r);
        }
    }
}

int handle_config(FILE *in, request_rec *r, char *error, char *tf,
                  int *sizefmt) {
    char tag[MAX_STRING_LEN];
    char *tag_val;
    table *env = r->subprocess_env;

    while(1) {
        if(!(tag_val = get_tag(r->pool, in, tag, MAX_STRING_LEN, 0)))
            return 1;
        if(!strcmp(tag,"errmsg"))
            strcpy(error,tag_val);
        else if(!strcmp(tag,"timefmt")) {
	    time_t date = time(NULL);
            strcpy(tf,tag_val);
            table_set (env, "DATE_LOCAL", ht_time(r->pool,date,tf,0));
            table_set (env, "DATE_GMT", ht_time(r->pool,date,tf,1));
            table_set (env, "LAST_MODIFIED", ht_time(r->pool,r->finfo.st_mtime,tf,0));
        }
        else if(!strcmp(tag,"sizefmt")) {
	    decodehtml(tag_val);
            if(!strcmp(tag_val,"bytes"))
                *sizefmt = SIZEFMT_BYTES;
            else if(!strcmp(tag_val,"abbrev"))
                *sizefmt = SIZEFMT_KMG;
        } 
        else if(!strcmp(tag,"done"))
            return 0;
        else {
            log_printf(r->server, "unknown parameter %s to tag config in %s",
                    tag, r->filename);
            rputs(error, r);
        }
    }
}



int find_file(request_rec *r, char *directive, char *tag, 
              char *tag_val, struct stat *finfo, char *error)
{
    char dir[MAX_STRING_LEN];
    char *to_send;

    if(!strcmp(tag,"file")) {
        getparents(tag_val); /* get rid of any nasties */
        getwd(dir);
        to_send = make_full_path (r->pool, dir, tag_val);
        if(stat(to_send,finfo) == -1) {
            log_printf(r->server,
                    "unable to get information about %s in parsed file %s",
                    to_send, r->filename);
            rputs(error, r);
            return -1;
        }
        return 0;
    }
    else if(!strcmp(tag,"virtual")) {
	request_rec *rr = sub_req_lookup_uri (tag_val, r);
	
	if (rr->status == 200 && rr->finfo.st_mode != 0) {
	    memcpy ((char*)finfo, (const char *)&rr->finfo, sizeof (struct stat));
	    destroy_sub_req (rr);
	    return 0;
        } else {
            log_printf(r->server,
                    "unable to get information about %s in parsed file %s",
                    tag_val, r->filename);
            rputs(error, r);
	    destroy_sub_req (rr);
            return -1;
        }
    }
    else {
        log_printf(r->server, "unknown parameter %s to tag %s in %s",
                tag, directive, r->filename);
	rputs(error, r);
        return -1;
    }
}


int handle_fsize(FILE *in, request_rec *r, char *error, int sizefmt) 
{
    char tag[MAX_STRING_LEN];
    char *tag_val;
    struct stat finfo;

    while(1) {
        if(!(tag_val = get_tag(r->pool, in, tag, MAX_STRING_LEN, 1)))
            return 1;
        else if(!strcmp(tag,"done"))
            return 0;
        else if(!find_file(r,"fsize",tag,tag_val,&finfo,error)) {
            if(sizefmt == SIZEFMT_KMG) {
                send_size(finfo.st_size, r);
            }
            else {
                int l,x;
#if defined(BSD) && BSD > 199305
                sprintf(tag,"%qd",finfo.st_size);
#else
                sprintf(tag,"%ld",finfo.st_size);
#endif
                l = strlen(tag); /* grrr */
                for(x=0;x<l;x++) {
                    if(x && (!((l-x) % 3))) {
                        rputc(',', r);
                    }
                    rputc (tag[x],r);
                }
            }
        }
    }
}

int handle_flastmod(FILE *in, request_rec *r, char *error, char *tf) 
{
    char tag[MAX_STRING_LEN];
    char *tag_val;
    struct stat finfo;

    while(1) {
        if(!(tag_val = get_tag(r->pool, in, tag, MAX_STRING_LEN, 1)))
            return 1;
        else if(!strcmp(tag,"done"))
            return 0;
        else if(!find_file(r,"flastmod",tag,tag_val,&finfo,error))
            rputs(ht_time(r->pool, finfo.st_mtime, tf, 0), r);
    }
}    



/* -------------------------- The main function --------------------------- */

/* This is a stub which parses a file descriptor. */

void send_parsed_content(FILE *f, request_rec *r)
{
    char directive[MAX_STRING_LEN], error[MAX_STRING_LEN];
    char timefmt[MAX_STRING_LEN];
    int noexec = allow_options (r) & OPT_INCNOEXEC;
    int ret, sizefmt;

    strcpy(error,DEFAULT_ERROR_MSG);
    strcpy(timefmt,DEFAULT_TIME_FORMAT);
    sizefmt = SIZEFMT_KMG;

    chdir_file (r->filename);

    while(1) {
        if(!find_string(f,STARTING_SEQUENCE,r)) {
            if(get_directive(f,directive,r->pool))
                return;
            if(!strcmp(directive,"exec")) {
                if(noexec) {
                    log_printf(r->server,
			       "httpd: exec used but not allowed in %s",
			       r->filename);
                    rputs(error, r);
                    ret = find_string(f,ENDING_SEQUENCE,NULL);
                } else 
                    ret=handle_exec(f, r, error);
            } 
            else if(!strcmp(directive,"config"))
                ret=handle_config(f, r, error, timefmt, &sizefmt);
            else if(!strcmp(directive,"include"))
                ret=handle_include(f, r, error, noexec);
            else if(!strcmp(directive,"echo"))
                ret=handle_echo(f, r, error);
            else if(!strcmp(directive,"fsize"))
                ret=handle_fsize(f, r, error, sizefmt);
            else if(!strcmp(directive,"flastmod"))
                ret=handle_flastmod(f, r, error, timefmt);
            else {
                log_printf(r->server, 
			   "httpd: unknown directive %s in parsed doc %s",
			   directive, r->filename);
                rputs(error, r);
                ret=find_string(f,ENDING_SEQUENCE,NULL);
            }
            if(ret) {
                log_printf(r->server, "httpd: premature EOF in parsed file %s",
			   r->filename);
                return;
            }
        } else 
            return;
    }
}

/*****************************************************************
 *
 * XBITHACK.  Sigh...  NB it's configurable per-directory; the compile-time
 * option only changes the default.
 */

module includes_module;
enum xbithack { xbithack_off, xbithack_on, xbithack_full };

#ifdef XBITHACK	
#define DEFAULT_XBITHACK xbithack_full
#else
#define DEFAULT_XBITHACK xbithack_off
#endif

void *create_includes_dir_config (pool *p, char *dummy)
{
    enum xbithack *result = (enum xbithack*)palloc(p, sizeof (enum xbithack));
    *result = DEFAULT_XBITHACK;
    return result;
}

char *set_xbithack (cmd_parms *cmd, void *xbp, char *arg)
{
   enum xbithack *state = (enum xbithack *)xbp;

   if (!strcasecmp (arg, "off")) *state = xbithack_off;
   else if (!strcasecmp (arg, "on")) *state = xbithack_on;
   else if (!strcasecmp (arg, "full")) *state = xbithack_full;
   else return "XBitHack must be set to Off, On, or Full";

   return NULL;
}

int send_parsed_file(request_rec *r)
{
    FILE *f;
    enum xbithack *state =
	(enum xbithack *)get_module_config(r->per_dir_config,&includes_module);
    int errstatus;

    if (!(allow_options (r) & OPT_INCLUDES)) return DECLINED;
    if (r->method_number != M_GET) return DECLINED;
    if (r->finfo.st_mode == 0) return NOT_FOUND;
	
    if (*state == xbithack_full
#ifndef __EMX__    
    /*  OS/2 dosen't support Groups. */
	&& (r->finfo.st_mode & S_IXGRP)
#endif
	&& (errstatus = set_last_modified (r, r->finfo.st_mtime)))
        return errstatus;
    
    if(!(f=pfopen(r->pool, r->filename, "r"))) {
        log_reason("file permissions deny server access", r->filename, r);
	return FORBIDDEN;
    }
    
    hard_timeout ("send", r);
    send_http_header(r);

    if (r->header_only) {
        kill_timeout (r);
	pfclose (r->pool, f);
	return OK;
    }
   
    if (r->main) {
	/* Kludge --- for nested includes, we want to keep the
	 * subprocess environment of the base document (for compatibility);
	 * that means torquing our own last_modified date as well so that
	 * the LAST_MODIFIED variable gets reset to the proper value if
	 * the nested document resets <!--#config timefmt-->
	 */
	r->subprocess_env = r->main->subprocess_env;
	r->finfo.st_mtime= r->main->finfo.st_mtime;
    } else { 
	add_common_vars (r);
	add_cgi_vars(r);
	add_include_vars (r, DEFAULT_TIME_FORMAT);
    }
    
    send_parsed_content (f, r);
    
    kill_timeout (r);
    return OK;
}

int send_shtml_file (request_rec *r)
{
    r->content_type = "text/html";
    return send_parsed_file(r);
}

int xbithack_handler (request_rec *r)
{
    enum xbithack *state;
	
#ifdef __EMX__
    /* OS/2 dosen't currently support the xbithack. This is being worked on. */
    return DECLINED;
#else

    if (!(r->finfo.st_mode & S_IXUSR)) return DECLINED;

    state = (enum xbithack *)get_module_config(r->per_dir_config,
					       &includes_module);
    
    if (*state == xbithack_off) return DECLINED;
    return send_parsed_file (r);
#endif    
}

command_rec includes_cmds[] = {
{ "XBitHack", set_xbithack, NULL, OR_OPTIONS, TAKE1, "Off, On, or Full" },
{ NULL }    
};

handler_rec includes_handlers[] = {
{ INCLUDES_MAGIC_TYPE, send_shtml_file },
{ INCLUDES_MAGIC_TYPE3, send_shtml_file },
{ "server-parsed", send_parsed_file },
{ "text/html", xbithack_handler },
{ NULL }
};

module includes_module = {
   STANDARD_MODULE_STUFF,
   NULL,			/* initializer */
   create_includes_dir_config,	/* dir config creater */
   NULL,			/* dir merger --- default is to override */
   NULL,			/* server config */
   NULL,			/* merge server config */
   includes_cmds,		/* command table */
   includes_handlers,		/* handlers */
   NULL,			/* filename translation */
   NULL,			/* check_user_id */
   NULL,			/* check auth */
   NULL,			/* check access */
   NULL,			/* type_checker */
   NULL,			/* fixups */
   NULL				/* logger */
};
