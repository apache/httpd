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
 * http_include.c: Handles the server-parsed HTML documents
 * 
 * Original by Rob McCool; substantial fixups by David Robinson;
 * incorporated into the Apache module framework by rst.
 * 
 */
/* 
 * sub key may be anything a Perl*Handler can be:
 * subroutine name, package name (defaults to package::handler),
 * Class->method call or anoymous sub {}
 *
 * Child <!--#perl sub="sub {print $$}" --> accessed
 * <!--#perl sub="sub {print ++$Access::Cnt }" --> times. <br>
 *
 * <!--#perl arg="one" sub="mymod::includer" -->
 *
 * -Doug MacEachern
 */

#ifdef USE_PERL_SSI
#include "config.h"
#undef VOIDUSED
#ifdef USE_SFIO
#undef USE_SFIO
#define USE_STDIO
#endif
#include "modules/perl/mod_perl.h"
#else
#include "httpd.h"
#include "http_config.h"
#include "http_request.h"
#include "http_core.h"
#include "http_protocol.h"
#include "http_log.h"
#include "http_main.h"
#include "util_script.h"
#endif

#define STARTING_SEQUENCE "<!--#"
#define ENDING_SEQUENCE "-->"
#define DEFAULT_ERROR_MSG "[an error occurred while processing this directive]"
#define DEFAULT_TIME_FORMAT "%A, %d-%b-%Y %H:%M:%S %Z"
#define SIZEFMT_BYTES 0
#define SIZEFMT_KMG 1
#ifdef CHARSET_EBCDIC
#define RAW_ASCII_CHAR(ch)  os_toebcdic[(unsigned char)ch]
#else /*CHARSET_EBCDIC*/
#define RAW_ASCII_CHAR(ch)  (ch)
#endif /*CHARSET_EBCDIC*/

module MODULE_VAR_EXPORT includes_module;

/* ------------------------ Environment function -------------------------- */

/* XXX: could use ap_table_overlap here */
static void add_include_vars(request_rec *r, char *timefmt)
{
#if !defined(WIN32) && !defined(NETWARE)
    struct passwd *pw;
#endif /* ndef WIN32 */
    table *e = r->subprocess_env;
    char *t;
    time_t date = r->request_time;

    ap_table_setn(e, "DATE_LOCAL", ap_ht_time(r->pool, date, timefmt, 0));
    ap_table_setn(e, "DATE_GMT", ap_ht_time(r->pool, date, timefmt, 1));
    ap_table_setn(e, "LAST_MODIFIED",
              ap_ht_time(r->pool, r->finfo.st_mtime, timefmt, 0));
    ap_table_setn(e, "DOCUMENT_URI", r->uri);
    ap_table_setn(e, "DOCUMENT_PATH_INFO", r->path_info);
#if !defined(WIN32) && !defined(NETWARE)
    pw = getpwuid(r->finfo.st_uid);
    if (pw) {
        ap_table_setn(e, "USER_NAME", ap_pstrdup(r->pool, pw->pw_name));
    }
    else {
        ap_table_setn(e, "USER_NAME", ap_psprintf(r->pool, "user#%lu",
                    (unsigned long) r->finfo.st_uid));
    }
#endif /* ndef WIN32 */

    if ((t = strrchr(r->filename, '/'))) {
        ap_table_setn(e, "DOCUMENT_NAME", ++t);
    }
    else {
        ap_table_setn(e, "DOCUMENT_NAME", r->uri);
    }
    if (r->args) {
        char *arg_copy = ap_pstrdup(r->pool, r->args);

        ap_unescape_url(arg_copy);
        ap_table_setn(e, "QUERY_STRING_UNESCAPED",
                  ap_escape_shell_cmd(r->pool, arg_copy));
    }
}



/* --------------------------- Parser functions --------------------------- */

#define OUTBUFSIZE 4096
/* PUT_CHAR and FLUSH_BUF currently only work within the scope of 
 * find_string(); they are hacks to avoid calling rputc for each and
 * every character output.  A common set of buffering calls for this 
 * type of output SHOULD be implemented.
 */
#define PUT_CHAR(c,r) \
 { \
    outbuf[outind++] = c; \
    if (outind == OUTBUFSIZE) { \
        FLUSH_BUF(r) \
    }; \
 }

/* there SHOULD be some error checking on the return value of
 * rwrite, however it is unclear what the API for rwrite returning
 * errors is and little can really be done to help the error in 
 * any case.
 */
#define FLUSH_BUF(r) \
 { \
   ap_rwrite(outbuf, outind, r); \
   outind = 0; \
 }

/*
 * f: file handle being read from
 * c: character to read into
 * ret: return value to use if input fails
 * r: current request_rec
 *
 * This macro is redefined after find_string() for historical reasons
 * to avoid too many code changes.  This is one of the many things
 * that should be fixed.
 */
#define GET_CHAR(f,c,ret,r) \
 { \
   int i = getc(f); \
   if (i == EOF) { /* either EOF or error -- needs error handling if latter */ \
       if (ferror(f)) { \
           fprintf(stderr, "encountered error in GET_CHAR macro, " \
                   "mod_include.\n"); \
       } \
       FLUSH_BUF(r); \
       ap_pfclose(r->pool, f); \
       return ret; \
   } \
   c = (char)i; \
 }

static int find_string(FILE *in, const char *str, request_rec *r, int printing)
{
    int x, l = strlen(str), p;
    char outbuf[OUTBUFSIZE];
    int outind = 0;
    char c;

    p = 0;
    while (1) {
        GET_CHAR(in, c, 1, r);
        if (c == str[p]) {
            if ((++p) == l) {
                FLUSH_BUF(r);
                return 0;
            }
        }
        else {
            if (printing) {
                for (x = 0; x < p; x++) {
                    PUT_CHAR(str[x], r);
                }
                PUT_CHAR(c, r);
            }
            p = 0;
        }
    }
}

#undef FLUSH_BUF
#undef PUT_CHAR
#undef GET_CHAR
#define GET_CHAR(f,c,r,p) \
 { \
   int i = getc(f); \
   if (i == EOF) { /* either EOF or error -- needs error handling if latter */ \
       if (ferror(f)) { \
           fprintf(stderr, "encountered error in GET_CHAR macro, " \
                   "mod_include.\n"); \
       } \
       ap_pfclose(p, f); \
       return r; \
   } \
   c = (char)i; \
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

static void decodehtml(char *s)
{
    int val, i, j;
    char *p = s;
    const char *ents;
    static const char * const entlist[MAXENTLEN + 1] =
    {
        NULL,                   /* 0 */
        NULL,                   /* 1 */
        "lt\074gt\076",         /* 2 */
        "amp\046ETH\320eth\360",        /* 3 */
        "quot\042Auml\304Euml\313Iuml\317Ouml\326Uuml\334auml\344euml\353\
iuml\357ouml\366uuml\374yuml\377",      /* 4 */
        "Acirc\302Aring\305AElig\306Ecirc\312Icirc\316Ocirc\324Ucirc\333\
THORN\336szlig\337acirc\342aring\345aelig\346ecirc\352icirc\356ocirc\364\
ucirc\373thorn\376",            /* 5 */
        "Agrave\300Aacute\301Atilde\303Ccedil\307Egrave\310Eacute\311\
Igrave\314Iacute\315Ntilde\321Ograve\322Oacute\323Otilde\325Oslash\330\
Ugrave\331Uacute\332Yacute\335agrave\340aacute\341atilde\343ccedil\347\
egrave\350eacute\351igrave\354iacute\355ntilde\361ograve\362oacute\363\
otilde\365oslash\370ugrave\371uacute\372yacute\375"     /* 6 */
    };

    for (; *s != '\0'; s++, p++) {
        if (*s != '&') {
            *p = *s;
            continue;
        }
        /* find end of entity */
        for (i = 1; s[i] != ';' && s[i] != '\0'; i++) {
            continue;
        }

        if (s[i] == '\0') {     /* treat as normal data */
            *p = *s;
            continue;
        }

        /* is it numeric ? */
        if (s[1] == '#') {
            for (j = 2, val = 0; j < i && ap_isdigit(s[j]); j++) {
                val = val * 10 + s[j] - '0';
            }
            s += i;
            if (j < i || val <= 8 || (val >= 11 && val <= 31) ||
                (val >= 127 && val <= 160) || val >= 256) {
                p--;            /* no data to output */
            }
            else {
                *p = RAW_ASCII_CHAR(val);
            }
        }
        else {
            j = i - 1;
            if (j > MAXENTLEN || entlist[j] == NULL) {
                /* wrong length */
                *p = '&';
                continue;       /* skip it */
            }
            for (ents = entlist[j]; *ents != '\0'; ents += i) {
                if (strncmp(s + 1, ents, j) == 0) {
                    break;
                }
            }

            if (*ents == '\0') {
                *p = '&';       /* unknown */
            }
            else {
                *p = RAW_ASCII_CHAR(((const unsigned char *) ents)[j]);
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

static char *get_tag(pool *p, FILE *in, char *tag, int tagbuf_len, int dodecode)
{
    char *t = tag, *tag_val, c, term;

    /* makes code below a little less cluttered */
    --tagbuf_len;

    do {                        /* skip whitespace */
        GET_CHAR(in, c, NULL, p);
    } while (ap_isspace(c));

    /* tags can't start with - */
    if (c == '-') {
        GET_CHAR(in, c, NULL, p);
        if (c == '-') {
            do {
                GET_CHAR(in, c, NULL, p);
            } while (ap_isspace(c));
            if (c == '>') {
                ap_cpystrn(tag, "done", tagbuf_len);
                return tag;
            }
        }
        return NULL;            /* failed */
    }

    /* find end of tag name */
    while (1) {
        if (t - tag == tagbuf_len) {
            *t = '\0';
            return NULL;
        }
        if (c == '=' || ap_isspace(c)) {
            break;
        }
        *(t++) = ap_tolower(c);
        GET_CHAR(in, c, NULL, p);
    }

    *t++ = '\0';
    tag_val = t;

    while (ap_isspace(c)) {
        GET_CHAR(in, c, NULL, p);       /* space before = */
    }
    if (c != '=') {
        ungetc(c, in);
        return NULL;
    }

    do {
        GET_CHAR(in, c, NULL, p);       /* space after = */
    } while (ap_isspace(c));

    /* we should allow a 'name' as a value */

    if (c != '"' && c != '\'') {
        return NULL;
    }
    term = c;
    while (1) {
        GET_CHAR(in, c, NULL, p);
        if (t - tag == tagbuf_len) {
            *t = '\0';
            return NULL;
        }
/* Want to accept \" as a valid character within a string. */
        if (c == '\\') {
            *(t++) = c;         /* Add backslash */
            GET_CHAR(in, c, NULL, p);
            if (c == term) {    /* Only if */
                *(--t) = c;     /* Replace backslash ONLY for terminator */
            }
        }
        else if (c == term) {
            break;
        }
        *(t++) = c;
    }
    *t = '\0';
    if (dodecode) {
        decodehtml(tag_val);
    }
    return ap_pstrdup(p, tag_val);
}

static int get_directive(FILE *in, char *dest, size_t len, pool *p)
{
    char *d = dest;
    char c;

    /* make room for nul terminator */
    --len;

    /* skip initial whitespace */
    while (1) {
        GET_CHAR(in, c, 1, p);
        if (!ap_isspace(c)) {
            break;
        }
    }
    /* now get directive */
    while (1) {
	if (d == len + dest) {
	    return 1;
	}
        *d++ = ap_tolower(c);
        GET_CHAR(in, c, 1, p);
        if (ap_isspace(c)) {
            break;
        }
    }
    *d = '\0';
    return 0;
}

/*
 * Do variable substitution on strings
 */
static void parse_string(request_rec *r, const char *in, char *out,
			size_t length, int leave_name)
{
    char ch;
    char *next = out;
    char *end_out;

    /* leave room for nul terminator */
    end_out = out + length - 1;

    while ((ch = *in++) != '\0') {
        switch (ch) {
        case '\\':
	    if (next == end_out) {
		/* truncated */
		*next = '\0';
		return;
	    }
            if (*in == '$') {
                *next++ = *in++;
            }
            else {
                *next++ = ch;
            }
            break;
        case '$':
            {
		char var[MAX_STRING_LEN];
		const char *start_of_var_name;
		const char *end_of_var_name;	/* end of var name + 1 */
		const char *expansion;
		const char *val;
		size_t l;

		/* guess that the expansion won't happen */
		expansion = in - 1;
		if (*in == '{') {
		    ++in;
		    start_of_var_name = in;
		    in = strchr(in, '}');
		    if (in == NULL) {
                        ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR,
				    r, "Missing '}' on variable \"%s\"",
				    expansion);
                        *next = '\0';
                        return;
                    }
		    end_of_var_name = in;
		    ++in;
		}
		else {
		    start_of_var_name = in;
		    while (ap_isalnum(*in) || *in == '_') {
			++in;
		    }
		    end_of_var_name = in;
		}
		/* what a pain, too bad there's no table_getn where you can
		 * pass a non-nul terminated string */
		l = end_of_var_name - start_of_var_name;
		if (l != 0) {
		    l = (l > sizeof(var) - 1) ? (sizeof(var) - 1) : l;
		    memcpy(var, start_of_var_name, l);
		    var[l] = '\0';

		    val = ap_table_get(r->subprocess_env, var);
		    if (val) {
			expansion = val;
			l = strlen(expansion);
		    }
		    else if (leave_name) {
			l = in - expansion;
		    }
		    else {
			break;	/* no expansion to be done */
		    }
		}
		else {
		    /* zero-length variable name causes just the $ to be copied */
		    l = 1;
		}
		l = (l + next > end_out) ? (end_out - next) : l;
		memcpy(next, expansion, l);
		next += l;
                break;
            }
        default:
	    if (next == end_out) {
		/* truncated */
		*next = '\0';
		return;
	    }
            *next++ = ch;
            break;
        }
    }
    *next = '\0';
    return;
}

/* --------------------------- Action handlers ---------------------------- */

static int include_cgi(char *s, request_rec *r)
{
    request_rec *rr = ap_sub_req_lookup_uri(s, r);
    int rr_status;

    if (rr->status != HTTP_OK) {
        return -1;
    }

    /* No hardwired path info or query allowed */

    if ((rr->path_info && rr->path_info[0]) || rr->args) {
        return -1;
    }
    if (rr->finfo.st_mode == 0) {
        return -1;
    }

    /* Script gets parameters of the *document*, for back compatibility */

    rr->path_info = r->path_info;       /* hard to get right; see mod_cgi.c */
    rr->args = r->args;

    /* Force sub_req to be treated as a CGI request, even if ordinary
     * typing rules would have called it something else.
     */

    rr->content_type = CGI_MAGIC_TYPE;

    /* Run it. */

    rr_status = ap_run_sub_req(rr);
    if (ap_is_HTTP_REDIRECT(rr_status)) {
        const char *location = ap_table_get(rr->headers_out, "Location");
        location = ap_escape_html(rr->pool, location);
        ap_rvputs(r, "<A HREF=\"", location, "\">", location, "</A>", NULL);
    }

    ap_destroy_sub_req(rr);
#if !defined(WIN32) && !defined(NETWARE)
    ap_chdir_file(r->filename);
#endif

    return 0;
}

/* ensure that path is relative, and does not contain ".." elements
 * ensentially ensure that it does not match the regex:
 * (^/|(^|/)\.\.(/|$))
 * XXX: this needs os abstraction... consider c:..\foo in win32
 * ???: No, c:../foo is not relative to ., it's potentially on another volume
 */
static int is_only_below(const char *path)
{
#ifdef HAVE_DRIVE_LETTERS
    if (path[1] == ':')
	return 0;
#endif
#ifdef NETWARE
    if (strchr(path, ':'))
	return 0;
#endif
    if (path[0] == '/') {
	return 0;
    }
    if (path[0] == '.' && path[1] == '.'
	&& (path[2] == '\0' || path[2] == '/')) {
	return 0;
    }
    while (*path) {
	if (*path == '/' && path[1] == '.' && path[2] == '.'
	    && (path[3] == '\0' || path[3] == '/')) {
	    return 0;
	}
	++path;
    }
    return 1;
}

static int handle_include(FILE *in, request_rec *r, const char *error, int noexec)
{
    char tag[MAX_STRING_LEN];
    char parsed_string[MAX_STRING_LEN];
    char *tag_val;

    while (1) {
        if (!(tag_val = get_tag(r->pool, in, tag, sizeof(tag), 1))) {
            return 1;
        }
        if (!strcmp(tag, "file") || !strcmp(tag, "virtual")) {
            request_rec *rr = NULL;
            char *error_fmt = NULL;

            parse_string(r, tag_val, parsed_string, sizeof(parsed_string), 0);
            if (tag[0] == 'f') {
                /* be safe; only files in this directory or below allowed */
		if (!is_only_below(parsed_string)) {
                    error_fmt = "unable to include file \"%s\" "
                        "in parsed file %s";
                }
                else {
                    rr = ap_sub_req_lookup_file(parsed_string, r);
                }
            }
            else {
                rr = ap_sub_req_lookup_uri(parsed_string, r);
            }

            if (!error_fmt && rr->status != HTTP_OK) {
                error_fmt = "unable to include \"%s\" in parsed file %s";
            }

            if (!error_fmt && noexec && rr->content_type
                && (strncmp(rr->content_type, "text/", 5))) {
                error_fmt = "unable to include potential exec \"%s\" "
                    "in parsed file %s";
            }
            if (error_fmt == NULL) {
		/* try to avoid recursive includes.  We do this by walking
		 * up the r->main list of subrequests, and at each level
		 * walking back through any internal redirects.  At each
		 * step, we compare the filenames and the URIs.  
		 *
		 * The filename comparison catches a recursive include
		 * with an ever-changing URL, eg.
		 * <!--#include virtual=
		 *      "$REQUEST_URI/$QUERY_STRING?$QUERY_STRING/x"-->
		 * which, although they would eventually be caught because
		 * we have a limit on the length of files, etc., can 
		 * recurse for a while.
		 *
		 * The URI comparison catches the case where the filename
		 * is changed while processing the request, so the 
		 * current name is never the same as any previous one.
		 * This can happen with "DocumentRoot /foo" when you
		 * request "/" on the server and it includes "/".
		 * This only applies to modules such as mod_dir that 
		 * (somewhat improperly) mess with r->filename outside 
		 * of a filename translation phase.
		 */
		int founddupe = 0;
                request_rec *p;
                for (p = r; p != NULL && !founddupe; p = p->main) {
		    request_rec *q;
		    for (q = p; q != NULL; q = q->prev) {
			if ( (q->filename && strcmp(q->filename, rr->filename) == 0) ||
			     (strcmp(q->uri, rr->uri) == 0) ){
			    founddupe = 1;
			    break;
			}
		    }
		}

                if (p != NULL) {
                    error_fmt = "Recursive include of \"%s\" "
                        "in parsed file %s";
                }
            }

	    /* see the Kludge in send_parsed_file for why */
	    if (rr) 
		ap_set_module_config(rr->request_config, &includes_module, r);

            if (!error_fmt && ap_run_sub_req(rr)) {
                error_fmt = "unable to include \"%s\" in parsed file %s";
            }
#if !defined(WIN32) && !defined(NETWARE)
            ap_chdir_file(r->filename);
#endif
            if (error_fmt) {
                ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR,
			    r, error_fmt, tag_val, r->filename);
                ap_rputs(error, r);
            }

	    if (rr != NULL) {
		ap_destroy_sub_req(rr);
            }
        }
        else if (!strcmp(tag, "done")) {
            return 0;
        }
        else {
            ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
                        "unknown parameter \"%s\" to tag include in %s",
                        tag, r->filename);
            ap_rputs(error, r);
        }
    }
}

typedef struct {
#ifdef TPF
    TPF_FORK_CHILD t;
#endif
    request_rec *r;
    char *s;
} include_cmd_arg;

static int include_cmd_child(void *arg, child_info *pinfo)
{
    request_rec *r = ((include_cmd_arg *) arg)->r;
    char *s = ((include_cmd_arg *) arg)->s;
    table *env = r->subprocess_env;
    int child_pid = 0;
#ifdef DEBUG_INCLUDE_CMD
#ifdef OS2
    /* under OS/2 /dev/tty is referenced as con */
    FILE *dbg = fopen("con", "w");
#else
    FILE *dbg = fopen("/dev/tty", "w");
#endif
#endif
#if !defined(WIN32) && !defined(OS2)
    char err_string[MAX_STRING_LEN];
#endif

#ifdef DEBUG_INCLUDE_CMD
    fprintf(dbg, "Attempting to include command '%s'\n", s);
#endif

    if (r->path_info && r->path_info[0] != '\0') {
        request_rec *pa_req;

        ap_table_setn(env, "PATH_INFO", ap_escape_shell_cmd(r->pool, r->path_info));

        pa_req = ap_sub_req_lookup_uri(ap_escape_uri(r->pool, r->path_info), r);
        if (pa_req->filename) {
            ap_table_setn(env, "PATH_TRANSLATED",
                      ap_pstrcat(r->pool, pa_req->filename, pa_req->path_info,
                              NULL));
        }
    }

    if (r->args) {
        char *arg_copy = ap_pstrdup(r->pool, r->args);

        ap_table_setn(env, "QUERY_STRING", r->args);
        ap_unescape_url(arg_copy);
        ap_table_setn(env, "QUERY_STRING_UNESCAPED",
                  ap_escape_shell_cmd(r->pool, arg_copy));
    }

    ap_error_log2stderr(r->server);

#ifdef DEBUG_INCLUDE_CMD
    fprintf(dbg, "Attempting to exec '%s'\n", s);
#endif
#ifdef TPF
    return (0);
#else
    ap_cleanup_for_exec();
    /* set shellcmd flag to pass arg to SHELL_PATH */
    child_pid = ap_call_exec(r, pinfo, s, ap_create_environment(r->pool, env),
			     1);
#if defined(WIN32) || defined(OS2)
    return (child_pid);
#else
    /* Oh, drat.  We're still here.  The log file descriptors are closed,
     * so we have to whimper a complaint onto stderr...
     */

#ifdef DEBUG_INCLUDE_CMD
    fprintf(dbg, "Exec failed\n");
#endif
    ap_snprintf(err_string, sizeof(err_string),
                "exec of %s failed, reason: %s (errno = %d)\n",
                SHELL_PATH, strerror(errno), errno);
    write(STDERR_FILENO, err_string, strlen(err_string));
    exit(0);
    /* NOT REACHED */
    return (child_pid);
#endif /* WIN32 */
#endif /* TPF */
}

static int include_cmd(char *s, request_rec *r)
{
    include_cmd_arg arg;
    BUFF *script_in;

    arg.r = r;
    arg.s = s;
#ifdef TPF
    arg.t.filename = r->filename;
    arg.t.subprocess_env = r->subprocess_env;
    arg.t.prog_type = FORK_FILE;
#endif

    if (!ap_bspawn_child(r->pool, include_cmd_child, &arg,
			 kill_after_timeout, NULL, &script_in, NULL)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, r,
		     "couldn't spawn include command");
        return -1;
    }

    ap_send_fb(script_in, r);
    ap_bclose(script_in);
    return 0;
}

static int handle_exec(FILE *in, request_rec *r, const char *error)
{
    char tag[MAX_STRING_LEN];
    char *tag_val;
    char *file = r->filename;
    char parsed_string[MAX_STRING_LEN];

    while (1) {
        if (!(tag_val = get_tag(r->pool, in, tag, sizeof(tag), 1))) {
            return 1;
        }
        if (!strcmp(tag, "cmd")) {
            parse_string(r, tag_val, parsed_string, sizeof(parsed_string), 1);
            if (include_cmd(parsed_string, r) == -1) {
                ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
                            "execution failure for parameter \"%s\" "
                            "to tag exec in file %s",
                            tag, r->filename);
                ap_rputs(error, r);
            }
            /* just in case some stooge changed directories */
#if !defined(WIN32) && !defined(NETWARE)
            ap_chdir_file(r->filename);
#endif
        }
        else if (!strcmp(tag, "cgi")) {
            parse_string(r, tag_val, parsed_string, sizeof(parsed_string), 0);
            if (include_cgi(parsed_string, r) == -1) {
                ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
                            "invalid CGI ref \"%s\" in %s", tag_val, file);
                ap_rputs(error, r);
            }
            /* grumble groan */
#if !defined(WIN32) && !defined(NETWARE)
            ap_chdir_file(r->filename);
#endif
        }
        else if (!strcmp(tag, "done")) {
            return 0;
        }
        else {
            ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
                        "unknown parameter \"%s\" to tag exec in %s",
                        tag, file);
            ap_rputs(error, r);
        }
    }

}

static int handle_echo(FILE *in, request_rec *r, const char *error)
{
    char tag[MAX_STRING_LEN];
    char *tag_val;
    enum {E_NONE, E_URL, E_ENTITY} encode;

    encode = E_ENTITY;

    while (1) {
        if (!(tag_val = get_tag(r->pool, in, tag, sizeof(tag), 1))) {
            return 1;
        }
        if (!strcmp(tag, "var")) {
            const char *val = ap_table_get(r->subprocess_env, tag_val);

            if (val) {
		if (encode == E_NONE) {
		    ap_rputs(val, r);
		}
		else if (encode == E_URL) {
		    ap_rputs(ap_escape_uri(r->pool, val), r);
		}
		else if (encode == E_ENTITY) {
		    ap_rputs(ap_escape_html(r->pool, val), r);
		}
            }
            else {
                ap_rputs("(none)", r);
            }
        }
        else if (!strcmp(tag, "done")) {
            return 0;
        }
	else if (!strcmp(tag, "encoding")) {
	    if (!strcasecmp(tag_val, "none")) encode = E_NONE;
	    else if (!strcasecmp(tag_val, "url")) encode = E_URL;
	    else if (!strcasecmp(tag_val, "entity")) encode = E_ENTITY;
	    else {
		ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
			    "unknown value \"%s\" to parameter \"encoding\" of "
			    "tag echo in %s",
			    tag_val, r->filename);
		ap_rputs(error, r);
	    }
	}

        else {
            ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
                        "unknown parameter \"%s\" to tag echo in %s",
                        tag, r->filename);
            ap_rputs(error, r);
        }
    }
}

#ifdef USE_PERL_SSI
static int handle_perl(FILE *in, request_rec *r, const char *error)
{
    char tag[MAX_STRING_LEN];
    char parsed_string[MAX_STRING_LEN];
    char *tag_val;
    SV *sub = Nullsv;
    AV *av = newAV();

    if (ap_allow_options(r) & OPT_INCNOEXEC) {
        ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
		      "#perl SSI disallowed by IncludesNoExec in %s",
		      r->filename);
        return DECLINED;
    }
    while (1) {
        if (!(tag_val = get_tag(r->pool, in, tag, sizeof(tag), 1))) {
            break;
        }
        if (strnEQ(tag, "sub", 3)) {
            sub = newSVpv(tag_val, 0);
        }
        else if (strnEQ(tag, "arg", 3)) {
            parse_string(r, tag_val, parsed_string, sizeof(parsed_string), 0);
            av_push(av, newSVpv(parsed_string, 0));
        }
        else if (strnEQ(tag, "done", 4)) {
            break;
        }
    }
    perl_stdout2client(r);
    perl_setup_env(r);
    perl_call_handler(sub, r, av);
    return OK;
}
#endif

/* error and tf must point to a string with room for at 
 * least MAX_STRING_LEN characters 
 */
static int handle_config(FILE *in, request_rec *r, char *error, char *tf,
                         int *sizefmt)
{
    char tag[MAX_STRING_LEN];
    char *tag_val;
    char parsed_string[MAX_STRING_LEN];
    table *env = r->subprocess_env;

    while (1) {
        if (!(tag_val = get_tag(r->pool, in, tag, sizeof(tag), 0))) {
            return 1;
        }
        if (!strcmp(tag, "errmsg")) {
            parse_string(r, tag_val, error, MAX_STRING_LEN, 0);
        }
        else if (!strcmp(tag, "timefmt")) {
            time_t date = r->request_time;

            parse_string(r, tag_val, tf, MAX_STRING_LEN, 0);
            ap_table_setn(env, "DATE_LOCAL", ap_ht_time(r->pool, date, tf, 0));
            ap_table_setn(env, "DATE_GMT", ap_ht_time(r->pool, date, tf, 1));
            ap_table_setn(env, "LAST_MODIFIED",
                      ap_ht_time(r->pool, r->finfo.st_mtime, tf, 0));
        }
        else if (!strcmp(tag, "sizefmt")) {
            parse_string(r, tag_val, parsed_string, sizeof(parsed_string), 0);
            decodehtml(parsed_string);
            if (!strcmp(parsed_string, "bytes")) {
                *sizefmt = SIZEFMT_BYTES;
            }
            else if (!strcmp(parsed_string, "abbrev")) {
                *sizefmt = SIZEFMT_KMG;
            }
        }
        else if (!strcmp(tag, "done")) {
            return 0;
        }
        else {
            ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
                        "unknown parameter \"%s\" to tag config in %s",
                        tag, r->filename);
            ap_rputs(error, r);
        }
    }
}


static int find_file(request_rec *r, const char *directive, const char *tag,
                     char *tag_val, struct stat *finfo, const char *error)
{
    char *to_send = tag_val;
    request_rec *rr = NULL;
    int ret=0;
    char *error_fmt = NULL;

    if (!strcmp(tag, "file")) {
        /* be safe; only files in this directory or below allowed */
        if (!is_only_below(tag_val)) {
            error_fmt = "unable to access file \"%s\" "
                        "in parsed file %s";
        }
        else {
            ap_getparents(tag_val);    /* get rid of any nasties */
            rr = ap_sub_req_lookup_file(tag_val, r);

            if (rr->status == HTTP_OK && rr->finfo.st_mode != 0) {
                to_send = rr->filename;
                if (stat(to_send, finfo)) {
                    error_fmt = "unable to get information about \"%s\" "
                                "in parsed file %s";
                }
            }
            else {
                error_fmt = "unable to lookup information about \"%s\" "
                            "in parsed file %s";
            }
        }

        if (error_fmt) {
            ret = -1;
            ap_log_rerror(APLOG_MARK, APLOG_ERR, r, error_fmt, to_send, r->filename);
            ap_rputs(error, r);
        }

        if (rr) ap_destroy_sub_req(rr);
        
        return ret;
    }
    else if (!strcmp(tag, "virtual")) {
        rr = ap_sub_req_lookup_uri(tag_val, r);

        if (rr->status == HTTP_OK && rr->finfo.st_mode != 0) {
            memcpy((char *) finfo, (const char *) &rr->finfo,
                   sizeof(struct stat));
            ap_destroy_sub_req(rr);
            return 0;
        }
        else {
            ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
                        "unable to get information about \"%s\" "
                        "in parsed file %s",
                        tag_val, r->filename);
            ap_rputs(error, r);
            ap_destroy_sub_req(rr);
            return -1;
        }
    }
    else {
        ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
                    "unknown parameter \"%s\" to tag %s in %s",
                    tag, directive, r->filename);
        ap_rputs(error, r);
        return -1;
    }
}


static int handle_fsize(FILE *in, request_rec *r, const char *error, int sizefmt)
{
    char tag[MAX_STRING_LEN];
    char *tag_val;
    struct stat finfo;
    char parsed_string[MAX_STRING_LEN];

    while (1) {
        if (!(tag_val = get_tag(r->pool, in, tag, sizeof(tag), 1))) {
            return 1;
        }
        else if (!strcmp(tag, "done")) {
            return 0;
        }
        else {
            parse_string(r, tag_val, parsed_string, sizeof(parsed_string), 0);
            if (!find_file(r, "fsize", tag, parsed_string, &finfo, error)) {
                if (sizefmt == SIZEFMT_KMG) {
                    ap_send_size(finfo.st_size, r);
                }
                else {
                    int l, x;
#if defined(AP_OFF_T_IS_QUAD)
                    ap_snprintf(tag, sizeof(tag), "%qd", finfo.st_size);
#else
                    ap_snprintf(tag, sizeof(tag), "%ld", finfo.st_size);
#endif
                    l = strlen(tag);    /* grrr */
                    for (x = 0; x < l; x++) {
                        if (x && (!((l - x) % 3))) {
                            ap_rputc(',', r);
                        }
                        ap_rputc(tag[x], r);
                    }
                }
            }
        }
    }
}

static int handle_flastmod(FILE *in, request_rec *r, const char *error, const char *tf)
{
    char tag[MAX_STRING_LEN];
    char *tag_val;
    struct stat finfo;
    char parsed_string[MAX_STRING_LEN];

    while (1) {
        if (!(tag_val = get_tag(r->pool, in, tag, sizeof(tag), 1))) {
            return 1;
        }
        else if (!strcmp(tag, "done")) {
            return 0;
        }
        else {
            parse_string(r, tag_val, parsed_string, sizeof(parsed_string), 0);
            if (!find_file(r, "flastmod", tag, parsed_string, &finfo, error)) {
                ap_rputs(ap_ht_time(r->pool, finfo.st_mtime, tf, 0), r);
            }
        }
    }
}

static int re_check(request_rec *r, char *string, char *rexp)
{
    regex_t *compiled;
    int regex_error;

    compiled = ap_pregcomp(r->pool, rexp, REG_EXTENDED | REG_NOSUB);
    if (compiled == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
                    "unable to compile pattern \"%s\"", rexp);
        return -1;
    }
    regex_error = ap_regexec(compiled, string, 0, (regmatch_t *) NULL, 0);
    ap_pregfree(r->pool, compiled);
    return (!regex_error);
}

enum token_type {
    token_string,
    token_and, token_or, token_not, token_eq, token_ne,
    token_rbrace, token_lbrace, token_group,
    token_ge, token_le, token_gt, token_lt
};
struct token {
    enum token_type type;
    char value[MAX_STRING_LEN];
};

/* there is an implicit assumption here that string is at most MAX_STRING_LEN-1
 * characters long...
 */
static const char *get_ptoken(request_rec *r, const char *string, struct token *token)
{
    char ch;
    int next = 0;
    int qs = 0;

    /* Skip leading white space */
    if (string == (char *) NULL) {
        return (char *) NULL;
    }
    while ((ch = *string++)) {
        if (!ap_isspace(ch)) {
            break;
        }
    }
    if (ch == '\0') {
        return (char *) NULL;
    }

    token->type = token_string; /* the default type */
    switch (ch) {
    case '(':
        token->type = token_lbrace;
        return (string);
    case ')':
        token->type = token_rbrace;
        return (string);
    case '=':
        token->type = token_eq;
        return (string);
    case '!':
        if (*string == '=') {
            token->type = token_ne;
            return (string + 1);
        }
        else {
            token->type = token_not;
            return (string);
        }
    case '\'':
        token->type = token_string;
        qs = 1;
        break;
    case '|':
        if (*string == '|') {
            token->type = token_or;
            return (string + 1);
        }
        break;
    case '&':
        if (*string == '&') {
            token->type = token_and;
            return (string + 1);
        }
        break;
    case '>':
        if (*string == '=') {
            token->type = token_ge;
            return (string + 1);
        }
        else {
            token->type = token_gt;
            return (string);
        }
    case '<':
        if (*string == '=') {
            token->type = token_le;
            return (string + 1);
        }
        else {
            token->type = token_lt;
            return (string);
        }
    default:
        token->type = token_string;
        break;
    }
    /* We should only be here if we are in a string */
    if (!qs) {
        token->value[next++] = ch;
    }

    /* 
     * Yes I know that goto's are BAD.  But, c doesn't allow me to
     * exit a loop from a switch statement.  Yes, I could use a flag,
     * but that is (IMHO) even less readable/maintainable than the goto.
     */
    /* 
     * I used the ++string throughout this section so that string
     * ends up pointing to the next token and I can just return it
     */
    for (ch = *string; ch != '\0'; ch = *++string) {
        if (ch == '\\') {
            if ((ch = *++string) == '\0') {
                goto TOKEN_DONE;
            }
            token->value[next++] = ch;
            continue;
        }
        if (!qs) {
            if (ap_isspace(ch)) {
                goto TOKEN_DONE;
            }
            switch (ch) {
            case '(':
                goto TOKEN_DONE;
            case ')':
                goto TOKEN_DONE;
            case '=':
                goto TOKEN_DONE;
            case '!':
                goto TOKEN_DONE;
            case '|':
                if (*(string + 1) == '|') {
                    goto TOKEN_DONE;
                }
                break;
            case '&':
                if (*(string + 1) == '&') {
                    goto TOKEN_DONE;
                }
                break;
            case '<':
                goto TOKEN_DONE;
            case '>':
                goto TOKEN_DONE;
            }
            token->value[next++] = ch;
        }
        else {
            if (ch == '\'') {
                qs = 0;
                ++string;
                goto TOKEN_DONE;
            }
            token->value[next++] = ch;
        }
    }
  TOKEN_DONE:
    /* If qs is still set, I have an unmatched ' */
    if (qs) {
        ap_rputs("\nUnmatched '\n", r);
        next = 0;
    }
    token->value[next] = '\0';
    return (string);
}


/*
 * Hey I still know that goto's are BAD.  I don't think that I've ever
 * used two in the same project, let alone the same file before.  But,
 * I absolutely want to make sure that I clean up the memory in all
 * cases.  And, without rewriting this completely, the easiest way
 * is to just branch to the return code which cleans it up.
 */
/* there is an implicit assumption here that expr is at most MAX_STRING_LEN-1
 * characters long...
 */
static int parse_expr(request_rec *r, const char *expr, const char *error)
{
    struct parse_node {
        struct parse_node *left, *right, *parent;
        struct token token;
        int value, done;
    }         *root, *current, *new;
    const char *parse;
    char buffer[MAX_STRING_LEN];
    pool *expr_pool;
    int retval = 0;

    if ((parse = expr) == (char *) NULL) {
        return (0);
    }
    root = current = (struct parse_node *) NULL;
    expr_pool = ap_make_sub_pool(r->pool);

    /* Create Parse Tree */
    while (1) {
        new = (struct parse_node *) ap_palloc(expr_pool,
                                           sizeof(struct parse_node));
        new->parent = new->left = new->right = (struct parse_node *) NULL;
        new->done = 0;
        if ((parse = get_ptoken(r, parse, &new->token)) == (char *) NULL) {
            break;
        }
        switch (new->token.type) {

        case token_string:
#ifdef DEBUG_INCLUDE
            ap_rvputs(r, "     Token: string (", new->token.value, ")\n", NULL);
#endif
            if (current == (struct parse_node *) NULL) {
                root = current = new;
                break;
            }
            switch (current->token.type) {
            case token_string:
                if (current->token.value[0] != '\0') {
                    strncat(current->token.value, " ",
                         sizeof(current->token.value)
			    - strlen(current->token.value) - 1);
                }
                strncat(current->token.value, new->token.value,
                         sizeof(current->token.value)
			    - strlen(current->token.value) - 1);
		current->token.value[sizeof(current->token.value) - 1] = '\0';
                break;
            case token_eq:
            case token_ne:
            case token_and:
            case token_or:
            case token_lbrace:
            case token_not:
            case token_ge:
            case token_gt:
            case token_le:
            case token_lt:
                new->parent = current;
                current = current->right = new;
                break;
            default:
                ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
                            "Invalid expression \"%s\" in file %s",
                            expr, r->filename);
                ap_rputs(error, r);
                goto RETURN;
            }
            break;

        case token_and:
        case token_or:
#ifdef DEBUG_INCLUDE
            ap_rputs("     Token: and/or\n", r);
#endif
            if (current == (struct parse_node *) NULL) {
                ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
                            "Invalid expression \"%s\" in file %s",
                            expr, r->filename);
                ap_rputs(error, r);
                goto RETURN;
            }
            /* Percolate upwards */
            while (current != (struct parse_node *) NULL) {
                switch (current->token.type) {
                case token_string:
                case token_group:
                case token_not:
                case token_eq:
                case token_ne:
                case token_and:
                case token_or:
                case token_ge:
                case token_gt:
                case token_le:
                case token_lt:
                    current = current->parent;
                    continue;
                case token_lbrace:
                    break;
                default:
                    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
                                "Invalid expression \"%s\" in file %s",
                                expr, r->filename);
                    ap_rputs(error, r);
                    goto RETURN;
                }
                break;
            }
            if (current == (struct parse_node *) NULL) {
                new->left = root;
                new->left->parent = new;
                new->parent = (struct parse_node *) NULL;
                root = new;
            }
            else {
                new->left = current->right;
                new->left->parent = new;
                current->right = new;
                new->parent = current;
            }
            current = new;
            break;

        case token_not:
#ifdef DEBUG_INCLUDE
            ap_rputs("     Token: not\n", r);
#endif
            if (current == (struct parse_node *) NULL) {
                root = current = new;
                break;
            }
            /* Percolate upwards */
            while (current != (struct parse_node *) NULL) {
                switch (current->token.type) {
                case token_not:
                case token_eq:
                case token_ne:
                case token_and:
                case token_or:
                case token_lbrace:
                case token_ge:
                case token_gt:
                case token_le:
                case token_lt:
                    break;
                default:
                    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
                                "Invalid expression \"%s\" in file %s",
                                expr, r->filename);
                    ap_rputs(error, r);
                    goto RETURN;
                }
                break;
            /* NOTREACHED */
            }
            if (current == (struct parse_node *) NULL) {
                new->left = root;
                new->left->parent = new;
                new->parent = (struct parse_node *) NULL;
                root = new;
            }
            else {
                new->left = current->right;
                current->right = new;
                new->parent = current;
            }
            current = new;
            break;

        case token_eq:
        case token_ne:
        case token_ge:
        case token_gt:
        case token_le:
        case token_lt:
#ifdef DEBUG_INCLUDE
            ap_rputs("     Token: eq/ne/ge/gt/le/lt\n", r);
#endif
            if (current == (struct parse_node *) NULL) {
                ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
                            "Invalid expression \"%s\" in file %s",
                            expr, r->filename);
                ap_rputs(error, r);
                goto RETURN;
            }
            /* Percolate upwards */
            while (current != (struct parse_node *) NULL) {
                switch (current->token.type) {
                case token_string:
                case token_group:
                    current = current->parent;
                    continue;
                case token_lbrace:
                case token_and:
                case token_or:
                    break;
                case token_not:
                case token_eq:
                case token_ne:
                case token_ge:
                case token_gt:
                case token_le:
                case token_lt:
                default:
                    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
                                "Invalid expression \"%s\" in file %s",
                                expr, r->filename);
                    ap_rputs(error, r);
                    goto RETURN;
                }
                break;
            }
            if (current == (struct parse_node *) NULL) {
                new->left = root;
                new->left->parent = new;
                new->parent = (struct parse_node *) NULL;
                root = new;
            }
            else {
                new->left = current->right;
                new->left->parent = new;
                current->right = new;
                new->parent = current;
            }
            current = new;
            break;

        case token_rbrace:
#ifdef DEBUG_INCLUDE
            ap_rputs("     Token: rbrace\n", r);
#endif
            while (current != (struct parse_node *) NULL) {
                if (current->token.type == token_lbrace) {
                    current->token.type = token_group;
                    break;
                }
                current = current->parent;
            }
            if (current == (struct parse_node *) NULL) {
                ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
                            "Unmatched ')' in \"%s\" in file %s",
			    expr, r->filename);
                ap_rputs(error, r);
                goto RETURN;
            }
            break;

        case token_lbrace:
#ifdef DEBUG_INCLUDE
            ap_rputs("     Token: lbrace\n", r);
#endif
            if (current == (struct parse_node *) NULL) {
                root = current = new;
                break;
            }
            /* Percolate upwards */
            while (current != (struct parse_node *) NULL) {
                switch (current->token.type) {
                case token_not:
                case token_eq:
                case token_ne:
                case token_and:
                case token_or:
                case token_lbrace:
                case token_ge:
                case token_gt:
                case token_le:
                case token_lt:
                    break;
                case token_string:
                case token_group:
                default:
                    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
                                "Invalid expression \"%s\" in file %s",
                                expr, r->filename);
                    ap_rputs(error, r);
                    goto RETURN;
                }
                break;
            /* NOTREACHED */
            }
            if (current == (struct parse_node *) NULL) {
                new->left = root;
                new->left->parent = new;
                new->parent = (struct parse_node *) NULL;
                root = new;
            }
            else {
                new->left = current->right;
                current->right = new;
                new->parent = current;
            }
            current = new;
            break;
        default:
            break;
        }
    }

    /* Evaluate Parse Tree */
    current = root;
    while (current != (struct parse_node *) NULL) {
        switch (current->token.type) {
        case token_string:
#ifdef DEBUG_INCLUDE
            ap_rputs("     Evaluate string\n", r);
#endif
            parse_string(r, current->token.value, buffer, sizeof(buffer), 0);
	    ap_cpystrn(current->token.value, buffer, sizeof(current->token.value));
            current->value = (current->token.value[0] != '\0');
            current->done = 1;
            current = current->parent;
            break;

        case token_and:
        case token_or:
#ifdef DEBUG_INCLUDE
            ap_rputs("     Evaluate and/or\n", r);
#endif
            if (current->left == (struct parse_node *) NULL ||
                current->right == (struct parse_node *) NULL) {
                ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
                            "Invalid expression \"%s\" in file %s",
                            expr, r->filename);
                ap_rputs(error, r);
                goto RETURN;
            }
            if (!current->left->done) {
                switch (current->left->token.type) {
                case token_string:
                    parse_string(r, current->left->token.value,
                                 buffer, sizeof(buffer), 0);
                    ap_cpystrn(current->left->token.value, buffer,
                            sizeof(current->left->token.value));
		    current->left->value = (current->left->token.value[0] != '\0');
                    current->left->done = 1;
                    break;
                default:
                    current = current->left;
                    continue;
                }
            }
            if (!current->right->done) {
                switch (current->right->token.type) {
                case token_string:
                    parse_string(r, current->right->token.value,
                                 buffer, sizeof(buffer), 0);
                    ap_cpystrn(current->right->token.value, buffer,
                            sizeof(current->right->token.value));
		    current->right->value = (current->right->token.value[0] != '\0');
                    current->right->done = 1;
                    break;
                default:
                    current = current->right;
                    continue;
                }
            }
#ifdef DEBUG_INCLUDE
            ap_rvputs(r, "     Left: ", current->left->value ? "1" : "0",
                   "\n", NULL);
            ap_rvputs(r, "     Right: ", current->right->value ? "1" : "0",
                   "\n", NULL);
#endif
            if (current->token.type == token_and) {
                current->value = current->left->value && current->right->value;
            }
            else {
                current->value = current->left->value || current->right->value;
            }
#ifdef DEBUG_INCLUDE
            ap_rvputs(r, "     Returning ", current->value ? "1" : "0",
                   "\n", NULL);
#endif
            current->done = 1;
            current = current->parent;
            break;

        case token_eq:
        case token_ne:
#ifdef DEBUG_INCLUDE
            ap_rputs("     Evaluate eq/ne\n", r);
#endif
            if ((current->left == (struct parse_node *) NULL) ||
                (current->right == (struct parse_node *) NULL) ||
                (current->left->token.type != token_string) ||
                (current->right->token.type != token_string)) {
                ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
                            "Invalid expression \"%s\" in file %s",
                            expr, r->filename);
                ap_rputs(error, r);
                goto RETURN;
            }
            parse_string(r, current->left->token.value,
                         buffer, sizeof(buffer), 0);
            ap_cpystrn(current->left->token.value, buffer,
			sizeof(current->left->token.value));
            parse_string(r, current->right->token.value,
                         buffer, sizeof(buffer), 0);
            ap_cpystrn(current->right->token.value, buffer,
			sizeof(current->right->token.value));
            if (current->right->token.value[0] == '/') {
                int len;
                len = strlen(current->right->token.value);
                if (current->right->token.value[len - 1] == '/') {
                    current->right->token.value[len - 1] = '\0';
                }
                else {
                    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
                                "Invalid rexp \"%s\" in file %s",
                                current->right->token.value, r->filename);
                    ap_rputs(error, r);
                    goto RETURN;
                }
#ifdef DEBUG_INCLUDE
                ap_rvputs(r, "     Re Compare (", current->left->token.value,
                  ") with /", &current->right->token.value[1], "/\n", NULL);
#endif
                current->value =
                    re_check(r, current->left->token.value,
                             &current->right->token.value[1]);
            }
            else {
#ifdef DEBUG_INCLUDE
                ap_rvputs(r, "     Compare (", current->left->token.value,
                       ") with (", current->right->token.value, ")\n", NULL);
#endif
                current->value =
                    (strcmp(current->left->token.value,
                            current->right->token.value) == 0);
            }
            if (current->token.type == token_ne) {
                current->value = !current->value;
            }
#ifdef DEBUG_INCLUDE
            ap_rvputs(r, "     Returning ", current->value ? "1" : "0",
                   "\n", NULL);
#endif
            current->done = 1;
            current = current->parent;
            break;
        case token_ge:
        case token_gt:
        case token_le:
        case token_lt:
#ifdef DEBUG_INCLUDE
            ap_rputs("     Evaluate ge/gt/le/lt\n", r);
#endif
            if ((current->left == (struct parse_node *) NULL) ||
                (current->right == (struct parse_node *) NULL) ||
                (current->left->token.type != token_string) ||
                (current->right->token.type != token_string)) {
                ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
                            "Invalid expression \"%s\" in file %s",
                            expr, r->filename);
                ap_rputs(error, r);
                goto RETURN;
            }
            parse_string(r, current->left->token.value,
                         buffer, sizeof(buffer), 0);
            ap_cpystrn(current->left->token.value, buffer,
			sizeof(current->left->token.value));
            parse_string(r, current->right->token.value,
                         buffer, sizeof(buffer), 0);
            ap_cpystrn(current->right->token.value, buffer,
			sizeof(current->right->token.value));
#ifdef DEBUG_INCLUDE
            ap_rvputs(r, "     Compare (", current->left->token.value,
                   ") with (", current->right->token.value, ")\n", NULL);
#endif
            current->value =
                strcmp(current->left->token.value,
                       current->right->token.value);
            if (current->token.type == token_ge) {
                current->value = current->value >= 0;
            }
            else if (current->token.type == token_gt) {
                current->value = current->value > 0;
            }
            else if (current->token.type == token_le) {
                current->value = current->value <= 0;
            }
            else if (current->token.type == token_lt) {
                current->value = current->value < 0;
            }
            else {
                current->value = 0;     /* Don't return -1 if unknown token */
            }
#ifdef DEBUG_INCLUDE
            ap_rvputs(r, "     Returning ", current->value ? "1" : "0",
                   "\n", NULL);
#endif
            current->done = 1;
            current = current->parent;
            break;

        case token_not:
            if (current->right != (struct parse_node *) NULL) {
                if (!current->right->done) {
                    current = current->right;
                    continue;
                }
                current->value = !current->right->value;
            }
            else {
                current->value = 0;
            }
#ifdef DEBUG_INCLUDE
            ap_rvputs(r, "     Evaluate !: ", current->value ? "1" : "0",
                   "\n", NULL);
#endif
            current->done = 1;
            current = current->parent;
            break;

        case token_group:
            if (current->right != (struct parse_node *) NULL) {
                if (!current->right->done) {
                    current = current->right;
                    continue;
                }
                current->value = current->right->value;
            }
            else {
                current->value = 1;
            }
#ifdef DEBUG_INCLUDE
            ap_rvputs(r, "     Evaluate (): ", current->value ? "1" : "0",
                   "\n", NULL);
#endif
            current->done = 1;
            current = current->parent;
            break;

        case token_lbrace:
            ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
                        "Unmatched '(' in \"%s\" in file %s",
                        expr, r->filename);
            ap_rputs(error, r);
            goto RETURN;

        case token_rbrace:
            ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
                        "Unmatched ')' in \"%s\" in file %s",
                        expr, r->filename);
            ap_rputs(error, r);
            goto RETURN;

        default:
            ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
			"bad token type");
            ap_rputs(error, r);
            goto RETURN;
        }
    }

    retval = (root == (struct parse_node *) NULL) ? 0 : root->value;
  RETURN:
    ap_destroy_pool(expr_pool);
    return (retval);
}

static int handle_if(FILE *in, request_rec *r, const char *error,
                     int *conditional_status, int *printing)
{
    char tag[MAX_STRING_LEN];
    char *tag_val;
    char *expr;

    expr = NULL;
    while (1) {
        tag_val = get_tag(r->pool, in, tag, sizeof(tag), 0);
        if (!tag_val || *tag == '\0') {
            return 1;
        }
        else if (!strcmp(tag, "done")) {
	    if (expr == NULL) {
		ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
			    "missing expr in if statement: %s",
			    r->filename);
		ap_rputs(error, r);
		return 1;
	    }
            *printing = *conditional_status = parse_expr(r, expr, error);
#ifdef DEBUG_INCLUDE
            ap_rvputs(r, "**** if conditional_status=\"",
                   *conditional_status ? "1" : "0", "\"\n", NULL);
#endif
            return 0;
        }
        else if (!strcmp(tag, "expr")) {
            expr = tag_val;
#ifdef DEBUG_INCLUDE
            ap_rvputs(r, "**** if expr=\"", expr, "\"\n", NULL);
#endif
        }
        else {
            ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
                        "unknown parameter \"%s\" to tag if in %s",
                        tag, r->filename);
            ap_rputs(error, r);
        }
    }
}

static int handle_elif(FILE *in, request_rec *r, const char *error,
                       int *conditional_status, int *printing)
{
    char tag[MAX_STRING_LEN];
    char *tag_val;
    char *expr;

    expr = NULL;
    while (1) {
        tag_val = get_tag(r->pool, in, tag, sizeof(tag), 0);
        if (!tag_val || *tag == '\0') {
            return 1;
        }
        else if (!strcmp(tag, "done")) {
#ifdef DEBUG_INCLUDE
            ap_rvputs(r, "**** elif conditional_status=\"",
                   *conditional_status ? "1" : "0", "\"\n", NULL);
#endif
            if (*conditional_status) {
                *printing = 0;
                return (0);
            }
	    if (expr == NULL) {
		ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
			    "missing expr in elif statement: %s",
			    r->filename);
		ap_rputs(error, r);
		return 1;
	    }
            *printing = *conditional_status = parse_expr(r, expr, error);
#ifdef DEBUG_INCLUDE
            ap_rvputs(r, "**** elif conditional_status=\"",
                   *conditional_status ? "1" : "0", "\"\n", NULL);
#endif
            return 0;
        }
        else if (!strcmp(tag, "expr")) {
            expr = tag_val;
#ifdef DEBUG_INCLUDE
            ap_rvputs(r, "**** if expr=\"", expr, "\"\n", NULL);
#endif
        }
        else {
            ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
                        "unknown parameter \"%s\" to tag if in %s",
                        tag, r->filename);
            ap_rputs(error, r);
        }
    }
}

static int handle_else(FILE *in, request_rec *r, const char *error,
                       int *conditional_status, int *printing)
{
    char tag[MAX_STRING_LEN];

    if (!get_tag(r->pool, in, tag, sizeof(tag), 1)) {
        return 1;
    }
    else if (!strcmp(tag, "done")) {
#ifdef DEBUG_INCLUDE
        ap_rvputs(r, "**** else conditional_status=\"",
               *conditional_status ? "1" : "0", "\"\n", NULL);
#endif
        *printing = !(*conditional_status);
        *conditional_status = 1;
        return 0;
    }
    else {
        ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
                    "else directive does not take tags in %s",
		    r->filename);
        if (*printing) {
            ap_rputs(error, r);
        }
        return -1;
    }
}

static int handle_endif(FILE *in, request_rec *r, const char *error,
                        int *conditional_status, int *printing)
{
    char tag[MAX_STRING_LEN];

    if (!get_tag(r->pool, in, tag, sizeof(tag), 1)) {
        return 1;
    }
    else if (!strcmp(tag, "done")) {
#ifdef DEBUG_INCLUDE
        ap_rvputs(r, "**** endif conditional_status=\"",
               *conditional_status ? "1" : "0", "\"\n", NULL);
#endif
        *printing = 1;
        *conditional_status = 1;
        return 0;
    }
    else {
        ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
                    "endif directive does not take tags in %s",
		    r->filename);
        ap_rputs(error, r);
        return -1;
    }
}

static int handle_set(FILE *in, request_rec *r, const char *error)
{
    char tag[MAX_STRING_LEN];
    char parsed_string[MAX_STRING_LEN];
    char *tag_val;
    char *var;

    var = (char *) NULL;
    while (1) {
        if (!(tag_val = get_tag(r->pool, in, tag, sizeof(tag), 1))) {
            return 1;
        }
        else if (!strcmp(tag, "done")) {
            return 0;
        }
        else if (!strcmp(tag, "var")) {
            var = tag_val;
        }
        else if (!strcmp(tag, "value")) {
            if (var == (char *) NULL) {
                ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
                            "variable must precede value in set directive in %s",
			    r->filename);
                ap_rputs(error, r);
                return -1;
            }
            parse_string(r, tag_val, parsed_string, sizeof(parsed_string), 0);
            ap_table_setn(r->subprocess_env, var, ap_pstrdup(r->pool, parsed_string));
        }
        else {
            ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
                        "Invalid tag for set directive in %s", r->filename);
            ap_rputs(error, r);
            return -1;
        }
    }
}

static int handle_printenv(FILE *in, request_rec *r, const char *error)
{
    char tag[MAX_STRING_LEN];
    char *tag_val;
    array_header *arr = ap_table_elts(r->subprocess_env);
    table_entry *elts = (table_entry *) arr->elts;
    int i;

    if (!(tag_val = get_tag(r->pool, in, tag, sizeof(tag), 1))) {
        return 1;
    }
    else if (!strcmp(tag, "done")) {
        for (i = 0; i < arr->nelts; ++i) {
            ap_rvputs(r, ap_escape_html(r->pool, elts[i].key), "=", 
		ap_escape_html(r->pool, elts[i].val), "\n", NULL);
        }
        return 0;
    }
    else {
        ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
                    "printenv directive does not take tags in %s",
		    r->filename);
        ap_rputs(error, r);
        return -1;
    }
}



/* -------------------------- The main function --------------------------- */

/* This is a stub which parses a file descriptor. */

static void send_parsed_content(FILE *f, request_rec *r)
{
#ifdef NETWARE
    /* NetWare has a fixed lengh stack.  Since MAX_STRING_LEN is set
       to 8k, one call to this function allocates 24k of stack space.
       During a server-side include evaluation this function is
       called recusively, allocating 24k each time.  Obviously it 
       doesn't take long to blow a 64k stack which is the default
       for Apache for NetWare.  Since MAX_STRING_LEN is used all
       throughout the Apache code, we should rethink using a default
       of 8k especially in recursive functions.
    */
    char directive[512], error[512];
    char timefmt[512];
#else
    char directive[MAX_STRING_LEN], error[MAX_STRING_LEN];
    char timefmt[MAX_STRING_LEN];
#endif
    int noexec = ap_allow_options(r) & OPT_INCNOEXEC;
    int ret, sizefmt;
    int if_nesting;
    int printing;
    int conditional_status;

    ap_cpystrn(error, DEFAULT_ERROR_MSG, sizeof(error));
    ap_cpystrn(timefmt, DEFAULT_TIME_FORMAT, sizeof(timefmt));
    sizefmt = SIZEFMT_KMG;

/*  Turn printing on */
    printing = conditional_status = 1;
    if_nesting = 0;

#if !defined(WIN32) && !defined(NETWARE)
    ap_chdir_file(r->filename);
#endif
    if (r->args) {              /* add QUERY stuff to env cause it ain't yet */
        char *arg_copy = ap_pstrdup(r->pool, r->args);

        ap_table_setn(r->subprocess_env, "QUERY_STRING", r->args);
        ap_unescape_url(arg_copy);
        ap_table_setn(r->subprocess_env, "QUERY_STRING_UNESCAPED",
                  ap_escape_shell_cmd(r->pool, arg_copy));
    }

    while (1) {
        if (!find_string(f, STARTING_SEQUENCE, r, printing)) {
            if (get_directive(f, directive, sizeof(directive), r->pool)) {
		ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
			    "mod_include: error reading directive in %s",
			    r->filename);
		ap_rputs(error, r);
                return;
            }
            if (!strcmp(directive, "if")) {
                ret = 0;
                if (!printing) {
                    if_nesting++;
                }
                else {
                    ret = handle_if(f, r, error, &conditional_status,
                                    &printing);
                    if_nesting = 0;
                }
            }
            else if (!strcmp(directive, "else")) {
                ret = 0;
                if (!if_nesting) {
                    ret = handle_else(f, r, error, &conditional_status,
                                      &printing);
                }
            }
            else if (!strcmp(directive, "elif")) {
                ret = 0;
                if (!if_nesting) {
                    ret = handle_elif(f, r, error, &conditional_status,
                                      &printing);
                }
            }
            else if (!strcmp(directive, "endif")) {
                ret = 0;
                if (!if_nesting) {
                    ret = handle_endif(f, r, error, &conditional_status,
                                       &printing);
                }
                else {
                    if_nesting--;
                }
            }
            else if (!printing) {
                continue;
            }
            else if (!strcmp(directive, "exec")) {
                if (noexec) {
                    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
				  "exec used but not allowed in %s",
				  r->filename);
                    if (printing) {
                        ap_rputs(error, r);
                    }
                    ret = find_string(f, ENDING_SEQUENCE, r, 0);
                }
                else {
                    ret = handle_exec(f, r, error);
                }
            }
            else if (!strcmp(directive, "config")) {
                ret = handle_config(f, r, error, timefmt, &sizefmt);
            }
            else if (!strcmp(directive, "set")) {
                ret = handle_set(f, r, error);
            }
            else if (!strcmp(directive, "include")) {
                ret = handle_include(f, r, error, noexec);
            }
            else if (!strcmp(directive, "echo")) {
                ret = handle_echo(f, r, error);
            }
            else if (!strcmp(directive, "fsize")) {
                ret = handle_fsize(f, r, error, sizefmt);
            }
            else if (!strcmp(directive, "flastmod")) {
                ret = handle_flastmod(f, r, error, timefmt);
            }
            else if (!strcmp(directive, "printenv")) {
                ret = handle_printenv(f, r, error);
            }
#ifdef USE_PERL_SSI
            else if (!strcmp(directive, "perl")) {
                ret = handle_perl(f, r, error);
            }
#endif
            else {
                ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
			      "unknown directive \"%s\" "
			      "in parsed doc %s",
			      directive, r->filename);
                if (printing) {
                    ap_rputs(error, r);
                }
                ret = find_string(f, ENDING_SEQUENCE, r, 0);
            }
            if (ret) {
                ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
			      "premature EOF in parsed file %s",
			      r->filename);
                return;
            }
        }
        else {
            return;
        }
    }
}

/*****************************************************************
 *
 * XBITHACK.  Sigh...  NB it's configurable per-directory; the compile-time
 * option only changes the default.
 */

module includes_module;
enum xbithack {
    xbithack_off, xbithack_on, xbithack_full
};

#ifdef XBITHACK
#define DEFAULT_XBITHACK xbithack_full
#else
#define DEFAULT_XBITHACK xbithack_off
#endif

static void *create_includes_dir_config(pool *p, char *dummy)
{
    enum xbithack *result = (enum xbithack *) ap_palloc(p, sizeof(enum xbithack));
    *result = DEFAULT_XBITHACK;
    return result;
}

static const char *set_xbithack(cmd_parms *cmd, void *xbp, char *arg)
{
    enum xbithack *state = (enum xbithack *) xbp;

    if (!strcasecmp(arg, "off")) {
        *state = xbithack_off;
    }
    else if (!strcasecmp(arg, "on")) {
        *state = xbithack_on;
    }
    else if (!strcasecmp(arg, "full")) {
        *state = xbithack_full;
    }
    else {
        return "XBitHack must be set to Off, On, or Full";
    }

    return NULL;
}

static int send_parsed_file(request_rec *r)
{
    FILE *f;
    enum xbithack *state =
    (enum xbithack *) ap_get_module_config(r->per_dir_config, &includes_module);
    int errstatus;
    request_rec *parent;

    if (!(ap_allow_options(r) & OPT_INCLUDES)) {
        return DECLINED;
    }
    r->allowed |= (1 << M_GET);
    if (r->method_number != M_GET) {
        return DECLINED;
    }
    if (r->finfo.st_mode == 0) {
        ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
		    "File does not exist: %s",
                    (r->path_info
                     ? ap_pstrcat(r->pool, r->filename, r->path_info, NULL)
                     : r->filename));
        return HTTP_NOT_FOUND;
    }

    if (!(f = ap_pfopen(r->pool, r->filename, "r"))) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, r,
                    "file permissions deny server access: %s", r->filename);
        return HTTP_FORBIDDEN;
    }

    if ((*state == xbithack_full)
#if !defined(OS2) && !defined(WIN32) && !defined(NETWARE)
    /*  OS/2 dosen't support Groups. */
        && (r->finfo.st_mode & S_IXGRP)
#endif
        ) {
        ap_update_mtime(r, r->finfo.st_mtime);
        ap_set_last_modified(r);
    }
    if ((errstatus = ap_meets_conditions(r)) != OK) {
        return errstatus;
    }

    ap_send_http_header(r);

    if (r->header_only) {
        ap_pfclose(r->pool, f);
        return OK;
    }

#define SUB_REQ_STRING	"Sub request to mod_include"
#define PARENT_STRING	"Parent request to mod_include"

    if (ap_table_get(r->notes, SUB_REQ_STRING)) {
	/*
	 * The note is a flag to mod_include that this request
	 * should be treated as if it was a subrequest originating
	 * in the handle_include() procedure of mod_include.
	 */

	/*
	 * There is no good way to pass the parent request_rec to mod_include.
	 * Tables only take string values and there is nowhere appropriate in
	 * in the request_rec that can safely be used. So, search for the
	 * parent note by walking up the r->main list of subrequests, and at
	 * each level walking back through any internal redirects. This is
	 * the same request walking that mod_include uses in the procedure
	 * handle_include().
	 */
	request_rec *p = r->main;
	request_rec *q = p;

	while (q) {
	    if (ap_table_get(q->notes, PARENT_STRING)) {
		/* Kludge --- See below */
		ap_set_module_config(r->request_config, &includes_module, q);

		/* Create the initial environment in the parent */
		ap_add_common_vars(q);
		ap_add_cgi_vars(q);
		add_include_vars(q, DEFAULT_TIME_FORMAT);

		/* Cleanup - This should allow this technique to nest */
		ap_table_unset(r->notes, SUB_REQ_STRING);
		ap_table_unset(q->notes, PARENT_STRING);
		break;
	    }
	    if (q->prev != NULL) {
		q = q->prev;
	    }
	    else {
		p = p->main;
		q = p;
	    }
	}
    }

    if ((parent = ap_get_module_config(r->request_config, &includes_module))) {
	/* Kludge --- for nested includes, we want to keep the subprocess
	 * environment of the base document (for compatibility); that means
	 * torquing our own last_modified date as well so that the
	 * LAST_MODIFIED variable gets reset to the proper value if the
	 * nested document resets <!--#config timefmt-->.
	 * We also insist that the memory for this subrequest not be
	 * destroyed, that's dealt with in handle_include().
	 */
	r->subprocess_env = parent->subprocess_env;
	ap_pool_join(parent->pool, r->pool);
	r->finfo.st_mtime = parent->finfo.st_mtime;
    }
    else {
	/* we're not a nested include, so we create an initial
	 * environment */
        ap_add_common_vars(r);
        ap_add_cgi_vars(r);
        add_include_vars(r, DEFAULT_TIME_FORMAT);
    }
    /* XXX: this is bogus, at some point we're going to do a subrequest,
     * and when we do it we're going to be subjecting code that doesn't
     * expect to be signal-ready to SIGALRM.  There is no clean way to
     * fix this, except to put alarm support into BUFF. -djg
     */
    ap_hard_timeout("send SSI", r);

#ifdef CHARSET_EBCDIC
    /* XXX:@@@ Is the generated/included output ALWAYS in text/ebcdic format? */
    ap_bsetflag(r->connection->client, B_EBCDIC2ASCII, 1);
#endif

    send_parsed_content(f, r);

    if (parent) {
	/*
	 * All the work is finished for this subrequest. The following
	 * makes it safe for the creator of the subrequest to destroy it
	 * via ap_destroy_sub_req() once the call to ap_run_sub_req()
	 * returns. This is required since the original pool of the
	 * subrequest has been merged into the pool of the parent request
	 * of the subrequest (see Kludge above). The alternative is to
	 * NOT destroy the subrequest.
	 */
	r->pool = ap_make_sub_pool(r->pool);
    }

    ap_kill_timeout(r);
    return OK;
}

static int send_shtml_file(request_rec *r)
{
    r->content_type = "text/html";
    return send_parsed_file(r);
}

static int xbithack_handler(request_rec *r)
{
#if defined(OS2) || defined(WIN32) || defined(NETWARE)
    /* OS/2 dosen't currently support the xbithack. This is being worked on. */
    return DECLINED;
#else
    enum xbithack *state;

    if (!(r->finfo.st_mode & S_IXUSR)) {
        return DECLINED;
    }

    state = (enum xbithack *) ap_get_module_config(r->per_dir_config,
                                                &includes_module);

    if (*state == xbithack_off) {
        return DECLINED;
    }
    return send_parsed_file(r);
#endif
}

static const command_rec includes_cmds[] =
{
    {"XBitHack", set_xbithack, NULL, OR_OPTIONS, TAKE1, "Off, On, or Full"},
    {NULL}
};

static const handler_rec includes_handlers[] =
{
    {INCLUDES_MAGIC_TYPE, send_shtml_file},
    {INCLUDES_MAGIC_TYPE3, send_shtml_file},
    {"server-parsed", send_parsed_file},
    {"text/html", xbithack_handler},
    {NULL}
};

module MODULE_VAR_EXPORT includes_module =
{
    STANDARD_MODULE_STUFF,
    NULL,                       /* initializer */
    create_includes_dir_config, /* dir config creater */
    NULL,                       /* dir merger --- default is to override */
    NULL,                       /* server config */
    NULL,                       /* merge server config */
    includes_cmds,              /* command table */
    includes_handlers,          /* handlers */
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
