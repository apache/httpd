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
 * util.c: string utility things
 * 
 * 3/21/93 Rob McCool
 * 1995-96 Many changes by the Apache Group
 * 
 */

/* Debugging aid:
 * #define DEBUG            to trace all cfg_open*()/cfg_closefile() calls
 * #define DEBUG_CFG_LINES  to trace every line read from the config files
 */

#include "httpd.h"
#include "http_conf_globals.h"	/* for user_id & group_id */
#include "http_log.h"
#if defined(SUNOS4)
/* stdio.h has been read in conf.h already. Add missing prototypes here: */
extern int fgetc(FILE *);
extern char *fgets(char *s, int, FILE*);
extern int fclose(FILE *);
#endif


const char month_snames[12][4] =
{
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
};

API_EXPORT(char *) get_time()
{
    time_t t;
    char *time_string;

    t = time(NULL);
    time_string = ctime(&t);
    time_string[strlen(time_string) - 1] = '\0';
    return (time_string);
}

API_EXPORT(char *) ht_time(pool *p, time_t t, const char *fmt, int gmt)
{
    char ts[MAX_STRING_LEN];
    struct tm *tms;

    tms = (gmt ? gmtime(&t) : localtime(&t));

    /* check return code? */
    strftime(ts, MAX_STRING_LEN, fmt, tms);
    ts[MAX_STRING_LEN - 1] = '\0';
    return pstrdup(p, ts);
}

API_EXPORT(char *) gm_timestr_822(pool *p, time_t sec)
{
    static const char *const days[7] =
    {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
    char ts[50];
    struct tm *tms;

    tms = gmtime(&sec);

    /* RFC date format; as strftime '%a, %d %b %Y %T GMT' */
    ap_snprintf(ts, sizeof(ts),
		"%s, %.2d %s %d %.2d:%.2d:%.2d GMT", days[tms->tm_wday],
		tms->tm_mday, month_snames[tms->tm_mon], tms->tm_year + 1900,
		tms->tm_hour, tms->tm_min, tms->tm_sec);

    return pstrdup(p, ts);
}

/* What a pain in the ass. */
#if defined(HAVE_GMTOFF)
API_EXPORT(struct tm *) get_gmtoff(int *tz)
{
    time_t tt = time(NULL);
    struct tm *t;

    t = localtime(&tt);
    *tz = (int) (t->tm_gmtoff / 60);
    return t;
}
#else
API_EXPORT(struct tm *) get_gmtoff(int *tz)
{
    time_t tt = time(NULL);
    struct tm gmt;
    struct tm *t;
    int days, hours, minutes;

    /* Assume we are never more than 24 hours away. */
    gmt = *gmtime(&tt);		/* remember gmtime/localtime return ptr to static */
    t = localtime(&tt);		/* buffer... so be careful */
    days = t->tm_yday - gmt.tm_yday;
    hours = ((days < -1 ? 24 : 1 < days ? -24 : days * 24)
	     + t->tm_hour - gmt.tm_hour);
    minutes = hours * 60 + t->tm_min - gmt.tm_min;
    *tz = minutes;
    return t;
}
#endif


/* Match = 0, NoMatch = 1, Abort = -1
 * Based loosely on sections of wildmat.c by Rich Salz
 * Hmmm... shouldn't this really go component by component?
 */
API_EXPORT(int) strcmp_match(const char *str, const char *exp)
{
    int x, y;

    for (x = 0, y = 0; exp[y]; ++y, ++x) {
	if ((!str[x]) && (exp[y] != '*'))
	    return -1;
	if (exp[y] == '*') {
	    while (exp[++y] == '*');
	    if (!exp[y])
		return 0;
	    while (str[x]) {
		int ret;
		if ((ret = strcmp_match(&str[x++], &exp[y])) != 1)
		    return ret;
	    }
	    return -1;
	}
	else if ((exp[y] != '?') && (str[x] != exp[y]))
	    return 1;
    }
    return (str[x] != '\0');
}

API_EXPORT(int) strcasecmp_match(const char *str, const char *exp)
{
    int x, y;

    for (x = 0, y = 0; exp[y]; ++y, ++x) {
	if ((!str[x]) && (exp[y] != '*'))
	    return -1;
	if (exp[y] == '*') {
	    while (exp[++y] == '*');
	    if (!exp[y])
		return 0;
	    while (str[x]) {
		int ret;
		if ((ret = strcasecmp_match(&str[x++], &exp[y])) != 1)
		    return ret;
	    }
	    return -1;
	}
	else if ((exp[y] != '?') && (tolower(str[x]) != tolower(exp[y])))
	    return 1;
    }
    return (str[x] != '\0');
}

API_EXPORT(int) is_matchexp(const char *str)
{
    register int x;

    for (x = 0; str[x]; x++)
	if ((str[x] == '*') || (str[x] == '?'))
	    return 1;
    return 0;
}

/* This function substitutes for $0-$9, filling in regular expression
 * submatches. Pass it the same nmatch and pmatch arguments that you
 * passed regexec(). pmatch should not be greater than the maximum number
 * of subexpressions - i.e. one more than the re_nsub member of regex_t.
 *
 * input should be the string with the $-expressions, source should be the
 * string that was matched against.
 *
 * It returns the substituted string, or NULL on error.
 *
 * Parts of this code are based on Henry Spencer's regsub(), from his
 * AT&T V8 regexp package.
 */

API_EXPORT(char *) pregsub(pool *p, const char *input, const char *source,
			   size_t nmatch, regmatch_t pmatch[])
{
    const char *src = input;
    char *dest, *dst;
    char c;
    size_t no;
    int len;

    if (!source)
	return NULL;
    if (!nmatch)
	return pstrdup(p, src);

    /* First pass, find the size */

    len = 0;

    while ((c = *src++) != '\0') {
	if (c == '&')
	    no = 0;
	else if (c == '$' && isdigit(*src))
	    no = *src++ - '0';
	else
	    no = 10;

	if (no > 9) {		/* Ordinary character. */
	    if (c == '\\' && (*src == '$' || *src == '&'))
		c = *src++;
	    len++;
	}
	else if (no < nmatch && pmatch[no].rm_so < pmatch[no].rm_eo) {
	    len += pmatch[no].rm_eo - pmatch[no].rm_so;
	}

    }

    dest = dst = pcalloc(p, len + 1);

    /* Now actually fill in the string */

    src = input;

    while ((c = *src++) != '\0') {
	if (c == '&')
	    no = 0;
	else if (c == '$' && isdigit(*src))
	    no = *src++ - '0';
	else
	    no = 10;

	if (no > 9) {		/* Ordinary character. */
	    if (c == '\\' && (*src == '$' || *src == '&'))
		c = *src++;
	    *dst++ = c;
	}
	else if (no < nmatch && pmatch[no].rm_so < pmatch[no].rm_eo) {
	    len = pmatch[no].rm_eo - pmatch[no].rm_so;
	    memcpy(dst, source + pmatch[no].rm_so, len);
	    dst += len;
	}

    }
    *dst = '\0';

    return dest;
}

/*
 * Parse .. so we don't compromise security
 */
API_EXPORT(void) getparents(char *name)
{
    int l, w;

    /* Four paseses, as per RFC 1808 */
    /* a) remove ./ path segments */

    for (l = 0, w = 0; name[l] != '\0';) {
	if (name[l] == '.' && name[l + 1] == '/' && (l == 0 || name[l - 1] == '/'))
	    l += 2;
	else
	    name[w++] = name[l++];
    }

    /* b) remove trailing . path, segment */
    if (w == 1 && name[0] == '.')
	w--;
    else if (w > 1 && name[w - 1] == '.' && name[w - 2] == '/')
	w--;
    name[w] = '\0';

    /* c) remove all xx/../ segments. (including leading ../ and /../) */
    l = 0;

    while (name[l] != '\0') {
	if (name[l] == '.' && name[l + 1] == '.' && name[l + 2] == '/' &&
	    (l == 0 || name[l - 1] == '/')) {
	    register int m = l + 3, n;

	    l = l - 2;
	    if (l >= 0) {
		while (l >= 0 && name[l] != '/')
		    l--;
		l++;
	    }
	    else
		l = 0;
	    n = l;
	    while ((name[n] = name[m]))
		(++n, ++m);
	}
	else
	    ++l;
    }

    /* d) remove trailing xx/.. segment. */
    if (l == 2 && name[0] == '.' && name[1] == '.')
	name[0] = '\0';
    else if (l > 2 && name[l - 1] == '.' && name[l - 2] == '.' && name[l - 3] == '/') {
	l = l - 4;
	if (l >= 0) {
	    while (l >= 0 && name[l] != '/')
		l--;
	    l++;
	}
	else
	    l = 0;
	name[l] = '\0';
    }
}

API_EXPORT(void) no2slash(char *name)
{
    char *d, *s;

    s = d = name;
    while (*s) {
	if ((*d++ = *s) == '/') {
	    do {
		++s;
	    } while (*s == '/');
	}
	else {
	    ++s;
	}
    }
    *d = '\0';
}


/*
 * copy at most n leading directories of s into d
 * d should be at least as large as s plus 1 extra byte
 * assumes n > 0
 * the return value is the ever useful pointer to the trailing \0 of d
 *
 * examples:
 *    /a/b, 1  ==> /
 *    /a/b, 2  ==> /a/
 *    /a/b, 3  ==> /a/b/
 *    /a/b, 4  ==> /a/b/
 */
API_EXPORT(char *) make_dirstr_prefix(char *d, const char *s, int n)
{
    for (;;) {
	*d = *s;
	if (*d == '\0') {
	    *d = '/';
	    break;
	}
	if (*d == '/' && (--n) == 0)
	    break;
	++d;
	++s;
    }
    *++d = 0;
    return (d);
}


/*
 * return the parent directory name including trailing / of the file s
 */
API_EXPORT(char *) make_dirstr_parent(pool *p, const char *s)
{
    char *last_slash = strrchr(s, '/');
    char *d;
    int l;

    if (last_slash == NULL) {
	/* XXX: well this is really broken if this happens */
	return (pstrdup(p, "/"));
    }
    l = (last_slash - s) + 1;
    d = palloc(p, l + 1);
    memcpy(d, s, l);
    d[l] = 0;
    return (d);
}


/*
 * This function is deprecated.  Use one of the preceeding two functions
 * which are faster.
 */
API_EXPORT(char *) make_dirstr(pool *p, const char *s, int n)
{
    register int x, f;
    char *res;

    for (x = 0, f = 0; s[x]; x++) {
	if (s[x] == '/')
	    if ((++f) == n) {
		res = palloc(p, x + 2);
		memcpy(res, s, x);
		res[x] = '/';
		res[x + 1] = '\0';
		return res;
	    }
    }

    if (s[strlen(s) - 1] == '/')
	return pstrdup(p, s);
    else
	return pstrcat(p, s, "/", NULL);
}

API_EXPORT(int) count_dirs(const char *path)
{
    register int x, n;

    for (x = 0, n = 0; path[x]; x++)
	if (path[x] == '/')
	    n++;
    return n;
}


API_EXPORT(void) chdir_file(const char *file)
{
    const char *x;
    char buf[HUGE_STRING_LEN];

    x = strrchr(file, '/');
    if (x == NULL) {
	chdir(file);
    }
    else if (x - file < sizeof(buf) - 1) {
	memcpy(buf, file, x - file);
	buf[x - file] = '\0';
	chdir(buf);
    }
    /* XXX: well, this is a silly function, no method of reporting an
     * error... ah well. */
}

API_EXPORT(char *) getword_nc(pool *atrans, char **line, char stop)
{
    return getword(atrans, (const char **) line, stop);
}

API_EXPORT(char *) getword(pool *atrans, const char **line, char stop)
{
    int pos = ind(*line, stop);
    char *res;

    if (pos == -1) {
	res = pstrdup(atrans, *line);
	*line += strlen(*line);
	return res;
    }

    res = palloc(atrans, pos + 1);
    ap_cpystrn(res, *line, pos + 1);

    while ((*line)[pos] == stop)
	++pos;

    *line += pos;

    return res;
}

API_EXPORT(char *) getword_white_nc(pool *atrans, char **line)
{
    return getword_white(atrans, (const char **) line);
}

API_EXPORT(char *) getword_white(pool *atrans, const char **line)
{
    int pos = -1, x;
    char *res;

    for (x = 0; (*line)[x]; x++) {
	if (isspace((*line)[x])) {
	    pos = x;
	    break;
	}
    }

    if (pos == -1) {
	res = pstrdup(atrans, *line);
	*line += strlen(*line);
	return res;
    }

    res = palloc(atrans, pos + 1);
    ap_cpystrn(res, *line, pos + 1);

    while (isspace((*line)[pos]))
	++pos;

    *line += pos;

    return res;
}

API_EXPORT(char *) getword_nulls_nc(pool *atrans, char **line, char stop)
{
    return getword_nulls(atrans, (const char **) line, stop);
}

API_EXPORT(char *) getword_nulls(pool *atrans, const char **line, char stop)
{
    int pos = ind(*line, stop);
    char *res;

    if (pos == -1) {
	res = pstrdup(atrans, *line);
	*line += strlen(*line);
	return res;
    }

    res = palloc(atrans, pos + 1);
    ap_cpystrn(res, *line, pos + 1);

    ++pos;

    *line += pos;

    return res;
}

/* Get a word, (new) config-file style --- quoted strings and backslashes
 * all honored
 */

static char *substring_conf(pool *p, const char *start, int len, char quote)
{
    char *result = palloc(p, len + 2);
    char *resp = result;
    int i;

    for (i = 0; i < len; ++i) {
	if (start[i] == '\\' && (start[i + 1] == '/'
				 || (quote && start[i + 1] == quote)))
	    *resp++ = start[++i];
	else
	    *resp++ = start[i];
    }

    *resp++ = '\0';
    return result;
}

API_EXPORT(char *) getword_conf_nc(pool *p, char **line)
{
    return getword_conf(p, (const char **) line);
}

API_EXPORT(char *) getword_conf(pool *p, const char **line)
{
    const char *str = *line, *strend;
    char *res;
    char quote;

    while (*str && isspace(*str))
	++str;

    if (!*str) {
	*line = str;
	return "";
    }

    if ((quote = *str) == '"' || quote == '\'') {
	strend = str + 1;
	while (*strend && *strend != quote) {
	    if (*strend == '\\' && strend[1] && strend[1] == quote)
		strend += 2;
	    else
		++strend;
	}
	res = substring_conf(p, str + 1, strend - str - 1, quote);

	if (*strend == quote)
	    ++strend;
    }
    else {
	strend = str;
	while (*strend && !isspace(*strend))
	    ++strend;

	res = substring_conf(p, str, strend - str, 0);
    }

    while (*strend && isspace(*strend))
	++strend;
    *line = strend;
    return res;
}

#ifdef UNDEF
/* this function is dangerous, and superceded by getword_white, so don't use it
 */
void cfg_getword(char *word, char *line)
{
    int x = 0, y;

    for (x = 0; line[x] && isspace(line[x]); x++);
    y = 0;
    while (1) {
	if (!(word[y] = line[x]))
	    break;
	if (isspace(line[x]))
	    if ((!x) || (line[x - 1] != '\\'))
		break;
	if (line[x] != '\\')
	    ++y;
	++x;
    }
    word[y] = '\0';
    while (line[x] && isspace(line[x]))
	++x;
    for (y = 0; (line[y] = line[x]); ++x, ++y);
}
#endif


/* Open a configfile_t as FILE, return open configfile_t struct pointer */
API_EXPORT(configfile_t *) pcfg_openfile(pool *p, const char *name)
{
    configfile_t *new_cfg;
    FILE *file;
#ifdef unvoted_DISALLOW_DEVICE_ACCESS
    struct stat stbuf;
#endif

    if (name == NULL) {
        aplog_error(APLOG_MARK, APLOG_ERR | APLOG_NOERRNO, NULL,
               "Internal error: pcfg_openfile() called with NULL filename");
        return NULL;
    }

    file = fopen(name, "r");
#ifdef DEBUG
    aplog_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, NULL,
                "Opening config file %s (%s)",
                name, (file == NULL) ? strerror(errno) : "successful");
#endif
    if (file == NULL)
        return NULL;

#ifdef unvoted_DISALLOW_DEVICE_ACCESS
    if (strcmp(name, "/dev/null") != 0 &&
        fstat(fileno(file), &stbuf) == 0 &&
        !S_ISREG(stbuf.st_mode)) {
        aplog_error(APLOG_MARK, APLOG_ERR | APLOG_NOERRNO, NULL,
                    "Access to file %s denied by server: not a regular file",
                    name);
        fclose(file);
        return NULL;
    }
#endif

    new_cfg = palloc(p, sizeof(*new_cfg));
    new_cfg->param = file;
    new_cfg->name = pstrdup(p, name);
    new_cfg->getch = (int (*)(void *)) fgetc;
    new_cfg->getstr = (void *(*)(void *, size_t, void *)) fgets;
    new_cfg->close = (int (*)(void *)) fclose;
    new_cfg->line_number = 0;
    return new_cfg;
}


/* Allocate a configfile_t handle with user defined functions and params */
API_EXPORT(configfile_t *) pcfg_open_custom(pool *p, const char *descr,
    void *param,
    int(*getch)(void *),
    void *(*getstr) (void *buf, size_t bufsiz, void *param),
    int(*close_func)(void *))
{
    configfile_t *new_cfg = palloc(p, sizeof(*new_cfg));
#ifdef DEBUG
    aplog_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, NULL, "Opening config handler %s", descr);
#endif
    new_cfg->param = param;
    new_cfg->name = descr;
    new_cfg->getch = getch;
    new_cfg->getstr = getstr;
    new_cfg->close = close_func;
    new_cfg->line_number = 0;
    return new_cfg;
}


/* Read one character from a configfile_t */
API_EXPORT(int) cfg_getc(configfile_t *cfp)
{
    register int ch = cfp->getch(cfp->param);
    if (ch == LF) 
	++cfp->line_number;
    return ch;
}


/* Read one line from open configfile_t, strip LF, increase line number */
/* If custom handler does not define a getstr() function, read char by char */
API_EXPORT(int) cfg_getline(char *buf, size_t bufsize, configfile_t *cfp)
{
    /* If a "get string" function is defined, use it */
    if (cfp->getstr != NULL) {
	char *src, *dst;
	++cfp->line_number;
	if (cfp->getstr(buf, bufsize, cfp->param) == NULL)
	    return 1;

	/* Compress the line, reducing all blanks and tabs to one space.
	 * Leading and trailing white space is eliminated completely
	 */
	src = dst = buf;
	while (isspace(*src))
	    ++src;
	while (*src != '\0')
	{
	    /* Copy words */
	    while (!isspace(*dst = *src) && *src != '\0') {
		++src;
		++dst;
	    }
	    *dst++ = ' ';
	    while (isspace(*src))
		++src;
	}
	*dst = '\0';
	/* blast trailing whitespace */
	while (--dst >= buf && isspace(*dst))
	    *dst = '\0';

#ifdef DEBUG_CFG_LINES
	aplog_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, NULL, "Read config: %s", buf);
#endif
	return 0;
    } else {
	/* No "get string" function defined; read character by character */
	register int c;
	register size_t i = 0;

	buf[0] = '\0';
	/* skip leading whitespace */
	do {
	    c = cfp->getch(cfp->param);
	} while (c == '\t' || c == ' ');

	if (c == EOF)
	    return 1;
	
	if(bufsize < 2) {
	    /* too small, assume caller is crazy */
	    return 1;
	}

	while (1) {
	    if ((c == '\t') || (c == ' ')) {
		buf[i++] = ' ';
		while ((c == '\t') || (c == ' '))
		    c = cfp->getch(cfp->param);
	    }
	    if (c == CR) {
		/* silently ignore CR (_assume_ that a LF follows) */
		c = cfp->getch(cfp->param);
	    }
	    if (c == LF) {
		/* increase line number and return on LF */
		++cfp->line_number;
	    }
	    if (c == EOF || c == 0x4 || c == LF || i >= (bufsize - 2)) {
		/* blast trailing whitespace */
		while (i > 0 && isspace(buf[i - 1]))
		    --i;
		buf[i] = '\0';
#ifdef DEBUG_CFG_LINES
		aplog_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, NULL, "Read config: %s", buf);
#endif
		return 0;
	    }
	    buf[i] = c;
	    ++i;
	    c = cfp->getch(cfp->param);
	}
    }
}

API_EXPORT(int) cfg_closefile(configfile_t *fp)
{
#ifdef DEBUG
    aplog_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, NULL, "Done with config file %s", fp->name);
#endif
    return (fp->close == NULL) ? 0 : fp->close(fp->param);
}


/* Retrieve a token, spacing over it and returning a pointer to
 * the first non-white byte afterwards.  Note that these tokens
 * are delimited by semis and commas; and can also be delimited
 * by whitespace at the caller's option.
 */

API_EXPORT(char *) get_token(pool *p, char **accept_line, int accept_white)
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
	   && *ptr != ';' && *ptr != ',') {
	if (*ptr++ == '"')
	    while (*ptr)
		if (*ptr++ == '"')
		    break;
    }

    tok_len = ptr - tok_start;
    token = palloc(p, tok_len + 1);
    ap_cpystrn(token, tok_start, tok_len + 1);

    /* Advance accept_line pointer to the next non-white byte */

    while (*ptr && isspace(*ptr))
	++ptr;

    *accept_line = ptr;
    return token;
}

static char *tspecials = " \t()<>@,;:\\/[]?={}";

/* Next HTTP token from a header line.  Warning --- destructive!
 * Use only with a copy!
 */

static char *next_token(char **toks)
{
    char *cp = *toks;
    char *ret;

    while (*cp && (iscntrl(*cp) || strchr(tspecials, *cp))) {
	if (*cp == '"')
	    while (*cp && (*cp != '"'))
		++cp;
	else
	    ++cp;
    }

    if (!*cp)
	ret = NULL;
    else {
	ret = cp;

	while (*cp && !iscntrl(*cp) && !strchr(tspecials, *cp))
	    ++cp;

	if (*cp) {
	    *toks = cp + 1;
	    *cp = '\0';
	}
	else
	    *toks = cp;
    }

    return ret;
}

API_EXPORT(int) find_token(pool *p, const char *line, const char *tok)
{
    char *ltok;
    char *lcopy;

    if (!line)
	return 0;

    lcopy = pstrdup(p, line);
    while ((ltok = next_token(&lcopy)))
	if (!strcasecmp(ltok, tok))
	    return 1;

    return 0;
}

API_EXPORT(int) find_last_token(pool *p, const char *line, const char *tok)
{
    int llen, tlen, lidx;

    if (!line)
	return 0;

    llen = strlen(line);
    tlen = strlen(tok);
    lidx = llen - tlen;

    if ((lidx < 0) ||
	((lidx > 0) && !(isspace(line[lidx - 1]) || line[lidx - 1] == ',')))
	return 0;

    return (strncasecmp(&line[lidx], tok, tlen) == 0);
}

API_EXPORT(char *) escape_shell_cmd(pool *p, const char *s)
{
    register int x, y, l;
    char *cmd;

    l = strlen(s);
    cmd = palloc(p, 2 * l + 1);	/* Be safe */
    strcpy(cmd, s);

    for (x = 0; cmd[x]; x++) {

#if defined(__EMX__) || defined(WIN32)
	/* Don't allow '&' in parameters under OS/2. */
	/* This can be used to send commands to the shell. */
	if (cmd[x] == '&') {
	    cmd[x] = ' ';
	}
#endif

	if (ind("&;`'\"|*?~<>^()[]{}$\\\n", cmd[x]) != -1) {
	    for (y = l + 1; y > x; y--)
		cmd[y] = cmd[y - 1];
	    l++;		/* length has been increased */
	    cmd[x] = '\\';
	    x++;		/* skip the character */
	}
    }

    return cmd;
}

void plustospace(char *str)
{
    register int x;

    for (x = 0; str[x]; x++)
	if (str[x] == '+')
	    str[x] = ' ';
}

void spacetoplus(char *str)
{
    register int x;

    for (x = 0; str[x]; x++)
	if (str[x] == ' ')
	    str[x] = '+';
}

static char x2c(const char *what)
{
    register char digit;

#ifndef CHARSET_EBCDIC
    digit = ((what[0] >= 'A') ? ((what[0] & 0xdf) - 'A') + 10 : (what[0] - '0'));
    digit *= 16;
    digit += (what[1] >= 'A' ? ((what[1] & 0xdf) - 'A') + 10 : (what[1] - '0'));
#else /*CHARSET_EBCDIC*/
    char xstr[5];
    xstr[0]='0';
    xstr[1]='x';
    xstr[2]=what[0];
    xstr[3]=what[1];
    xstr[4]='\0';
    digit = os_toebcdic[0xFF & strtol(xstr, NULL, 16)];
#endif /*CHARSET_EBCDIC*/
    return (digit);
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
API_EXPORT(int) unescape_url(char *url)
{
    register int x, y, badesc, badpath;

    badesc = 0;
    badpath = 0;
    for (x = 0, y = 0; url[y]; ++x, ++y) {
	if (url[y] != '%')
	    url[x] = url[y];
	else {
	    if (!isxdigit(url[y + 1]) || !isxdigit(url[y + 2])) {
		badesc = 1;
		url[x] = '%';
	    }
	    else {
		url[x] = x2c(&url[y + 1]);
		y += 2;
		if (url[x] == '/' || url[x] == '\0')
		    badpath = 1;
	    }
	}
    }
    url[x] = '\0';
    if (badesc)
	return BAD_REQUEST;
    else if (badpath)
	return NOT_FOUND;
    else
	return OK;
}

API_EXPORT(char *) construct_server(pool *p, const char *hostname,
				    unsigned port, const request_rec *r)
{
    char portnum[22];
    /* Long enough, even if port > 16 bits for some reason */

    if (is_default_port(port, r))
	return pstrdup(p, hostname);
    else {
	ap_snprintf(portnum, sizeof(portnum), "%u", port);
	return pstrcat(p, hostname, ":", portnum, NULL);
    }
}

#define c2x(what,where) sprintf(where,"%%%02x",(unsigned char)what)

/*
 * escape_path_segment() escapes a path segment, as defined in RFC 1808. This
 * routine is (should be) OS independent.
 *
 * os_escape_path() converts an OS path to a URL, in an OS dependent way. In all
 * cases if a ':' occurs before the first '/' in the URL, the URL should be
 * prefixed with "./" (or the ':' escaped). In the case of Unix, this means
 * leaving '/' alone, but otherwise doing what escape_path_segment() does. For
 * efficiency reasons, we don't use escape_path_segment(), which is provided for
 * reference. Again, RFC 1808 is where this stuff is defined.
 *
 * If partial is set, os_escape_path() assumes that the path will be appended to
 * something with a '/' in it (and thus does not prefix "./").
 */

API_EXPORT(char *) escape_path_segment(pool *p, const char *segment)
{
    register int x, y;
    char *copy = palloc(p, 3 * strlen(segment) + 1);

    for (x = 0, y = 0; segment[x]; x++, y++) {
	char c = segment[x];
#ifndef CHARSET_EBCDIC
	if ((c < 'A' || c > 'Z') && (c < 'a' || c > 'z') && (c < '0' || c > '9')
#else /* CHARSET_EBCDIC*/
	if (!isalnum(c)
#endif /*CHARSET_EBCDIC*/
	    && ind("$-_.+!*'(),:@&=~", c) == -1) {
	    c2x(c, &copy[y]);
	    y += 2;
	}
	else
	    copy[y] = c;
    }
    copy[y] = '\0';
    return copy;
}

API_EXPORT(char *) os_escape_path(pool *p, const char *path, int partial)
{
    char *copy = palloc(p, 3 * strlen(path) + 3);
    char *s = copy;

    if (!partial) {
	int colon = ind(path, ':');
	int slash = ind(path, '/');

	if (colon >= 0 && (colon < slash || slash < 0)) {
	    *s++ = '.';
	    *s++ = '/';
	}
    }
    for (; *path; ++path) {
	char c = *path;
#ifndef CHARSET_EBCDIC
	if ((c < 'A' || c > 'Z') && (c < 'a' || c > 'z') && (c < '0' || c > '9')
#else /* CHARSET_EBCDIC*/
	if (!isalnum(c)
#endif /*CHARSET_EBCDIC*/
	    && ind("$-_.+!*'(),:@&=/~", c) == -1) {
	    c2x(c, s);
	    s += 3;
	}
	else
	    *s++ = c;
    }
    *s = '\0';
    return copy;
}

/* escape_uri is now a macro for os_escape_path */

API_EXPORT(char *) escape_html(pool *p, const char *s)
{
    int i, j;
    char *x;

    /* first, count the number of extra characters */
    for (i = 0, j = 0; s[i] != '\0'; i++)
	if (s[i] == '<' || s[i] == '>')
	    j += 3;
	else if (s[i] == '&')
	    j += 4;

    if (j == 0)
	return pstrdup(p, s);
    x = palloc(p, i + j + 1);
    for (i = 0, j = 0; s[i] != '\0'; i++, j++)
	if (s[i] == '<') {
	    memcpy(&x[j], "&lt;", 4);
	    j += 3;
	}
	else if (s[i] == '>') {
	    memcpy(&x[j], "&gt;", 4);
	    j += 3;
	}
	else if (s[i] == '&') {
	    memcpy(&x[j], "&amp;", 5);
	    j += 4;
	}
	else
	    x[j] = s[i];

    x[j] = '\0';
    return x;
}

API_EXPORT(int) is_directory(const char *path)
{
    struct stat finfo;

    if (stat(path, &finfo) == -1)
	return 0;		/* in error condition, just return no */

    return (S_ISDIR(finfo.st_mode));
}

API_EXPORT(char *) make_full_path(pool *a, const char *src1,
				  const char *src2)
{
    register int x;

    x = strlen(src1);
    if (x == 0)
	return pstrcat(a, "/", src2, NULL);

    if (src1[x - 1] != '/')
	return pstrcat(a, src1, "/", src2, NULL);
    else
	return pstrcat(a, src1, src2, NULL);
}

/*
 * Check for an absoluteURI syntax (see section 3.2 in RFC2068).
 */
API_EXPORT(int) is_url(const char *u)
{
    register int x;

    for (x = 0; u[x] != ':'; x++) {
	if ((!u[x]) ||
	    ((!isalpha(u[x])) && (!isdigit(u[x])) &&
	     (u[x] != '+') && (u[x] != '-') && (u[x] != '.'))) {
	    return 0;
	}
    }

    return (x ? 1 : 0);		/* If the first character is ':', it's broken, too */
}

API_EXPORT(int) can_exec(const struct stat *finfo)
{
#ifdef MULTIPLE_GROUPS
    int cnt;
#endif
#if defined(__EMX__) || defined(WIN32)
    /* OS/2 dosen't have Users and Groups */
    return 1;
#else
    if (user_id == finfo->st_uid)
	if (finfo->st_mode & S_IXUSR)
	    return 1;
    if (group_id == finfo->st_gid)
	if (finfo->st_mode & S_IXGRP)
	    return 1;
#ifdef MULTIPLE_GROUPS
    for (cnt = 0; cnt < NGROUPS_MAX; cnt++) {
	if (group_id_list[cnt] == finfo->st_gid)
	    if (finfo->st_mode & S_IXGRP)
		return 1;
    }
#endif
    return (finfo->st_mode & S_IXOTH);
#endif
}

#ifdef NEED_STRDUP
char *strdup(const char *str)
{
    char *dup;

    if (!(dup = (char *) malloc(strlen(str) + 1)))
	return NULL;
    dup = strcpy(dup, str);

    return dup;
}
#endif

/* The following two routines were donated for SVR4 by Andreas Vogel */
#ifdef NEED_STRCASECMP
int strcasecmp(const char *a, const char *b)
{
    const char *p = a;
    const char *q = b;
    for (p = a, q = b; *p && *q; p++, q++) {
	int diff = tolower(*p) - tolower(*q);
	if (diff)
	    return diff;
    }
    if (*p)
	return 1;		/* p was longer than q */
    if (*q)
	return -1;		/* p was shorter than q */
    return 0;			/* Exact match */
}

#endif

#ifdef NEED_STRNCASECMP
int strncasecmp(const char *a, const char *b, int n)
{
    const char *p = a;
    const char *q = b;

    for (p = a, q = b; /*NOTHING */ ; p++, q++) {
	int diff;
	if (p == a + n)
	    return 0;		/*   Match up to n characters */
	if (!(*p && *q))
	    return *p - *q;
	diff = tolower(*p) - tolower(*q);
	if (diff)
	    return diff;
    }
    /*NOTREACHED */
}
#endif



#ifdef NEED_INITGROUPS
int initgroups(const char *name, gid_t basegid)
{
#if defined(QNX) || defined(MPE) || defined(BEOS) || defined(_OSD_POSIX)
/* QNX, MPE and BeOS do not appear to support supplementary groups. */
    return 0;
#else /* ndef QNX */
    gid_t groups[NGROUPS_MAX];
    struct group *g;
    int index = 0;

    setgrent();

    groups[index++] = basegid;

    while (index < NGROUPS_MAX && ((g = getgrent()) != NULL))
	if (g->gr_gid != basegid) {
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
/* From ikluft@amdahl.com
 * this is not ideal but it works for SVR3 variants
 * httpd does not use the options so this doesn't implement them
 */
int waitpid(pid_t pid, int *statusp, int options)
{
    int tmp_pid;
    if (kill(pid, 0) == -1) {
	errno = ECHILD;
	return -1;
    }
    while (((tmp_pid = wait(statusp)) != pid) && (tmp_pid != -1));
    return tmp_pid;
}
#endif

API_EXPORT(int) ind(const char *s, char c)
{
    register int x;

    for (x = 0; s[x]; x++)
	if (s[x] == c)
	    return x;

    return -1;
}

API_EXPORT(int) rind(const char *s, char c)
{
    register int x;

    for (x = strlen(s) - 1; x != -1; x--)
	if (s[x] == c)
	    return x;

    return -1;
}

API_EXPORT(void) str_tolower(char *str)
{
    while (*str) {
	*str = tolower(*str);
	++str;
    }
}

API_EXPORT(uid_t) uname2id(const char *name)
{
#ifdef WIN32
    return (1);
#else
    struct passwd *ent;

    if (name[0] == '#')
	return (atoi(&name[1]));

    if (!(ent = getpwnam(name))) {
	fprintf(stderr, "httpd: bad user name %s\n", name);
	exit(1);
    }
    return (ent->pw_uid);
#endif
}

API_EXPORT(gid_t) gname2id(const char *name)
{
#ifdef WIN32
    return (1);
#else
    struct group *ent;

    if (name[0] == '#')
	return (atoi(&name[1]));

    if (!(ent = getgrnam(name))) {
	fprintf(stderr, "httpd: bad group name %s\n", name);
	exit(1);
    }
    return (ent->gr_gid);
#endif
}

#if 0
int get_portnum(int sd)
{
    struct sockaddr addr;
    int len;

    len = sizeof(struct sockaddr);
    if (getsockname(sd, &addr, &len) < 0)
	return -1;
    return ntohs(((struct sockaddr_in *) &addr)->sin_port);
}

struct in_addr get_local_addr(int sd)
{
    struct sockaddr addr;
    int len;

    len = sizeof(struct sockaddr);
    if (getsockname(sd, &addr, &len) < 0) {
	perror("getsockname");
	fprintf(stderr, "Can't get local host address!\n");
	exit(1);
    }

    return ((struct sockaddr_in *) &addr)->sin_addr;
}

#endif

/*
 * Parses a host of the form <address>[:port]
 * :port is permitted if 'port' is not NULL
 */
unsigned long get_virthost_addr(const char *w, unsigned short *ports)
{
    struct hostent *hep;
    unsigned long my_addr;
    char *p;

    p = strchr(w, ':');
    if (ports != NULL) {
	*ports = 0;
	if (p != NULL && strcmp(p + 1, "*") != 0)
	    *ports = atoi(p + 1);
    }

    if (p != NULL)
	*p = '\0';
    if (strcmp(w, "*") == 0) {
	if (p != NULL)
	    *p = ':';
	return htonl(INADDR_ANY);
    }

    my_addr = ap_inet_addr(w);
    if (my_addr != INADDR_NONE) {
	if (p != NULL)
	    *p = ':';
	return my_addr;
    }

    hep = gethostbyname(w);

    if ((!hep) || (hep->h_addrtype != AF_INET || !hep->h_addr_list[0])) {
	fprintf(stderr, "Cannot resolve host name %s --- exiting!\n", w);
	exit(1);
    }

    if (hep->h_addr_list[1]) {
	fprintf(stderr, "Host %s has multiple addresses ---\n", w);
	fprintf(stderr, "you must choose one explicitly for use as\n");
	fprintf(stderr, "a virtual host.  Exiting!!!\n");
	exit(1);
    }

    if (p != NULL)
	*p = ':';

    return ((struct in_addr *) (hep->h_addr))->s_addr;
}


static char *find_fqdn(pool *a, struct hostent *p)
{
    int x;

    if (ind(p->h_name, '.') == -1) {
	for (x = 0; p->h_aliases[x]; ++x) {
	    if ((ind(p->h_aliases[x], '.') != -1) &&
		(!strncasecmp(p->h_aliases[x], p->h_name, strlen(p->h_name))))
		return pstrdup(a, p->h_aliases[x]);
	}
	return NULL;
    }
    return pstrdup(a, (void *) p->h_name);
}

char *get_local_host(pool *a)
{
#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN 256
#endif
    char str[MAXHOSTNAMELEN + 1];
    char *server_hostname;
    struct hostent *p;

    if (gethostname(str, sizeof(str) - 1) != 0) {
	perror("Unable to gethostname");
	exit(1);
    }
    str[MAXHOSTNAMELEN] = '\0';
    if ((!(p = gethostbyname(str))) || (!(server_hostname = find_fqdn(a, p)))) {
	fprintf(stderr, "httpd: cannot determine local host name.\n");
	fprintf(stderr, "Use ServerName to set it manually.\n");
	exit(1);
    }

    return server_hostname;
}

/* aaaack but it's fast and const should make it shared text page. */
const int pr2six[256] =
{
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 62, 64, 64, 64, 63, 52, 53, 54,
    55, 56, 57, 58, 59, 60, 61, 64, 64, 64, 64, 64, 64, 64, 0, 1, 2, 3,
    4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
    22, 23, 24, 25, 64, 64, 64, 64, 64, 64, 26, 27, 28, 29, 30, 31, 32,
    33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49,
    50, 51, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64
};

API_EXPORT(char *) uudecode(pool *p, const char *bufcoded)
{
    int nbytesdecoded;
    register const unsigned char *bufin;
    register char *bufplain;
    register unsigned char *bufout;
    register int nprbytes;

    /* Strip leading whitespace. */

    while (*bufcoded == ' ' || *bufcoded == '\t')
	bufcoded++;

    /* Figure out how many characters are in the input buffer.
     * Allocate this many from the per-transaction pool for the result.
     */
#ifndef CHARSET_EBCDIC
    bufin = (const unsigned char *) bufcoded;
    while (pr2six[*(bufin++)] <= 63);
    nprbytes = (bufin - (const unsigned char *) bufcoded) - 1;
    nbytesdecoded = ((nprbytes + 3) / 4) * 3;

    bufplain = palloc(p, nbytesdecoded + 1);
    bufout = (unsigned char *) bufplain;

    bufin = (const unsigned char *) bufcoded;

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

    if (nprbytes & 03) {
	if (pr2six[bufin[-2]] > 63)
	    nbytesdecoded -= 2;
	else
	    nbytesdecoded -= 1;
    }
    bufplain[nbytesdecoded] = '\0';
#else /*CHARSET_EBCDIC*/
    bufin = (const unsigned char *) bufcoded;
    while (pr2six[os_toascii[(unsigned char)*(bufin++)]] <= 63);
    nprbytes = (bufin - (const unsigned char *) bufcoded) - 1;
    nbytesdecoded = ((nprbytes + 3) / 4) * 3;

    bufplain = palloc(p, nbytesdecoded + 1);
    bufout = (unsigned char *) bufplain;

    bufin = (const unsigned char *) bufcoded;

    while (nprbytes > 0) {
	*(bufout++) = os_toebcdic[
	    (unsigned char) (pr2six[os_toascii[*bufin]] << 2 | pr2six[os_toascii[bufin[1]]] >> 4)];
	*(bufout++) = os_toebcdic[
	    (unsigned char) (pr2six[os_toascii[bufin[1]]] << 4 | pr2six[os_toascii[bufin[2]]] >> 2)];
	*(bufout++) = os_toebcdic[
	    (unsigned char) (pr2six[os_toascii[bufin[2]]] << 6 | pr2six[os_toascii[bufin[3]]])];
	bufin += 4;
	nprbytes -= 4;
    }

    if (nprbytes & 03) {
	if (pr2six[os_toascii[bufin[-2]]] > 63)
	    nbytesdecoded -= 2;
	else
	    nbytesdecoded -= 1;
    }
    bufplain[nbytesdecoded] = '\0';
#endif /*CHARSET_EBCDIC*/
    return bufplain;
}

#ifdef __EMX__
void os2pathname(char *path)
{
    char newpath[MAX_STRING_LEN];
    int loop;
    int offset;

    offset = 0;
    for (loop = 0; loop < (strlen(path) + 1) && loop < sizeof(newpath) - 1; loop++) {
	if (path[loop] == '/') {
	    newpath[offset] = '\\';
	    /*
	       offset = offset + 1;
	       newpath[offset] = '\\';
	     */
	}
	else
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
     strerror(int err)
{

    char *p;
    extern char *const sys_errlist[];

    p = sys_errlist[err];
    return (p);
}
#endif

#if defined(NEED_DIFFTIME)
double difftime(time_t time1, time_t time0)
{
    return (time1 - time0);
}
#endif
