/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * util.c: string utility things
 *
 * 3/21/93 Rob McCool
 * 1995-96 Many changes by the Apache Software Foundation
 *
 */

/* Debugging aid:
 * #define DEBUG            to trace all cfg_open*()/cfg_closefile() calls
 * #define DEBUG_CFG_LINES  to trace every line read from the config files
 */

#include "apr.h"
#include "apr_strings.h"
#include "apr_lib.h"

#define APR_WANT_STDIO
#define APR_WANT_STRFUNC
#include "apr_want.h"

#if APR_HAVE_UNISTD_H
#include <unistd.h>
#endif
#if APR_HAVE_PROCESS_H
#include <process.h>            /* for getpid() on Win32 */
#endif
#if APR_HAVE_NETDB_H
#include <netdb.h>              /* for gethostbyname() */
#endif

#include "ap_config.h"
#include "apr_base64.h"
#include "httpd.h"
#include "http_main.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_config.h"
#include "http_core.h"
#include "util_ebcdic.h"
#include "util_varbuf.h"

#ifdef HAVE_PWD_H
#include <pwd.h>
#endif
#ifdef HAVE_GRP_H
#include <grp.h>
#endif

/* A bunch of functions in util.c scan strings looking for certain characters.
 * To make that more efficient we encode a lookup table.  The test_char_table
 * is generated automatically by gen_test_char.c.
 */
#include "test_char.h"

/* we assume the folks using this ensure 0 <= c < 256... which means
 * you need a cast to (unsigned char) first, you can't just plug a
 * char in here and get it to work, because if char is signed then it
 * will first be sign extended.
 */
#define TEST_CHAR(c, f)        (test_char_table[(unsigned)(c)] & (f))

/* Win32/NetWare/OS2 need to check for both forward and back slashes
 * in ap_getparents() and ap_escape_url.
 */
#ifdef CASE_BLIND_FILESYSTEM
#define IS_SLASH(s) ((s == '/') || (s == '\\'))
#define SLASHES "/\\"
#else
#define IS_SLASH(s) (s == '/')
#define SLASHES "/"
#endif

/* we know core's module_index is 0 */
#undef APLOG_MODULE_INDEX
#define APLOG_MODULE_INDEX AP_CORE_MODULE_INDEX


/*
 * Examine a field value (such as a media-/content-type) string and return
 * it sans any parameters; e.g., strip off any ';charset=foo' and the like.
 */
AP_DECLARE(char *) ap_field_noparam(apr_pool_t *p, const char *intype)
{
    const char *semi;

    if (intype == NULL) return NULL;

    semi = ap_strchr_c(intype, ';');
    if (semi == NULL) {
        return apr_pstrdup(p, intype);
    }
    else {
        while ((semi > intype) && apr_isspace(semi[-1])) {
            semi--;
        }
        return apr_pstrndup(p, intype, semi - intype);
    }
}

AP_DECLARE(char *) ap_ht_time(apr_pool_t *p, apr_time_t t, const char *fmt,
                              int gmt)
{
    apr_size_t retcode;
    char ts[MAX_STRING_LEN];
    char tf[MAX_STRING_LEN];
    apr_time_exp_t xt;

    if (gmt) {
        const char *f;
        char *strp;

        apr_time_exp_gmt(&xt, t);
        /* Convert %Z to "GMT" and %z to "+0000";
         * on hosts that do not have a time zone string in struct tm,
         * strftime must assume its argument is local time.
         */
        for(strp = tf, f = fmt; strp < tf + sizeof(tf) - 6 && (*strp = *f)
            ; f++, strp++) {
            if (*f != '%') continue;
            switch (f[1]) {
            case '%':
                *++strp = *++f;
                break;
            case 'Z':
                *strp++ = 'G';
                *strp++ = 'M';
                *strp = 'T';
                f++;
                break;
            case 'z': /* common extension */
                *strp++ = '+';
                *strp++ = '0';
                *strp++ = '0';
                *strp++ = '0';
                *strp = '0';
                f++;
                break;
            }
        }
        *strp = '\0';
        fmt = tf;
    }
    else {
        apr_time_exp_lt(&xt, t);
    }

    /* check return code? */
    apr_strftime(ts, &retcode, MAX_STRING_LEN, fmt, &xt);
    ts[MAX_STRING_LEN - 1] = '\0';
    return apr_pstrdup(p, ts);
}

/* Roy owes Rob beer. */
/* Rob owes Roy dinner. */

/* These legacy comments would make a lot more sense if Roy hadn't
 * replaced the old later_than() routine with util_date.c.
 *
 * Well, okay, they still wouldn't make any sense.
 */

/* Match = 0, NoMatch = 1, Abort = -1
 * Based loosely on sections of wildmat.c by Rich Salz
 * Hmmm... shouldn't this really go component by component?
 */
AP_DECLARE(int) ap_strcmp_match(const char *str, const char *expected)
{
    int x, y;

    for (x = 0, y = 0; expected[y]; ++y, ++x) {
        if ((!str[x]) && (expected[y] != '*'))
            return -1;
        if (expected[y] == '*') {
            while (expected[++y] == '*');
            if (!expected[y])
                return 0;
            while (str[x]) {
                int ret;
                if ((ret = ap_strcmp_match(&str[x++], &expected[y])) != 1)
                    return ret;
            }
            return -1;
        }
        else if ((expected[y] != '?') && (str[x] != expected[y]))
            return 1;
    }
    return (str[x] != '\0');
}

AP_DECLARE(int) ap_strcasecmp_match(const char *str, const char *expected)
{
    int x, y;

    for (x = 0, y = 0; expected[y]; ++y, ++x) {
        if (!str[x] && expected[y] != '*')
            return -1;
        if (expected[y] == '*') {
            while (expected[++y] == '*');
            if (!expected[y])
                return 0;
            while (str[x]) {
                int ret;
                if ((ret = ap_strcasecmp_match(&str[x++], &expected[y])) != 1)
                    return ret;
            }
            return -1;
        }
        else if (expected[y] != '?'
                 && apr_tolower(str[x]) != apr_tolower(expected[y]))
            return 1;
    }
    return (str[x] != '\0');
}

/* We actually compare the canonical root to this root, (but we don't
 * waste time checking the case), since every use of this function in
 * httpd-2.1 tests if the path is 'proper', meaning we've already passed
 * it through apr_filepath_merge, or we haven't.
 */
AP_DECLARE(int) ap_os_is_path_absolute(apr_pool_t *p, const char *dir)
{
    const char *newpath;
    const char *ourdir = dir;
    if (apr_filepath_root(&newpath, &dir, 0, p) != APR_SUCCESS
            || strncmp(newpath, ourdir, strlen(newpath)) != 0) {
        return 0;
    }
    return 1;
}

AP_DECLARE(int) ap_is_matchexp(const char *str)
{
    register int x;

    for (x = 0; str[x]; x++)
        if ((str[x] == '*') || (str[x] == '?'))
            return 1;
    return 0;
}

/*
 * Here's a pool-based interface to the POSIX-esque ap_regcomp().
 * Note that we return ap_regex_t instead of being passed one.
 * The reason is that if you use an already-used ap_regex_t structure,
 * the memory that you've already allocated gets forgotten, and
 * regfree() doesn't clear it. So we don't allow it.
 */

static apr_status_t regex_cleanup(void *preg)
{
    ap_regfree((ap_regex_t *) preg);
    return APR_SUCCESS;
}

AP_DECLARE(ap_regex_t *) ap_pregcomp(apr_pool_t *p, const char *pattern,
                                     int cflags)
{
    ap_regex_t *preg = apr_palloc(p, sizeof *preg);

    if (ap_regcomp(preg, pattern, cflags)) {
        return NULL;
    }

    apr_pool_cleanup_register(p, (void *) preg, regex_cleanup,
                              apr_pool_cleanup_null);

    return preg;
}

AP_DECLARE(void) ap_pregfree(apr_pool_t *p, ap_regex_t *reg)
{
    ap_regfree(reg);
    apr_pool_cleanup_kill(p, (void *) reg, regex_cleanup);
}

/*
 * Similar to standard strstr() but we ignore case in this version.
 * Based on the strstr() implementation further below.
 */
AP_DECLARE(char *) ap_strcasestr(const char *s1, const char *s2)
{
    char *p1, *p2;
    if (*s2 == '\0') {
        /* an empty s2 */
        return((char *)s1);
    }
    while(1) {
        for ( ; (*s1 != '\0') && (apr_tolower(*s1) != apr_tolower(*s2)); s1++);
        if (*s1 == '\0') {
            return(NULL);
        }
        /* found first character of s2, see if the rest matches */
        p1 = (char *)s1;
        p2 = (char *)s2;
        for (++p1, ++p2; apr_tolower(*p1) == apr_tolower(*p2); ++p1, ++p2) {
            if (*p1 == '\0') {
                /* both strings ended together */
                return((char *)s1);
            }
        }
        if (*p2 == '\0') {
            /* second string ended, a match */
            break;
        }
        /* didn't find a match here, try starting at next character in s1 */
        s1++;
    }
    return((char *)s1);
}

/*
 * Returns an offsetted pointer in bigstring immediately after
 * prefix. Returns bigstring if bigstring doesn't start with
 * prefix or if prefix is longer than bigstring while still matching.
 * NOTE: pointer returned is relative to bigstring, so we
 * can use standard pointer comparisons in the calling function
 * (eg: test if ap_stripprefix(a,b) == a)
 */
AP_DECLARE(const char *) ap_stripprefix(const char *bigstring,
                                        const char *prefix)
{
    const char *p1;

    if (*prefix == '\0')
        return bigstring;

    p1 = bigstring;
    while (*p1 && *prefix) {
        if (*p1++ != *prefix++)
            return bigstring;
    }
    if (*prefix == '\0')
        return p1;

    /* hit the end of bigstring! */
    return bigstring;
}

/* This function substitutes for $0-$9, filling in regular expression
 * submatches. Pass it the same nmatch and pmatch arguments that you
 * passed ap_regexec(). pmatch should not be greater than the maximum number
 * of subexpressions - i.e. one more than the re_nsub member of ap_regex_t.
 *
 * nmatch must be <=AP_MAX_REG_MATCH (10).
 *
 * input should be the string with the $-expressions, source should be the
 * string that was matched against.
 *
 * It returns the substituted string, or NULL if a vbuf is used.
 * On errors, returns the orig string.
 *
 * Parts of this code are based on Henry Spencer's regsub(), from his
 * AT&T V8 regexp package.
 */

static apr_status_t regsub_core(apr_pool_t *p, char **result,
                                struct ap_varbuf *vb, const char *input,
                                const char *source, apr_size_t nmatch,
                                ap_regmatch_t pmatch[], apr_size_t maxlen)
{
    const char *src = input;
    char *dst;
    char c;
    apr_size_t no;
    apr_size_t len = 0;

    AP_DEBUG_ASSERT((result && p && !vb) || (vb && !p && !result));
    if (!source || nmatch>AP_MAX_REG_MATCH)
        return APR_EINVAL;
    if (!nmatch) {
        len = strlen(src);
        if (maxlen > 0 && len >= maxlen)
            return APR_ENOMEM;
        if (!vb) {
            *result = apr_pstrmemdup(p, src, len);
            return APR_SUCCESS;
        }
        else {
            ap_varbuf_strmemcat(vb, src, len);
            return APR_SUCCESS;
        }
    }

    /* First pass, find the size */
    while ((c = *src++) != '\0') {
        if (c == '$' && apr_isdigit(*src))
            no = *src++ - '0';
        else
            no = AP_MAX_REG_MATCH;

        if (no >= AP_MAX_REG_MATCH) {  /* Ordinary character. */
            if (c == '\\' && *src)
                src++;
            len++;
        }
        else if (no < nmatch && pmatch[no].rm_so < pmatch[no].rm_eo) {
            if (APR_SIZE_MAX - len <= pmatch[no].rm_eo - pmatch[no].rm_so)
                return APR_ENOMEM;
            len += pmatch[no].rm_eo - pmatch[no].rm_so;
        }

    }

    if (len >= maxlen && maxlen > 0)
        return APR_ENOMEM;

    if (!vb) {
        *result = dst = apr_palloc(p, len + 1);
    }
    else {
        if (vb->buf && vb->strlen == AP_VARBUF_UNKNOWN)
            vb->strlen = strlen(vb->buf);
        ap_varbuf_grow(vb, vb->strlen + len);
        dst = vb->buf + vb->strlen;
        vb->strlen += len;
    }

    /* Now actually fill in the string */

    src = input;

    while ((c = *src++) != '\0') {
        if (c == '$' && apr_isdigit(*src))
            no = *src++ - '0';
        else
            no = AP_MAX_REG_MATCH;

        if (no >= AP_MAX_REG_MATCH) {  /* Ordinary character. */
            if (c == '\\' && *src)
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

    return APR_SUCCESS;
}

#ifndef AP_PREGSUB_MAXLEN
#define AP_PREGSUB_MAXLEN   (HUGE_STRING_LEN * 8)
#endif
AP_DECLARE(char *) ap_pregsub(apr_pool_t *p, const char *input,
                              const char *source, apr_size_t nmatch,
                              ap_regmatch_t pmatch[])
{
    char *result;
    apr_status_t rc = regsub_core(p, &result, NULL, input, source, nmatch,
                                  pmatch, AP_PREGSUB_MAXLEN);
    if (rc != APR_SUCCESS)
        result = NULL;
    return result;
}

AP_DECLARE(apr_status_t) ap_pregsub_ex(apr_pool_t *p, char **result,
                                       const char *input, const char *source,
                                       apr_size_t nmatch, ap_regmatch_t pmatch[],
                                       apr_size_t maxlen)
{
    apr_status_t rc = regsub_core(p, result, NULL, input, source, nmatch,
                                  pmatch, maxlen);
    if (rc != APR_SUCCESS)
        *result = NULL;
    return rc;
}

/*
 * Parse .. so we don't compromise security
 */
AP_DECLARE(void) ap_getparents(char *name)
{
    char *next;
    int l, w, first_dot;

    /* Four paseses, as per RFC 1808 */
    /* a) remove ./ path segments */
    for (next = name; *next && (*next != '.'); next++) {
    }

    l = w = first_dot = next - name;
    while (name[l] != '\0') {
        if (name[l] == '.' && IS_SLASH(name[l + 1])
            && (l == 0 || IS_SLASH(name[l - 1])))
            l += 2;
        else
            name[w++] = name[l++];
    }

    /* b) remove trailing . path, segment */
    if (w == 1 && name[0] == '.')
        w--;
    else if (w > 1 && name[w - 1] == '.' && IS_SLASH(name[w - 2]))
        w--;
    name[w] = '\0';

    /* c) remove all xx/../ segments. (including leading ../ and /../) */
    l = first_dot;

    while (name[l] != '\0') {
        if (name[l] == '.' && name[l + 1] == '.' && IS_SLASH(name[l + 2])
            && (l == 0 || IS_SLASH(name[l - 1]))) {
            register int m = l + 3, n;

            l = l - 2;
            if (l >= 0) {
                while (l >= 0 && !IS_SLASH(name[l]))
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
    else if (l > 2 && name[l - 1] == '.' && name[l - 2] == '.'
             && IS_SLASH(name[l - 3])) {
        l = l - 4;
        if (l >= 0) {
            while (l >= 0 && !IS_SLASH(name[l]))
                l--;
            l++;
        }
        else
            l = 0;
        name[l] = '\0';
    }
}

AP_DECLARE(void) ap_no2slash(char *name)
{
    char *d, *s;

    s = d = name;

#ifdef HAVE_UNC_PATHS
    /* Check for UNC names.  Leave leading two slashes. */
    if (s[0] == '/' && s[1] == '/')
        *d++ = *s++;
#endif

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
 * MODIFIED FOR HAVE_DRIVE_LETTERS and NETWARE environments,
 * so that if n == 0, "/" is returned in d with n == 1
 * and s == "e:/test.html", "e:/" is returned in d
 * *** See also directory_walk in modules/http/http_request.c

 * examples:
 *    /a/b, 0  ==> /  (true for all platforms)
 *    /a/b, 1  ==> /
 *    /a/b, 2  ==> /a/
 *    /a/b, 3  ==> /a/b/
 *    /a/b, 4  ==> /a/b/
 *
 *    c:/a/b 0 ==> /
 *    c:/a/b 1 ==> c:/
 *    c:/a/b 2 ==> c:/a/
 *    c:/a/b 3 ==> c:/a/b
 *    c:/a/b 4 ==> c:/a/b
 */
AP_DECLARE(char *) ap_make_dirstr_prefix(char *d, const char *s, int n)
{
    if (n < 1) {
        *d = '/';
        *++d = '\0';
        return (d);
    }

    for (;;) {
        if (*s == '\0' || (*s == '/' && (--n) == 0)) {
            *d = '/';
            break;
        }
        *d++ = *s++;
    }
    *++d = 0;
    return (d);
}


/*
 * return the parent directory name including trailing / of the file s
 */
AP_DECLARE(char *) ap_make_dirstr_parent(apr_pool_t *p, const char *s)
{
    const char *last_slash = ap_strrchr_c(s, '/');
    char *d;
    int l;

    if (last_slash == NULL) {
        return apr_pstrdup(p, "");
    }
    l = (last_slash - s) + 1;
    d = apr_pstrmemdup(p, s, l);

    return (d);
}


AP_DECLARE(int) ap_count_dirs(const char *path)
{
    register int x, n;

    for (x = 0, n = 0; path[x]; x++)
        if (path[x] == '/')
            n++;
    return n;
}

AP_DECLARE(char *) ap_getword_nc(apr_pool_t *atrans, char **line, char stop)
{
    return ap_getword(atrans, (const char **) line, stop);
}

AP_DECLARE(char *) ap_getword(apr_pool_t *atrans, const char **line, char stop)
{
    const char *pos = *line;
    int len;
    char *res;

    while ((*pos != stop) && *pos) {
        ++pos;
    }

    len = pos - *line;
    res = apr_pstrmemdup(atrans, *line, len);

    if (stop) {
        while (*pos == stop) {
            ++pos;
        }
    }
    *line = pos;

    return res;
}

AP_DECLARE(char *) ap_getword_white_nc(apr_pool_t *atrans, char **line)
{
    return ap_getword_white(atrans, (const char **) line);
}

AP_DECLARE(char *) ap_getword_white(apr_pool_t *atrans, const char **line)
{
    const char *pos = *line;
    int len;
    char *res;

    while (!apr_isspace(*pos) && *pos) {
        ++pos;
    }

    len = pos - *line;
    res = apr_pstrmemdup(atrans, *line, len);

    while (apr_isspace(*pos)) {
        ++pos;
    }

    *line = pos;

    return res;
}

AP_DECLARE(char *) ap_getword_nulls_nc(apr_pool_t *atrans, char **line,
                                       char stop)
{
    return ap_getword_nulls(atrans, (const char **) line, stop);
}

AP_DECLARE(char *) ap_getword_nulls(apr_pool_t *atrans, const char **line,
                                    char stop)
{
    const char *pos = ap_strchr_c(*line, stop);
    char *res;

    if (!pos) {
        apr_size_t len = strlen(*line);
        res = apr_pstrmemdup(atrans, *line, len);
        *line += len;
        return res;
    }

    res = apr_pstrndup(atrans, *line, pos - *line);

    ++pos;

    *line = pos;

    return res;
}

/* Get a word, (new) config-file style --- quoted strings and backslashes
 * all honored
 */

static char *substring_conf(apr_pool_t *p, const char *start, int len,
                            char quote)
{
    char *result = apr_palloc(p, len + 2);
    char *resp = result;
    int i;

    for (i = 0; i < len; ++i) {
        if (start[i] == '\\' && (start[i + 1] == '\\'
                                 || (quote && start[i + 1] == quote)))
            *resp++ = start[++i];
        else
            *resp++ = start[i];
    }

    *resp++ = '\0';
#if RESOLVE_ENV_PER_TOKEN
    return (char *)ap_resolve_env(p,result);
#else
    return result;
#endif
}

AP_DECLARE(char *) ap_getword_conf_nc(apr_pool_t *p, char **line)
{
    return ap_getword_conf(p, (const char **) line);
}

AP_DECLARE(char *) ap_getword_conf(apr_pool_t *p, const char **line)
{
    const char *str = *line, *strend;
    char *res;
    char quote;

    while (*str && apr_isspace(*str))
        ++str;

    if (!*str) {
        *line = str;
        return "";
    }

    if ((quote = *str) == '"' || quote == '\'') {
        strend = str + 1;
        while (*strend && *strend != quote) {
            if (*strend == '\\' && strend[1] &&
                (strend[1] == quote || strend[1] == '\\')) {
                strend += 2;
            }
            else {
                ++strend;
            }
        }
        res = substring_conf(p, str + 1, strend - str - 1, quote);

        if (*strend == quote)
            ++strend;
    }
    else {
        strend = str;
        while (*strend && !apr_isspace(*strend))
            ++strend;

        res = substring_conf(p, str, strend - str, 0);
    }

    while (*strend && apr_isspace(*strend))
        ++strend;
    *line = strend;
    return res;
}

AP_DECLARE(int) ap_cfg_closefile(ap_configfile_t *cfp)
{
#ifdef DEBUG
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, NULL, APLOGNO(00551)
        "Done with config file %s", cfp->name);
#endif
    return (cfp->close == NULL) ? 0 : cfp->close(cfp->param);
}

/* we can't use apr_file_* directly because of linking issues on Windows */
static apr_status_t cfg_close(void *param)
{
    return apr_file_close(param);
}

static apr_status_t cfg_getch(char *ch, void *param)
{
    return apr_file_getc(ch, param);
}

static apr_status_t cfg_getstr(void *buf, apr_size_t bufsiz, void *param)
{
    return apr_file_gets(buf, bufsiz, param);
}

/* Open a ap_configfile_t as FILE, return open ap_configfile_t struct pointer */
AP_DECLARE(apr_status_t) ap_pcfg_openfile(ap_configfile_t **ret_cfg,
                                          apr_pool_t *p, const char *name)
{
    ap_configfile_t *new_cfg;
    apr_file_t *file = NULL;
    apr_finfo_t finfo;
    apr_status_t status;
#ifdef DEBUG
    char buf[120];
#endif

    if (name == NULL) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, APLOGNO(00552)
               "Internal error: pcfg_openfile() called with NULL filename");
        return APR_EBADF;
    }

    status = apr_file_open(&file, name, APR_READ | APR_BUFFERED,
                           APR_OS_DEFAULT, p);
#ifdef DEBUG
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, NULL, APLOGNO(00553)
                "Opening config file %s (%s)",
                name, (status != APR_SUCCESS) ?
                apr_strerror(status, buf, sizeof(buf)) : "successful");
#endif
    if (status != APR_SUCCESS)
        return status;

    status = apr_file_info_get(&finfo, APR_FINFO_TYPE, file);
    if (status != APR_SUCCESS)
        return status;

    if (finfo.filetype != APR_REG &&
#if defined(WIN32) || defined(OS2) || defined(NETWARE)
        strcasecmp(apr_filepath_name_get(name), "nul") != 0) {
#else
        strcmp(name, "/dev/null") != 0) {
#endif /* WIN32 || OS2 */
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, APLOGNO(00554)
                     "Access to file %s denied by server: not a regular file",
                     name);
        apr_file_close(file);
        return APR_EBADF;
    }

#ifdef WIN32
    /* Some twisted character [no pun intended] at MS decided that a
     * zero width joiner as the lead wide character would be ideal for
     * describing Unicode text files.  This was further convoluted to
     * another MSism that the same character mapped into utf-8, EF BB BF
     * would signify utf-8 text files.
     *
     * Since MS configuration files are all protecting utf-8 encoded
     * Unicode path, file and resource names, we already have the correct
     * WinNT encoding.  But at least eat the stupid three bytes up front.
     */
    {
        unsigned char buf[4];
        apr_size_t len = 3;
        status = apr_file_read(file, buf, &len);
        if ((status != APR_SUCCESS) || (len < 3)
              || memcmp(buf, "\xEF\xBB\xBF", 3) != 0) {
            apr_off_t zero = 0;
            apr_file_seek(file, APR_SET, &zero);
        }
    }
#endif

    new_cfg = apr_palloc(p, sizeof(*new_cfg));
    new_cfg->param = file;
    new_cfg->name = apr_pstrdup(p, name);
    new_cfg->getch = cfg_getch;
    new_cfg->getstr = cfg_getstr;
    new_cfg->close = cfg_close;
    new_cfg->line_number = 0;
    *ret_cfg = new_cfg;
    return APR_SUCCESS;
}


/* Allocate a ap_configfile_t handle with user defined functions and params */
AP_DECLARE(ap_configfile_t *) ap_pcfg_open_custom(
            apr_pool_t *p, const char *descr, void *param,
            apr_status_t (*getc_func) (char *ch, void *param),
            apr_status_t (*gets_func) (void *buf, apr_size_t bufsize, void *param),
            apr_status_t (*close_func) (void *param))
{
    ap_configfile_t *new_cfg = apr_palloc(p, sizeof(*new_cfg));
    new_cfg->param = param;
    new_cfg->name = descr;
    new_cfg->getch = getc_func;
    new_cfg->getstr = gets_func;
    new_cfg->close = close_func;
    new_cfg->line_number = 0;
    return new_cfg;
}

/* Read one character from a configfile_t */
AP_DECLARE(apr_status_t) ap_cfg_getc(char *ch, ap_configfile_t *cfp)
{
    apr_status_t rc = cfp->getch(ch, cfp->param);
    if (rc == APR_SUCCESS && *ch == LF)
        ++cfp->line_number;
    return rc;
}

AP_DECLARE(const char *) ap_pcfg_strerror(apr_pool_t *p, ap_configfile_t *cfp,
                                          apr_status_t rc)
{
    char buf[MAX_STRING_LEN];
    if (rc == APR_SUCCESS)
        return NULL;
    return apr_psprintf(p, "Error reading %s at line %d: %s",
                        cfp->name, cfp->line_number,
                        rc == APR_ENOSPC ? "Line too long"
                                         : apr_strerror(rc, buf, sizeof(buf)));
}

/* Read one line from open ap_configfile_t, strip LF, increase line number */
/* If custom handler does not define a getstr() function, read char by char */
static apr_status_t ap_cfg_getline_core(char *buf, apr_size_t bufsize,
                                        ap_configfile_t *cfp)
{
    apr_status_t rc;
    /* If a "get string" function is defined, use it */
    if (cfp->getstr != NULL) {
        char *cp;
        char *cbuf = buf;
        apr_size_t cbufsize = bufsize;

        while (1) {
            ++cfp->line_number;
            rc = cfp->getstr(cbuf, cbufsize, cfp->param);
            if (rc == APR_EOF) {
                if (cbuf != buf) {
                    *cbuf = '\0';
                    break;
                }
                else {
                    return APR_EOF;
                }
            }
            if (rc != APR_SUCCESS) {
                return rc;
            }

            /*
             *  check for line continuation,
             *  i.e. match [^\\]\\[\r]\n only
             */
            cp = cbuf;
            cp += strlen(cp);
            if (cp > cbuf && cp[-1] == LF) {
                cp--;
                if (cp > cbuf && cp[-1] == CR)
                    cp--;
                if (cp > cbuf && cp[-1] == '\\') {
                    cp--;
                    /*
                     * line continuation requested -
                     * then remove backslash and continue
                     */
                    cbufsize -= (cp-cbuf);
                    cbuf = cp;
                    continue;
                }
            }
            else if (cp - buf >= bufsize - 1) {
                return APR_ENOSPC;
            }
            break;
        }
    } else {
        /* No "get string" function defined; read character by character */
        apr_size_t i = 0;

        if (bufsize < 2) {
            /* too small, assume caller is crazy */
            return APR_EINVAL;
        }
        buf[0] = '\0';

        while (1) {
            char c;
            rc = cfp->getch(&c, cfp->param);
            if (rc == APR_EOF) {
                if (i > 0)
                    break;
                else
                    return APR_EOF;
            }
            if (rc != APR_SUCCESS)
                return rc;
            if (c == LF) {
                ++cfp->line_number;
                /* check for line continuation */
                if (i > 0 && buf[i-1] == '\\') {
                    i--;
                    continue;
                }
                else {
                    break;
                }
            }
            else if (i >= bufsize - 2) {
                return APR_ENOSPC;
            }
            buf[i] = c;
            ++i;
        }
        buf[i] = '\0';
    }
    return APR_SUCCESS;
}

static int cfg_trim_line(char *buf)
{
    char *start, *end;
    /*
     * Leading and trailing white space is eliminated completely
     */
    start = buf;
    while (apr_isspace(*start))
        ++start;
    /* blast trailing whitespace */
    end = &start[strlen(start)];
    while (--end >= start && apr_isspace(*end))
        *end = '\0';
    /* Zap leading whitespace by shifting */
    if (start != buf)
        memmove(buf, start, end - start + 2);
#ifdef DEBUG_CFG_LINES
    ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, NULL, APLOGNO(00555) "Read config: '%s'", buf);
#endif
    return end - start + 1;
}

/* Read one line from open ap_configfile_t, strip LF, increase line number */
/* If custom handler does not define a getstr() function, read char by char */
AP_DECLARE(apr_status_t) ap_cfg_getline(char *buf, apr_size_t bufsize,
                                        ap_configfile_t *cfp)
{
    apr_status_t rc = ap_cfg_getline_core(buf, bufsize, cfp);
    if (rc == APR_SUCCESS)
        cfg_trim_line(buf);
    return rc;
}

AP_DECLARE(apr_status_t) ap_varbuf_cfg_getline(struct ap_varbuf *vb,
                                               ap_configfile_t *cfp,
                                               apr_size_t max_len)
{
    apr_status_t rc;
    vb->strlen = 0;
    *vb->buf = '\0';

    for (;;) {
        apr_size_t new_len;
        rc = ap_cfg_getline_core(vb->buf + vb->strlen, vb->avail - vb->strlen, cfp);
        if (rc == APR_ENOSPC || rc == APR_SUCCESS)
            vb->strlen += strlen(vb->buf + vb->strlen);
        if (rc != APR_ENOSPC)
            break;
        if (vb->avail >= max_len)
            return APR_ENOSPC;
        new_len = vb->avail * 2;
        if (new_len > max_len)
            new_len = max_len;
        ap_varbuf_grow(vb, new_len);
        --cfp->line_number;
    }
    if (vb->strlen > max_len)
        return APR_ENOSPC;
    if (rc == APR_SUCCESS)
        vb->strlen = cfg_trim_line(vb->buf);
    return rc;
}

/* Size an HTTP header field list item, as separated by a comma.
 * The return value is a pointer to the beginning of the non-empty list item
 * within the original string (or NULL if there is none) and the address
 * of field is shifted to the next non-comma, non-whitespace character.
 * len is the length of the item excluding any beginning whitespace.
 */
AP_DECLARE(const char *) ap_size_list_item(const char **field, int *len)
{
    const unsigned char *ptr = (const unsigned char *)*field;
    const unsigned char *token;
    int in_qpair, in_qstr, in_com;

    /* Find first non-comma, non-whitespace byte */

    while (*ptr == ',' || apr_isspace(*ptr))
        ++ptr;

    token = ptr;

    /* Find the end of this item, skipping over dead bits */

    for (in_qpair = in_qstr = in_com = 0;
         *ptr && (in_qpair || in_qstr || in_com || *ptr != ',');
         ++ptr) {

        if (in_qpair) {
            in_qpair = 0;
        }
        else {
            switch (*ptr) {
                case '\\': in_qpair = 1;      /* quoted-pair         */
                           break;
                case '"' : if (!in_com)       /* quoted string delim */
                               in_qstr = !in_qstr;
                           break;
                case '(' : if (!in_qstr)      /* comment (may nest)  */
                               ++in_com;
                           break;
                case ')' : if (in_com)        /* end comment         */
                               --in_com;
                           break;
                default  : break;
            }
        }
    }

    if ((*len = (ptr - token)) == 0) {
        *field = (const char *)ptr;
        return NULL;
    }

    /* Advance field pointer to the next non-comma, non-white byte */

    while (*ptr == ',' || apr_isspace(*ptr))
        ++ptr;

    *field = (const char *)ptr;
    return (const char *)token;
}

/* Retrieve an HTTP header field list item, as separated by a comma,
 * while stripping insignificant whitespace and lowercasing anything not in
 * a quoted string or comment.  The return value is a new string containing
 * the converted list item (or NULL if none) and the address pointed to by
 * field is shifted to the next non-comma, non-whitespace.
 */
AP_DECLARE(char *) ap_get_list_item(apr_pool_t *p, const char **field)
{
    const char *tok_start;
    const unsigned char *ptr;
    unsigned char *pos;
    char *token;
    int addspace = 0, in_qpair = 0, in_qstr = 0, in_com = 0, tok_len = 0;

    /* Find the beginning and maximum length of the list item so that
     * we can allocate a buffer for the new string and reset the field.
     */
    if ((tok_start = ap_size_list_item(field, &tok_len)) == NULL) {
        return NULL;
    }
    token = apr_palloc(p, tok_len + 1);

    /* Scan the token again, but this time copy only the good bytes.
     * We skip extra whitespace and any whitespace around a '=', '/',
     * or ';' and lowercase normal characters not within a comment,
     * quoted-string or quoted-pair.
     */
    for (ptr = (const unsigned char *)tok_start, pos = (unsigned char *)token;
         *ptr && (in_qpair || in_qstr || in_com || *ptr != ',');
         ++ptr) {

        if (in_qpair) {
            in_qpair = 0;
            *pos++ = *ptr;
        }
        else {
            switch (*ptr) {
                case '\\': in_qpair = 1;
                           if (addspace == 1)
                               *pos++ = ' ';
                           *pos++ = *ptr;
                           addspace = 0;
                           break;
                case '"' : if (!in_com)
                               in_qstr = !in_qstr;
                           if (addspace == 1)
                               *pos++ = ' ';
                           *pos++ = *ptr;
                           addspace = 0;
                           break;
                case '(' : if (!in_qstr)
                               ++in_com;
                           if (addspace == 1)
                               *pos++ = ' ';
                           *pos++ = *ptr;
                           addspace = 0;
                           break;
                case ')' : if (in_com)
                               --in_com;
                           *pos++ = *ptr;
                           addspace = 0;
                           break;
                case ' ' :
                case '\t': if (addspace)
                               break;
                           if (in_com || in_qstr)
                               *pos++ = *ptr;
                           else
                               addspace = 1;
                           break;
                case '=' :
                case '/' :
                case ';' : if (!(in_com || in_qstr))
                               addspace = -1;
                           *pos++ = *ptr;
                           break;
                default  : if (addspace == 1)
                               *pos++ = ' ';
                           *pos++ = (in_com || in_qstr) ? *ptr
                                                        : apr_tolower(*ptr);
                           addspace = 0;
                           break;
            }
        }
    }
    *pos = '\0';

    return token;
}

/* Find an item in canonical form (lowercase, no extra spaces) within
 * an HTTP field value list.  Returns 1 if found, 0 if not found.
 * This would be much more efficient if we stored header fields as
 * an array of list items as they are received instead of a plain string.
 */
AP_DECLARE(int) ap_find_list_item(apr_pool_t *p, const char *line,
                                  const char *tok)
{
    const unsigned char *pos;
    const unsigned char *ptr = (const unsigned char *)line;
    int good = 0, addspace = 0, in_qpair = 0, in_qstr = 0, in_com = 0;

    if (!line || !tok)
        return 0;

    do {  /* loop for each item in line's list */

        /* Find first non-comma, non-whitespace byte */

        while (*ptr == ',' || apr_isspace(*ptr))
            ++ptr;

        if (*ptr)
            good = 1;  /* until proven otherwise for this item */
        else
            break;     /* no items left and nothing good found */

        /* We skip extra whitespace and any whitespace around a '=', '/',
         * or ';' and lowercase normal characters not within a comment,
         * quoted-string or quoted-pair.
         */
        for (pos = (const unsigned char *)tok;
             *ptr && (in_qpair || in_qstr || in_com || *ptr != ',');
             ++ptr) {

            if (in_qpair) {
                in_qpair = 0;
                if (good)
                    good = (*pos++ == *ptr);
            }
            else {
                switch (*ptr) {
                    case '\\': in_qpair = 1;
                               if (addspace == 1)
                                   good = good && (*pos++ == ' ');
                               good = good && (*pos++ == *ptr);
                               addspace = 0;
                               break;
                    case '"' : if (!in_com)
                                   in_qstr = !in_qstr;
                               if (addspace == 1)
                                   good = good && (*pos++ == ' ');
                               good = good && (*pos++ == *ptr);
                               addspace = 0;
                               break;
                    case '(' : if (!in_qstr)
                                   ++in_com;
                               if (addspace == 1)
                                   good = good && (*pos++ == ' ');
                               good = good && (*pos++ == *ptr);
                               addspace = 0;
                               break;
                    case ')' : if (in_com)
                                   --in_com;
                               good = good && (*pos++ == *ptr);
                               addspace = 0;
                               break;
                    case ' ' :
                    case '\t': if (addspace || !good)
                                   break;
                               if (in_com || in_qstr)
                                   good = (*pos++ == *ptr);
                               else
                                   addspace = 1;
                               break;
                    case '=' :
                    case '/' :
                    case ';' : if (!(in_com || in_qstr))
                                   addspace = -1;
                               good = good && (*pos++ == *ptr);
                               break;
                    default  : if (!good)
                                   break;
                               if (addspace == 1)
                                   good = (*pos++ == ' ');
                               if (in_com || in_qstr)
                                   good = good && (*pos++ == *ptr);
                               else
                                   good = good && (*pos++ == apr_tolower(*ptr));
                               addspace = 0;
                               break;
                }
            }
        }
        if (good && *pos)
            good = 0;          /* not good if only a prefix was matched */

    } while (*ptr && !good);

    return good;
}


/* Retrieve a token, spacing over it and returning a pointer to
 * the first non-white byte afterwards.  Note that these tokens
 * are delimited by semis and commas; and can also be delimited
 * by whitespace at the caller's option.
 */

AP_DECLARE(char *) ap_get_token(apr_pool_t *p, const char **accept_line,
                                int accept_white)
{
    const char *ptr = *accept_line;
    const char *tok_start;
    char *token;
    int tok_len;

    /* Find first non-white byte */

    while (*ptr && apr_isspace(*ptr))
        ++ptr;

    tok_start = ptr;

    /* find token end, skipping over quoted strings.
     * (comments are already gone).
     */

    while (*ptr && (accept_white || !apr_isspace(*ptr))
           && *ptr != ';' && *ptr != ',') {
        if (*ptr++ == '"')
            while (*ptr)
                if (*ptr++ == '"')
                    break;
    }

    tok_len = ptr - tok_start;
    token = apr_pstrndup(p, tok_start, tok_len);

    /* Advance accept_line pointer to the next non-white byte */

    while (*ptr && apr_isspace(*ptr))
        ++ptr;

    *accept_line = ptr;
    return token;
}


/* find http tokens, see the definition of token from RFC2068 */
AP_DECLARE(int) ap_find_token(apr_pool_t *p, const char *line, const char *tok)
{
    const unsigned char *start_token;
    const unsigned char *s;

    if (!line)
        return 0;

    s = (const unsigned char *)line;
    for (;;) {
        /* find start of token, skip all stop characters, note NUL
         * isn't a token stop, so we don't need to test for it
         */
        while (TEST_CHAR(*s, T_HTTP_TOKEN_STOP)) {
            ++s;
        }
        if (!*s) {
            return 0;
        }
        start_token = s;
        /* find end of the token */
        while (*s && !TEST_CHAR(*s, T_HTTP_TOKEN_STOP)) {
            ++s;
        }
        if (!strncasecmp((const char *)start_token, (const char *)tok,
                         s - start_token)) {
            return 1;
        }
        if (!*s) {
            return 0;
        }
    }
}


AP_DECLARE(int) ap_find_last_token(apr_pool_t *p, const char *line,
                                   const char *tok)
{
    int llen, tlen, lidx;

    if (!line)
        return 0;

    llen = strlen(line);
    tlen = strlen(tok);
    lidx = llen - tlen;

    if (lidx < 0 ||
        (lidx > 0 && !(apr_isspace(line[lidx - 1]) || line[lidx - 1] == ',')))
        return 0;

    return (strncasecmp(&line[lidx], tok, tlen) == 0);
}

AP_DECLARE(char *) ap_escape_shell_cmd(apr_pool_t *p, const char *str)
{
    char *cmd;
    unsigned char *d;
    const unsigned char *s;

    cmd = apr_palloc(p, 2 * strlen(str) + 1);        /* Be safe */
    d = (unsigned char *)cmd;
    s = (const unsigned char *)str;
    for (; *s; ++s) {

#if defined(OS2) || defined(WIN32)
        /*
         * Newlines to Win32/OS2 CreateProcess() are ill advised.
         * Convert them to spaces since they are effectively white
         * space to most applications
         */
        if (*s == '\r' || *s == '\n') {
             *d++ = ' ';
             continue;
         }
#endif

        if (TEST_CHAR(*s, T_ESCAPE_SHELL_CMD)) {
            *d++ = '\\';
        }
        *d++ = *s;
    }
    *d = '\0';

    return cmd;
}

static char x2c(const char *what)
{
    register char digit;

#if !APR_CHARSET_EBCDIC
    digit = ((what[0] >= 'A') ? ((what[0] & 0xdf) - 'A') + 10
             : (what[0] - '0'));
    digit *= 16;
    digit += (what[1] >= 'A' ? ((what[1] & 0xdf) - 'A') + 10
              : (what[1] - '0'));
#else /*APR_CHARSET_EBCDIC*/
    char xstr[5];
    xstr[0]='0';
    xstr[1]='x';
    xstr[2]=what[0];
    xstr[3]=what[1];
    xstr[4]='\0';
    digit = apr_xlate_conv_byte(ap_hdrs_from_ascii,
                                0xFF & strtol(xstr, NULL, 16));
#endif /*APR_CHARSET_EBCDIC*/
    return (digit);
}

/*
 * Unescapes a URL, leaving reserved characters intact.
 * Returns 0 on success, non-zero on error
 * Failure is due to
 *   bad % escape       returns HTTP_BAD_REQUEST
 *
 *   decoding %00 or a forbidden character returns HTTP_NOT_FOUND
 */

static int unescape_url(char *url, const char *forbid, const char *reserved)
{
    register int badesc, badpath;
    char *x, *y;

    badesc = 0;
    badpath = 0;
    /* Initial scan for first '%'. Don't bother writing values before
     * seeing a '%' */
    y = strchr(url, '%');
    if (y == NULL) {
        return OK;
    }
    for (x = y; *y; ++x, ++y) {
        if (*y != '%') {
            *x = *y;
        }
        else {
            if (!apr_isxdigit(*(y + 1)) || !apr_isxdigit(*(y + 2))) {
                badesc = 1;
                *x = '%';
            }
            else {
                char decoded;
                decoded = x2c(y + 1);
                if ((decoded == '\0')
                    || (forbid && ap_strchr_c(forbid, decoded))) {
                    badpath = 1;
                    *x = decoded;
                    y += 2;
                }
                else if (reserved && ap_strchr_c(reserved, decoded)) {
                    *x++ = *y++;
                    *x++ = *y++;
                    *x = *y;
                }
                else {
                    *x = decoded;
                    y += 2;
                }
            }
        }
    }
    *x = '\0';
    if (badesc) {
        return HTTP_BAD_REQUEST;
    }
    else if (badpath) {
        return HTTP_NOT_FOUND;
    }
    else {
        return OK;
    }
}
AP_DECLARE(int) ap_unescape_url(char *url)
{
    /* Traditional */
    return unescape_url(url, SLASHES, NULL);
}
AP_DECLARE(int) ap_unescape_url_keep2f(char *url, int decode_slashes)
{
    /* AllowEncodedSlashes (corrected) */
    if (decode_slashes) {
        /* no chars reserved */
        return unescape_url(url, NULL, NULL);
    } else {
        /* reserve (do not decode) encoded slashes */
        return unescape_url(url, NULL, SLASHES);
    }
}
#ifdef NEW_APIS
/* IFDEF these out until they've been thought through.
 * Just a germ of an API extension for now
 */
AP_DECLARE(int) ap_unescape_url_proxy(char *url)
{
    /* leave RFC1738 reserved characters intact, * so proxied URLs
     * don't get mangled.  Where does that leave encoded '&' ?
     */
    return unescape_url(url, NULL, "/;?");
}
AP_DECLARE(int) ap_unescape_url_reserved(char *url, const char *reserved)
{
    return unescape_url(url, NULL, reserved);
}
#endif

AP_DECLARE(int) ap_unescape_urlencoded(char *query)
{
    char *slider;

    /* replace plus with a space */
    if (query) {
        for (slider = query; *slider; slider++) {
            if (*slider == '+') {
                *slider = ' ';
            }
        }
    }

    /* unescape everything else */
    return unescape_url(query, NULL, NULL);
}

AP_DECLARE(char *) ap_construct_server(apr_pool_t *p, const char *hostname,
                                       apr_port_t port, const request_rec *r)
{
    if (ap_is_default_port(port, r)) {
        return apr_pstrdup(p, hostname);
    }
    else {
        return apr_psprintf(p, "%s:%u", hostname, port);
    }
}

AP_DECLARE(int) ap_unescape_all(char *url)
{
    return unescape_url(url, NULL, NULL);
}

/* c2x takes an unsigned, and expects the caller has guaranteed that
 * 0 <= what < 256... which usually means that you have to cast to
 * unsigned char first, because (unsigned)(char)(x) first goes through
 * signed extension to an int before the unsigned cast.
 *
 * The reason for this assumption is to assist gcc code generation --
 * the unsigned char -> unsigned extension is already done earlier in
 * both uses of this code, so there's no need to waste time doing it
 * again.
 */
static const char c2x_table[] = "0123456789abcdef";

static APR_INLINE unsigned char *c2x(unsigned what, unsigned char prefix,
                                     unsigned char *where)
{
#if APR_CHARSET_EBCDIC
    what = apr_xlate_conv_byte(ap_hdrs_to_ascii, (unsigned char)what);
#endif /*APR_CHARSET_EBCDIC*/
    *where++ = prefix;
    *where++ = c2x_table[what >> 4];
    *where++ = c2x_table[what & 0xf];
    return where;
}

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

AP_DECLARE(char *) ap_escape_path_segment_buffer(char *copy, const char *segment)
{
    const unsigned char *s = (const unsigned char *)segment;
    unsigned char *d = (unsigned char *)copy;
    unsigned c;

    while ((c = *s)) {
        if (TEST_CHAR(c, T_ESCAPE_PATH_SEGMENT)) {
            d = c2x(c, '%', d);
        }
        else {
            *d++ = c;
        }
        ++s;
    }
    *d = '\0';
    return copy;
}

AP_DECLARE(char *) ap_escape_path_segment(apr_pool_t *p, const char *segment)
{
    return ap_escape_path_segment_buffer(apr_palloc(p, 3 * strlen(segment) + 1), segment);
}

AP_DECLARE(char *) ap_os_escape_path(apr_pool_t *p, const char *path, int partial)
{
    char *copy = apr_palloc(p, 3 * strlen(path) + 3);
    const unsigned char *s = (const unsigned char *)path;
    unsigned char *d = (unsigned char *)copy;
    unsigned c;

    if (!partial) {
        const char *colon = ap_strchr_c(path, ':');
        const char *slash = ap_strchr_c(path, '/');

        if (colon && (!slash || colon < slash)) {
            *d++ = '.';
            *d++ = '/';
        }
    }
    while ((c = *s)) {
        if (TEST_CHAR(c, T_OS_ESCAPE_PATH)) {
            d = c2x(c, '%', d);
        }
        else {
            *d++ = c;
        }
        ++s;
    }
    *d = '\0';
    return copy;
}

AP_DECLARE(char *) ap_escape_urlencoded_buffer(char *copy, const char *buffer)
{
    const unsigned char *s = (const unsigned char *)buffer;
    unsigned char *d = (unsigned char *)copy;
    unsigned c;

    while ((c = *s)) {
        if (TEST_CHAR(c, T_ESCAPE_URLENCODED)) {
            d = c2x(c, '%', d);
        }
        else if (c == ' ') {
            *d++ = '+';
        }
        else {
            *d++ = c;
        }
        ++s;
    }
    *d = '\0';
    return copy;
}

AP_DECLARE(char *) ap_escape_urlencoded(apr_pool_t *p, const char *buffer)
{
    return ap_escape_urlencoded_buffer(apr_palloc(p, 3 * strlen(buffer) + 1), buffer);
}

/* ap_escape_uri is now a macro for os_escape_path */

AP_DECLARE(char *) ap_escape_html2(apr_pool_t *p, const char *s, int toasc)
{
    int i, j;
    char *x;

    /* first, count the number of extra characters */
    for (i = 0, j = 0; s[i] != '\0'; i++)
        if (s[i] == '<' || s[i] == '>')
            j += 3;
        else if (s[i] == '&')
            j += 4;
        else if (s[i] == '"')
            j += 5;
        else if (toasc && !apr_isascii(s[i]))
            j += 5;

    if (j == 0)
        return apr_pstrmemdup(p, s, i);

    x = apr_palloc(p, i + j + 1);
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
        else if (s[i] == '"') {
            memcpy(&x[j], "&quot;", 6);
            j += 5;
        }
        else if (toasc && !apr_isascii(s[i])) {
            char *esc = apr_psprintf(p, "&#%3.3d;", (unsigned char)s[i]);
            memcpy(&x[j], esc, 6);
            j += 5;
        }
        else
            x[j] = s[i];

    x[j] = '\0';
    return x;
}
AP_DECLARE(char *) ap_escape_logitem(apr_pool_t *p, const char *str)
{
    char *ret;
    unsigned char *d;
    const unsigned char *s;

    if (!str) {
        return NULL;
    }

    ret = apr_palloc(p, 4 * strlen(str) + 1); /* Be safe */
    d = (unsigned char *)ret;
    s = (const unsigned char *)str;
    for (; *s; ++s) {

        if (TEST_CHAR(*s, T_ESCAPE_LOGITEM)) {
            *d++ = '\\';
            switch(*s) {
            case '\b':
                *d++ = 'b';
                break;
            case '\n':
                *d++ = 'n';
                break;
            case '\r':
                *d++ = 'r';
                break;
            case '\t':
                *d++ = 't';
                break;
            case '\v':
                *d++ = 'v';
                break;
            case '\\':
            case '"':
                *d++ = *s;
                break;
            default:
                c2x(*s, 'x', d);
                d += 3;
            }
        }
        else {
            *d++ = *s;
        }
    }
    *d = '\0';

    return ret;
}

AP_DECLARE(apr_size_t) ap_escape_errorlog_item(char *dest, const char *source,
                                               apr_size_t buflen)
{
    unsigned char *d, *ep;
    const unsigned char *s;

    if (!source || !buflen) { /* be safe */
        return 0;
    }

    d = (unsigned char *)dest;
    s = (const unsigned char *)source;
    ep = d + buflen - 1;

    for (; d < ep && *s; ++s) {

        if (TEST_CHAR(*s, T_ESCAPE_LOGITEM)) {
            *d++ = '\\';
            if (d >= ep) {
                --d;
                break;
            }

            switch(*s) {
            case '\b':
                *d++ = 'b';
                break;
            case '\n':
                *d++ = 'n';
                break;
            case '\r':
                *d++ = 'r';
                break;
            case '\t':
                *d++ = 't';
                break;
            case '\v':
                *d++ = 'v';
                break;
            case '\\':
                *d++ = *s;
                break;
            case '"': /* no need for this in error log */
                d[-1] = *s;
                break;
            default:
                if (d >= ep - 2) {
                    ep = --d; /* break the for loop as well */
                    break;
                }
                c2x(*s, 'x', d);
                d += 3;
            }
        }
        else {
            *d++ = *s;
        }
    }
    *d = '\0';

    return (d - (unsigned char *)dest);
}

AP_DECLARE(int) ap_is_directory(apr_pool_t *p, const char *path)
{
    apr_finfo_t finfo;

    if (apr_stat(&finfo, path, APR_FINFO_TYPE, p) != APR_SUCCESS)
        return 0;                /* in error condition, just return no */

    return (finfo.filetype == APR_DIR);
}

AP_DECLARE(int) ap_is_rdirectory(apr_pool_t *p, const char *path)
{
    apr_finfo_t finfo;

    if (apr_stat(&finfo, path, APR_FINFO_LINK | APR_FINFO_TYPE, p) != APR_SUCCESS)
        return 0;                /* in error condition, just return no */

    return (finfo.filetype == APR_DIR);
}

AP_DECLARE(char *) ap_make_full_path(apr_pool_t *a, const char *src1,
                                  const char *src2)
{
    apr_size_t len1, len2;
    char *path;

    len1 = strlen(src1);
    len2 = strlen(src2);
     /* allocate +3 for '/' delimiter, trailing NULL and overallocate
      * one extra byte to allow the caller to add a trailing '/'
      */
    path = (char *)apr_palloc(a, len1 + len2 + 3);
    if (len1 == 0) {
        *path = '/';
        memcpy(path + 1, src2, len2 + 1);
    }
    else {
        char *next;
        memcpy(path, src1, len1);
        next = path + len1;
        if (next[-1] != '/') {
            *next++ = '/';
        }
        memcpy(next, src2, len2 + 1);
    }
    return path;
}

/*
 * Check for an absoluteURI syntax (see section 3.2 in RFC2068).
 */
AP_DECLARE(int) ap_is_url(const char *u)
{
    register int x;

    for (x = 0; u[x] != ':'; x++) {
        if ((!u[x]) ||
            ((!apr_isalpha(u[x])) && (!apr_isdigit(u[x])) &&
             (u[x] != '+') && (u[x] != '-') && (u[x] != '.'))) {
            return 0;
        }
    }

    return (x ? 1 : 0);                /* If the first character is ':', it's broken, too */
}

AP_DECLARE(int) ap_ind(const char *s, char c)
{
    const char *p = ap_strchr_c(s, c);

    if (p == NULL)
        return -1;
    return p - s;
}

AP_DECLARE(int) ap_rind(const char *s, char c)
{
    const char *p = ap_strrchr_c(s, c);

    if (p == NULL)
        return -1;
    return p - s;
}

AP_DECLARE(void) ap_str_tolower(char *str)
{
    while (*str) {
        *str = apr_tolower(*str);
        ++str;
    }
}

AP_DECLARE(void) ap_str_toupper(char *str)
{
    while (*str) {
        *str = apr_toupper(*str);
        ++str;
    }
}

/*
 * We must return a FQDN
 */
char *ap_get_local_host(apr_pool_t *a)
{
#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN 256
#endif
    char str[MAXHOSTNAMELEN + 1];
    char *server_hostname = NULL;
    apr_sockaddr_t *sockaddr;
    char *hostname;

    if (apr_gethostname(str, sizeof(str) - 1, a) != APR_SUCCESS) {
        ap_log_perror(APLOG_MARK, APLOG_STARTUP | APLOG_WARNING, 0, a, APLOGNO(00556)
                     "%s: apr_gethostname() failed to determine ServerName",
                     ap_server_argv0);
    } else {
        str[sizeof(str) - 1] = '\0';
        if (apr_sockaddr_info_get(&sockaddr, str, APR_UNSPEC, 0, 0, a) == APR_SUCCESS) {
            if ( (apr_getnameinfo(&hostname, sockaddr, 0) == APR_SUCCESS) &&
                (ap_strchr_c(hostname, '.')) ) {
                server_hostname = apr_pstrdup(a, hostname);
                return server_hostname;
            } else if (ap_strchr_c(str, '.')) {
                server_hostname = apr_pstrdup(a, str);
            } else {
                apr_sockaddr_ip_get(&hostname, sockaddr);
                server_hostname = apr_pstrdup(a, hostname);
            }
        } else {
            ap_log_perror(APLOG_MARK, APLOG_STARTUP | APLOG_WARNING, 0, a, APLOGNO(00557)
                         "%s: apr_sockaddr_info_get() failed for %s",
                         ap_server_argv0, str);
        }
    }

    if (!server_hostname)
        server_hostname = apr_pstrdup(a, "127.0.0.1");

    ap_log_perror(APLOG_MARK, APLOG_ALERT|APLOG_STARTUP, 0, a, APLOGNO(00558)
                 "%s: Could not reliably determine the server's fully qualified "
                 "domain name, using %s. Set the 'ServerName' directive globally "
                 "to suppress this message",
                 ap_server_argv0, server_hostname);

    return server_hostname;
}

/* simple 'pool' alloc()ing glue to apr_base64.c
 */
AP_DECLARE(char *) ap_pbase64decode(apr_pool_t *p, const char *bufcoded)
{
    char *decoded;
    int l;

    decoded = (char *) apr_palloc(p, 1 + apr_base64_decode_len(bufcoded));
    l = apr_base64_decode(decoded, bufcoded);
    decoded[l] = '\0'; /* make binary sequence into string */

    return decoded;
}

AP_DECLARE(char *) ap_pbase64encode(apr_pool_t *p, char *string)
{
    char *encoded;
    int l = strlen(string);

    encoded = (char *) apr_palloc(p, 1 + apr_base64_encode_len(l));
    l = apr_base64_encode(encoded, string, l);
    encoded[l] = '\0'; /* make binary sequence into string */

    return encoded;
}

/* we want to downcase the type/subtype for comparison purposes
 * but nothing else because ;parameter=foo values are case sensitive.
 * XXX: in truth we want to downcase parameter names... but really,
 * apache has never handled parameters and such correctly.  You
 * also need to compress spaces and such to be able to compare
 * properly. -djg
 */
AP_DECLARE(void) ap_content_type_tolower(char *str)
{
    char *semi;

    semi = strchr(str, ';');
    if (semi) {
        *semi = '\0';
    }

    ap_str_tolower(str);

    if (semi) {
        *semi = ';';
    }
}

/*
 * Given a string, replace any bare " with \" .
 */
AP_DECLARE(char *) ap_escape_quotes(apr_pool_t *p, const char *instring)
{
    int newlen = 0;
    const char *inchr = instring;
    char *outchr, *outstring;

    /*
     * Look through the input string, jogging the length of the output
     * string up by an extra byte each time we find an unescaped ".
     */
    while (*inchr != '\0') {
        newlen++;
        if (*inchr == '"') {
            newlen++;
        }
        /*
         * If we find a slosh, and it's not the last byte in the string,
         * it's escaping something - advance past both bytes.
         */
        if ((*inchr == '\\') && (inchr[1] != '\0')) {
            inchr++;
            newlen++;
        }
        inchr++;
    }
    outstring = apr_palloc(p, newlen + 1);
    inchr = instring;
    outchr = outstring;
    /*
     * Now copy the input string to the output string, inserting a slosh
     * in front of every " that doesn't already have one.
     */
    while (*inchr != '\0') {
        if ((*inchr == '\\') && (inchr[1] != '\0')) {
            *outchr++ = *inchr++;
            *outchr++ = *inchr++;
        }
        if (*inchr == '"') {
            *outchr++ = '\\';
        }
        if (*inchr != '\0') {
            *outchr++ = *inchr++;
        }
    }
    *outchr = '\0';
    return outstring;
}

/*
 * Given a string, append the PID deliminated by delim.
 * Usually used to create a pid-appended filepath name
 * (eg: /a/b/foo -> /a/b/foo.6726). A function, and not
 * a macro, to avoid unistd.h dependency
 */
AP_DECLARE(char *) ap_append_pid(apr_pool_t *p, const char *string,
                                    const char *delim)
{
    return apr_psprintf(p, "%s%s%" APR_PID_T_FMT, string,
                        delim, getpid());

}

/**
 * Parse a given timeout parameter string into an apr_interval_time_t value.
 * The unit of the time interval is given as postfix string to the numeric
 * string. Currently the following units are understood:
 *
 * ms    : milliseconds
 * s     : seconds
 * mi[n] : minutes
 * h     : hours
 *
 * If no unit is contained in the given timeout parameter the default_time_unit
 * will be used instead.
 * @param timeout_parameter The string containing the timeout parameter.
 * @param timeout The timeout value to be returned.
 * @param default_time_unit The default time unit to use if none is specified
 * in timeout_parameter.
 * @return Status value indicating whether the parsing was successful or not.
 */
AP_DECLARE(apr_status_t) ap_timeout_parameter_parse(
                                               const char *timeout_parameter,
                                               apr_interval_time_t *timeout,
                                               const char *default_time_unit)
{
    char *endp;
    const char *time_str;
    apr_int64_t tout;

    tout = apr_strtoi64(timeout_parameter, &endp, 10);
    if (errno) {
        return errno;
    }
    if (!endp || !*endp) {
        time_str = default_time_unit;
    }
    else {
        time_str = endp;
    }

    switch (*time_str) {
        /* Time is in seconds */
    case 's':
        *timeout = (apr_interval_time_t) apr_time_from_sec(tout);
        break;
    case 'h':
        /* Time is in hours */
        *timeout = (apr_interval_time_t) apr_time_from_sec(tout * 3600);
        break;
    case 'm':
        switch (*(++time_str)) {
        /* Time is in milliseconds */
        case 's':
            *timeout = (apr_interval_time_t) tout * 1000;
            break;
        /* Time is in minutes */
        case 'i':
            *timeout = (apr_interval_time_t) apr_time_from_sec(tout * 60);
            break;
        default:
            return APR_EGENERAL;
        }
        break;
    default:
        return APR_EGENERAL;
    }
    return APR_SUCCESS;
}

/**
 * Determine if a request has a request body or not.
 *
 * @param r the request_rec of the request
 * @return truth value
 */
AP_DECLARE(int) ap_request_has_body(request_rec *r)
{
    apr_off_t cl;
    char *estr;
    const char *cls;
    int has_body;

    has_body = (!r->header_only
                && (r->kept_body
                    || apr_table_get(r->headers_in, "Transfer-Encoding")
                    || ( (cls = apr_table_get(r->headers_in, "Content-Length"))
                        && (apr_strtoff(&cl, cls, &estr, 10) == APR_SUCCESS)
                        && (!*estr)
                        && (cl > 0) )
                    )
                );
    return has_body;
}

AP_DECLARE_NONSTD(apr_status_t) ap_pool_cleanup_set_null(void *data_)
{
    void **ptr = (void **)data_;
    *ptr = NULL;
    return APR_SUCCESS;
}

AP_DECLARE(apr_status_t) ap_str2_alnum(const char *src, char *dest) {

    for ( ; *src; src++, dest++)
    {
        if (!apr_isprint(*src))
            *dest = 'x';
        else if (!apr_isalnum(*src))
            *dest = '_';
        else
            *dest = (char)*src;
    }
    *dest = '\0';
    return APR_SUCCESS;

}

AP_DECLARE(apr_status_t) ap_pstr2_alnum(apr_pool_t *p, const char *src,
                                        const char **dest)
{
    char *new = apr_palloc(p, strlen(src)+1);
    if (!new)
        return APR_ENOMEM;
    *dest = new;
    return ap_str2_alnum(src, new);
}

/**
 * Read the body and parse any form found, which must be of the
 * type application/x-www-form-urlencoded.
 *
 * Name/value pairs are returned in an array, with the names as
 * strings with a maximum length of HUGE_STRING_LEN, and the
 * values as bucket brigades. This allows values to be arbitrarily
 * large.
 *
 * All url-encoding is removed from both the names and the values
 * on the fly. The names are interpreted as strings, while the
 * values are interpreted as blocks of binary data, that may
 * contain the 0 character.
 *
 * In order to ensure that resource limits are not exceeded, a
 * maximum size must be provided. If the sum of the lengths of
 * the names and the values exceed this size, this function
 * will return HTTP_REQUEST_ENTITY_TOO_LARGE.
 *
 * An optional number of parameters can be provided, if the number
 * of parameters provided exceeds this amount, this function will
 * return HTTP_REQUEST_ENTITY_TOO_LARGE. If this value is negative,
 * no limit is imposed, and the number of parameters is in turn
 * constrained by the size parameter above.
 *
 * This function honours any kept_body configuration, and the
 * original raw request body will be saved to the kept_body brigade
 * if so configured, just as ap_discard_request_body does.
 *
 * NOTE: File upload is not yet supported, but can be without change
 * to the function call.
 */

/* form parsing stuff */
typedef enum {
    FORM_NORMAL,
    FORM_AMP,
    FORM_NAME,
    FORM_VALUE,
    FORM_PERCENTA,
    FORM_PERCENTB,
    FORM_ABORT
} ap_form_type_t;

AP_DECLARE(int) ap_parse_form_data(request_rec *r, ap_filter_t *f,
                                   apr_array_header_t **ptr,
                                   apr_size_t num, apr_size_t usize)
{
    apr_bucket_brigade *bb = NULL;
    int seen_eos = 0;
    char buffer[HUGE_STRING_LEN + 1];
    const char *ct;
    apr_size_t offset = 0;
    apr_ssize_t size;
    ap_form_type_t state = FORM_NAME, percent = FORM_NORMAL;
    ap_form_pair_t *pair = NULL;
    apr_array_header_t *pairs = apr_array_make(r->pool, 4, sizeof(ap_form_pair_t));

    char hi = 0;
    char low = 0;

    *ptr = pairs;

    /* sanity check - we only support forms for now */
    ct = apr_table_get(r->headers_in, "Content-Type");
    if (!ct || strcmp("application/x-www-form-urlencoded", ct)) {
        return ap_discard_request_body(r);
    }

    if (usize > APR_SIZE_MAX >> 1)
        size = APR_SIZE_MAX >> 1;
    else
        size = usize;

    if (!f) {
        f = r->input_filters;
    }

    bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);
    do {
        apr_bucket *bucket = NULL, *last = NULL;

        int rv = ap_get_brigade(f, bb, AP_MODE_READBYTES,
                                APR_BLOCK_READ, HUGE_STRING_LEN);
        if (rv != APR_SUCCESS) {
            apr_brigade_destroy(bb);
            return (rv == AP_FILTER_ERROR) ? rv : HTTP_BAD_REQUEST;
        }

        for (bucket = APR_BRIGADE_FIRST(bb);
             bucket != APR_BRIGADE_SENTINEL(bb);
             last = bucket, bucket = APR_BUCKET_NEXT(bucket)) {
            const char *data;
            apr_size_t len, slide;

            if (last) {
                apr_bucket_delete(last);
            }
            if (APR_BUCKET_IS_EOS(bucket)) {
                seen_eos = 1;
                break;
            }
            if (bucket->length == 0) {
                continue;
            }

            rv = apr_bucket_read(bucket, &data, &len, APR_BLOCK_READ);
            if (rv != APR_SUCCESS) {
                apr_brigade_destroy(bb);
                return HTTP_BAD_REQUEST;
            }

            slide = len;
            while (state != FORM_ABORT && slide-- > 0 && size >= 0 && num != 0) {
                char c = *data++;
                if ('+' == c) {
                    c = ' ';
                }
                else if ('&' == c) {
                    state = FORM_AMP;
                }
                if ('%' == c) {
                    percent = FORM_PERCENTA;
                    continue;
                }
                if (FORM_PERCENTA == percent) {
                    if (c >= 'a') {
                        hi = c - 'a' + 10;
                    }
                    else if (c >= 'A') {
                        hi = c - 'A' + 10;
                    }
                    else if (c >= '0') {
                        hi = c - '0';
                    }
                    hi = hi << 4;
                    percent = FORM_PERCENTB;
                    continue;
                }
                if (FORM_PERCENTB == percent) {
                    if (c >= 'a') {
                        low = c - 'a' + 10;
                    }
                    else if (c >= 'A') {
                        low = c - 'A' + 10;
                    }
                    else if (c >= '0') {
                        low = c - '0';
                    }
                    c = low | hi;
                    percent = FORM_NORMAL;
                }
                switch (state) {
                    case FORM_AMP:
                        if (pair) {
                            const char *tmp = apr_pmemdup(r->pool, buffer, offset);
                            apr_bucket *b = apr_bucket_pool_create(tmp, offset, r->pool, r->connection->bucket_alloc);
                            APR_BRIGADE_INSERT_TAIL(pair->value, b);
                        }
                        state = FORM_NAME;
                        pair = NULL;
                        offset = 0;
                        num--;
                        break;
                    case FORM_NAME:
                        if (offset < HUGE_STRING_LEN) {
                            if ('=' == c) {
                                buffer[offset] = 0;
                                offset = 0;
                                pair = (ap_form_pair_t *) apr_array_push(pairs);
                                pair->name = apr_pstrdup(r->pool, buffer);
                                pair->value = apr_brigade_create(r->pool, r->connection->bucket_alloc);
                                state = FORM_VALUE;
                            }
                            else {
                                buffer[offset++] = c;
                                size--;
                            }
                        }
                        else {
                            state = FORM_ABORT;
                        }
                        break;
                    case FORM_VALUE:
                        if (offset >= HUGE_STRING_LEN) {
                            const char *tmp = apr_pmemdup(r->pool, buffer, offset);
                            apr_bucket *b = apr_bucket_pool_create(tmp, offset, r->pool, r->connection->bucket_alloc);
                            APR_BRIGADE_INSERT_TAIL(pair->value, b);
                            offset = 0;
                        }
                        buffer[offset++] = c;
                        size--;
                        break;
                    default:
                        break;
                }
            }

        }

        apr_brigade_cleanup(bb);
    } while (!seen_eos);

    if (FORM_ABORT == state || size < 0 || num == 0) {
        return HTTP_REQUEST_ENTITY_TOO_LARGE;
    }
    else if (FORM_VALUE == state && pair && offset > 0) {
        const char *tmp = apr_pmemdup(r->pool, buffer, offset);
        apr_bucket *b = apr_bucket_pool_create(tmp, offset, r->pool, r->connection->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(pair->value, b);
    }

    return OK;

}

#define VARBUF_SMALL_SIZE 2048
#define VARBUF_MAX_SIZE   (APR_SIZE_MAX - 1 -                                \
                           APR_ALIGN_DEFAULT(sizeof(struct ap_varbuf_info)))

struct ap_varbuf_info {
    struct apr_memnode_t *node;
    apr_allocator_t *allocator;
};

static apr_status_t varbuf_cleanup(void *info_)
{
    struct ap_varbuf_info *info = info_;
    info->node->next = NULL;
    apr_allocator_free(info->allocator, info->node);
    return APR_SUCCESS;
}

const char nul = '\0';
static char * const varbuf_empty = (char *)&nul;

AP_DECLARE(void) ap_varbuf_init(apr_pool_t *p, struct ap_varbuf *vb,
                                apr_size_t init_size)
{
    vb->buf = varbuf_empty;
    vb->avail = 0;
    vb->strlen = AP_VARBUF_UNKNOWN;
    vb->pool = p;
    vb->info = NULL;

    ap_varbuf_grow(vb, init_size);
}

AP_DECLARE(void) ap_varbuf_grow(struct ap_varbuf *vb, apr_size_t new_len)
{
    apr_memnode_t *new_node = NULL;
    apr_allocator_t *allocator;
    struct ap_varbuf_info *new_info;
    char *new;

    if (new_len <= vb->avail)
        return;

    if (new_len < 2 * vb->avail && vb->avail < VARBUF_MAX_SIZE/2) {
        /* at least double the size, to avoid repeated reallocations */
        new_len = 2 * vb->avail;
    }
    else if (new_len > VARBUF_MAX_SIZE) {
        apr_abortfunc_t abort_fn = apr_pool_abort_get(vb->pool);
        ap_assert(abort_fn != NULL);
        abort_fn(APR_ENOMEM);
        return;
    }

    new_len++;  /* add space for trailing \0 */
    if (new_len <= VARBUF_SMALL_SIZE) {
        new_len = APR_ALIGN_DEFAULT(new_len);
        new = apr_palloc(vb->pool, new_len);
        if (vb->avail && vb->strlen != 0) {
            AP_DEBUG_ASSERT(vb->buf != NULL);
            AP_DEBUG_ASSERT(vb->buf != varbuf_empty);
            if (new == vb->buf + vb->avail + 1) {
                /* We are lucky: the new memory lies directly after our old
                 * buffer, we can now use both.
                 */
                vb->avail += new_len;
                return;
            }
            else {
                /* copy up to vb->strlen + 1 bytes */
                memcpy(new, vb->buf, vb->strlen == AP_VARBUF_UNKNOWN ?
                                     vb->avail + 1 : vb->strlen + 1);
            }
        }
        else {
            *new = '\0';
        }
        vb->avail = new_len - 1;
        vb->buf = new;
        return;
    }

    /* The required block is rather larger. Use allocator directly so that
     * the memory can be freed independently from the pool. */
    allocator = apr_pool_allocator_get(vb->pool);
    if (new_len <= VARBUF_MAX_SIZE)
        new_node = apr_allocator_alloc(allocator,
                                       new_len + APR_ALIGN_DEFAULT(sizeof(*new_info)));
    if (!new_node) {
        apr_abortfunc_t abort_fn = apr_pool_abort_get(vb->pool);
        ap_assert(abort_fn != NULL);
        abort_fn(APR_ENOMEM);
        return;
    }
    new_info = (struct ap_varbuf_info *)new_node->first_avail;
    new_node->first_avail += APR_ALIGN_DEFAULT(sizeof(*new_info));
    new_info->node = new_node;
    new_info->allocator = allocator;
    new = new_node->first_avail;
    AP_DEBUG_ASSERT(new_node->endp - new_node->first_avail >= new_len);
    new_len = new_node->endp - new_node->first_avail;

    if (vb->avail && vb->strlen != 0)
        memcpy(new, vb->buf, vb->strlen == AP_VARBUF_UNKNOWN ?
                             vb->avail + 1 : vb->strlen + 1);
    else
        *new = '\0';
    if (vb->info)
        apr_pool_cleanup_run(vb->pool, vb->info, varbuf_cleanup);
    apr_pool_cleanup_register(vb->pool, new_info, varbuf_cleanup,
                              apr_pool_cleanup_null);
    vb->info = new_info;
    vb->buf = new;
    vb->avail = new_len - 1;
}

AP_DECLARE(void) ap_varbuf_strmemcat(struct ap_varbuf *vb, const char *str,
                                     int len)
{
    if (len == 0)
        return;
    if (!vb->avail) {
        ap_varbuf_grow(vb, len);
        memcpy(vb->buf, str, len);
        vb->buf[len] = '\0';
        vb->strlen = len;
        return;
    }
    if (vb->strlen == AP_VARBUF_UNKNOWN)
        vb->strlen = strlen(vb->buf);
    ap_varbuf_grow(vb, vb->strlen + len);
    memcpy(vb->buf + vb->strlen, str, len);
    vb->strlen += len;
    vb->buf[vb->strlen] = '\0';
}

AP_DECLARE(void) ap_varbuf_free(struct ap_varbuf *vb)
{
    if (vb->info) {
        apr_pool_cleanup_run(vb->pool, vb->info, varbuf_cleanup);
        vb->info = NULL;
    }
    vb->buf = NULL;
}

AP_DECLARE(char *) ap_varbuf_pdup(apr_pool_t *p, struct ap_varbuf *buf,
                                  const char *prepend, apr_size_t prepend_len,
                                  const char *append, apr_size_t append_len,
                                  apr_size_t *new_len)
{
    apr_size_t i = 0;
    struct iovec vec[3];

    if (prepend) {
        vec[i].iov_base = (void *)prepend;
        vec[i].iov_len = prepend_len;
        i++;
    }
    if (buf->avail && buf->strlen) {
        vec[i].iov_base = (void *)buf->buf;
        vec[i].iov_len = (buf->strlen == AP_VARBUF_UNKNOWN) ? buf->avail
                                                            : buf->strlen;
        i++;
    }
    if (append) {
        vec[i].iov_base = (void *)append;
        vec[i].iov_len = append_len;
        i++;
    }
    if (i)
        return apr_pstrcatv(p, vec, i, new_len);

    if (new_len)
        *new_len = 0;
    return "";
}

AP_DECLARE(apr_status_t) ap_varbuf_regsub(struct ap_varbuf *vb,
                                          const char *input,
                                          const char *source,
                                          apr_size_t nmatch,
                                          ap_regmatch_t pmatch[],
                                          apr_size_t maxlen)
{
    return regsub_core(NULL, NULL, vb, input, source, nmatch, pmatch, maxlen);
}

static const char * const oom_message = "[crit] Memory allocation failed, "
                                        "aborting process." APR_EOL_STR;

AP_DECLARE(void) ap_abort_on_oom()
{
    int written, count = strlen(oom_message);
    const char *buf = oom_message;
    do {
        written = write(STDERR_FILENO, buf, count);
        if (written == count)
            break;
        if (written > 0) {
            buf += written;
            count -= written;
        }
    } while (written >= 0 || errno == EINTR);
    abort();
}

AP_DECLARE(void *) ap_malloc(size_t size)
{
    void *p = malloc(size);
    if (p == NULL && size != 0)
        ap_abort_on_oom();
    return p;
}

AP_DECLARE(void *) ap_calloc(size_t nelem, size_t size)
{
    void *p = calloc(nelem, size);
    if (p == NULL && nelem != 0 && size != 0)
        ap_abort_on_oom();
    return p;
}

AP_DECLARE(void *) ap_realloc(void *ptr, size_t size)
{
    void *p = realloc(ptr, size);
    if (p == NULL && size != 0)
        ap_abort_on_oom();
    return p;
}
