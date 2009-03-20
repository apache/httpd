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
 * mod_mime_magic: MIME type lookup via file magic numbers
 * Copyright (c) 1996-1997 Cisco Systems, Inc.
 *
 * This software was submitted by Cisco Systems to the Apache Software Foundation in July
 * 1997.  Future revisions and derivatives of this source code must
 * acknowledge Cisco Systems as the original contributor of this module.
 * All other licensing and usage conditions are those of the Apache Software Foundation.
 *
 * Some of this code is derived from the free version of the file command
 * originally posted to comp.sources.unix.  Copyright info for that program
 * is included below as required.
 * ---------------------------------------------------------------------------
 * - Copyright (c) Ian F. Darwin, 1987. Written by Ian F. Darwin.
 *
 * This software is not subject to any license of the American Telephone and
 * Telegraph Company or of the Regents of the University of California.
 *
 * Permission is granted to anyone to use this software for any purpose on any
 * computer system, and to alter it and redistribute it freely, subject to
 * the following restrictions:
 *
 * 1. The author is not responsible for the consequences of use of this
 * software, no matter how awful, even if they arise from flaws in it.
 *
 * 2. The origin of this software must not be misrepresented, either by
 * explicit claim or by omission.  Since few users ever read sources, credits
 * must appear in the documentation.
 *
 * 3. Altered versions must be plainly marked as such, and must not be
 * misrepresented as being the original software.  Since few users ever read
 * sources, credits must appear in the documentation.
 *
 * 4. This notice may not be removed or altered.
 * -------------------------------------------------------------------------
 *
 * For compliance with Mr Darwin's terms: this has been very significantly
 * modified from the free "file" command.
 * - all-in-one file for compilation convenience when moving from one
 *   version of Apache to the next.
 * - Memory allocation is done through the Apache API's apr_pool_t structure.
 * - All functions have had necessary Apache API request or server
 *   structures passed to them where necessary to call other Apache API
 *   routines.  (i.e. usually for logging, files, or memory allocation in
 *   itself or a called function.)
 * - struct magic has been converted from an array to a single-ended linked
 *   list because it only grows one record at a time, it's only accessed
 *   sequentially, and the Apache API has no equivalent of realloc().
 * - Functions have been changed to get their parameters from the server
 *   configuration instead of globals.  (It should be reentrant now but has
 *   not been tested in a threaded environment.)
 * - Places where it used to print results to stdout now saves them in a
 *   list where they're used to set the MIME type in the Apache request
 *   record.
 * - Command-line flags have been removed since they will never be used here.
 *
 * Ian Kluft <ikluft@cisco.com>
 * Engineering Information Framework
 * Central Engineering
 * Cisco Systems, Inc.
 * San Jose, CA, USA
 *
 * Initial installation          July/August 1996
 * Misc bug fixes                May 1997
 * Submission to Apache Software Foundation    July 1997
 *
 */

#include "apr.h"
#include "apr_strings.h"
#include "apr_lib.h"
#define APR_WANT_STRFUNC
#include "apr_want.h"

#if APR_HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "ap_config.h"
#include "httpd.h"
#include "http_config.h"
#include "http_request.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "util_script.h"

/* ### this isn't set by configure? does anybody set this? */
#ifdef HAVE_UTIME_H
#include <utime.h>
#endif

/*
 * data structures and related constants
 */

#define MODNAME        "mod_mime_magic"
#define MIME_MAGIC_DEBUG        0

#define MIME_BINARY_UNKNOWN    "application/octet-stream"
#define MIME_TEXT_UNKNOWN    "text/plain"

#define MAXMIMESTRING        256

/* HOWMANY must be at least 4096 to make gzip -dcq work */
#define HOWMANY  4096
/* SMALL_HOWMANY limits how much work we do to figure out text files */
#define SMALL_HOWMANY 1024
#define MAXDESC    50   /* max leng of text description */
#define MAXstring 64    /* max leng of "string" types */

struct magic {
    struct magic *next;     /* link to next entry */
    int lineno;             /* line number from magic file */

    short flag;
#define INDIR  1            /* if '>(...)' appears,  */
#define UNSIGNED 2          /* comparison is unsigned */
    short cont_level;       /* level of ">" */
    struct {
        char type;          /* byte short long */
        long offset;        /* offset from indirection */
    } in;
    long offset;            /* offset to magic number */
    unsigned char reln;     /* relation (0=eq, '>'=gt, etc) */
    char type;              /* int, short, long or string. */
    char vallen;            /* length of string value, if any */
#define BYTE      1
#define SHORT     2
#define LONG      4
#define STRING    5
#define DATE      6
#define BESHORT   7
#define BELONG    8
#define BEDATE    9
#define LESHORT  10
#define LELONG   11
#define LEDATE   12
    union VALUETYPE {
        unsigned char b;
        unsigned short h;
        unsigned long l;
        char s[MAXstring];
        unsigned char hs[2];   /* 2 bytes of a fixed-endian "short" */
        unsigned char hl[4];   /* 2 bytes of a fixed-endian "long" */
    } value;                   /* either number or string */
    unsigned long mask;        /* mask before comparison with value */
    char nospflag;             /* supress space character */

    /* NOTE: this string is suspected of overrunning - find it! */
    char desc[MAXDESC];        /* description */
};

/*
 * data structures for tar file recognition
 * --------------------------------------------------------------------------
 * Header file for public domain tar (tape archive) program.
 *
 * @(#)tar.h 1.20 86/10/29    Public Domain. Created 25 August 1985 by John
 * Gilmore, ihnp4!hoptoad!gnu.
 *
 * Header block on tape.
 *
 * I'm going to use traditional DP naming conventions here. A "block" is a big
 * chunk of stuff that we do I/O on. A "record" is a piece of info that we
 * care about. Typically many "record"s fit into a "block".
 */
#define RECORDSIZE    512
#define NAMSIZ    100
#define TUNMLEN    32
#define TGNMLEN    32

union record {
    char charptr[RECORDSIZE];
    struct header {
        char name[NAMSIZ];
        char mode[8];
        char uid[8];
        char gid[8];
        char size[12];
        char mtime[12];
        char chksum[8];
        char linkflag;
        char linkname[NAMSIZ];
        char magic[8];
        char uname[TUNMLEN];
        char gname[TGNMLEN];
        char devmajor[8];
        char devminor[8];
    } header;
};

/* The magic field is filled with this if uname and gname are valid. */
#define    TMAGIC        "ustar  "   /* 7 chars and a null */

/*
 * file-function prototypes
 */
static int ascmagic(request_rec *, unsigned char *, apr_size_t);
static int is_tar(unsigned char *, apr_size_t);
static int softmagic(request_rec *, unsigned char *, apr_size_t);
static int tryit(request_rec *, unsigned char *, apr_size_t, int);
static int zmagic(request_rec *, unsigned char *, apr_size_t);

static int getvalue(server_rec *, struct magic *, char **);
static int hextoint(int);
static char *getstr(server_rec *, char *, char *, int, int *);
static int parse(server_rec *, apr_pool_t *p, char *, int);

static int match(request_rec *, unsigned char *, apr_size_t);
static int mget(request_rec *, union VALUETYPE *, unsigned char *,
                struct magic *, apr_size_t);
static int mcheck(request_rec *, union VALUETYPE *, struct magic *);
static void mprint(request_rec *, union VALUETYPE *, struct magic *);

static int uncompress(request_rec *, int,
                      unsigned char **, apr_size_t);
static long from_oct(int, char *);
static int fsmagic(request_rec *r, const char *fn);

/*
 * includes for ASCII substring recognition formerly "names.h" in file
 * command
 *
 * Original notes: names and types used by ascmagic in file(1). These tokens are
 * here because they can appear anywhere in the first HOWMANY bytes, while
 * tokens in /etc/magic must appear at fixed offsets into the file. Don't
 * make HOWMANY too high unless you have a very fast CPU.
 */

/* these types are used to index the apr_table_t 'types': keep em in sync! */
/* HTML inserted in first because this is a web server module now */
#define L_HTML    0   /* HTML */
#define L_C       1   /* first and foremost on UNIX */
#define L_FORT    2   /* the oldest one */
#define L_MAKE    3   /* Makefiles */
#define L_PLI     4   /* PL/1 */
#define L_MACH    5   /* some kinda assembler */
#define L_ENG     6   /* English */
#define L_PAS     7   /* Pascal */
#define L_MAIL    8   /* Electronic mail */
#define L_NEWS    9   /* Usenet Netnews */

static const char *types[] =
{
    "text/html",             /* HTML */
    "text/plain",            /* "c program text", */
    "text/plain",            /* "fortran program text", */
    "text/plain",            /* "make commands text", */
    "text/plain",            /* "pl/1 program text", */
    "text/plain",            /* "assembler program text", */
    "text/plain",            /* "English text", */
    "text/plain",            /* "pascal program text", */
    "message/rfc822",        /* "mail text", */
    "message/news",          /* "news text", */
    "application/binary",    /* "can't happen error on names.h/types", */
    0
};

static const struct names {
    const char *name;
    short type;
} names[] = {

    /* These must be sorted by eye for optimal hit rate */
    /* Add to this list only after substantial meditation */
    {
        "<html>", L_HTML
    },
    {
        "<HTML>", L_HTML
    },
    {
        "<head>", L_HTML
    },
    {
        "<HEAD>", L_HTML
    },
    {
        "<title>", L_HTML
    },
    {
        "<TITLE>", L_HTML
    },
    {
        "<h1>", L_HTML
    },
    {
        "<H1>", L_HTML
    },
    {
        "<!--", L_HTML
    },
    {
        "<!DOCTYPE HTML", L_HTML
    },
    {
        "/*", L_C
    },               /* must precede "The", "the", etc. */
    {
        "#include", L_C
    },
    {
        "char", L_C
    },
    {
        "The", L_ENG
    },
    {
        "the", L_ENG
    },
    {
        "double", L_C
    },
    {
        "extern", L_C
    },
    {
        "float", L_C
    },
    {
        "real", L_C
    },
    {
        "struct", L_C
    },
    {
        "union", L_C
    },
    {
        "CFLAGS", L_MAKE
    },
    {
        "LDFLAGS", L_MAKE
    },
    {
        "all:", L_MAKE
    },
    {
        ".PRECIOUS", L_MAKE
    },
    /*
     * Too many files of text have these words in them.  Find another way to
     * recognize Fortrash.
     */
#ifdef    NOTDEF
    {
        "subroutine", L_FORT
    },
    {
        "function", L_FORT
    },
    {
        "block", L_FORT
    },
    {
        "common", L_FORT
    },
    {
        "dimension", L_FORT
    },
    {
        "integer", L_FORT
    },
    {
        "data", L_FORT
    },
#endif /* NOTDEF */
    {
        ".ascii", L_MACH
    },
    {
        ".asciiz", L_MACH
    },
    {
        ".byte", L_MACH
    },
    {
        ".even", L_MACH
    },
    {
        ".globl", L_MACH
    },
    {
        "clr", L_MACH
    },
    {
        "(input,", L_PAS
    },
    {
        "dcl", L_PLI
    },
    {
        "Received:", L_MAIL
    },
    {
        ">From", L_MAIL
    },
    {
        "Return-Path:", L_MAIL
    },
    {
        "Cc:", L_MAIL
    },
    {
        "Newsgroups:", L_NEWS
    },
    {
        "Path:", L_NEWS
    },
    {
        "Organization:", L_NEWS
    },
    {
        NULL, 0
    }
};

#define NNAMES ((sizeof(names)/sizeof(struct names)) - 1)

/*
 * Result String List (RSL)
 *
 * The file(1) command prints its output.  Instead, we store the various
 * "printed" strings in a list (allocating memory as we go) and concatenate
 * them at the end when we finally know how much space they'll need.
 */

typedef struct magic_rsl_s {
    const char *str;                  /* string, possibly a fragment */
    struct magic_rsl_s *next;   /* pointer to next fragment */
} magic_rsl;

/*
 * Apache module configuration structures
 */

/* per-server info */
typedef struct {
    const char *magicfile;    /* where magic be found */
    struct magic *magic;      /* head of magic config list */
    struct magic *last;
} magic_server_config_rec;

/* per-request info */
typedef struct {
    magic_rsl *head;          /* result string list */
    magic_rsl *tail;
    unsigned suf_recursion;   /* recursion depth in suffix check */
} magic_req_rec;

/*
 * configuration functions - called by Apache API routines
 */

module AP_MODULE_DECLARE_DATA mime_magic_module;

static void *create_magic_server_config(apr_pool_t *p, server_rec *d)
{
    /* allocate the config - use pcalloc because it needs to be zeroed */
    return apr_pcalloc(p, sizeof(magic_server_config_rec));
}

static void *merge_magic_server_config(apr_pool_t *p, void *basev, void *addv)
{
    magic_server_config_rec *base = (magic_server_config_rec *) basev;
    magic_server_config_rec *add = (magic_server_config_rec *) addv;
    magic_server_config_rec *new = (magic_server_config_rec *)
                            apr_palloc(p, sizeof(magic_server_config_rec));

    new->magicfile = add->magicfile ? add->magicfile : base->magicfile;
    new->magic = NULL;
    new->last = NULL;
    return new;
}

static const char *set_magicfile(cmd_parms *cmd, void *dummy, const char *arg)
{
    magic_server_config_rec *conf = (magic_server_config_rec *)
    ap_get_module_config(cmd->server->module_config,
                      &mime_magic_module);

    if (!conf) {
        return MODNAME ": server structure not allocated";
    }
    conf->magicfile = arg;
    return NULL;
}

/*
 * configuration file commands - exported to Apache API
 */

static const command_rec mime_magic_cmds[] =
{
    AP_INIT_TAKE1("MimeMagicFile", set_magicfile, NULL, RSRC_CONF,
     "Path to MIME Magic file (in file(1) format)"),
    {NULL}
};

/*
 * RSL (result string list) processing routines
 *
 * These collect strings that would have been printed in fragments by file(1)
 * into a list of magic_rsl structures with the strings. When complete,
 * they're concatenated together to become the MIME content and encoding
 * types.
 *
 * return value conventions for these functions: functions which return int:
 * failure = -1, other = result functions which return pointers: failure = 0,
 * other = result
 */

/* allocate a per-request structure and put it in the request record */
static magic_req_rec *magic_set_config(request_rec *r)
{
    magic_req_rec *req_dat = (magic_req_rec *) apr_palloc(r->pool,
                                                      sizeof(magic_req_rec));

    req_dat->head = req_dat->tail = (magic_rsl *) NULL;
    ap_set_module_config(r->request_config, &mime_magic_module, req_dat);
    return req_dat;
}

/* add a string to the result string list for this request */
/* it is the responsibility of the caller to allocate "str" */
static int magic_rsl_add(request_rec *r, const char *str)
{
    magic_req_rec *req_dat = (magic_req_rec *)
                    ap_get_module_config(r->request_config, &mime_magic_module);
    magic_rsl *rsl;

    /* make sure we have a list to put it in */
    if (!req_dat) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, APR_EINVAL, r,
                    MODNAME ": request config should not be NULL");
        if (!(req_dat = magic_set_config(r))) {
            /* failure */
            return -1;
        }
    }

    /* allocate the list entry */
    rsl = (magic_rsl *) apr_palloc(r->pool, sizeof(magic_rsl));

    /* fill it */
    rsl->str = str;
    rsl->next = (magic_rsl *) NULL;

    /* append to the list */
    if (req_dat->head && req_dat->tail) {
        req_dat->tail->next = rsl;
        req_dat->tail = rsl;
    }
    else {
        req_dat->head = req_dat->tail = rsl;
    }

    /* success */
    return 0;
}

/* RSL hook for puts-type functions */
static int magic_rsl_puts(request_rec *r, const char *str)
{
    return magic_rsl_add(r, str);
}

/* RSL hook for printf-type functions */
static int magic_rsl_printf(request_rec *r, char *str,...)
{
    va_list ap;

    char buf[MAXMIMESTRING];

    /* assemble the string into the buffer */
    va_start(ap, str);
    apr_vsnprintf(buf, sizeof(buf), str, ap);
    va_end(ap);

    /* add the buffer to the list */
    return magic_rsl_add(r, apr_pstrdup(r->pool, buf));
}

/* RSL hook for putchar-type functions */
static int magic_rsl_putchar(request_rec *r, char c)
{
    char str[2];

    /* high overhead for 1 char - just hope they don't do this much */
    str[0] = c;
    str[1] = '\0';
    return magic_rsl_add(r, str);
}

/* allocate and copy a contiguous string from a result string list */
static char *rsl_strdup(request_rec *r, int start_frag, int start_pos, int len)
{
    char *result;       /* return value */
    int cur_frag,       /* current fragment number/counter */
        cur_pos,        /* current position within fragment */
        res_pos;        /* position in result string */
    magic_rsl *frag;    /* list-traversal pointer */
    magic_req_rec *req_dat = (magic_req_rec *)
                    ap_get_module_config(r->request_config, &mime_magic_module);

    /* allocate the result string */
    result = (char *) apr_palloc(r->pool, len + 1);

    /* loop through and collect the string */
    res_pos = 0;
    for (frag = req_dat->head, cur_frag = 0;
         frag->next;
         frag = frag->next, cur_frag++) {
        /* loop to the first fragment */
        if (cur_frag < start_frag)
            continue;

        /* loop through and collect chars */
        for (cur_pos = (cur_frag == start_frag) ? start_pos : 0;
             frag->str[cur_pos];
             cur_pos++) {
            if (cur_frag >= start_frag
                && cur_pos >= start_pos
                && res_pos <= len) {
                result[res_pos++] = frag->str[cur_pos];
                if (res_pos > len) {
                    break;
                }
            }
        }
    }

    /* clean up and return */
    result[res_pos] = 0;
#if MIME_MAGIC_DEBUG
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
             MODNAME ": rsl_strdup() %d chars: %s", res_pos - 1, result);
#endif
    return result;
}

/* states for the state-machine algorithm in magic_rsl_to_request() */
typedef enum {
    rsl_leading_space, rsl_type, rsl_subtype, rsl_separator, rsl_encoding
} rsl_states;

/* process the RSL and set the MIME info in the request record */
static int magic_rsl_to_request(request_rec *r)
{
    int cur_frag,         /* current fragment number/counter */
        cur_pos,          /* current position within fragment */
        type_frag,        /* content type starting point: fragment */
        type_pos,         /* content type starting point: position */
        type_len,         /* content type length */
        encoding_frag,    /* content encoding starting point: fragment */
        encoding_pos,     /* content encoding starting point: position */
        encoding_len;     /* content encoding length */

    magic_rsl *frag;      /* list-traversal pointer */
    rsl_states state;

    magic_req_rec *req_dat = (magic_req_rec *)
                    ap_get_module_config(r->request_config, &mime_magic_module);

    /* check if we have a result */
    if (!req_dat || !req_dat->head) {
        /* empty - no match, we defer to other Apache modules */
        return DECLINED;
    }

    /* start searching for the type and encoding */
    state = rsl_leading_space;
    type_frag = type_pos = type_len = 0;
    encoding_frag = encoding_pos = encoding_len = 0;
    for (frag = req_dat->head, cur_frag = 0;
         frag && frag->next;
         frag = frag->next, cur_frag++) {
        /* loop through the characters in the fragment */
        for (cur_pos = 0; frag->str[cur_pos]; cur_pos++) {
            if (apr_isspace(frag->str[cur_pos])) {
                /* process whitespace actions for each state */
                if (state == rsl_leading_space) {
                    /* eat whitespace in this state */
                    continue;
                }
                else if (state == rsl_type) {
                    /* whitespace: type has no slash! */
                    return DECLINED;
                }
                else if (state == rsl_subtype) {
                    /* whitespace: end of MIME type */
                    state++;
                    continue;
                }
                else if (state == rsl_separator) {
                    /* eat whitespace in this state */
                    continue;
                }
                else if (state == rsl_encoding) {
                    /* whitespace: end of MIME encoding */
                    /* we're done */
                    frag = req_dat->tail;
                    break;
                }
                else {
                    /* should not be possible */
                    /* abandon malfunctioning module */
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                                MODNAME ": bad state %d (ws)", state);
                    return DECLINED;
                }
                /* NOTREACHED */
            }
            else if (state == rsl_type &&
                     frag->str[cur_pos] == '/') {
                /* copy the char and go to rsl_subtype state */
                type_len++;
                state++;
            }
            else {
                /* process non-space actions for each state */
                if (state == rsl_leading_space) {
                    /* non-space: begin MIME type */
                    state++;
                    type_frag = cur_frag;
                    type_pos = cur_pos;
                    type_len = 1;
                    continue;
                }
                else if (state == rsl_type ||
                         state == rsl_subtype) {
                    /* non-space: adds to type */
                    type_len++;
                    continue;
                }
                else if (state == rsl_separator) {
                    /* non-space: begin MIME encoding */
                    state++;
                    encoding_frag = cur_frag;
                    encoding_pos = cur_pos;
                    encoding_len = 1;
                    continue;
                }
                else if (state == rsl_encoding) {
                    /* non-space: adds to encoding */
                    encoding_len++;
                    continue;
                }
                else {
                    /* should not be possible */
                    /* abandon malfunctioning module */
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                                MODNAME ": bad state %d (ns)", state);
                    return DECLINED;
                }
                /* NOTREACHED */
            }
            /* NOTREACHED */
        }
    }

    /* if we ended prior to state rsl_subtype, we had incomplete info */
    if (state != rsl_subtype && state != rsl_separator &&
        state != rsl_encoding) {
        /* defer to other modules */
        return DECLINED;
    }

    /* save the info in the request record */
    if (state == rsl_subtype || state == rsl_encoding ||
        state == rsl_encoding) {
        char *tmp;
        tmp = rsl_strdup(r, type_frag, type_pos, type_len);
        /* XXX: this could be done at config time I'm sure... but I'm
         * confused by all this magic_rsl stuff. -djg */
        ap_content_type_tolower(tmp);
        ap_set_content_type(r, tmp);
    }
    if (state == rsl_encoding) {
        char *tmp;
        tmp = rsl_strdup(r, encoding_frag,
                                         encoding_pos, encoding_len);
        /* XXX: this could be done at config time I'm sure... but I'm
         * confused by all this magic_rsl stuff. -djg */
        ap_str_tolower(tmp);
        r->content_encoding = tmp;
    }

    /* detect memory allocation or other errors */
    if (!r->content_type ||
        (state == rsl_encoding && !r->content_encoding)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      MODNAME ": unexpected state %d; could be caused by bad "
                      "data in magic file",
                      state);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    /* success! */
    return OK;
}

/*
 * magic_process - process input file r        Apache API request record
 * (formerly called "process" in file command, prefix added for clarity) Opens
 * the file and reads a fixed-size buffer to begin processing the contents.
 */
static int magic_process(request_rec *r)
{
    apr_file_t *fd = NULL;
    unsigned char buf[HOWMANY + 1];  /* one extra for terminating '\0' */
    apr_size_t nbytes = 0;           /* number of bytes read from a datafile */
    int result;

    /*
     * first try judging the file based on its filesystem status
     */
    switch ((result = fsmagic(r, r->filename))) {
    case DONE:
        magic_rsl_putchar(r, '\n');
        return OK;
    case OK:
        break;
    default:
        /* fatal error, bail out */
        return result;
    }

    if (apr_file_open(&fd, r->filename, APR_READ, APR_OS_DEFAULT, r->pool) != APR_SUCCESS) {
        /* We can't open it, but we were able to stat it. */
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                    MODNAME ": can't read `%s'", r->filename);
        /* let some other handler decide what the problem is */
        return DECLINED;
    }

    /*
     * try looking at the first HOWMANY bytes
     */
    nbytes = sizeof(buf) - 1;
    if ((result = apr_file_read(fd, (char *) buf, &nbytes)) != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, result, r,
                    MODNAME ": read failed: %s", r->filename);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    if (nbytes == 0) {
        return DECLINED;
    }
    else {
        buf[nbytes++] = '\0';  /* null-terminate it */
        result = tryit(r, buf, nbytes, 1);
        if (result != OK) {
            return result;
        }
    }

    (void) apr_file_close(fd);
    (void) magic_rsl_putchar(r, '\n');

    return OK;
}


static int tryit(request_rec *r, unsigned char *buf, apr_size_t nb,
                 int checkzmagic)
{
    /*
     * Try compression stuff
     */
    if (checkzmagic == 1) {
        if (zmagic(r, buf, nb) == 1)
            return OK;
    }

    /*
     * try tests in /etc/magic (or surrogate magic file)
     */
    if (softmagic(r, buf, nb) == 1)
        return OK;

    /*
     * try known keywords, check for ascii-ness too.
     */
    if (ascmagic(r, buf, nb) == 1)
        return OK;

    /*
     * abandon hope, all ye who remain here
     */
    return DECLINED;
}

#define    EATAB {while (apr_isspace(*l))  ++l;}

/*
 * apprentice - load configuration from the magic file r
 *  API request record
 */
static int apprentice(server_rec *s, apr_pool_t *p)
{
    apr_file_t *f = NULL;
    apr_status_t result;
    char line[BUFSIZ + 1];
    int errs = 0;
    int lineno;
#if MIME_MAGIC_DEBUG
    int rule = 0;
    struct magic *m, *prevm;
#endif
    magic_server_config_rec *conf = (magic_server_config_rec *)
                    ap_get_module_config(s->module_config, &mime_magic_module);
    const char *fname = ap_server_root_relative(p, conf->magicfile);

    if (!fname) {
        ap_log_error(APLOG_MARK, APLOG_ERR, APR_EBADPATH, s,
                     MODNAME ": Invalid magic file path %s", conf->magicfile);
        return -1;
    }
    if ((result = apr_file_open(&f, fname, APR_READ | APR_BUFFERED,
                                APR_OS_DEFAULT, p)) != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, result, s,
                     MODNAME ": can't read magic file %s", fname);
        return -1;
    }

    /* set up the magic list (empty) */
    conf->magic = conf->last = NULL;

    /* parse it */
    for (lineno = 1; apr_file_gets(line, BUFSIZ, f) == APR_SUCCESS; lineno++) {
        int ws_offset;
        char *last = line + strlen(line) - 1; /* guaranteed that len >= 1 since an
                                               * "empty" line contains a '\n'
                                               */

        /* delete newline and any other trailing whitespace */
        while (last >= line
               && apr_isspace(*last)) {
            *last = '\0';
            --last;
        }

        /* skip leading whitespace */
        ws_offset = 0;
        while (line[ws_offset] && apr_isspace(line[ws_offset])) {
            ws_offset++;
        }

        /* skip blank lines */
        if (line[ws_offset] == 0) {
            continue;
        }

        /* comment, do not parse */
        if (line[ws_offset] == '#')
            continue;

#if MIME_MAGIC_DEBUG
        /* if we get here, we're going to use it so count it */
        rule++;
#endif

        /* parse it */
        if (parse(s, p, line + ws_offset, lineno) != 0)
            ++errs;
    }

    (void) apr_file_close(f);

#if MIME_MAGIC_DEBUG
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                MODNAME ": apprentice conf=%x file=%s m=%s m->next=%s last=%s",
                conf,
                conf->magicfile ? conf->magicfile : "NULL",
                conf->magic ? "set" : "NULL",
                (conf->magic && conf->magic->next) ? "set" : "NULL",
                conf->last ? "set" : "NULL");
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                MODNAME ": apprentice read %d lines, %d rules, %d errors",
                lineno, rule, errs);
#endif

#if MIME_MAGIC_DEBUG
    prevm = 0;
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                MODNAME ": apprentice test");
    for (m = conf->magic; m; m = m->next) {
        if (apr_isprint((((unsigned long) m) >> 24) & 255) &&
            apr_isprint((((unsigned long) m) >> 16) & 255) &&
            apr_isprint((((unsigned long) m) >> 8) & 255) &&
            apr_isprint(((unsigned long) m) & 255)) {
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                        MODNAME ": apprentice: POINTER CLOBBERED! "
                        "m=\"%c%c%c%c\" line=%d",
                        (((unsigned long) m) >> 24) & 255,
                        (((unsigned long) m) >> 16) & 255,
                        (((unsigned long) m) >> 8) & 255,
                        ((unsigned long) m) & 255,
                        prevm ? prevm->lineno : -1);
            break;
        }
        prevm = m;
    }
#endif

    return (errs ? -1 : 0);
}

/*
 * extend the sign bit if the comparison is to be signed
 */
static unsigned long signextend(server_rec *s, struct magic *m, unsigned long v)
{
    if (!(m->flag & UNSIGNED))
        switch (m->type) {
            /*
             * Do not remove the casts below.  They are vital. When later
             * compared with the data, the sign extension must have happened.
             */
        case BYTE:
            v = (char) v;
            break;
        case SHORT:
        case BESHORT:
        case LESHORT:
            v = (short) v;
            break;
        case DATE:
        case BEDATE:
        case LEDATE:
        case LONG:
        case BELONG:
        case LELONG:
            v = (long) v;
            break;
        case STRING:
            break;
        default:
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                        MODNAME ": can't happen: m->type=%d", m->type);
            return -1;
        }
    return v;
}

/*
 * parse one line from magic file, put into magic[index++] if valid
 */
static int parse(server_rec *serv, apr_pool_t *p, char *l, int lineno)
{
    struct magic *m;
    char *t, *s;
    magic_server_config_rec *conf = (magic_server_config_rec *)
                    ap_get_module_config(serv->module_config, &mime_magic_module);

    /* allocate magic structure entry */
    m = (struct magic *) apr_pcalloc(p, sizeof(struct magic));

    /* append to linked list */
    m->next = NULL;
    if (!conf->magic || !conf->last) {
        conf->magic = conf->last = m;
    }
    else {
        conf->last->next = m;
        conf->last = m;
    }

    /* set values in magic structure */
    m->flag = 0;
    m->cont_level = 0;
    m->lineno = lineno;

    while (*l == '>') {
        ++l;  /* step over */
        m->cont_level++;
    }

    if (m->cont_level != 0 && *l == '(') {
        ++l;  /* step over */
        m->flag |= INDIR;
    }

    /* get offset, then skip over it */
    m->offset = (int) strtol(l, &t, 0);
    if (l == t) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, serv,
                    MODNAME ": offset %s invalid", l);
    }
    l = t;

    if (m->flag & INDIR) {
        m->in.type = LONG;
        m->in.offset = 0;
        /*
         * read [.lbs][+-]nnnnn)
         */
        if (*l == '.') {
            switch (*++l) {
            case 'l':
                m->in.type = LONG;
                break;
            case 's':
                m->in.type = SHORT;
                break;
            case 'b':
                m->in.type = BYTE;
                break;
            default:
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, serv,
                        MODNAME ": indirect offset type %c invalid", *l);
                break;
            }
            l++;
        }
        s = l;
        if (*l == '+' || *l == '-')
            l++;
        if (apr_isdigit((unsigned char) *l)) {
            m->in.offset = strtol(l, &t, 0);
            if (*s == '-')
                m->in.offset = -m->in.offset;
        }
        else
            t = l;
        if (*t++ != ')') {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, serv,
                        MODNAME ": missing ')' in indirect offset");
        }
        l = t;
    }


    while (apr_isdigit((unsigned char) *l))
        ++l;
    EATAB;

#define NBYTE           4
#define NSHORT          5
#define NLONG           4
#define NSTRING         6
#define NDATE           4
#define NBESHORT        7
#define NBELONG         6
#define NBEDATE         6
#define NLESHORT        7
#define NLELONG         6
#define NLEDATE         6

    if (*l == 'u') {
        ++l;
        m->flag |= UNSIGNED;
    }

    /* get type, skip it */
    if (strncmp(l, "byte", NBYTE) == 0) {
        m->type = BYTE;
        l += NBYTE;
    }
    else if (strncmp(l, "short", NSHORT) == 0) {
        m->type = SHORT;
        l += NSHORT;
    }
    else if (strncmp(l, "long", NLONG) == 0) {
        m->type = LONG;
        l += NLONG;
    }
    else if (strncmp(l, "string", NSTRING) == 0) {
        m->type = STRING;
        l += NSTRING;
    }
    else if (strncmp(l, "date", NDATE) == 0) {
        m->type = DATE;
        l += NDATE;
    }
    else if (strncmp(l, "beshort", NBESHORT) == 0) {
        m->type = BESHORT;
        l += NBESHORT;
    }
    else if (strncmp(l, "belong", NBELONG) == 0) {
        m->type = BELONG;
        l += NBELONG;
    }
    else if (strncmp(l, "bedate", NBEDATE) == 0) {
        m->type = BEDATE;
        l += NBEDATE;
    }
    else if (strncmp(l, "leshort", NLESHORT) == 0) {
        m->type = LESHORT;
        l += NLESHORT;
    }
    else if (strncmp(l, "lelong", NLELONG) == 0) {
        m->type = LELONG;
        l += NLELONG;
    }
    else if (strncmp(l, "ledate", NLEDATE) == 0) {
        m->type = LEDATE;
        l += NLEDATE;
    }
    else {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, serv,
                    MODNAME ": type %s invalid", l);
        return -1;
    }
    /* New-style anding: "0 byte&0x80 =0x80 dynamically linked" */
    if (*l == '&') {
        ++l;
        m->mask = signextend(serv, m, strtol(l, &l, 0));
    }
    else
        m->mask = ~0L;
    EATAB;

    switch (*l) {
    case '>':
    case '<':
        /* Old-style anding: "0 byte &0x80 dynamically linked" */
    case '&':
    case '^':
    case '=':
        m->reln = *l;
        ++l;
        break;
    case '!':
        if (m->type != STRING) {
            m->reln = *l;
            ++l;
            break;
        }
        /* FALL THROUGH */
    default:
        if (*l == 'x' && apr_isspace(l[1])) {
            m->reln = *l;
            ++l;
            goto GetDesc;  /* Bill The Cat */
        }
        m->reln = '=';
        break;
    }
    EATAB;

    if (getvalue(serv, m, &l))
        return -1;
    /*
     * now get last part - the description
     */
  GetDesc:
    EATAB;
    if (l[0] == '\b') {
        ++l;
        m->nospflag = 1;
    }
    else if ((l[0] == '\\') && (l[1] == 'b')) {
        ++l;
        ++l;
        m->nospflag = 1;
    }
    else
        m->nospflag = 0;
    strncpy(m->desc, l, sizeof(m->desc) - 1);
    m->desc[sizeof(m->desc) - 1] = '\0';

#if MIME_MAGIC_DEBUG
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, serv,
                MODNAME ": parse line=%d m=%x next=%x cont=%d desc=%s",
                lineno, m, m->next, m->cont_level, m->desc);
#endif /* MIME_MAGIC_DEBUG */

    return 0;
}

/*
 * Read a numeric value from a pointer, into the value union of a magic
 * pointer, according to the magic type.  Update the string pointer to point
 * just after the number read.  Return 0 for success, non-zero for failure.
 */
static int getvalue(server_rec *s, struct magic *m, char **p)
{
    int slen;

    if (m->type == STRING) {
        *p = getstr(s, *p, m->value.s, sizeof(m->value.s), &slen);
        m->vallen = slen;
    }
    else if (m->reln != 'x')
        m->value.l = signextend(s, m, strtol(*p, p, 0));
    return 0;
}

/*
 * Convert a string containing C character escapes.  Stop at an unescaped
 * space or tab. Copy the converted version to "p", returning its length in
 * *slen. Return updated scan pointer as function result.
 */
static char *getstr(server_rec *serv, register char *s, register char *p,
                    int plen, int *slen)
{
    char *origs = s, *origp = p;
    char *pmax = p + plen - 1;
    register int c;
    register int val;

    while ((c = *s++) != '\0') {
        if (apr_isspace(c))
            break;
        if (p >= pmax) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, serv,
                        MODNAME ": string too long: %s", origs);
            break;
        }
        if (c == '\\') {
            switch (c = *s++) {

            case '\0':
                goto out;

            default:
                *p++ = (char) c;
                break;

            case 'n':
                *p++ = '\n';
                break;

            case 'r':
                *p++ = '\r';
                break;

            case 'b':
                *p++ = '\b';
                break;

            case 't':
                *p++ = '\t';
                break;

            case 'f':
                *p++ = '\f';
                break;

            case 'v':
                *p++ = '\v';
                break;

                /* \ and up to 3 octal digits */
            case '0':
            case '1':
            case '2':
            case '3':
            case '4':
            case '5':
            case '6':
            case '7':
                val = c - '0';
                c = *s++;  /* try for 2 */
                if (c >= '0' && c <= '7') {
                    val = (val << 3) | (c - '0');
                    c = *s++;  /* try for 3 */
                    if (c >= '0' && c <= '7')
                        val = (val << 3) | (c - '0');
                    else
                        --s;
                }
                else
                    --s;
                *p++ = (char) val;
                break;

                /* \x and up to 3 hex digits */
            case 'x':
                val = 'x';            /* Default if no digits */
                c = hextoint(*s++);   /* Get next char */
                if (c >= 0) {
                    val = c;
                    c = hextoint(*s++);
                    if (c >= 0) {
                        val = (val << 4) + c;
                        c = hextoint(*s++);
                        if (c >= 0) {
                            val = (val << 4) + c;
                        }
                        else
                            --s;
                    }
                    else
                        --s;
                }
                else
                    --s;
                *p++ = (char) val;
                break;
            }
        }
        else
            *p++ = (char) c;
    }
  out:
    *p = '\0';
    *slen = p - origp;
    return s;
}


/* Single hex char to int; -1 if not a hex char. */
static int hextoint(int c)
{
    if (apr_isdigit(c))
        return c - '0';
    if ((c >= 'a') && (c <= 'f'))
        return c + 10 - 'a';
    if ((c >= 'A') && (c <= 'F'))
        return c + 10 - 'A';
    return -1;
}


/*
 * return DONE to indicate it's been handled
 * return OK to indicate it's a regular file still needing handling
 * other returns indicate a failure of some sort
 */
static int fsmagic(request_rec *r, const char *fn)
{
    switch (r->finfo.filetype) {
    case APR_DIR:
        magic_rsl_puts(r, DIR_MAGIC_TYPE);
        return DONE;
    case APR_CHR:
        /*
         * (void) magic_rsl_printf(r,"character special (%d/%d)",
         * major(sb->st_rdev), minor(sb->st_rdev));
         */
        (void) magic_rsl_puts(r, MIME_BINARY_UNKNOWN);
        return DONE;
    case APR_BLK:
        /*
         * (void) magic_rsl_printf(r,"block special (%d/%d)",
         * major(sb->st_rdev), minor(sb->st_rdev));
         */
        (void) magic_rsl_puts(r, MIME_BINARY_UNKNOWN);
        return DONE;
        /* TODO add code to handle V7 MUX and Blit MUX files */
    case APR_PIPE:
        /*
         * magic_rsl_puts(r,"fifo (named pipe)");
         */
        (void) magic_rsl_puts(r, MIME_BINARY_UNKNOWN);
        return DONE;
    case APR_LNK:
        /* We used stat(), the only possible reason for this is that the
         * symlink is broken.
         */
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                    MODNAME ": broken symlink (%s)", fn);
        return HTTP_INTERNAL_SERVER_ERROR;
    case APR_SOCK:
        magic_rsl_puts(r, MIME_BINARY_UNKNOWN);
        return DONE;
    case APR_REG:
        break;
    default:
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      MODNAME ": invalid file type %d.", r->finfo.filetype);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    /*
     * regular file, check next possibility
     */
    if (r->finfo.size == 0) {
        magic_rsl_puts(r, MIME_TEXT_UNKNOWN);
        return DONE;
    }
    return OK;
}

/*
 * softmagic - lookup one file in database (already read from /etc/magic by
 * apprentice.c). Passed the name and FILE * of one file to be typed.
 */
                /* ARGSUSED1 *//* nbytes passed for regularity, maybe need later */
static int softmagic(request_rec *r, unsigned char *buf, apr_size_t nbytes)
{
    if (match(r, buf, nbytes))
        return 1;

    return 0;
}

/*
 * Go through the whole list, stopping if you find a match.  Process all the
 * continuations of that match before returning.
 *
 * We support multi-level continuations:
 *
 * At any time when processing a successful top-level match, there is a current
 * continuation level; it represents the level of the last successfully
 * matched continuation.
 *
 * Continuations above that level are skipped as, if we see one, it means that
 * the continuation that controls them - i.e, the lower-level continuation
 * preceding them - failed to match.
 *
 * Continuations below that level are processed as, if we see one, it means
 * we've finished processing or skipping higher-level continuations under the
 * control of a successful or unsuccessful lower-level continuation, and are
 * now seeing the next lower-level continuation and should process it.  The
 * current continuation level reverts to the level of the one we're seeing.
 *
 * Continuations at the current level are processed as, if we see one, there's
 * no lower-level continuation that may have failed.
 *
 * If a continuation matches, we bump the current continuation level so that
 * higher-level continuations are processed.
 */
static int match(request_rec *r, unsigned char *s, apr_size_t nbytes)
{
#if MIME_MAGIC_DEBUG
    int rule_counter = 0;
#endif
    int cont_level = 0;
    int need_separator = 0;
    union VALUETYPE p;
    magic_server_config_rec *conf = (magic_server_config_rec *)
                ap_get_module_config(r->server->module_config, &mime_magic_module);
    struct magic *m;

#if MIME_MAGIC_DEBUG
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                MODNAME ": match conf=%x file=%s m=%s m->next=%s last=%s",
                conf,
                conf->magicfile ? conf->magicfile : "NULL",
                conf->magic ? "set" : "NULL",
                (conf->magic && conf->magic->next) ? "set" : "NULL",
                conf->last ? "set" : "NULL");
#endif

#if MIME_MAGIC_DEBUG
    for (m = conf->magic; m; m = m->next) {
        if (apr_isprint((((unsigned long) m) >> 24) & 255) &&
            apr_isprint((((unsigned long) m) >> 16) & 255) &&
            apr_isprint((((unsigned long) m) >> 8) & 255) &&
            apr_isprint(((unsigned long) m) & 255)) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                        MODNAME ": match: POINTER CLOBBERED! "
                        "m=\"%c%c%c%c\"",
                        (((unsigned long) m) >> 24) & 255,
                        (((unsigned long) m) >> 16) & 255,
                        (((unsigned long) m) >> 8) & 255,
                        ((unsigned long) m) & 255);
            break;
        }
    }
#endif

    for (m = conf->magic; m; m = m->next) {
#if MIME_MAGIC_DEBUG
        rule_counter++;
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                    MODNAME ": line=%d desc=%s", m->lineno, m->desc);
#endif

        /* check if main entry matches */
        if (!mget(r, &p, s, m, nbytes) ||
            !mcheck(r, &p, m)) {
            struct magic *m_cont;

            /*
             * main entry didn't match, flush its continuations
             */
            if (!m->next || (m->next->cont_level == 0)) {
                continue;
            }

            m_cont = m->next;
            while (m_cont && (m_cont->cont_level != 0)) {
#if MIME_MAGIC_DEBUG
                rule_counter++;
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                        MODNAME ": line=%d mc=%x mc->next=%x cont=%d desc=%s",
                            m_cont->lineno, m_cont,
                            m_cont->next, m_cont->cont_level,
                            m_cont->desc);
#endif
                /*
                 * this trick allows us to keep *m in sync when the continue
                 * advances the pointer
                 */
                m = m_cont;
                m_cont = m_cont->next;
            }
            continue;
        }

        /* if we get here, the main entry rule was a match */
        /* this will be the last run through the loop */
#if MIME_MAGIC_DEBUG
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                    MODNAME ": rule matched, line=%d type=%d %s",
                    m->lineno, m->type,
                    (m->type == STRING) ? m->value.s : "");
#endif

        /* print the match */
        mprint(r, &p, m);

        /*
         * If we printed something, we'll need to print a blank before we
         * print something else.
         */
        if (m->desc[0])
            need_separator = 1;
        /* and any continuations that match */
        cont_level++;
        /*
         * while (m && m->next && m->next->cont_level != 0 && ( m = m->next
         * ))
         */
        m = m->next;
        while (m && (m->cont_level != 0)) {
#if MIME_MAGIC_DEBUG
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                        MODNAME ": match line=%d cont=%d type=%d %s",
                        m->lineno, m->cont_level, m->type,
                        (m->type == STRING) ? m->value.s : "");
#endif
            if (cont_level >= m->cont_level) {
                if (cont_level > m->cont_level) {
                    /*
                     * We're at the end of the level "cont_level"
                     * continuations.
                     */
                    cont_level = m->cont_level;
                }
                if (mget(r, &p, s, m, nbytes) &&
                    mcheck(r, &p, m)) {
                    /*
                     * This continuation matched. Print its message, with a
                     * blank before it if the previous item printed and this
                     * item isn't empty.
                     */
                    /* space if previous printed */
                    if (need_separator
                        && (m->nospflag == 0)
                        && (m->desc[0] != '\0')
                        ) {
                        (void) magic_rsl_putchar(r, ' ');
                        need_separator = 0;
                    }
                    mprint(r, &p, m);
                    if (m->desc[0])
                        need_separator = 1;

                    /*
                     * If we see any continuations at a higher level, process
                     * them.
                     */
                    cont_level++;
                }
            }

            /* move to next continuation record */
            m = m->next;
        }
#if MIME_MAGIC_DEBUG
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                    MODNAME ": matched after %d rules", rule_counter);
#endif
        return 1;  /* all through */
    }
#if MIME_MAGIC_DEBUG
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                MODNAME ": failed after %d rules", rule_counter);
#endif
    return 0;  /* no match at all */
}

static void mprint(request_rec *r, union VALUETYPE *p, struct magic *m)
{
    char *pp;
    unsigned long v;
    char time_str[APR_CTIME_LEN];

    switch (m->type) {
    case BYTE:
        v = p->b;
        break;

    case SHORT:
    case BESHORT:
    case LESHORT:
        v = p->h;
        break;

    case LONG:
    case BELONG:
    case LELONG:
        v = p->l;
        break;

    case STRING:
        if (m->reln == '=') {
            (void) magic_rsl_printf(r, m->desc, m->value.s);
        }
        else {
            (void) magic_rsl_printf(r, m->desc, p->s);
        }
        return;

    case DATE:
    case BEDATE:
    case LEDATE:
        apr_ctime(time_str, apr_time_from_sec(*(time_t *)&p->l));
        pp = time_str;
        (void) magic_rsl_printf(r, m->desc, pp);
        return;
    default:
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                    MODNAME ": invalid m->type (%d) in mprint().",
                    m->type);
        return;
    }

    v = signextend(r->server, m, v) & m->mask;
    (void) magic_rsl_printf(r, m->desc, (unsigned long) v);
}

/*
 * Convert the byte order of the data we are looking at
 */
static int mconvert(request_rec *r, union VALUETYPE *p, struct magic *m)
{
    char *rt;

    switch (m->type) {
    case BYTE:
    case SHORT:
    case LONG:
    case DATE:
        return 1;
    case STRING:
        /* Null terminate and eat the return */
        p->s[sizeof(p->s) - 1] = '\0';
        if ((rt = strchr(p->s, '\n')) != NULL)
            *rt = '\0';
        return 1;
    case BESHORT:
        p->h = (short) ((p->hs[0] << 8) | (p->hs[1]));
        return 1;
    case BELONG:
    case BEDATE:
        p->l = (long)
            ((p->hl[0] << 24) | (p->hl[1] << 16) | (p->hl[2] << 8) | (p->hl[3]));
        return 1;
    case LESHORT:
        p->h = (short) ((p->hs[1] << 8) | (p->hs[0]));
        return 1;
    case LELONG:
    case LEDATE:
        p->l = (long)
            ((p->hl[3] << 24) | (p->hl[2] << 16) | (p->hl[1] << 8) | (p->hl[0]));
        return 1;
    default:
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                    MODNAME ": invalid type %d in mconvert().", m->type);
        return 0;
    }
}


static int mget(request_rec *r, union VALUETYPE *p, unsigned char *s,
                struct magic *m, apr_size_t nbytes)
{
    long offset = m->offset;

    if (offset + sizeof(union VALUETYPE) > nbytes)
                  return 0;

    memcpy(p, s + offset, sizeof(union VALUETYPE));

    if (!mconvert(r, p, m))
        return 0;

    if (m->flag & INDIR) {

        switch (m->in.type) {
        case BYTE:
            offset = p->b + m->in.offset;
            break;
        case SHORT:
            offset = p->h + m->in.offset;
            break;
        case LONG:
            offset = p->l + m->in.offset;
            break;
        }

        if (offset + sizeof(union VALUETYPE) > nbytes)
                      return 0;

        memcpy(p, s + offset, sizeof(union VALUETYPE));

        if (!mconvert(r, p, m))
            return 0;
    }
    return 1;
}

static int mcheck(request_rec *r, union VALUETYPE *p, struct magic *m)
{
    register unsigned long l = m->value.l;
    register unsigned long v;
    int matched;

    if ((m->value.s[0] == 'x') && (m->value.s[1] == '\0')) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                    MODNAME ": BOINK");
        return 1;
    }

    switch (m->type) {
    case BYTE:
        v = p->b;
        break;

    case SHORT:
    case BESHORT:
    case LESHORT:
        v = p->h;
        break;

    case LONG:
    case BELONG:
    case LELONG:
    case DATE:
    case BEDATE:
    case LEDATE:
        v = p->l;
        break;

    case STRING:
        l = 0;
        /*
         * What we want here is: v = strncmp(m->value.s, p->s, m->vallen);
         * but ignoring any nulls.  bcmp doesn't give -/+/0 and isn't
         * universally available anyway.
         */
        v = 0;
        {
            register unsigned char *a = (unsigned char *) m->value.s;
            register unsigned char *b = (unsigned char *) p->s;
            register int len = m->vallen;

            while (--len >= 0)
                if ((v = *b++ - *a++) != 0)
                    break;
        }
        break;
    default:
        /*  bogosity, pretend that it just wasn't a match */
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                    MODNAME ": invalid type %d in mcheck().", m->type);
        return 0;
    }

    v = signextend(r->server, m, v) & m->mask;

    switch (m->reln) {
    case 'x':
#if MIME_MAGIC_DEBUG
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                    "%lu == *any* = 1", v);
#endif
        matched = 1;
        break;

    case '!':
        matched = v != l;
#if MIME_MAGIC_DEBUG
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                    "%lu != %lu = %d", v, l, matched);
#endif
        break;

    case '=':
        matched = v == l;
#if MIME_MAGIC_DEBUG
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                    "%lu == %lu = %d", v, l, matched);
#endif
        break;

    case '>':
        if (m->flag & UNSIGNED) {
            matched = v > l;
#if MIME_MAGIC_DEBUG
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                        "%lu > %lu = %d", v, l, matched);
#endif
        }
        else {
            matched = (long) v > (long) l;
#if MIME_MAGIC_DEBUG
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                        "%ld > %ld = %d", v, l, matched);
#endif
        }
        break;

    case '<':
        if (m->flag & UNSIGNED) {
            matched = v < l;
#if MIME_MAGIC_DEBUG
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                        "%lu < %lu = %d", v, l, matched);
#endif
        }
        else {
            matched = (long) v < (long) l;
#if MIME_MAGIC_DEBUG
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                        "%ld < %ld = %d", v, l, matched);
#endif
        }
        break;

    case '&':
        matched = (v & l) == l;
#if MIME_MAGIC_DEBUG
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                    "((%lx & %lx) == %lx) = %d", v, l, l, matched);
#endif
        break;

    case '^':
        matched = (v & l) != l;
#if MIME_MAGIC_DEBUG
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                    "((%lx & %lx) != %lx) = %d", v, l, l, matched);
#endif
        break;

    default:
        /* bogosity, pretend it didn't match */
        matched = 0;
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                    MODNAME ": mcheck: can't happen: invalid relation %d.",
                    m->reln);
        break;
    }

    return matched;
}

/* an optimization over plain strcmp() */
#define    STREQ(a, b)    (*(a) == *(b) && strcmp((a), (b)) == 0)

static int ascmagic(request_rec *r, unsigned char *buf, apr_size_t nbytes)
{
    int has_escapes = 0;
    unsigned char *s;
    char nbuf[HOWMANY + 1];  /* one extra for terminating '\0' */
    char *token;
    const struct names *p;
    int small_nbytes;
    char *strtok_state;

    /* these are easy, do them first */

    /*
     * for troff, look for . + letter + letter or .\"; this must be done to
     * disambiguate tar archives' ./file and other trash from real troff
     * input.
     */
    if (*buf == '.') {
        unsigned char *tp = buf + 1;

        while (apr_isspace(*tp))
            ++tp;  /* skip leading whitespace */
        if ((apr_isalnum(*tp) || *tp == '\\') &&
             (apr_isalnum(*(tp + 1)) || *tp == '"')) {
            magic_rsl_puts(r, "application/x-troff");
            return 1;
        }
    }
    if ((*buf == 'c' || *buf == 'C') && apr_isspace(*(buf + 1))) {
        /* Fortran */
        magic_rsl_puts(r, "text/plain");
        return 1;
    }

    /* look for tokens from names.h - this is expensive!, so we'll limit
     * ourselves to only SMALL_HOWMANY bytes */
    small_nbytes = (nbytes > SMALL_HOWMANY) ? SMALL_HOWMANY : nbytes;
    /* make a copy of the buffer here because apr_strtok() will destroy it */
    s = (unsigned char *) memcpy(nbuf, buf, small_nbytes);
    s[small_nbytes] = '\0';
    has_escapes = (memchr(s, '\033', small_nbytes) != NULL);
    while ((token = apr_strtok((char *) s, " \t\n\r\f", &strtok_state)) != NULL) {
        s = NULL;  /* make apr_strtok() keep on tokin' */
        for (p = names; p < names + NNAMES; p++) {
            if (STREQ(p->name, token)) {
                magic_rsl_puts(r, types[p->type]);
                if (has_escapes)
                    magic_rsl_puts(r, " (with escape sequences)");
                return 1;
            }
        }
    }

    switch (is_tar(buf, nbytes)) {
    case 1:
        /* V7 tar archive */
        magic_rsl_puts(r, "application/x-tar");
        return 1;
    case 2:
        /* POSIX tar archive */
        magic_rsl_puts(r, "application/x-tar");
        return 1;
    }

    /* all else fails, but it is ascii... */
    return 0;
}


/*
 * compress routines: zmagic() - returns 0 if not recognized, uncompresses
 * and prints information if recognized uncompress(s, method, old, n, newch)
 * - uncompress old into new, using method, return sizeof new
 */

static struct {
    char *magic;
    apr_size_t maglen;
    char *argv[3];
    int silent;
    char *encoding;  /* MUST be lowercase */
} compr[] = {

    /* we use gzip here rather than uncompress because we have to pass
     * it a full filename -- and uncompress only considers filenames
     * ending with .Z
     */
    {
        "\037\235", 2, {
            "gzip", "-dcq", NULL
        }, 0, "x-compress"
    },
    {
        "\037\213", 2, {
            "gzip", "-dcq", NULL
        }, 1, "x-gzip"
    },
    /*
     * XXX pcat does not work, cause I don't know how to make it read stdin,
     * so we use gzip
     */
    {
        "\037\036", 2, {
            "gzip", "-dcq", NULL
        }, 0, "x-gzip"
    },
};

static int ncompr = sizeof(compr) / sizeof(compr[0]);

static int zmagic(request_rec *r, unsigned char *buf, apr_size_t nbytes)
{
    unsigned char *newbuf;
    int newsize;
    int i;

    for (i = 0; i < ncompr; i++) {
        if (nbytes < compr[i].maglen)
            continue;
        if (memcmp(buf, compr[i].magic, compr[i].maglen) == 0)
            break;
    }

    if (i == ncompr)
        return 0;

    if ((newsize = uncompress(r, i, &newbuf, nbytes)) > 0) {
        if (tryit(r, newbuf, newsize, 0) != OK) {
            return 0;
        }

        /* set encoding type in the request record */
        r->content_encoding = compr[i].encoding;
    }
    return 1;
}


struct uncompress_parms {
    request_rec *r;
    int method;
};

static int create_uncompress_child(struct uncompress_parms *parm, apr_pool_t *cntxt,
                                   apr_file_t **pipe_in)
{
    int rc = 1;
    const char *new_argv[4];
    const char *const *env;
    request_rec *r = parm->r;
    apr_pool_t *child_context = cntxt;
    apr_procattr_t *procattr;
    apr_proc_t *procnew;

    /* XXX missing 1.3 logic:
     *
     * what happens when !compr[parm->method].silent?
     * Should we create the err pipe, read it, and copy to the log?
     */

    env = (const char *const *)ap_create_environment(child_context, r->subprocess_env);

    if ((apr_procattr_create(&procattr, child_context) != APR_SUCCESS) ||
        (apr_procattr_io_set(procattr, APR_FULL_BLOCK,
                           APR_FULL_BLOCK, APR_NO_PIPE)   != APR_SUCCESS) ||
        (apr_procattr_dir_set(procattr,
                              ap_make_dirstr_parent(r->pool, r->filename)) != APR_SUCCESS) ||
        (apr_procattr_cmdtype_set(procattr, APR_PROGRAM)    != APR_SUCCESS)) {
        /* Something bad happened, tell the world. */
        ap_log_rerror(APLOG_MARK, APLOG_ERR, APR_ENOPROC, r,
               "couldn't setup child process: %s", r->filename);
    }
    else {
        new_argv[0] = compr[parm->method].argv[0];
        new_argv[1] = compr[parm->method].argv[1];
        new_argv[2] = r->filename;
        new_argv[3] = NULL;

        procnew = apr_pcalloc(child_context, sizeof(*procnew));
        rc = apr_proc_create(procnew, compr[parm->method].argv[0],
                               new_argv, env, procattr, child_context);

        if (rc != APR_SUCCESS) {
            /* Bad things happened. Everyone should have cleaned up. */
            ap_log_rerror(APLOG_MARK, APLOG_ERR, APR_ENOPROC, r,
                          MODNAME ": could not execute `%s'.",
                          compr[parm->method].argv[0]);
        }
        else {
            apr_pool_note_subprocess(child_context, procnew, APR_KILL_AFTER_TIMEOUT);
            *pipe_in = procnew->out;
        }
    }

    return (rc);
}

static int uncompress(request_rec *r, int method,
                      unsigned char **newch, apr_size_t n)
{
    struct uncompress_parms parm;
    apr_file_t *pipe_out = NULL;
    apr_pool_t *sub_context;
    apr_status_t rv;

    parm.r = r;
    parm.method = method;

    /* We make a sub_pool so that we can collect our child early, otherwise
     * there are cases (i.e. generating directory indicies with mod_autoindex)
     * where we would end up with LOTS of zombies.
     */
    if (apr_pool_create(&sub_context, r->pool) != APR_SUCCESS)
        return -1;

    if ((rv = create_uncompress_child(&parm, sub_context, &pipe_out)) != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                    MODNAME ": couldn't spawn uncompress process: %s", r->uri);
        return -1;
    }

    *newch = (unsigned char *) apr_palloc(r->pool, n);
    rv = apr_file_read(pipe_out, *newch, &n);
    if (n == 0) {
        apr_pool_destroy(sub_context);
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
            MODNAME ": read failed from uncompress of %s", r->filename);
        return -1;
    }
    apr_pool_destroy(sub_context);
    return n;
}

/*
 * is_tar() -- figure out whether file is a tar archive.
 *
 * Stolen (by author of file utility) from the public domain tar program: Public
 * Domain version written 26 Aug 1985 John Gilmore (ihnp4!hoptoad!gnu).
 *
 * @(#)list.c 1.18 9/23/86 Public Domain - gnu $Id: mod_mime_magic.c,v 1.7
 * 1997/06/24 00:41:02 ikluft Exp ikluft $
 *
 * Comments changed and some code/comments reformatted for file command by Ian
 * Darwin.
 */

#define isodigit(c) (((unsigned char)(c) >= '0') && ((unsigned char)(c) <= '7'))

/*
 * Return 0 if the checksum is bad (i.e., probably not a tar archive), 1 for
 * old UNIX tar file, 2 for Unix Std (POSIX) tar file.
 */

static int is_tar(unsigned char *buf, apr_size_t nbytes)
{
    register union record *header = (union record *) buf;
    register int i;
    register long sum, recsum;
    register char *p;

    if (nbytes < sizeof(union record))
               return 0;

    recsum = from_oct(8, header->header.chksum);

    sum = 0;
    p = header->charptr;
    for (i = sizeof(union record); --i >= 0;) {
        /*
         * We can't use unsigned char here because of old compilers, e.g. V7.
         */
        sum += 0xFF & *p++;
    }

    /* Adjust checksum to count the "chksum" field as blanks. */
    for (i = sizeof(header->header.chksum); --i >= 0;)
        sum -= 0xFF & header->header.chksum[i];
    sum += ' ' * sizeof header->header.chksum;

    if (sum != recsum)
        return 0;   /* Not a tar archive */

    if (0 == strcmp(header->header.magic, TMAGIC))
        return 2;   /* Unix Standard tar archive */

    return 1;       /* Old fashioned tar archive */
}


/*
 * Quick and dirty octal conversion.
 *
 * Result is -1 if the field is invalid (all blank, or nonoctal).
 */
static long from_oct(int digs, char *where)
{
    register long value;

    while (apr_isspace(*where)) {  /* Skip spaces */
        where++;
        if (--digs <= 0)
            return -1;  /* All blank field */
    }
    value = 0;
    while (digs > 0 && isodigit(*where)) {  /* Scan til nonoctal */
        value = (value << 3) | (*where++ - '0');
        --digs;
    }

    if (digs > 0 && *where && !apr_isspace(*where))
        return -1;  /* Ended on non-space/nul */

    return value;
}

/*
 * Check for file-revision suffix
 *
 * This is for an obscure document control system used on an intranet.
 * The web representation of each file's revision has an @1, @2, etc
 * appended with the revision number.  This needs to be stripped off to
 * find the file suffix, which can be recognized by sending the name back
 * through a sub-request.  The base file name (without the @num suffix)
 * must exist because its type will be used as the result.
 */
static int revision_suffix(request_rec *r)
{
    int suffix_pos, result;
    char *sub_filename;
    request_rec *sub;

#if MIME_MAGIC_DEBUG
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                MODNAME ": revision_suffix checking %s", r->filename);
#endif /* MIME_MAGIC_DEBUG */

    /* check for recognized revision suffix */
    suffix_pos = strlen(r->filename) - 1;
    if (!apr_isdigit(r->filename[suffix_pos])) {
        return 0;
    }
    while (suffix_pos >= 0 && apr_isdigit(r->filename[suffix_pos]))
        suffix_pos--;
    if (suffix_pos < 0 || r->filename[suffix_pos] != '@') {
        return 0;
    }

    /* perform sub-request for the file name without the suffix */
    result = 0;
    sub_filename = apr_pstrndup(r->pool, r->filename, suffix_pos);
#if MIME_MAGIC_DEBUG
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                MODNAME ": subrequest lookup for %s", sub_filename);
#endif /* MIME_MAGIC_DEBUG */
    sub = ap_sub_req_lookup_file(sub_filename, r, NULL);

    /* extract content type/encoding/language from sub-request */
    if (sub->content_type) {
        ap_set_content_type(r, apr_pstrdup(r->pool, sub->content_type));
#if MIME_MAGIC_DEBUG
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                    MODNAME ": subrequest %s got %s",
                    sub_filename, r->content_type);
#endif /* MIME_MAGIC_DEBUG */
        if (sub->content_encoding)
            r->content_encoding =
                apr_pstrdup(r->pool, sub->content_encoding);
        if (sub->content_languages) {
            int n;
            r->content_languages = apr_array_copy(r->pool,
                                                  sub->content_languages);
            for (n = 0; n < r->content_languages->nelts; ++n) {
                char **lang = ((char **)r->content_languages->elts) + n;
                *lang = apr_pstrdup(r->pool, *lang);
            }
        }
        result = 1;
    }

    /* clean up */
    ap_destroy_sub_req(sub);

    return result;
}

/*
 * initialize the module
 */
static int magic_init(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *main_server)
{
    int result;
    magic_server_config_rec *conf;
    magic_server_config_rec *main_conf;
    server_rec *s;
#if MIME_MAGIC_DEBUG
    struct magic *m, *prevm;
#endif /* MIME_MAGIC_DEBUG */

    main_conf = ap_get_module_config(main_server->module_config, &mime_magic_module);
    for (s = main_server; s; s = s->next) {
        conf = ap_get_module_config(s->module_config, &mime_magic_module);
        if (conf->magicfile == NULL && s != main_server) {
            /* inherits from the parent */
            *conf = *main_conf;
        }
        else if (conf->magicfile) {
            result = apprentice(s, p);
            if (result == -1)
                return OK;
#if MIME_MAGIC_DEBUG
            prevm = 0;
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                        MODNAME ": magic_init 1 test");
            for (m = conf->magic; m; m = m->next) {
                if (apr_isprint((((unsigned long) m) >> 24) & 255) &&
                    apr_isprint((((unsigned long) m) >> 16) & 255) &&
                    apr_isprint((((unsigned long) m) >> 8) & 255) &&
                    apr_isprint(((unsigned long) m) & 255)) {
                    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                                MODNAME ": magic_init 1: POINTER CLOBBERED! "
                                "m=\"%c%c%c%c\" line=%d",
                                (((unsigned long) m) >> 24) & 255,
                                (((unsigned long) m) >> 16) & 255,
                                (((unsigned long) m) >> 8) & 255,
                                ((unsigned long) m) & 255,
                                prevm ? prevm->lineno : -1);
                    break;
                }
                prevm = m;
            }
#endif
        }
    }
    return OK;
}

/*
 * Find the Content-Type from any resource this module has available
 */

static int magic_find_ct(request_rec *r)
{
    int result;
    magic_server_config_rec *conf;

    /* the file has to exist */
    if (r->finfo.filetype == 0 || !r->filename) {
        return DECLINED;
    }

    /* was someone else already here? */
    if (r->content_type) {
        return DECLINED;
    }

    conf = ap_get_module_config(r->server->module_config, &mime_magic_module);
    if (!conf || !conf->magic) {
        return DECLINED;
    }

    /* initialize per-request info */
    if (!magic_set_config(r)) {
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    /* try excluding file-revision suffixes */
    if (revision_suffix(r) != 1) {
        /* process it based on the file contents */
        if ((result = magic_process(r)) != OK) {
            return result;
        }
    }

    /* if we have any results, put them in the request structure */
    return magic_rsl_to_request(r);
}

static void register_hooks(apr_pool_t *p)
{
    static const char * const aszPre[]={ "mod_mime.c", NULL };

    /* mod_mime_magic should be run after mod_mime, if at all. */

    ap_hook_type_checker(magic_find_ct, aszPre, NULL, APR_HOOK_MIDDLE);
    ap_hook_post_config(magic_init, NULL, NULL, APR_HOOK_FIRST);
}

/*
 * Apache API module interface
 */

module AP_MODULE_DECLARE_DATA mime_magic_module =
{
    STANDARD20_MODULE_STUFF,
    NULL,                      /* dir config creator */
    NULL,                      /* dir merger --- default is to override */
    create_magic_server_config,        /* server config */
    merge_magic_server_config, /* merge server config */
    mime_magic_cmds,           /* command apr_table_t */
    register_hooks              /* register hooks */
};
