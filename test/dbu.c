/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000 The Apache Software Foundation.  All rights
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
 * This file came from the SDBM package (written by oz@nexus.yorku.ca).
 * That package was under public domain. This file has been ported to
 * APR, updated to ANSI C and other, newer idioms, and added to the Apache
 * codebase under the above copyright and license.
 */

#include "apr.h"
#include "apr_general.h"
#include "apr_pools.h"
#include "apr_errno.h"
#include "apr_getopt.h"
#include "apr_time.h"

#if APR_HAVE_STDIO_H
#include <stdio.h>
#endif
#include <unistd.h>
#include <stdlib.h>     /* for atexit(), malloc() */
#include <string.h>

#include "apr_dbm.h"

static const char *progname;
static int rflag;
static const char *usage = "%s [-R] cat | look |... dbmname";

#define DERROR	0
#define DLOOK	1
#define DINSERT	2
#define DDELETE 3
#define	DCAT	4
#define DBUILD	5
#define DPRESS	6
#define DCREAT	7

#define LINEMAX	8192

typedef struct {
    const char *sname;
    int scode;
    int flags;
} cmd;

static const cmd cmds[] = {

    { "fetch", DLOOK,	 	APR_DBM_READONLY, },
    { "get", DLOOK,		APR_DBM_READONLY, },
    { "look", DLOOK,		APR_DBM_READONLY, },
    { "add", DINSERT,		APR_DBM_READWRITE, },
    { "insert", DINSERT,	APR_DBM_READWRITE, },
    { "store", DINSERT,		APR_DBM_READWRITE, },
    { "delete", DDELETE,	APR_DBM_READWRITE, },
    { "remove", DDELETE,	APR_DBM_READWRITE, },
    { "dump", DCAT,		APR_DBM_READONLY, },
    { "list", DCAT, 		APR_DBM_READONLY, },
    { "cat", DCAT,		APR_DBM_READONLY, },
#if 0
    { "creat", DCREAT,		APR_DBM_RWCREATE | O_TRUNC, },
    { "new", DCREAT,		APR_DBM_RWCREATE | O_TRUNC, },
#endif
    { "build", DBUILD,		APR_DBM_RWCREATE, },
    { "squash", DPRESS,		APR_DBM_READWRITE, },
    { "compact", DPRESS,	APR_DBM_READWRITE, },
    { "compress", DPRESS,	APR_DBM_READWRITE, },
};

#define CTABSIZ (sizeof (cmds)/sizeof (cmd))

static void doit(const cmd *act, const char *file, apr_pool_t *pool);
static void badk(const char *word);
static const cmd *parse(const char *str);
static void prdatum(FILE *stream, apr_datum_t d);
static void oops(const char *s1, const char *s2);


int main(int argc, const char * const * argv)
{
    apr_pool_t *pool;
    const cmd *act;
    apr_getopt_t *os;
    char optch;
    const char *optarg;

    (void) apr_initialize();
    atexit(apr_terminate);

    apr_create_pool(&pool, NULL);

    (void) apr_initopt(&os, pool, argc, argv);

    progname = argv[0];

    while (apr_getopt(os, "R", &optch, &optarg) == APR_SUCCESS)
        switch (optch) {
        case 'R':	       /* raw processing  */
            rflag++;
            break;

        default:
            oops("(unknown option) usage: %s", usage);
            break;
        }

    if (os->ind + 2 > argc)
        oops("usage: %s", usage);

    if ((act = parse(argv[os->ind])) == NULL)
        badk(argv[os->ind]);
    os->ind++;
    doit(act, argv[os->ind], pool);
    return 0;
}

static void doit(const cmd *act, const char *file, apr_pool_t *pool)
{
    apr_status_t rv;
    apr_datum_t key;
    apr_datum_t val;
    apr_dbm_t *db;
    char *op;
    int n;
    char *line;
#ifdef TIME
    long start;
    extern long time();
#endif

    if (apr_dbm_open(file, pool, act->flags, &db) != APR_SUCCESS)
        oops("cannot open: %s", file);

    if ((line = (char *) malloc(LINEMAX)) == NULL)
        oops("%s: cannot get memory", "line alloc");

    switch (act->scode) {

    case DLOOK:
        while (fgets(line, LINEMAX, stdin) != NULL) {
            n = strlen(line) - 1;
            line[n] = 0;
            key.dptr = line;
            key.dsize = n;
            rv = apr_dbm_fetch(db, key, &val);
            if (rv == APR_SUCCESS) {
                prdatum(stdout, val);
                putchar('\n');
                continue;
            }
            prdatum(stderr, key);
            fprintf(stderr, ": not found.\n");
        }
        break;
    case DINSERT:
        break;
    case DDELETE:
        while (fgets(line, LINEMAX, stdin) != NULL) {
            n = strlen(line) - 1;
            line[n] = 0;
            key.dptr = line;
            key.dsize = n;
            if (apr_dbm_delete(db, key) != APR_SUCCESS) {
                prdatum(stderr, key);
                fprintf(stderr, ": not found.\n");
            }
        }
        break;
    case DCAT:
        if (apr_dbm_firstkey(db, &key) != APR_SUCCESS)
            oops("could not fetch first key: %s", file);

        for (; key.dptr != 0; (void) apr_dbm_nextkey(db, &key)) {
            prdatum(stdout, key);
            putchar('\t');
            (void) apr_dbm_fetch(db, key, &val);
            prdatum(stdout, val);
            putchar('\n');
        }
        break;
    case DBUILD:
#ifdef TIME
        start = time(0);
#endif
        while (fgets(line, LINEMAX, stdin) != NULL) {
            n = strlen(line) - 1;
            line[n] = 0;
            key.dptr = line;
            if ((op = strchr(line, '\t')) != 0) {
                key.dsize = op - line;
                *op++ = 0;
                val.dptr = op;
                val.dsize = line + n - op;
            }
            else
                oops("bad input: %s", line);
	
            if (apr_dbm_store(db, key, val) != APR_SUCCESS) {
                prdatum(stderr, key);
                fprintf(stderr, ": ");
                oops("store: %s", "failed");
            }
        }
#ifdef TIME
        printf("done: %d seconds.\n", time(0) - start);
#endif
        break;
    case DPRESS:
        break;
    case DCREAT:
        break;
    }

    apr_dbm_close(db);
}

static void badk(const char *word)
{
    int i;

    if (progname)
        fprintf(stderr, "%s: ", progname);
    fprintf(stderr, "bad keywd %s. use one of\n", word);
    for (i = 0; i < (int)CTABSIZ; i++)
        fprintf(stderr, "%-8s%c", cmds[i].sname,
                ((i + 1) % 6 == 0) ? '\n' : ' ');
    fprintf(stderr, "\n");
    exit(1);
    /*NOTREACHED*/
}

static const cmd *parse(const char *str)
{
    int i = CTABSIZ;
    const cmd *p;
	
    for (p = cmds; i--; p++)
        if (strcmp(p->sname, str) == 0)
            return p;
    return NULL;
}

static void prdatum(FILE *stream, apr_datum_t d)
{
    int c;
    const char *p = d.dptr;
    int n = d.dsize;

    while (n--) {
        c = *p++ & 0377;
        if (c & 0200) {
            fprintf(stream, "M-");
            c &= 0177;
        }
        if (c == 0177 || c < ' ') 
            fprintf(stream, "^%c", (c == 0177) ? '?' : c + '@');
        else
            putc(c, stream);
    }
}

static void oops(const char *s1, const char *s2)
{
    if (progname)
        fprintf(stderr, "%s: ", progname);
    fprintf(stderr, s1, s2);
    if (errno > 0 && errno < sys_nerr)
        fprintf(stderr, " (%s)", sys_errlist[errno]);
    fprintf(stderr, "\n");
    exit(1);
}
