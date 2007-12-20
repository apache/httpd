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
 * httxt2dbm.c: simple program for converting RewriteMap text files to DBM
 * Rewrite databases for the Apache HTTP server
 *
 */

#include "apr.h"
#include "apr_lib.h"
#include "apr_strings.h"
#include "apr_file_io.h"
#include "apr_file_info.h"
#include "apr_pools.h"
#include "apr_getopt.h"
#include "apu.h"
#include "apr_dbm.h"

#if APR_HAVE_STDLIB_H
#include <stdlib.h> /* for atexit() */
#endif

static const char *input;
static const char *output;
static const char *format;
static const char *shortname;
static apr_file_t *errfile;
static char errbuf[120];
static int verbose;

/* From mod_rewrite.c */
#ifndef REWRITE_MAX_TXT_MAP_LINE
#define REWRITE_MAX_TXT_MAP_LINE 1024
#endif

#define NL APR_EOL_STR

#define AVAIL "available"
#define UNAVAIL "unavailable"

static void usage(void)
{
    const char *have_sdbm;
    const char *have_gdbm;
    const char *have_ndbm;
    const char *have_db;

#if APU_HAVE_SDBM
    have_sdbm = AVAIL;
#else
    have_sdbm = UNAVAIL;
#endif
#if APU_HAVE_GDBM
    have_gdbm = AVAIL;
#else
    have_gdbm = UNAVAIL;
#endif
#if APU_HAVE_NDBM
    have_ndbm = AVAIL;
#else
    have_ndbm = UNAVAIL;
#endif
#if APU_HAVE_DB
    have_db = AVAIL;
#else
    have_db = UNAVAIL;
#endif

    apr_file_printf(errfile,
    "%s -- Program to Create DBM Files for use by RewriteMap" NL
    "Usage: %s [-v] [-f format] -i SOURCE_TXT -o OUTPUT_DBM" NL
    NL
    "Options: " NL
    " -v    More verbose output"NL
    NL
    " -i    Source Text File. If '-', use stdin."NL
    NL
    " -o    Output DBM."NL
    NL
    " -f    DBM Format.  If not specified, will use the APR Default." NL
    "           GDBM for GDBM files (%s)" NL
    "           SDBM for SDBM files (%s)" NL
    "           DB   for berkeley DB files (%s)" NL
    "           NDBM for NDBM files (%s)" NL
    "           default for the default DBM type" NL
    NL,
    shortname,
    shortname,
    have_gdbm,
    have_sdbm,
    have_db,
    have_ndbm);
}


static apr_status_t to_dbm(apr_dbm_t *dbm, apr_file_t *fp, apr_pool_t *pool)
{
    apr_status_t rv = APR_SUCCESS;
    char line[REWRITE_MAX_TXT_MAP_LINE + 1]; /* +1 for \0 */
    apr_datum_t dbmkey;
    apr_datum_t dbmval;
    apr_pool_t* p;

    apr_pool_create(&p, pool);

    while (apr_file_gets(line, sizeof(line), fp) == APR_SUCCESS) {
        char *c, *value;

        if (*line == '#' || apr_isspace(*line)) {
            continue;
        }

        c = line;

        while (*c && !apr_isspace(*c)) {
            ++c;
        }

        if (!*c) {
            /* no value. solid line of data. */
            continue;
        }

        dbmkey.dptr = apr_pstrmemdup(p, line,  c - line);
        dbmkey.dsize = (c - line);

        while (*c && apr_isspace(*c)) {
            ++c;
        }

        if (!*c) {
            apr_pool_clear(p);
            continue;
        }

        value = c;

        while (*c && !apr_isspace(*c)) {
            ++c;
        }

        dbmval.dptr = apr_pstrmemdup(p, value,  c - value);
        dbmval.dsize = (c - line);

        if (verbose) {
            apr_file_printf(errfile, "    '%s' -> '%s'"NL,
                            dbmkey.dptr, dbmval.dptr);
        }

        rv = apr_dbm_store(dbm, dbmkey, dbmval);

        apr_pool_clear(p);

        if (rv != APR_SUCCESS) {
            break;
        }
    }

    return rv;
}

int main(int argc, const char *const argv[])
{
    apr_pool_t *pool;
    apr_status_t rv = APR_SUCCESS;
    apr_getopt_t *opt;
    const char *optarg;
    char ch;
    apr_file_t *infile;
    apr_dbm_t *outdbm;

    apr_app_initialize(&argc, &argv, NULL);
    atexit(apr_terminate);

    verbose = 0;
    format = NULL;
    input = NULL;
    output = NULL;

    apr_pool_create(&pool, NULL);

    if (argc) {
        shortname = apr_filepath_name_get(argv[0]);
    }
    else {
        shortname = "httxt2dbm";
    }

    apr_file_open_stderr(&errfile, pool);
    rv = apr_getopt_init(&opt, pool, argc, argv);

    if (rv != APR_SUCCESS) {
        apr_file_printf(errfile, "Error: apr_getopt_init failed."NL NL);
        return 1;
    }

    if (argc <= 1) {
        usage();
        return 1;
    }

    while ((rv = apr_getopt(opt, "vf::i::o::", &ch, &optarg)) == APR_SUCCESS) {
        switch (ch) {
        case 'v':
            if (verbose) {
                apr_file_printf(errfile, "Error: -v can only be passed once" NL NL);
                usage();
                return 1;
            }
            verbose = 1;
            break;
        case 'f':
            if (format) {
                apr_file_printf(errfile, "Error: -f can only be passed once" NL NL);
                usage();
                return 1;
            }
            format = apr_pstrdup(pool, optarg);
            break;
        case 'i':
            if (input) {
                apr_file_printf(errfile, "Error: -i can only be passed once" NL NL);
                usage();
                return 1;
            }
            input = apr_pstrdup(pool, optarg);
            break;
        case 'o':
            if (output) {
                apr_file_printf(errfile, "Error: -o can only be passed once" NL NL);
                usage();
                return 1;
            }
            output = apr_pstrdup(pool, optarg);
            break;
        }
    }

    if (rv != APR_EOF) {
        apr_file_printf(errfile, "Error: Parsing Arguments Failed" NL NL);
        usage();
        return 1;
    }

    if (!input) {
        apr_file_printf(errfile, "Error: No input file specified." NL NL);
        usage();
        return 1;
    }

    if (!output) {
        apr_file_printf(errfile, "Error: No output DBM specified." NL NL);
        usage();
        return 1;
    }

    if (!format) {
        format = "default";
    }

    if (verbose) {
        apr_file_printf(errfile, "DBM Format: %s"NL, format);
    }

    if (!strcmp(input, "-")) {
        rv = apr_file_open_stdin(&infile, pool);
    }
    else {
        rv = apr_file_open(&infile, input, APR_READ|APR_BUFFERED,
                           APR_OS_DEFAULT, pool);
    }

    if (rv != APR_SUCCESS) {
        apr_file_printf(errfile,
                        "Error: Cannot open input file '%s': (%d) %s" NL NL,
                         input, rv, apr_strerror(rv, errbuf, sizeof(errbuf)));
        return 1;
    }

    if (verbose) {
        apr_file_printf(errfile, "Input File: %s"NL, input);
    }

    rv = apr_dbm_open_ex(&outdbm, format, output, APR_DBM_RWCREATE,
                    APR_OS_DEFAULT, pool);

    if (APR_STATUS_IS_ENOTIMPL(rv)) {
        apr_file_printf(errfile,
                        "Error: The requested DBM Format '%s' is not available." NL NL,
                         format);
        return 1;
    }

    if (rv != APR_SUCCESS) {
        apr_file_printf(errfile,
                        "Error: Cannot open output DBM '%s': (%d) %s" NL NL,
                         output, rv, apr_strerror(rv, errbuf, sizeof(errbuf)));
        return 1;
    }

    if (verbose) {
        apr_file_printf(errfile, "DBM File: %s"NL, output);
    }

    rv = to_dbm(outdbm, infile, pool);

    if (rv != APR_SUCCESS) {
        apr_file_printf(errfile,
                        "Error: Converting to DBM: (%d) %s" NL NL,
                         rv, apr_strerror(rv, errbuf, sizeof(errbuf)));
        return 1;
    }

    apr_dbm_close(outdbm);

    if (verbose) {
        apr_file_printf(errfile, "Conversion Complete." NL);
    }

    return 0;
}

