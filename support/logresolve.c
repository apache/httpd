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
 * logresolve 2.0
 *
 * Tom Rathborne - tomr uunet.ca - http://www.uunet.ca/~tomr/
 * UUNET Canada, April 16, 1995
 *
 * Rewritten by David Robinson. (drtr ast.cam.ac.uk)
 * Rewritten again, and ported to APR by Colm MacCarthaigh
 *
 * Usage: logresolve [-s filename] [-c] < access_log > new_log
 *
 * Arguments:
 *    -s filename     name of a file to record statistics
 *    -c              check the DNS for a matching A record for the host.
 *
 * Notes:             (For historical interest)
 *
 * To generate meaningful statistics from an HTTPD log file, it's good
 * to have the domain name of each machine that accessed your site, but
 * doing this on the fly can slow HTTPD down.
 *
 * Compiling NCSA HTTPD with the -DMINIMAL_DNS flag turns IP#->hostname
 * resolution off. Before running your stats program, just run your log
 * file through this program (logresolve) and all of your IP numbers will
 * be resolved into hostnames (where possible).
 *
 * logresolve takes an HTTPD access log (in the COMMON log file format,
 * or any other format that has the IP number/domain name as the first
 * field for that matter), and outputs the same file with all of the
 * domain names looked up. Where no domain name can be found, the IP
 * number is left in.
 *
 * To minimize impact on your nameserver, logresolve has its very own
 * internal hash-table cache. This means that each IP number will only
 * be looked up the first time it is found in the log file.
 *
 * The -c option causes logresolve to apply the same check as httpd
 * compiled with -DMAXIMUM_DNS; after finding the hostname from the IP
 * address, it looks up the IP addresses for the hostname and checks
 * that one of these matches the original address.
 */

#include "apr.h"
#include "apr_lib.h"
#include "apr_hash.h"
#include "apr_getopt.h"
#include "apr_strings.h"
#include "apr_file_io.h"
#include "apr_network_io.h"

#if APR_HAVE_STDLIB_H
#include <stdlib.h>
#endif

#define READ_BUF_SIZE 10240
#define WRITE_BUF_SIZE 10240
#define LINE_BUF_SIZE 2048

static apr_file_t *errfile;
static const char *shortname = "logresolve";
static apr_hash_t *cache;

/* Statistics */
static int cachehits = 0;
static int cachesize = 0;
static int entries = 0;
static int resolves = 0;
static int withname = 0;
static int doublefailed = 0;
static int noreverse = 0;

/*
 * prints various statistics to output
 */
#define NL APR_EOL_STR
static void print_statistics (apr_file_t *output)
{
    apr_file_printf(output, "logresolve Statistics:" NL);
    apr_file_printf(output, "Entries: %d" NL, entries);
    apr_file_printf(output, "    With name   : %d" NL, withname);
    apr_file_printf(output, "    Resolves    : %d" NL, resolves);

    if (noreverse) {
        apr_file_printf(output, "    - No reverse : %d" NL,
                        noreverse);
    }

    if (doublefailed) {
        apr_file_printf(output, "    - Double lookup failed : %d" NL,
                        doublefailed);
    }

    apr_file_printf(output, "Cache hits      : %d" NL, cachehits);
    apr_file_printf(output, "Cache size      : %d" NL, cachesize);
}

/*
 * usage info
 */
static void usage(void)
{
    apr_file_printf(errfile,
    "%s -- Resolve IP-addresses to hostnames in Apache log files."           NL
    "Usage: %s [-s STATFILE] [-c]"                                           NL
                                                                             NL
    "Options:"                                                               NL
    "  -s   Record statistics to STATFILE when finished."                    NL
                                                                             NL
    "  -c   Perform double lookups when resolving IP addresses."            NL,
    shortname, shortname);
    exit(1);
}
#undef NL

int main(int argc, const char * const argv[])
{
    apr_file_t * outfile;
    apr_file_t * infile;
    apr_getopt_t * o;
    apr_pool_t * pool;
    apr_pool_t *pline;
    apr_status_t status;
    const char * arg;
    char * stats = NULL;
    char * inbuffer;
    char * outbuffer;
    char line[LINE_BUF_SIZE];
    int doublelookups = 0;

    if (apr_app_initialize(&argc, &argv, NULL) != APR_SUCCESS) {
        return 1;
    }
    atexit(apr_terminate);

    if (argc) {
        shortname = apr_filepath_name_get(argv[0]);
    }

    if (apr_pool_create(&pool, NULL) != APR_SUCCESS) {
        return 1;
    }
    apr_file_open_stderr(&errfile, pool);
    apr_getopt_init(&o, pool, argc, argv);

    while (1) {
        char opt;
        status = apr_getopt(o, "s:c", &opt, &arg);
        if (status == APR_EOF) {
            break;
        }
        else if (status != APR_SUCCESS) {
            usage();
        }
        else {
            switch (opt) {
            case 'c':
                if (doublelookups) {
                    usage();
                }
                doublelookups = 1;
                break;
            case 's':
                if (stats) {
                    usage();
                }
                stats = apr_pstrdup(pool, arg);
                break;
            } /* switch */
        } /* else */
    } /* while */

    apr_file_open_stdout(&outfile, pool);
    apr_file_open_stdin(&infile, pool);

    /* Allocate two new 10k file buffers */
    if ((outbuffer = apr_palloc(pool, WRITE_BUF_SIZE)) == NULL ||
        (inbuffer = apr_palloc(pool, READ_BUF_SIZE)) == NULL) {
        return 1;
    }

    /* Set the buffers */
    apr_file_buffer_set(infile, inbuffer, READ_BUF_SIZE);
    apr_file_buffer_set(outfile, outbuffer, WRITE_BUF_SIZE);

    cache = apr_hash_make(pool);
    if(apr_pool_create(&pline, pool) != APR_SUCCESS){
        return 1;
    }

    while (apr_file_gets(line, sizeof(line), infile) == APR_SUCCESS) {
        char *hostname;
        char *space;
        apr_sockaddr_t *ip;
        apr_sockaddr_t *ipdouble;
        char dummy[] = " " APR_EOL_STR;

        if (line[0] == '\0') {
            continue;
        }

        /* Count our log entries */
        entries++;

        /* Check if this could even be an IP address */
        if (!apr_isxdigit(line[0]) && line[0] != ':') {
                withname++;
            apr_file_puts(line, outfile);
            continue;
        }

        /* Terminate the line at the next space */
        if ((space = strchr(line, ' ')) != NULL) {
            *space = '\0';
        }
        else {
            space = dummy;
        }

        /* See if we have it in our cache */
        hostname = (char *) apr_hash_get(cache, line, APR_HASH_KEY_STRING);
        if (hostname) {
            apr_file_printf(outfile, "%s %s", hostname, space + 1);
            cachehits++;
            continue;
        }

        /* Parse the IP address */
        status = apr_sockaddr_info_get(&ip, line, APR_UNSPEC, 0, 0, pline);
        if (status != APR_SUCCESS) {
            /* Not an IP address */
            withname++;
            *space = ' ';
            apr_file_puts(line, outfile);
            continue;
        }

        /* This does not make much sense, but historically "resolves" means
         * "parsed as an IP address". It does not mean we actually resolved
         * the IP address into a hostname.
         */
        resolves++;

        /* From here on our we cache each result, even if it was not
         * succesful
         */
        cachesize++;

        /* Try and perform a reverse lookup */
        status = apr_getnameinfo(&hostname, ip, 0) != APR_SUCCESS;
        if (status || hostname == NULL) {
            /* Could not perform a reverse lookup */
            *space = ' ';
            apr_file_puts(line, outfile);
            noreverse++;

            /* Add to cache */
            *space = '\0';
            apr_hash_set(cache, line, APR_HASH_KEY_STRING,
                         apr_pstrdup(apr_hash_pool_get(cache), line));
            continue;
        }

        /* Perform a double lookup */
        if (doublelookups) {
            /* Do a forward lookup on our hostname, and see if that matches our
             * original IP address.
             */
            status = apr_sockaddr_info_get(&ipdouble, hostname, ip->family, 0,
                                           0, pline);
            if (status == APR_SUCCESS ||
                memcmp(ipdouble->ipaddr_ptr, ip->ipaddr_ptr, ip->ipaddr_len)) {
                /* Double-lookup failed  */
                *space = ' ';
                apr_file_puts(line, outfile);
                doublefailed++;

                /* Add to cache */
                *space = '\0';
                apr_hash_set(cache, line, APR_HASH_KEY_STRING,
                             apr_pstrdup(apr_hash_pool_get(cache), line));
                continue;
            }
        }

        /* Outout the resolved name */
        apr_file_printf(outfile, "%s %s", hostname, space + 1);

        /* Store it in the cache */
        apr_hash_set(cache, line, APR_HASH_KEY_STRING,
                     apr_pstrdup(apr_hash_pool_get(cache), hostname));

        apr_pool_clear(pline);
    }

    /* Flush any remaining output */
    apr_file_flush(outfile);

    if (stats) {
        apr_file_t *statsfile;
        if (apr_file_open(&statsfile, stats,
                       APR_FOPEN_WRITE | APR_FOPEN_CREATE | APR_FOPEN_TRUNCATE,
                          APR_OS_DEFAULT, pool) != APR_SUCCESS) {
            apr_file_printf(errfile, "%s: Could not open %s for writing.",
                            shortname, stats);
            return 1;
        }
        print_statistics(statsfile);
        apr_file_close(statsfile);
    }

    return 0;
}
