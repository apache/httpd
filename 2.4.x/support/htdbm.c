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
 * htdbm.c: simple program for manipulating DBM
 * password databases for the Apache HTTP server
 *
 * Contributed by Mladen Turk <mturk mappingsoft.com>
 * 12 Oct 2001
 */

#include "passwd_common.h"
#include "apr_file_io.h"
#include "apr_file_info.h"
#include "apr_pools.h"
#include "apr_signal.h"
#include "apr_md5.h"
#include "apr_sha1.h"
#include "apr_dbm.h"
#include "apr_getopt.h"

#if APR_HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if APR_HAVE_STRING_H
#include <string.h>
#endif
#if APR_HAVE_STRINGS_H
#include <strings.h>
#endif
#include <time.h>

#if APR_CHARSET_EBCDIC
#include "apr_xlate.h"
#endif /*APR_CHARSET_EBCDIC*/

#if APR_HAVE_UNISTD_H
#include <unistd.h>
#endif
#if APR_HAVE_CRYPT_H
#include <crypt.h>
#endif


typedef struct htdbm_t htdbm_t;

struct htdbm_t {
    apr_dbm_t               *dbm;
    struct passwd_ctx       ctx;
#if APR_CHARSET_EBCDIC
    apr_xlate_t             *to_ascii;
#endif
    char                    *filename;
    char                    *username;
    char                    *comment;
    char                    *type;
    int                     create;
    int                     rdonly;
};


#define HTDBM_MAKE   0
#define HTDBM_DELETE 1
#define HTDBM_VERIFY 2
#define HTDBM_LIST   3
#define HTDBM_NOFILE 4

static void terminate(void)
{
    apr_terminate();
#ifdef NETWARE
    pressanykey();
#endif
}

static void htdbm_terminate(htdbm_t *htdbm)
{
    if (htdbm->dbm)
        apr_dbm_close(htdbm->dbm);
    htdbm->dbm = NULL;
}

static htdbm_t *h;

static void htdbm_interrupted(void)
{
    htdbm_terminate(h);
    fprintf(stderr, "htdbm Interrupted !\n");
    exit(ERR_INTERRUPTED);
}

static apr_status_t htdbm_init(apr_pool_t **pool, htdbm_t **hdbm)
{

#if APR_CHARSET_EBCDIC
    apr_status_t rv;
#endif

    apr_pool_create( pool, NULL);
    apr_pool_abort_set(abort_on_oom, *pool);
    apr_file_open_stderr(&errfile, *pool);
    apr_signal(SIGINT, (void (*)(int)) htdbm_interrupted);

    (*hdbm) = (htdbm_t *)apr_pcalloc(*pool, sizeof(htdbm_t));
    (*hdbm)->ctx.pool = *pool;

#if APR_CHARSET_EBCDIC
    rv = apr_xlate_open(&((*hdbm)->to_ascii), "ISO-8859-1", APR_DEFAULT_CHARSET, (*hdbm)->ctx.pool);
    if (rv) {
        fprintf(stderr, "apr_xlate_open(to ASCII)->%d\n", rv);
        return APR_EGENERAL;
    }
    rv = apr_SHA1InitEBCDIC((*hdbm)->to_ascii);
    if (rv) {
        fprintf(stderr, "apr_SHA1InitEBCDIC()->%d\n", rv);
        return APR_EGENERAL;
    }
    rv = apr_MD5InitEBCDIC((*hdbm)->to_ascii);
    if (rv) {
        fprintf(stderr, "apr_MD5InitEBCDIC()->%d\n", rv);
        return APR_EGENERAL;
    }
#endif /*APR_CHARSET_EBCDIC*/

    /* Set MD5 as default */
    (*hdbm)->ctx.alg = ALG_APMD5;
    (*hdbm)->type = "default";
    return APR_SUCCESS;
}

static apr_status_t htdbm_open(htdbm_t *htdbm)
{
    if (htdbm->create)
        return apr_dbm_open_ex(&htdbm->dbm, htdbm->type, htdbm->filename, APR_DBM_RWCREATE,
                            APR_OS_DEFAULT, htdbm->ctx.pool);
    else
        return apr_dbm_open_ex(&htdbm->dbm, htdbm->type, htdbm->filename,
                            htdbm->rdonly ? APR_DBM_READONLY : APR_DBM_READWRITE,
                            APR_OS_DEFAULT, htdbm->ctx.pool);
}

static apr_status_t htdbm_save(htdbm_t *htdbm, int *changed)
{
    apr_datum_t key, val;

    if (!htdbm->username)
        return APR_SUCCESS;

    key.dptr = htdbm->username;
    key.dsize = strlen(htdbm->username);
    if (apr_dbm_exists(htdbm->dbm, key))
        *changed = 1;

    val.dsize = strlen(htdbm->ctx.passwd);
    if (!htdbm->comment)
        val.dptr  = htdbm->ctx.passwd;
    else {
        val.dptr = apr_pstrcat(htdbm->ctx.pool, htdbm->ctx.passwd, ":",
                               htdbm->comment, NULL);
        val.dsize += (strlen(htdbm->comment) + 1);
    }
    return apr_dbm_store(htdbm->dbm, key, val);
}

static apr_status_t htdbm_del(htdbm_t *htdbm)
{
    apr_datum_t key;

    key.dptr = htdbm->username;
    key.dsize = strlen(htdbm->username);
    if (!apr_dbm_exists(htdbm->dbm, key))
        return APR_ENOENT;

    return apr_dbm_delete(htdbm->dbm, key);
}

static apr_status_t htdbm_verify(htdbm_t *htdbm)
{
    apr_datum_t key, val;
    char *pwd;
    char *rec, *cmnt;

    key.dptr = htdbm->username;
    key.dsize = strlen(htdbm->username);
    if (!apr_dbm_exists(htdbm->dbm, key))
        return APR_ENOENT;
    if (apr_dbm_fetch(htdbm->dbm, key, &val) != APR_SUCCESS)
        return APR_ENOENT;
    rec = apr_pstrndup(htdbm->ctx.pool, val.dptr, val.dsize);
    cmnt = strchr(rec, ':');
    if (cmnt)
        pwd = apr_pstrndup(htdbm->ctx.pool, rec, cmnt - rec);
    else
        pwd = apr_pstrdup(htdbm->ctx.pool, rec);
    return apr_password_validate(htdbm->ctx.passwd, pwd);
}

static apr_status_t htdbm_list(htdbm_t *htdbm)
{
    apr_status_t rv;
    apr_datum_t key, val;
    char *cmnt;
    int i = 0;

    rv = apr_dbm_firstkey(htdbm->dbm, &key);
    if (rv != APR_SUCCESS) {
        fprintf(stderr, "Empty database -- %s\n", htdbm->filename);
        return APR_ENOENT;
    }
    fprintf(stderr, "Dumping records from database -- %s\n", htdbm->filename);
    fprintf(stderr, "    %-32s Comment\n", "Username");
    while (key.dptr != NULL) {
        rv = apr_dbm_fetch(htdbm->dbm, key, &val);
        if (rv != APR_SUCCESS) {
            fprintf(stderr, "Failed getting data from %s\n", htdbm->filename);
            return APR_EGENERAL;
        }
        /* Note: we don't store \0-terminators on our dbm data */
        fprintf(stderr, "    %-32.*s", (int)key.dsize, key.dptr);
        cmnt = memchr(val.dptr, ':', val.dsize);
        if (cmnt)
            fprintf(stderr, " %.*s", (int)(val.dptr+val.dsize - (cmnt+1)), cmnt + 1);
        fprintf(stderr, "\n");
        rv = apr_dbm_nextkey(htdbm->dbm, &key);
        if (rv != APR_SUCCESS)
            fprintf(stderr, "Failed getting NextKey\n");
        ++i;
    }

    fprintf(stderr, "Total #records : %d\n", i);
    return APR_SUCCESS;
}

static int htdbm_make(htdbm_t *htdbm)
{
    char cpw[MAX_STRING_LEN];
    int ret;

    htdbm->ctx.out = cpw;
    htdbm->ctx.out_len = sizeof(cpw);
    ret = mkhash(&htdbm->ctx);
    if (ret != 0) {
        fprintf(stderr, "Error: %s\n", htdbm->ctx.errstr);
        return ret;
    }
    htdbm->ctx.passwd = apr_pstrdup(htdbm->ctx.pool, cpw);
    return 0;
}

static apr_status_t htdbm_valid_username(htdbm_t *htdbm)
{
    if (!htdbm->username || (strlen(htdbm->username) > 64) || (strlen(htdbm->username) < 1)) {
        fprintf(stderr, "Invalid username length\n");
        return APR_EINVAL;
    }
    if (strchr(htdbm->username, ':')) {
        fprintf(stderr, "Username contains invalid characters\n");
        return APR_EINVAL;
    }
    return APR_SUCCESS;
}

static void htdbm_usage(void)
{
    fprintf(stderr,
        "htdbm -- program for manipulating DBM password databases.\n\n"
        "Usage: htdbm   [-cimBdpstvx] [-C cost] [-TDBTYPE] database username\n"
        "                -b[cmBdptsv] [-C cost] [-TDBTYPE] database username password\n"
        "                -n[imBdpst]  [-C cost] username\n"
        "                -nb[mBdpst]  [-C cost] username password\n"
        "                -v[imBdps]   [-C cost] [-TDBTYPE] database username\n"
        "                -vb[mBdps]   [-C cost] [-TDBTYPE] database username password\n"
        "                -x                     [-TDBTYPE] database username\n"
        "                -l                     [-TDBTYPE] database\n"
        "Options:\n"
        "   -c   Create a new database.\n"
        "   -n   Don't update database; display results on stdout.\n"
        "   -b   Use the password from the command line rather than prompting for it.\n"
        "   -i   Read password from stdin without verification (for script usage).\n"
        "   -m   Force MD5 encryption of the password (default).\n"
        "   -B   Force BCRYPT encryption of the password (very secure).\n"
        "   -C   Set the computing time used for the bcrypt algorithm\n"
        "        (higher is more secure but slower, default: %d, valid: 4 to 31).\n"
        "   -d   Force CRYPT encryption of the password (8 chars max, insecure).\n"
        "   -s   Force SHA encryption of the password (insecure).\n"
        "   -p   Do not encrypt the password (plaintext, insecure).\n"
        "   -T   DBM Type (SDBM|GDBM|DB|default).\n"
        "   -l   Display usernames from database on stdout.\n"
        "   -v   Verify the username/password.\n"
        "   -x   Remove the username record from database.\n"
        "   -t   The last param is username comment.\n"
        "The SHA algorithm does not use a salt and is less secure than the "
        "MD5 algorithm.\n",
        BCRYPT_DEFAULT_COST);
    exit(ERR_SYNTAX);
}

int main(int argc, const char * const argv[])
{
    apr_pool_t *pool;
    apr_status_t rv;
    char errbuf[MAX_STRING_LEN];
    int  need_file = 1;
    int  need_user = 1;
    int  need_pwd  = 1;
    int  need_cmnt = 0;
    int  changed = 0;
    int  cmd = HTDBM_MAKE;
    int  i, ret, args_left = 2;
    apr_getopt_t *state;
    char opt;
    const char *opt_arg;

    apr_app_initialize(&argc, &argv, NULL);
    atexit(terminate);

    if ((rv = htdbm_init(&pool, &h)) != APR_SUCCESS) {
        fprintf(stderr, "Unable to initialize htdbm terminating!\n");
        apr_strerror(rv, errbuf, sizeof(errbuf));
        exit(1);
    }

    rv = apr_getopt_init(&state, pool, argc, argv);
    if (rv != APR_SUCCESS)
        exit(ERR_SYNTAX);

    while ((rv = apr_getopt(state, "cnmspdBbtivxlC:T:", &opt, &opt_arg)) == APR_SUCCESS) {
        switch (opt) {
        case 'c':
            h->create = 1;
            break;
        case 'n':
            need_file = 0;
            cmd = HTDBM_NOFILE;
            args_left--;
            break;
        case 'l':
            need_pwd = 0;
            need_user = 0;
            cmd = HTDBM_LIST;
            h->rdonly = 1;
            args_left--;
            break;
        case 't':
            need_cmnt = 1;
            args_left++;
            break;
        case 'T':
            h->type = apr_pstrdup(h->ctx.pool, opt_arg);
            break;
        case 'v':
            h->rdonly = 1;
            cmd = HTDBM_VERIFY;
            break;
        case 'x':
            need_pwd = 0;
            cmd = HTDBM_DELETE;
            break;
        default:
            ret = parse_common_options(&h->ctx, opt, opt_arg);
            if (ret) {
                fprintf(stderr, "Error: %s\n", h->ctx.errstr);
                exit(ret);
            }
        }
    }
    if (h->ctx.passwd_src == PW_ARG) {
            need_pwd = 0;
            args_left++;
    }
    /*
     * Make sure we still have exactly the right number of arguments left
     * (the filename, the username, and possibly the password if -b was
     * specified).
     */
    i = state->ind;
    if (rv != APR_EOF || argc - i != args_left)
        htdbm_usage();

    if (need_file) {
        h->filename = apr_pstrdup(h->ctx.pool, argv[i++]);
        if ((rv = htdbm_open(h)) != APR_SUCCESS) {
            fprintf(stderr, "Error opening database %s\n", h->filename);
            apr_strerror(rv, errbuf, sizeof(errbuf));
            fprintf(stderr,"%s\n",errbuf);
            exit(ERR_FILEPERM);
        }
    }
    if (need_user) {
        h->username = apr_pstrdup(pool, argv[i++]);
        if (htdbm_valid_username(h) != APR_SUCCESS)
            exit(ERR_BADUSER);
    }
    if (h->ctx.passwd_src == PW_ARG)
        h->ctx.passwd = apr_pstrdup(pool, argv[i++]);

    if (need_pwd) {
        ret = get_password(&h->ctx);
        if (ret) {
            fprintf(stderr, "Error: %s\n", h->ctx.errstr);
            exit(ret);
        }
    }
    if (need_cmnt)
        h->comment = apr_pstrdup(pool, argv[i++]);

    switch (cmd) {
        case HTDBM_VERIFY:
            if ((rv = htdbm_verify(h)) != APR_SUCCESS) {
                if (APR_STATUS_IS_ENOENT(rv)) {
                    fprintf(stderr, "The user '%s' could not be found in database\n", h->username);
                    exit(ERR_BADUSER);
                }
                else {
                    fprintf(stderr, "Password mismatch for user '%s'\n", h->username);
                    exit(ERR_PWMISMATCH);
                }
            }
            else
                fprintf(stderr, "Password validated for user '%s'\n", h->username);
            break;
        case HTDBM_DELETE:
            if (htdbm_del(h) != APR_SUCCESS) {
                fprintf(stderr, "Cannot find user '%s' in database\n", h->username);
                exit(ERR_BADUSER);
            }
            h->username = NULL;
            changed = 1;
            break;
        case HTDBM_LIST:
            htdbm_list(h);
            break;
        default:
            ret = htdbm_make(h);
            if (ret)
                exit(ret);
            break;
    }
    if (need_file && !h->rdonly) {
        if ((rv = htdbm_save(h, &changed)) != APR_SUCCESS) {
            apr_strerror(rv, errbuf, sizeof(errbuf));
            exit(ERR_FILEPERM);
        }
        fprintf(stdout, "Database %s %s.\n", h->filename,
                h->create ? "created" : (changed ? "modified" : "updated"));
    }
    if (cmd == HTDBM_NOFILE) {
        if (!need_cmnt) {
            fprintf(stderr, "%s:%s\n", h->username, h->ctx.passwd);
        }
        else {
            fprintf(stderr, "%s:%s:%s\n", h->username, h->ctx.passwd,
                    h->comment);
        }
    }
    htdbm_terminate(h);

    return 0; /* Suppress compiler warning. */
}
