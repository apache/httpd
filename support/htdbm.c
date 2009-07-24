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

#include "apr.h"
#include "apr_lib.h"
#include "apr_strings.h"
#include "apr_file_io.h"
#include "apr_file_info.h"
#include "apr_pools.h"
#include "apr_signal.h"
#include "apr_md5.h"
#include "apr_sha1.h"
#include "apr_dbm.h"

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


#if !APR_CHARSET_EBCDIC
#define LF 10
#define CR 13
#else /*APR_CHARSET_EBCDIC*/
#define LF '\n'
#define CR '\r'
#endif /*APR_CHARSET_EBCDIC*/

#define MAX_STRING_LEN 256
#define ALG_PLAIN 0
#define ALG_APMD5 1
#define ALG_APSHA 2

#if (!(defined(WIN32) || defined(NETWARE)))
#define ALG_CRYPT 3
#endif


#define ERR_FILEPERM    1
#define ERR_SYNTAX      2
#define ERR_PWMISMATCH  3
#define ERR_INTERRUPTED 4
#define ERR_OVERFLOW    5
#define ERR_BADUSER     6
#define ERR_EMPTY       7


typedef struct htdbm_t htdbm_t;

struct htdbm_t {
    apr_dbm_t               *dbm;
    apr_pool_t              *pool;
#if APR_CHARSET_EBCDIC
    apr_xlate_t             *to_ascii;
#endif
    char                    *filename;
    char                    *username;
    char                    *userpass;
    char                    *comment;
    char                    *type;
    int                     create;
    int                     rdonly;
    int                     alg;
};


#define HTDBM_MAKE   0
#define HTDBM_DELETE 1
#define HTDBM_VERIFY 2
#define HTDBM_LIST   3
#define HTDBM_NOFILE 4
#define HTDBM_STDIN  5

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
    apr_signal(SIGINT, (void (*)(int)) htdbm_interrupted);

    (*hdbm) = (htdbm_t *)apr_pcalloc(*pool, sizeof(htdbm_t));
    (*hdbm)->pool = *pool;

#if APR_CHARSET_EBCDIC
    rv = apr_xlate_open(&((*hdbm)->to_ascii), "ISO-8859-1", APR_DEFAULT_CHARSET, (*hdbm)->pool);
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
    (*hdbm)->alg = ALG_APMD5;
    (*hdbm)->type = "default";
    return APR_SUCCESS;
}

static apr_status_t htdbm_open(htdbm_t *htdbm)
{
    if (htdbm->create)
        return apr_dbm_open_ex(&htdbm->dbm, htdbm->type, htdbm->filename, APR_DBM_RWCREATE,
                            APR_OS_DEFAULT, htdbm->pool);
    else
        return apr_dbm_open_ex(&htdbm->dbm, htdbm->type, htdbm->filename,
                            htdbm->rdonly ? APR_DBM_READONLY : APR_DBM_READWRITE,
                            APR_OS_DEFAULT, htdbm->pool);
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

    val.dsize = strlen(htdbm->userpass);
    if (!htdbm->comment)
        val.dptr  = htdbm->userpass;
    else {
        val.dptr = apr_pstrcat(htdbm->pool, htdbm->userpass, ":",
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
    rec = apr_pstrndup(htdbm->pool, val.dptr, val.dsize);
    cmnt = strchr(rec, ':');
    if (cmnt)
        pwd = apr_pstrndup(htdbm->pool, rec, cmnt - rec);
    else
        pwd = apr_pstrdup(htdbm->pool, rec);
    return apr_password_validate(htdbm->userpass, pwd);
}

static apr_status_t htdbm_list(htdbm_t *htdbm)
{
    apr_status_t rv;
    apr_datum_t key, val;
    char *rec, *cmnt;
    char *kb;
    int i = 0;

    rv = apr_dbm_firstkey(htdbm->dbm, &key);
    if (rv != APR_SUCCESS) {
        fprintf(stderr, "Empty database -- %s\n", htdbm->filename);
        return APR_ENOENT;
    }
    fprintf(stderr, "Dumping records from database -- %s\n", htdbm->filename);
    fprintf(stderr, "    %-32sComment\n", "Username");
    while (key.dptr != NULL) {
        rv = apr_dbm_fetch(htdbm->dbm, key, &val);
        if (rv != APR_SUCCESS) {
            fprintf(stderr, "Failed getting data from %s\n", htdbm->filename);
            return APR_EGENERAL;
        }
        kb = apr_pstrndup(htdbm->pool, key.dptr, key.dsize);
        fprintf(stderr, "    %-32s", kb);
        rec = apr_pstrndup(htdbm->pool, val.dptr, val.dsize);
        cmnt = strchr(rec, ':');
        if (cmnt)
            fprintf(stderr, "%s", cmnt + 1);
        fprintf(stderr, "\n");
        rv = apr_dbm_nextkey(htdbm->dbm, &key);
        if (rv != APR_SUCCESS)
            fprintf(stderr, "Failed getting NextKey\n");
        ++i;
    }

    fprintf(stderr, "Total #records : %d\n", i);
    return APR_SUCCESS;
}

static void to64(char *s, unsigned long v, int n)
{
    static unsigned char itoa64[] =         /* 0 ... 63 => ASCII - 64 */
    "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

    while (--n >= 0) {
        *s++ = itoa64[v&0x3f];
        v >>= 6;
    }
}

static apr_status_t htdbm_make(htdbm_t *htdbm)
{
    char cpw[MAX_STRING_LEN];
    char salt[9];

    switch (htdbm->alg) {
        case ALG_APSHA:
            /* XXX cpw >= 28 + strlen(sha1) chars - fixed len SHA */
            apr_sha1_base64(htdbm->userpass,strlen(htdbm->userpass),cpw);
        break;

        case ALG_APMD5:
            (void) srand((int) time((time_t *) NULL));
            to64(&salt[0], rand(), 8);
            salt[8] = '\0';
            apr_md5_encode((const char *)htdbm->userpass, (const char *)salt,
                            cpw, sizeof(cpw));
        break;
        case ALG_PLAIN:
            /* XXX this len limitation is not in sync with any HTTPd len. */
            apr_cpystrn(cpw,htdbm->userpass,sizeof(cpw));
#if (!(defined(WIN32) || defined(NETWARE)))
            fprintf(stderr, "Warning: Plain text passwords aren't supported by the "
                    "server on this platform!\n");
#endif
        break;
#if (!(defined(WIN32) || defined(NETWARE)))
        case ALG_CRYPT:
            (void) srand((int) time((time_t *) NULL));
            to64(&salt[0], rand(), 8);
            salt[8] = '\0';
            apr_cpystrn(cpw, crypt(htdbm->userpass, salt), sizeof(cpw) - 1);
            fprintf(stderr, "CRYPT is now deprecated, use MD5 instead!\n");
#endif
        default:
        break;
    }
    htdbm->userpass = apr_pstrdup(htdbm->pool, cpw);
    return APR_SUCCESS;
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

#if (!(defined(WIN32) || defined(NETWARE)))
#define CRYPT_OPTION "d"
#else
#define CRYPT_OPTION ""
#endif
    fprintf(stderr, "htdbm -- program for manipulating DBM password databases.\n\n");
    fprintf(stderr, "Usage: htdbm    [-cm"CRYPT_OPTION"pstvx] [-TDBTYPE] database username\n");
    fprintf(stderr, "                -b[cm"CRYPT_OPTION"ptsv] [-TDBTYPE] database username password\n");
    fprintf(stderr, "                -n[m"CRYPT_OPTION"pst]   username\n");
    fprintf(stderr, "                -nb[m"CRYPT_OPTION"pst]  username password\n");
    fprintf(stderr, "                -v[m"CRYPT_OPTION"ps]    [-TDBTYPE] database username\n");
    fprintf(stderr, "                -vb[m"CRYPT_OPTION"ps]   [-TDBTYPE] database username password\n");
    fprintf(stderr, "                -x[m"CRYPT_OPTION"ps]    [-TDBTYPE] database username\n");
    fprintf(stderr, "                -l                       [-TDBTYPE] database\n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "   -b   Use the password from the command line rather "
                    "than prompting for it.\n");
    fprintf(stderr, "   -c   Create a new database.\n");
    fprintf(stderr, "   -n   Don't update database; display results on stdout.\n");
    fprintf(stderr, "   -m   Force MD5 encryption of the password (default).\n");
#if (!(defined(WIN32) || defined(NETWARE)))
    fprintf(stderr, "   -d   Force CRYPT encryption of the password (now deprecated).\n");
#endif
    fprintf(stderr, "   -p   Do not encrypt the password (plaintext).\n");
    fprintf(stderr, "   -s   Force SHA encryption of the password.\n");
    fprintf(stderr, "   -T   DBM Type (SDBM|GDBM|DB|default).\n");
    fprintf(stderr, "   -l   Display usernames from database on stdout.\n");
    fprintf(stderr, "   -t   The last param is username comment.\n");
    fprintf(stderr, "   -v   Verify the username/password.\n");
    fprintf(stderr, "   -x   Remove the username record from database.\n");
    exit(ERR_SYNTAX);

}


int main(int argc, const char * const argv[])
{
    apr_pool_t *pool;
    apr_status_t rv;
    apr_size_t l;
    char pwi[MAX_STRING_LEN];
    char pwc[MAX_STRING_LEN];
    char errbuf[MAX_STRING_LEN];
    const char *arg;
    int  need_file = 1;
    int  need_user = 1;
    int  need_pwd  = 1;
    int  need_cmnt = 0;
    int  pwd_supplied = 0;
    int  changed = 0;
    int  cmd = HTDBM_MAKE;
    int  i;
    int args_left = 2;

    apr_app_initialize(&argc, &argv, NULL);
    atexit(terminate);

    if ((rv = htdbm_init(&pool, &h)) != APR_SUCCESS) {
        fprintf(stderr, "Unable to initialize htdbm terminating!\n");
        apr_strerror(rv, errbuf, sizeof(errbuf));
        exit(1);
    }
    /*
     * Preliminary check to make sure they provided at least
     * three arguments, we'll do better argument checking as
     * we parse the command line.
     */
    if (argc < 3)
       htdbm_usage();
    /*
     * Go through the argument list and pick out any options.  They
     * have to precede any other arguments.
     */
    for (i = 1; i < argc; i++) {
        arg = argv[i];
        if (*arg != '-')
            break;

        while (*++arg != '\0') {
            switch (*arg) {
            case 'b':
                pwd_supplied = 1;
                need_pwd = 0;
                args_left++;
                break;
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
                h->type = apr_pstrdup(h->pool, ++arg);
                while (*arg != '\0')
                    ++arg;
                --arg; /* so incrementing this in the loop with find a null */
                break;
            case 'v':
                h->rdonly = 1;
                cmd = HTDBM_VERIFY;
                break;
            case 'x':
                need_pwd = 0;
                cmd = HTDBM_DELETE;
                break;
            case 'm':
                h->alg = ALG_APMD5;
                break;
            case 'p':
                h->alg = ALG_PLAIN;
                break;
            case 's':
                h->alg = ALG_APSHA;
                break;
#if (!(defined(WIN32) || defined(NETWARE)))
            case 'd':
                h->alg = ALG_CRYPT;
                break;
#endif
            default:
                htdbm_usage();
                break;
            }
        }
    }
    /*
     * Make sure we still have exactly the right number of arguments left
     * (the filename, the username, and possibly the password if -b was
     * specified).
     */
    if ((argc - i) != args_left)
        htdbm_usage();

    if (!need_file)
        i--;
    else {
        h->filename = apr_pstrdup(h->pool, argv[i]);
            if ((rv = htdbm_open(h)) != APR_SUCCESS) {
            fprintf(stderr, "Error opening database %s\n", argv[i]);
            apr_strerror(rv, errbuf, sizeof(errbuf));
            fprintf(stderr,"%s\n",errbuf);
            exit(ERR_FILEPERM);
        }
    }
    if (need_user) {
        h->username = apr_pstrdup(pool, argv[i+1]);
        if (htdbm_valid_username(h) != APR_SUCCESS)
            exit(ERR_BADUSER);
    }
    if (pwd_supplied)
        h->userpass = apr_pstrdup(pool, argv[i+2]);

    if (need_pwd) {
        l = sizeof(pwc);
        if (apr_password_get("Enter password        : ", pwi, &l) != APR_SUCCESS) {
            fprintf(stderr, "Password too long\n");
            exit(ERR_OVERFLOW);
        }
        l = sizeof(pwc);
        if (apr_password_get("Re-type password      : ", pwc, &l) != APR_SUCCESS) {
            fprintf(stderr, "Password too long\n");
            exit(ERR_OVERFLOW);
        }
        if (strcmp(pwi, pwc) != 0) {
            fprintf(stderr, "Password verification error\n");
            exit(ERR_PWMISMATCH);
        }

        h->userpass = apr_pstrdup(pool,  pwi);
    }
    if (need_cmnt && pwd_supplied)
        h->comment = apr_pstrdup(pool, argv[i+3]);
    else if (need_cmnt)
        h->comment = apr_pstrdup(pool, argv[i+2]);

    switch (cmd) {
        case HTDBM_VERIFY:
            if ((rv = htdbm_verify(h)) != APR_SUCCESS) {
                if(rv == APR_ENOENT) {
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
            htdbm_make(h);
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
            fprintf(stderr, "%s:%s\n", h->username, h->userpass);
        }
        else {
            fprintf(stderr, "%s:%s:%s\n", h->username, h->userpass,
                    h->comment);
        }
    }
    htdbm_terminate(h);

    return 0; /* Suppress compiler warning. */
}
