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

/*                      _             _
 *  _ __ ___   ___   __| |    ___ ___| |  mod_ssl
 * | '_ ` _ \ / _ \ / _` |   / __/ __| |  Apache Interface to OpenSSL
 * | | | | | | (_) | (_| |   \__ \__ \ |
 * |_| |_| |_|\___/ \__,_|___|___/___/_|
 *                      |_____|
 *  ssl_engine_pphrase.c
 *  Pass Phrase Dialog
 */
                             /* ``Treat your password like your
                                  toothbrush. Don't let anybody
                                  else use it, and get a new one
                                  every six months.''
                                           -- Clifford Stoll     */
#include "ssl_private.h"

#include <openssl/ui.h>
#if MODSSL_HAVE_OPENSSL_STORE
#include <openssl/store.h>
#endif

typedef struct {
    server_rec         *s;
    apr_pool_t         *p;
    apr_array_header_t *aPassPhrase;
    int                 nPassPhraseCur;
    char               *cpPassPhraseCur;
    int                 nPassPhraseDialog;
    int                 nPassPhraseDialogCur;
    BOOL                bPassPhraseDialogOnce;
    const char         *key_id;
    const char         *pkey_file;
} pphrase_cb_arg_t;

#ifdef HAVE_ECC
static const char *key_types[] = {"RSA", "DSA", "ECC"};
#else
static const char *key_types[] = {"RSA", "DSA"};
#endif

/*
 * Return true if the named file exists and is readable
 */

static apr_status_t exists_and_readable(const char *fname, apr_pool_t *pool,
                                        apr_time_t *mtime)
{
    apr_status_t stat;
    apr_finfo_t sbuf;
    apr_file_t *fd;

    if ((stat = apr_stat(&sbuf, fname, APR_FINFO_MIN, pool)) != APR_SUCCESS)
        return stat;

    if (sbuf.filetype != APR_REG)
        return APR_EGENERAL;

    if ((stat = apr_file_open(&fd, fname, APR_READ, 0, pool)) != APR_SUCCESS)
        return stat;

    if (mtime) {
        *mtime = sbuf.mtime;
    }

    apr_file_close(fd);
    return APR_SUCCESS;
}

/*
 * reuse vhost keys for asn1 tables where keys are allocated out
 * of s->process->pool to prevent "leaking" each time we format
 * a vhost key.  since the key is stored in a table with lifetime
 * of s->process->pool, the key needs to have the same lifetime.
 *
 * XXX: probably seems silly to use a hash table with keys and values
 * being the same, but it is easier than doing a linear search
 * and will make it easier to remove keys if needed in the future.
 * also have the problem with apr_array_header_t that if we
 * underestimate the number of vhost keys when we apr_array_make(),
 * the array will get resized when we push past the initial number
 * of elts.  this resizing in the s->process->pool means "leaking"
 * since apr_array_push() will apr_alloc arr->nalloc * 2 elts,
 * leaving the original arr->elts to waste.
 */
static const char *asn1_table_vhost_key(SSLModConfigRec *mc, apr_pool_t *p,
                                  const char *id, int i)
{
    /* 'p' pool used here is cleared on restarts (or sooner) */
    char *key = apr_psprintf(p, "%s:%d", id, i);
    void *keyptr = apr_hash_get(mc->tVHostKeys, key,
                                APR_HASH_KEY_STRING);

    if (!keyptr) {
        /* make a copy out of s->process->pool */
        keyptr = apr_pstrdup(mc->pPool, key);
        apr_hash_set(mc->tVHostKeys, keyptr,
                     APR_HASH_KEY_STRING, keyptr);
    }

    return (char *)keyptr;
}

/*  _________________________________________________________________
**
**  Pass Phrase and Private Key Handling
**  _________________________________________________________________
*/

#define BUILTIN_DIALOG_BACKOFF 2
#define BUILTIN_DIALOG_RETRIES 5

static apr_file_t *writetty = NULL;
static apr_file_t *readtty = NULL;

int ssl_pphrase_Handle_CB(char *, int, int, void *);

static char *pphrase_array_get(apr_array_header_t *arr, int idx)
{
    if ((idx < 0) || (idx >= arr->nelts)) {
        return NULL;
    }

    return ((char **)arr->elts)[idx];
}

apr_status_t ssl_load_encrypted_pkey(server_rec *s, apr_pool_t *p, int idx,
                                     const char *pkey_file,
                                     apr_array_header_t **pphrases)
{
    SSLModConfigRec *mc = myModConfig(s);
    SSLSrvConfigRec *sc = mySrvConfig(s);
    const char *key_id = asn1_table_vhost_key(mc, p, sc->vhost_id, idx);
    EVP_PKEY *pPrivateKey = NULL;
    ssl_asn1_t *asn1;
    int nPassPhrase = (*pphrases)->nelts;
    int nPassPhraseRetry = 0;
    apr_time_t pkey_mtime = 0;
    apr_status_t rv;
    pphrase_cb_arg_t ppcb_arg;

    if (!pkey_file) {
         ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s, APLOGNO(02573)
                      "Init: No private key specified for %s", key_id);
         return ssl_die(s);
    }
    else if ((rv = exists_and_readable(pkey_file, p, &pkey_mtime))
             != APR_SUCCESS ) {
         ap_log_error(APLOG_MARK, APLOG_EMERG, rv, s, APLOGNO(02574)
                      "Init: Can't open server private key file %s", pkey_file);
         return ssl_die(s);
    }

    ppcb_arg.s                     = s;
    ppcb_arg.p                     = p;
    ppcb_arg.aPassPhrase           = *pphrases;
    ppcb_arg.nPassPhraseCur        = 0;
    ppcb_arg.cpPassPhraseCur       = NULL;
    ppcb_arg.nPassPhraseDialog     = 0;
    ppcb_arg.nPassPhraseDialogCur  = 0;
    ppcb_arg.bPassPhraseDialogOnce = TRUE;
    ppcb_arg.key_id                = key_id;
    ppcb_arg.pkey_file             = pkey_file;

    /*
     * if the private key is encrypted and SSLPassPhraseDialog
     * is configured to "builtin" it isn't possible to prompt for
     * a password after httpd has detached from the tty.
     * in this case if we already have a private key and the
     * file name/mtime hasn't changed, then reuse the existing key.
     * we also reuse existing private keys that were encrypted for
     * exec: and pipe: dialogs to minimize chances to snoop the
     * password.  that and pipe: dialogs might prompt the user
     * for password, which on win32 for example could happen 4
     * times at startup.  twice for each child and twice within
     * each since apache "restarts itself" on startup.
     * of course this will not work for the builtin dialog if
     * the server was started without LoadModule ssl_module
     * configured, then restarted with it configured.
     * but we fall through with a chance of success if the key
     * is not encrypted or can be handled via exec or pipe dialog.
     * and in the case of fallthrough, pkey_mtime and isatty()
     * are used to give a better idea as to what failed.
     */
    if (pkey_mtime) {
        ssl_asn1_t *asn1 = ssl_asn1_table_get(mc->tPrivateKey, key_id);
        if (asn1 && (asn1->source_mtime == pkey_mtime)) {
            ap_log_error(APLOG_MARK, APLOG_INFO, 0, s, APLOGNO(02575)
                         "Reusing existing private key from %s on restart",
                         ppcb_arg.pkey_file);
            return APR_SUCCESS;
        }
    }

    ap_log_error(APLOG_MARK, APLOG_INFO, 0, s, APLOGNO(02576)
                 "Attempting to load encrypted (?) private key %s", key_id);

    for (;;) {
        /*
         * Try to read the private key file with the help of
         * the callback function which serves the pass
         * phrases to OpenSSL
         */

        ppcb_arg.cpPassPhraseCur = NULL;

        /* Ensure that the error stack is empty; some SSL
         * functions will fail spuriously if the error stack
         * is not empty. */
        ERR_clear_error();

        pPrivateKey = modssl_read_privatekey(ppcb_arg.pkey_file,
                                             ssl_pphrase_Handle_CB, &ppcb_arg);
        /* If the private key was successfully read, nothing more to
           do here. */
        if (pPrivateKey != NULL)
            break;

        /*
         * when we have more remembered pass phrases
         * try to reuse these first.
         */
        if (ppcb_arg.nPassPhraseCur < nPassPhrase) {
            ppcb_arg.nPassPhraseCur++;
            continue;
        }

        /*
         * else it's not readable and we have no more
         * remembered pass phrases. Then this has to mean
         * that the callback function popped up the dialog
         * but a wrong pass phrase was entered.  We give the
         * user (but not the dialog program) a few more
         * chances...
         */
#ifndef WIN32
        if ((sc->server->pphrase_dialog_type == SSL_PPTYPE_BUILTIN
             || sc->server->pphrase_dialog_type == SSL_PPTYPE_PIPE)
#else
        if (sc->server->pphrase_dialog_type == SSL_PPTYPE_PIPE
#endif
            && ppcb_arg.cpPassPhraseCur != NULL
            && nPassPhraseRetry < BUILTIN_DIALOG_RETRIES ) {
            apr_file_printf(writetty, "Apache:mod_ssl:Error: Pass phrase incorrect "
                    "(%d more retr%s permitted).\n",
                    (BUILTIN_DIALOG_RETRIES-nPassPhraseRetry),
                    (BUILTIN_DIALOG_RETRIES-nPassPhraseRetry) == 1 ? "y" : "ies");
            nPassPhraseRetry++;
            if (nPassPhraseRetry > BUILTIN_DIALOG_BACKOFF)
                apr_sleep((nPassPhraseRetry-BUILTIN_DIALOG_BACKOFF)
                            * 5 * APR_USEC_PER_SEC);
            continue;
        }
#ifdef WIN32
        if (sc->server->pphrase_dialog_type == SSL_PPTYPE_BUILTIN) {
            ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s, APLOGNO(02577)
                         "Init: SSLPassPhraseDialog builtin is not "
                         "supported on Win32 (key file "
                         "%s)", ppcb_arg.pkey_file);
            return ssl_die(s);
        }
#endif /* WIN32 */

        /*
         * Ok, anything else now means a fatal error.
         */
        if (ppcb_arg.cpPassPhraseCur == NULL) {
            if (ppcb_arg.nPassPhraseDialogCur && pkey_mtime &&
                !isatty(fileno(stdout))) /* XXX: apr_isatty() */
            {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0,
                             s, APLOGNO(02578)
                             "Init: Unable to read pass phrase "
                             "[Hint: key introduced or changed "
                             "before restart?]");
                ssl_log_ssl_error(SSLLOG_MARK, APLOG_ERR, s);
            }
            else {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0,
                             s, APLOGNO(02579) "Init: Private key not found");
                ssl_log_ssl_error(SSLLOG_MARK, APLOG_ERR, s);
            }
            if (writetty) {
                apr_file_printf(writetty, "Apache:mod_ssl:Error: Private key not found.\n");
                apr_file_printf(writetty, "**Stopped\n");
            }
        }
        else {
            ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s, APLOGNO(02580)
                         "Init: Pass phrase incorrect for key %s",
                         key_id);
            ssl_log_ssl_error(SSLLOG_MARK, APLOG_EMERG, s);

            if (writetty) {
                apr_file_printf(writetty, "Apache:mod_ssl:Error: Pass phrase incorrect.\n");
                apr_file_printf(writetty, "**Stopped\n");
            }
        }
        return ssl_die(s);
    }

    if (pPrivateKey == NULL) {
        ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s, APLOGNO(02581)
                     "Init: Unable to read server private key from file %s",
                     ppcb_arg.pkey_file);
        ssl_log_ssl_error(SSLLOG_MARK, APLOG_EMERG, s);
        return ssl_die(s);
    }

    /*
     * Log the type of reading
     */
    if (ppcb_arg.nPassPhraseDialogCur == 0) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO(02582)
                     "unencrypted %s private key - pass phrase not "
                     "required", key_id);
    }
    else {
        if (ppcb_arg.cpPassPhraseCur != NULL) {
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0,
                         s, APLOGNO(02583)
                         "encrypted %s private key - pass phrase "
                         "requested", key_id);
        }
        else {
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0,
                         s, APLOGNO(02584)
                         "encrypted %s private key - pass phrase"
                         " reused", key_id);
        }
    }

    /*
     * Ok, when we have one more pass phrase store it
     */
    if (ppcb_arg.cpPassPhraseCur != NULL) {
        *(const char **)apr_array_push(ppcb_arg.aPassPhrase) =
            ppcb_arg.cpPassPhraseCur;
        nPassPhrase++;
    }

    /* Cache the private key in the global module configuration so it
     * can be used after subsequent reloads. */
    asn1 = ssl_asn1_table_set(mc->tPrivateKey, key_id, pPrivateKey);

    if (ppcb_arg.nPassPhraseDialogCur != 0) {
        /* remember mtime of encrypted keys */
        asn1->source_mtime = pkey_mtime;
    }

    /*
     * Free the private key structure
     */
    EVP_PKEY_free(pPrivateKey);

    /*
     * Let the user know when we're successful.
     */
    if ((ppcb_arg.nPassPhraseDialog > 0) &&
        (ppcb_arg.cpPassPhraseCur != NULL)) {
        if (writetty) {
            apr_file_printf(writetty, "\n"
                            "OK: Pass Phrase Dialog successful.\n");
        }
    }

    /* Close the pipes if they were opened
     */
    if (readtty) {
        apr_file_close(readtty);
        apr_file_close(writetty);
        readtty = writetty = NULL;
    }

    return APR_SUCCESS;
}

static apr_status_t ssl_pipe_child_create(apr_pool_t *p, const char *progname)
{
    /* Child process code for 'ErrorLog "|..."';
     * may want a common framework for this, since I expect it will
     * be common for other foo-loggers to want this sort of thing...
     */
    apr_status_t rc;
    apr_procattr_t *procattr;
    apr_proc_t *procnew;

    if (((rc = apr_procattr_create(&procattr, p)) == APR_SUCCESS) &&
        ((rc = apr_procattr_io_set(procattr,
                                   APR_FULL_BLOCK,
                                   APR_FULL_BLOCK,
                                   APR_NO_PIPE)) == APR_SUCCESS)) {
        char **args;

        apr_tokenize_to_argv(progname, &args, p);
        procnew = (apr_proc_t *)apr_pcalloc(p, sizeof(*procnew));
        rc = apr_proc_create(procnew, args[0], (const char * const *)args,
                             NULL, procattr, p);
        if (rc == APR_SUCCESS) {
            /* XXX: not sure if we aught to...
             * apr_pool_note_subprocess(p, procnew, APR_KILL_AFTER_TIMEOUT);
             */
            writetty = procnew->in;
            readtty = procnew->out;
        }
    }

    return rc;
}

static int pipe_get_passwd_cb(char *buf, int length, char *prompt, int verify)
{
    apr_status_t rc;
    char *p;

    apr_file_puts(prompt, writetty);

    buf[0]='\0';
    rc = apr_file_gets(buf, length, readtty);
    apr_file_puts(APR_EOL_STR, writetty);

    if (rc != APR_SUCCESS || apr_file_eof(readtty)) {
        memset(buf, 0, length);
        return 1;  /* failure */
    }
    if ((p = strchr(buf, '\n')) != NULL) {
        *p = '\0';
    }
#ifdef WIN32
    /* XXX: apr_sometest */
    if ((p = strchr(buf, '\r')) != NULL) {
        *p = '\0';
    }
#endif
    return 0;
}

int ssl_pphrase_Handle_CB(char *buf, int bufsize, int verify, void *srv)
{
    pphrase_cb_arg_t *ppcb_arg = (pphrase_cb_arg_t *)srv;
    SSLSrvConfigRec *sc = mySrvConfig(ppcb_arg->s);
    char *cpp;
    int len = -1;

    ppcb_arg->nPassPhraseDialog++;
    ppcb_arg->nPassPhraseDialogCur++;

    /*
     * When remembered pass phrases are available use them...
     */
    if ((cpp = pphrase_array_get(ppcb_arg->aPassPhrase,
                                 ppcb_arg->nPassPhraseCur)) != NULL) {
        apr_cpystrn(buf, cpp, bufsize);
        len = strlen(buf);
        return len;
    }

    /*
     * Builtin or Pipe dialog
     */
    if (sc->server->pphrase_dialog_type == SSL_PPTYPE_BUILTIN
          || sc->server->pphrase_dialog_type == SSL_PPTYPE_PIPE) {
        char *prompt;
        int i;

        if (sc->server->pphrase_dialog_type == SSL_PPTYPE_PIPE) {
            if (!readtty) {
                ap_log_error(APLOG_MARK, APLOG_INFO, 0, ppcb_arg->s,
                             APLOGNO(01965)
                             "Init: Creating pass phrase dialog pipe child "
                             "'%s'", sc->server->pphrase_dialog_path);
                if (ssl_pipe_child_create(ppcb_arg->p,
                                          sc->server->pphrase_dialog_path)
                        != APR_SUCCESS) {
                    ap_log_error(APLOG_MARK, APLOG_ERR, 0, ppcb_arg->s,
                                 APLOGNO(01966)
                                 "Init: Failed to create pass phrase pipe '%s'",
                                 sc->server->pphrase_dialog_path);
                    PEMerr(PEM_F_PEM_DEF_CALLBACK,
                           PEM_R_PROBLEMS_GETTING_PASSWORD);
                    memset(buf, 0, (unsigned int)bufsize);
                    return (-1);
                }
            }
            ap_log_error(APLOG_MARK, APLOG_INFO, 0, ppcb_arg->s, APLOGNO(01967)
                         "Init: Requesting pass phrase via piped dialog");
        }
        else { /* sc->server->pphrase_dialog_type == SSL_PPTYPE_BUILTIN */
#ifdef WIN32
            PEMerr(PEM_F_PEM_DEF_CALLBACK, PEM_R_PROBLEMS_GETTING_PASSWORD);
            memset(buf, 0, (unsigned int)bufsize);
            return (-1);
#else
            /*
             * stderr has already been redirected to the error_log.
             * rather than attempting to temporarily rehook it to the terminal,
             * we print the prompt to stdout before EVP_read_pw_string turns
             * off tty echo
             */
            apr_file_open_stdout(&writetty, ppcb_arg->p);

            ap_log_error(APLOG_MARK, APLOG_INFO, 0, ppcb_arg->s, APLOGNO(01968)
                         "Init: Requesting pass phrase via builtin terminal "
                         "dialog");
#endif
        }

        /*
         * The first time display a header to inform the user about what
         * program he actually speaks to, which module is responsible for
         * this terminal dialog and why to the hell he has to enter
         * something...
         */
        if (ppcb_arg->nPassPhraseDialog == 1) {
            apr_file_printf(writetty, "%s mod_ssl (Pass Phrase Dialog)\n",
                            AP_SERVER_BASEVERSION);
            apr_file_printf(writetty, "Some of your private key files are encrypted for security reasons.\n");
            apr_file_printf(writetty, "In order to read them you have to provide the pass phrases.\n");
        }
        if (ppcb_arg->bPassPhraseDialogOnce) {
            ppcb_arg->bPassPhraseDialogOnce = FALSE;
            apr_file_printf(writetty, "\n");
            apr_file_printf(writetty, "Private key %s (%s)\n",
                            ppcb_arg->key_id, ppcb_arg->pkey_file);
        }

        /*
         * Emulate the OpenSSL internal pass phrase dialog
         * (see crypto/pem/pem_lib.c:def_callback() for details)
         */
        prompt = "Enter pass phrase:";

        for (;;) {
            apr_file_puts(prompt, writetty);
            if (sc->server->pphrase_dialog_type == SSL_PPTYPE_PIPE) {
                i = pipe_get_passwd_cb(buf, bufsize, "", FALSE);
            }
            else { /* sc->server->pphrase_dialog_type == SSL_PPTYPE_BUILTIN */
                i = EVP_read_pw_string(buf, bufsize, "", FALSE);
            }
            if (i != 0) {
                PEMerr(PEM_F_PEM_DEF_CALLBACK,PEM_R_PROBLEMS_GETTING_PASSWORD);
                memset(buf, 0, (unsigned int)bufsize);
                return (-1);
            }
            len = strlen(buf);
            if (len < 1)
                apr_file_printf(writetty, "Apache:mod_ssl:Error: Pass phrase empty (needs to be at least 1 character).\n");
            else
                break;
        }
    }

    /*
     * Filter program
     */
    else if (sc->server->pphrase_dialog_type == SSL_PPTYPE_FILTER) {
        const char *cmd = sc->server->pphrase_dialog_path;
        const char **argv = apr_palloc(ppcb_arg->p, sizeof(char *) * 4);
        const char *idx = ap_strrchr_c(ppcb_arg->key_id, ':') + 1;
        char *result;
        int i;

        ap_log_error(APLOG_MARK, APLOG_INFO, 0, ppcb_arg->s, APLOGNO(01969)
                     "Init: Requesting pass phrase from dialog filter "
                     "program (%s)", cmd);

        argv[0] = cmd;
        argv[1] = apr_pstrndup(ppcb_arg->p, ppcb_arg->key_id,
                               idx-1 - ppcb_arg->key_id);
        if ((i = atoi(idx)) < CERTKEYS_IDX_MAX+1) {
            /*
             * For compatibility with existing 2.4.x configurations, use
             * "RSA", "DSA" and "ECC" strings for the first two/three keys
             */
            argv[2] = key_types[i];
        } else {
            /* Four and above: use the integer index */
            argv[2] = apr_pstrdup(ppcb_arg->p, idx);
        }
        argv[3] = NULL;

        result = ssl_util_readfilter(ppcb_arg->s, ppcb_arg->p, cmd, argv);
        apr_cpystrn(buf, result, bufsize);
        len = strlen(buf);
    }

    /*
     * Ok, we now have the pass phrase, so give it back
     */
    ppcb_arg->cpPassPhraseCur = apr_pstrdup(ppcb_arg->p, buf);

    /*
     * And return its length to OpenSSL...
     */
    return (len);
}

#if MODSSL_HAVE_ENGINE_API || MODSSL_HAVE_OPENSSL_STORE

/* OpenSSL UI implementation for passphrase entry; largely duplicated
 * from ssl_pphrase_Handle_CB but adjusted for UI API. TODO: Might be
 * worth trying to shift pphrase handling over to the UI API
 * completely. */
static int passphrase_ui_open(UI *ui)
{
    pphrase_cb_arg_t *ppcb = UI_get0_user_data(ui);
    SSLSrvConfigRec *sc = mySrvConfig(ppcb->s);

    ppcb->nPassPhraseDialog++;
    ppcb->nPassPhraseDialogCur++;

    /*
     * Builtin or Pipe dialog
     */
    if (sc->server->pphrase_dialog_type == SSL_PPTYPE_BUILTIN
        || sc->server->pphrase_dialog_type == SSL_PPTYPE_PIPE) {
        if (sc->server->pphrase_dialog_type == SSL_PPTYPE_PIPE) {
            if (!readtty) {
                ap_log_error(APLOG_MARK, APLOG_INFO, 0, ppcb->s,
                             APLOGNO(10143)
                             "Init: Creating pass phrase dialog pipe child "
                             "'%s'", sc->server->pphrase_dialog_path);
                if (ssl_pipe_child_create(ppcb->p,
                            sc->server->pphrase_dialog_path)
                        != APR_SUCCESS) {
                    ap_log_error(APLOG_MARK, APLOG_ERR, 0, ppcb->s,
                                 APLOGNO(10144)
                                 "Init: Failed to create pass phrase pipe '%s'",
                                 sc->server->pphrase_dialog_path);
                    return 0;
                }
            }
            ap_log_error(APLOG_MARK, APLOG_INFO, 0, ppcb->s, APLOGNO(10145)
                         "Init: Requesting pass phrase via piped dialog");
        }
        else { /* sc->server->pphrase_dialog_type == SSL_PPTYPE_BUILTIN */
#ifdef WIN32
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, ppcb->s, APLOGNO(10146)
                         "Init: Failed to create pass phrase pipe '%s'",
                         sc->server->pphrase_dialog_path);
            return 0;
#else
            /*
             * stderr has already been redirected to the error_log.
             * rather than attempting to temporarily rehook it to the terminal,
             * we print the prompt to stdout before EVP_read_pw_string turns
             * off tty echo
             */
            apr_file_open_stdout(&writetty, ppcb->p);

            ap_log_error(APLOG_MARK, APLOG_INFO, 0, ppcb->s, APLOGNO(10147)
                         "Init: Requesting pass phrase via builtin terminal "
                         "dialog");
#endif
        }

        /*
         * The first time display a header to inform the user about what
         * program he actually speaks to, which module is responsible for
         * this terminal dialog and why to the hell he has to enter
         * something...
         */
        if (ppcb->nPassPhraseDialog == 1) {
            apr_file_printf(writetty, "%s mod_ssl (Pass Phrase Dialog)\n",
                            AP_SERVER_BASEVERSION);
            apr_file_printf(writetty,
                            "A pass phrase is required to access the private key.\n");
        }
        if (ppcb->bPassPhraseDialogOnce) {
            ppcb->bPassPhraseDialogOnce = FALSE;
            apr_file_printf(writetty, "\n");
            apr_file_printf(writetty, "Private key %s (%s)\n",
                            ppcb->key_id, ppcb->pkey_file);
        }
    }

    return 1;
}

static int passphrase_ui_read(UI *ui, UI_STRING *uis)
{
    pphrase_cb_arg_t *ppcb = UI_get0_user_data(ui);
    SSLSrvConfigRec *sc = mySrvConfig(ppcb->s);
    const char *prompt;
    int i;
    int bufsize;
    int len;
    char *buf;

    prompt = UI_get0_output_string(uis);
    if (prompt == NULL) {
        prompt = "Enter pass phrase:";
    }

    /*
     * Get the maximum expected size and allocate the buffer
     */
    bufsize = UI_get_result_maxsize(uis);
    buf = apr_pcalloc(ppcb->p, bufsize);

    if (sc->server->pphrase_dialog_type == SSL_PPTYPE_BUILTIN
        || sc->server->pphrase_dialog_type == SSL_PPTYPE_PIPE) {
        /*
         * Get the pass phrase through a callback.
         * Empty input is not accepted.
         */
        for (;;) {
            if (sc->server->pphrase_dialog_type == SSL_PPTYPE_PIPE) {
                i = pipe_get_passwd_cb(buf, bufsize, "", FALSE);
            }
            else { /* sc->server->pphrase_dialog_type == SSL_PPTYPE_BUILTIN */
                i = EVP_read_pw_string(buf, bufsize, "", FALSE);
            }
            if (i != 0) {
                OPENSSL_cleanse(buf, bufsize);
                return 0;
            }
            len = strlen(buf);
            if (len < 1){
                apr_file_printf(writetty, "Apache:mod_ssl:Error: Pass phrase"
                                "empty (needs to be at least 1 character).\n");
                apr_file_puts(prompt, writetty);
            }
            else {
                break;
            }
        }
    }
    /*
     * Filter program
     */
    else if (sc->server->pphrase_dialog_type == SSL_PPTYPE_FILTER) {
        const char *cmd = sc->server->pphrase_dialog_path;
        const char **argv = apr_palloc(ppcb->p, sizeof(char *) * 3);
        char *result;

        ap_log_error(APLOG_MARK, APLOG_INFO, 0, ppcb->s, APLOGNO(10148)
                     "Init: Requesting pass phrase from dialog filter "
                     "program (%s)", cmd);

        argv[0] = cmd;
        argv[1] = ppcb->key_id;
        argv[2] = NULL;

        result = ssl_util_readfilter(ppcb->s, ppcb->p, cmd, argv);
        apr_cpystrn(buf, result, bufsize);
        len = strlen(buf);
    }

    /*
     * Ok, we now have the pass phrase, so give it back
     */
    ppcb->cpPassPhraseCur = apr_pstrdup(ppcb->p, buf);
    UI_set_result(ui, uis, buf);

    /* Clear sensitive data. */
    OPENSSL_cleanse(buf, bufsize);
    return 1;
}

static int passphrase_ui_write(UI *ui, UI_STRING *uis)
{
    pphrase_cb_arg_t *ppcb = UI_get0_user_data(ui);
    SSLSrvConfigRec *sc;
    const char *prompt;

    sc = mySrvConfig(ppcb->s);

    if (sc->server->pphrase_dialog_type == SSL_PPTYPE_BUILTIN
        || sc->server->pphrase_dialog_type == SSL_PPTYPE_PIPE) {
        prompt = UI_get0_output_string(uis);
        apr_file_puts(prompt, writetty);
    }

    return 1;
}

static int passphrase_ui_close(UI *ui)
{
    /*
     * Close the pipes if they were opened
     */
    if (readtty) {
        apr_file_close(readtty);
        apr_file_close(writetty);
        readtty = writetty = NULL;
    }
    return 1;
}

static apr_status_t pp_ui_method_cleanup(void *uip)
{
    UI_METHOD *uim = uip;
    
    UI_destroy_method(uim);

    return APR_SUCCESS;
}

static UI_METHOD *get_passphrase_ui(apr_pool_t *p)
{
    UI_METHOD *ui_method = UI_create_method("Passphrase UI");

    UI_method_set_opener(ui_method, passphrase_ui_open);
    UI_method_set_reader(ui_method, passphrase_ui_read);
    UI_method_set_writer(ui_method, passphrase_ui_write);
    UI_method_set_closer(ui_method, passphrase_ui_close);

    apr_pool_cleanup_register(p, ui_method, pp_ui_method_cleanup,
                              pp_ui_method_cleanup);
    
    return ui_method;
}
#endif

#if MODSSL_HAVE_ENGINE_API
static apr_status_t modssl_engine_cleanup(void *engine)
{
    ENGINE *e = engine;

    ENGINE_finish(e);

    return APR_SUCCESS;
}

static apr_status_t modssl_load_keypair_engine(server_rec *s, apr_pool_t *pconf,
                                               apr_pool_t *ptemp,
                                               const char *vhostid,
                                               const char *certid,
                                               const char *keyid,
                                               X509 **pubkey,
                                               EVP_PKEY **privkey)
{
    const char *c, *scheme;
    ENGINE *e;
    UI_METHOD *ui_method = get_passphrase_ui(ptemp);
    pphrase_cb_arg_t ppcb;

    memset(&ppcb, 0, sizeof ppcb);
    ppcb.s = s;
    ppcb.p = ptemp;
    ppcb.bPassPhraseDialogOnce = TRUE;
    ppcb.key_id = vhostid;
    ppcb.pkey_file = keyid;

    c = ap_strchr_c(keyid, ':');
    if (!c || c == keyid) {
        ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s, APLOGNO(10131)
                     "Init: Unrecognized private key identifier `%s'",
                     keyid);
        return ssl_die(s);
    }

    scheme = apr_pstrmemdup(ptemp, keyid, c - keyid);
    if (!(e = ENGINE_by_id(scheme))) {
        ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s, APLOGNO(10132)
                     "Init: Failed to load engine for private key %s",
                     keyid);
        ssl_log_ssl_error(SSLLOG_MARK, APLOG_EMERG, s);
        return ssl_die(s);
    }

    if (!ENGINE_init(e)) {
        ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s, APLOGNO(10149)
                     "Init: Failed to initialize engine %s for private key %s",
                     scheme, keyid);
        ssl_log_ssl_error(SSLLOG_MARK, APLOG_EMERG, s);
        return ssl_die(s);
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, 
                 "Init: Initialized engine %s for private key %s",
                 scheme, keyid);

    if (APLOGdebug(s)) {
        ENGINE_ctrl_cmd_string(e, "VERBOSE", NULL, 0);
    }

    if (certid) {
        struct {
            const char *cert_id;
            X509 *cert;
        } params = { certid, NULL };

        if (!ENGINE_ctrl_cmd(e, "LOAD_CERT_CTRL", 0, &params, NULL, 1)) {
            ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s, APLOGNO(10136)
                         "Init: Unable to get the certificate");
            ssl_log_ssl_error(SSLLOG_MARK, APLOG_EMERG, s);
            return ssl_die(s);
        }

        *pubkey = params.cert;
    }

    *privkey = ENGINE_load_private_key(e, keyid, ui_method, &ppcb);
    if (*privkey == NULL) {
        ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s, APLOGNO(10133)
                     "Init: Unable to get the private key");
        ssl_log_ssl_error(SSLLOG_MARK, APLOG_EMERG, s);
        return ssl_die(s);
    }

    /* Release the functional reference obtained by ENGINE_init() only
     * when after the ENGINE is no longer used. */
    apr_pool_cleanup_register(pconf, e, modssl_engine_cleanup, modssl_engine_cleanup);

    /* Release the structural reference obtained by ENGINE_by_id()
     * immediately. */
    ENGINE_free(e);

    return APR_SUCCESS;
}
#endif

#if MODSSL_HAVE_OPENSSL_STORE
static OSSL_STORE_INFO *modssl_load_store_uri(server_rec *s, apr_pool_t *p,
                                              const char *vhostid,
                                              const char *uri, int info_type)
{
    OSSL_STORE_CTX *sctx;
    UI_METHOD *ui_method = get_passphrase_ui(p);
    pphrase_cb_arg_t ppcb;
    OSSL_STORE_INFO *info = NULL;

    memset(&ppcb, 0, sizeof ppcb);
    ppcb.s = s;
    ppcb.p = p;
    ppcb.bPassPhraseDialogOnce = TRUE;
    ppcb.key_id = vhostid;
    ppcb.pkey_file = uri;

    sctx = OSSL_STORE_open(uri, ui_method, &ppcb, NULL, NULL);
    if (!sctx) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, APLOGNO(10491)
                     "Init: OSSL_STORE_open failed for PKCS#11 URI `%s'",
                     uri);
        return NULL;
    }

    while (!OSSL_STORE_eof(sctx)) {
        info = OSSL_STORE_load(sctx);
        if (!info)
            break;

        if (OSSL_STORE_INFO_get_type(info) == info_type)
            break;

        OSSL_STORE_INFO_free(info);
        info = NULL;
    }

    OSSL_STORE_close(sctx);

    return info;
}

static apr_status_t modssl_load_keypair_store(server_rec *s, apr_pool_t *p,
                                              const char *vhostid,
                                              const char *certid,
                                              const char *keyid,
                                              X509 **pubkey,
                                              EVP_PKEY **privkey)
{
    OSSL_STORE_INFO *info = NULL;

    *privkey = NULL;
    *pubkey = NULL;

    info = modssl_load_store_uri(s, p, vhostid, keyid, OSSL_STORE_INFO_PKEY);
    if (!info) {
        ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s, APLOGNO(10492)
                     "Init: OSSL_STORE_INFO_PKEY lookup failed for private key identifier `%s'",
                     keyid);
        return ssl_die(s);
    }

    *privkey = OSSL_STORE_INFO_get1_PKEY(info);
    OSSL_STORE_INFO_free(info);
    if (!*privkey) {
        ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s, APLOGNO(10493)
                     "Init: OSSL_STORE_INFO_PKEY lookup failed for private key identifier `%s'",
                     keyid);
        return ssl_die(s);
    }

    if (certid) {
        info = modssl_load_store_uri(s, p, vhostid, certid, OSSL_STORE_INFO_CERT);
        if (!info) {
            ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s, APLOGNO(10494)
                         "Init: OSSL_STORE_INFO_CERT lookup failed for certificate identifier `%s'",
                         keyid);
            return ssl_die(s);
        }

        *pubkey = OSSL_STORE_INFO_get1_CERT(info);
        OSSL_STORE_INFO_free(info);
        if (!*pubkey) {
            ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s, APLOGNO(10495)
                     "Init: OSSL_STORE_INFO_CERT lookup failed for certificate identifier `%s'",
                     certid);
            return ssl_die(s);
        }
    }

    return APR_SUCCESS;
}
#endif

apr_status_t modssl_load_engine_keypair(server_rec *s,
                                        apr_pool_t *pconf, apr_pool_t *ptemp,
                                        const char *vhostid,
                                        const char *certid, const char *keyid,
                                        X509 **pubkey, EVP_PKEY **privkey)
{
#if MODSSL_HAVE_ENGINE_API 
    SSLModConfigRec *mc = myModConfig(s);

    /* For OpenSSL 3.x, use the STORE-based API if either ENGINE
     * support was not present compile-time, or if it's built but
     * SSLCryptoDevice is not configured. */
    if (mc->szCryptoDevice)
        return modssl_load_keypair_engine(s, pconf, ptemp,
                                          vhostid, certid, keyid,
                                          pubkey, privkey);
#endif
#if MODSSL_HAVE_OPENSSL_STORE
    return modssl_load_keypair_store(s, ptemp, vhostid, certid, keyid,
                                     pubkey, privkey);
#else
    ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s, APLOGNO(10496)
                 "Init: no method for loading keypair for %s (%s | %s)",
                 vhostid, certid ? certid : "no cert", keyid);
    return APR_ENOTIMPL;
#endif
}
