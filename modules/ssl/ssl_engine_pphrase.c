/*                      _             _
**  _ __ ___   ___   __| |    ___ ___| |  mod_ssl
** | '_ ` _ \ / _ \ / _` |   / __/ __| |  Apache Interface to OpenSSL
** | | | | | | (_) | (_| |   \__ \__ \ |  www.modssl.org
** |_| |_| |_|\___/ \__,_|___|___/___/_|  ftp.modssl.org
**                      |_____|
**  ssl_engine_pphrase.c
**  Pass Phrase Dialog
*/

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
 */
                             /* ``Treat your password like your
                                  toothbrush. Don't let anybody
                                  else use it, and get a new one
                                  every six months.''
                                           -- Clifford Stoll     */
#include "mod_ssl.h"

/*
 * Return true if the named file exists and is readable
 */

static apr_status_t exists_and_readable(char *fname, apr_pool_t *pool, apr_time_t *mtime)
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
static char *asn1_table_vhost_key(SSLModConfigRec *mc, apr_pool_t *p,
                                  char *id, char *an)
{
    /* 'p' pool used here is cleared on restarts (or sooner) */
    char *key = apr_psprintf(p, "%s:%s", id, an);
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

/*
 * sslc has a nasty flaw where its
 * PEM_read_bio_PrivateKey does not take a callback arg.
 */
static server_rec *ssl_pphrase_server_rec = NULL;

#ifdef SSLC_VERSION_NUMBER
int ssl_pphrase_Handle_CB(char *, int, int);
#else
int ssl_pphrase_Handle_CB(char *, int, int, void *);
#endif

static char *pphrase_array_get(apr_array_header_t *arr, int idx)
{
    if ((idx < 0) || (idx >= arr->nelts)) {
        return NULL;
    }

    return ((char **)arr->elts)[idx];
}

static void pphrase_array_clear(apr_array_header_t *arr)
{
    if (arr->nelts > 0) {
        memset(arr->elts, 0, arr->elt_size * arr->nelts);
    }
    arr->nelts = 0;
}

void ssl_pphrase_Handle(server_rec *s, apr_pool_t *p)
{
    SSLModConfigRec *mc = myModConfig(s);
    SSLSrvConfigRec *sc;
    server_rec *pServ;
    char *cpVHostID;
    char szPath[MAX_STRING_LEN];
    EVP_PKEY *pPrivateKey;
    ssl_asn1_t *asn1;
    unsigned char *ucp;
    long int length;
    X509 *pX509Cert;
    BOOL bReadable;
    apr_array_header_t *aPassPhrase;
    int nPassPhrase;
    int nPassPhraseCur;
    char *cpPassPhraseCur;
    int nPassPhraseRetry;
    int nPassPhraseDialog;
    int nPassPhraseDialogCur;
    BOOL bPassPhraseDialogOnce;
    char **cpp;
    int i, j;
    ssl_algo_t algoCert, algoKey, at;
    char *an;
    char *cp;
    apr_time_t pkey_mtime = 0;
    int isterm = 1;
    apr_status_t rv;
    /*
     * Start with a fresh pass phrase array
     */
    aPassPhrase       = apr_array_make(p, 2, sizeof(char *));
    nPassPhrase       = 0;
    nPassPhraseDialog = 0;

    /*
     * Walk through all configured servers
     */
    for (pServ = s; pServ != NULL; pServ = pServ->next) {
        sc = mySrvConfig(pServ);

        if (!sc->enabled)
            continue;

        cpVHostID = ssl_util_vhostid(p, pServ);
        ap_log_error(APLOG_MARK, APLOG_INFO, 0, pServ,
                     "Loading certificate & private key of SSL-aware server");

        /*
         * Read in server certificate(s): This is the easy part
         * because this file isn't encrypted in any way.
         */
        if (sc->server->pks->cert_files[0] == NULL) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, pServ,
                         "Server should be SSL-aware but has no certificate "
                         "configured [Hint: SSLCertificateFile]");
            ssl_die();
        }
        algoCert = SSL_ALGO_UNKNOWN;
        algoKey  = SSL_ALGO_UNKNOWN;
        for (i = 0, j = 0; i < SSL_AIDX_MAX && sc->server->pks->cert_files[i] != NULL; i++) {

            apr_cpystrn(szPath, sc->server->pks->cert_files[i], sizeof(szPath));
            if ((rv = exists_and_readable(szPath, p, NULL)) != APR_SUCCESS) {
                ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                             "Init: Can't open server certificate file %s",
                             szPath);
                ssl_die();
            }
            if ((pX509Cert = SSL_read_X509(szPath, NULL, NULL)) == NULL) {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                        "Init: Unable to read server certificate from file %s", szPath);
                ssl_log_ssl_error(APLOG_MARK, APLOG_ERR, s);
                ssl_die();
            }

            /*
             * check algorithm type of certificate and make
             * sure only one certificate per type is used.
             */
            at = ssl_util_algotypeof(pX509Cert, NULL);
            an = ssl_util_algotypestr(at);
            if (algoCert & at) {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                             "Init: Multiple %s server certificates not "
                             "allowed", an);
                ssl_log_ssl_error(APLOG_MARK, APLOG_ERR, s);
                ssl_die();
            }
            algoCert |= at;

            /*
             * Insert the certificate into global module configuration to let it
             * survive the processing between the 1st Apache API init round (where
             * we operate here) and the 2nd Apache init round (where the
             * certificate is actually used to configure mod_ssl's per-server
             * configuration structures).
             */
            cp = asn1_table_vhost_key(mc, p, cpVHostID, an);
            length = i2d_X509(pX509Cert, NULL);
            ucp = ssl_asn1_table_set(mc->tPublicCert, cp, length);
            (void)i2d_X509(pX509Cert, &ucp); /* 2nd arg increments */

            /*
             * Free the X509 structure
             */
            X509_free(pX509Cert);

            /*
             * Read in the private key: This is the non-trivial part, because the
             * key is typically encrypted, so a pass phrase dialog has to be used
             * to request it from the user (or it has to be alternatively gathered
             * from a dialog program). The important point here is that ISPs
             * usually have hundrets of virtual servers configured and a lot of
             * them use SSL, so really we have to minimize the pass phrase
             * dialogs.
             *
             * The idea is this: When N virtual hosts are configured and all of
             * them use encrypted private keys with different pass phrases, we
             * have no chance and have to pop up N pass phrase dialogs. But
             * usually the admin is clever enough and uses the same pass phrase
             * for more private key files (typically he even uses one single pass
             * phrase for all). When this is the case we can minimize the dialogs
             * by trying to re-use already known/entered pass phrases.
             */
            if (sc->server->pks->key_files[j] != NULL)
                apr_cpystrn(szPath, sc->server->pks->key_files[j++], sizeof(szPath));

            /*
             * Try to read the private key file with the help of
             * the callback function which serves the pass
             * phrases to OpenSSL
             */
            myCtxVarSet(mc,  1, pServ);
            myCtxVarSet(mc,  2, p);
            myCtxVarSet(mc,  3, aPassPhrase);
            myCtxVarSet(mc,  4, &nPassPhraseCur);
            myCtxVarSet(mc,  5, &cpPassPhraseCur);
            myCtxVarSet(mc,  6, cpVHostID);
            myCtxVarSet(mc,  7, an);
            myCtxVarSet(mc,  8, &nPassPhraseDialog);
            myCtxVarSet(mc,  9, &nPassPhraseDialogCur);
            myCtxVarSet(mc, 10, &bPassPhraseDialogOnce);

            nPassPhraseCur        = 0;
            nPassPhraseRetry      = 0;
            nPassPhraseDialogCur  = 0;
            bPassPhraseDialogOnce = TRUE;

            pPrivateKey = NULL;

            for (;;) {
                /*
                 * Try to read the private key file with the help of
                 * the callback function which serves the pass
                 * phrases to OpenSSL
                 */
                if ((rv = exists_and_readable(szPath, p,
                                              &pkey_mtime)) != APR_SUCCESS ) {
                     ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                                  "Init: Can't open server private key file "
                                  "%s",szPath);
                     ssl_die();
                }

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
                    int i;

                    for (i=0; i < SSL_AIDX_MAX; i++) {
                        const char *key_id =
                            ssl_asn1_table_keyfmt(p, cpVHostID, i);
                        ssl_asn1_t *asn1 = 
                            ssl_asn1_table_get(mc->tPrivateKey, key_id);
                    
                        if (asn1 && (asn1->source_mtime == pkey_mtime)) {
                            ap_log_error(APLOG_MARK, APLOG_INFO,
                                         0, pServ,
                                         "%s reusing existing "
                                         "%s private key on restart",
                                         cpVHostID, ssl_asn1_keystr(i));
                            return;
                        }
                    }
                }

                cpPassPhraseCur = NULL;
                ssl_pphrase_server_rec = s; /* to make up for sslc flaw */

                bReadable = ((pPrivateKey = SSL_read_PrivateKey(szPath, NULL,
                            ssl_pphrase_Handle_CB, s)) != NULL ? TRUE : FALSE);

                /*
                 * when the private key file now was readable,
                 * it's fine and we go out of the loop
                 */
                if (bReadable)
                   break;

                /*
                 * when we have more remembered pass phrases
                 * try to reuse these first.
                 */
                if (nPassPhraseCur < nPassPhrase) {
                    nPassPhraseCur++;
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
                    && cpPassPhraseCur != NULL
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
                    ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                                 "Init: SSLPassPhraseDialog builtin is not "
                                 "supported on Win32 (key file "
                                 "%s)", szPath);
                    ssl_die();
                }
#endif /* WIN32 */

                /*
                 * Ok, anything else now means a fatal error.
                 */
                if (cpPassPhraseCur == NULL) {
                    if (nPassPhraseDialogCur && pkey_mtime &&
                        !(isterm = isatty(fileno(stdout)))) /* XXX: apr_isatty() */
                    {
                        ap_log_error(APLOG_MARK, APLOG_ERR, 0,
                                     pServ,
                                     "Init: Unable to read pass phrase "
                                     "[Hint: key introduced or changed "
                                     "before restart?]");
                        ssl_log_ssl_error(APLOG_MARK, APLOG_ERR, pServ);
                    }
                    else {
                        ap_log_error(APLOG_MARK, APLOG_ERR, 0,
                                     pServ, "Init: Private key not found");
                        ssl_log_ssl_error(APLOG_MARK, APLOG_ERR, pServ);
                    }
                    if (writetty) {
                        apr_file_printf(writetty, "Apache:mod_ssl:Error: Private key not found.\n");
                        apr_file_printf(writetty, "**Stopped\n");
                    }
                }
                else {
                    ap_log_error(APLOG_MARK, APLOG_ERR, 0,
                                 pServ, "Init: Pass phrase incorrect");
                    ssl_log_ssl_error(APLOG_MARK, APLOG_ERR, pServ);

                    if (writetty) {
                        apr_file_printf(writetty, "Apache:mod_ssl:Error: Pass phrase incorrect.\n");
                        apr_file_printf(writetty, "**Stopped\n");
                    }
                }
                ssl_die();
            }

            if (pPrivateKey == NULL) {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                            "Init: Unable to read server private key from "
                            "file %s [Hint: Perhaps it is in a separate file? "
                            "  See SSLCertificateKeyFile]", szPath);
                ssl_log_ssl_error(APLOG_MARK, APLOG_ERR, s);
                ssl_die();
            }

            /*
             * check algorithm type of private key and make
             * sure only one private key per type is used.
             */
            at = ssl_util_algotypeof(NULL, pPrivateKey);
            an = ssl_util_algotypestr(at);
            if (algoKey & at) {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                             "Init: Multiple %s server private keys not "
                             "allowed", an);
                ssl_log_ssl_error(APLOG_MARK, APLOG_ERR, s);
                ssl_die();
            }
            algoKey |= at;

            /*
             * Log the type of reading
             */
            if (nPassPhraseDialogCur == 0) {
                ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, pServ, 
                             "unencrypted %s private key - pass phrase not "
                             "required", an);
            }
            else {
                if (cpPassPhraseCur != NULL) {
                    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0,
                                 pServ, 
                                 "encrypted %s private key - pass phrase "
                                 "requested", an);
                }
                else {
                    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0,
                                 pServ, 
                                 "encrypted %s private key - pass phrase"
                                 " reused", an);
                }
            }

            /*
             * Ok, when we have one more pass phrase store it
             */
            if (cpPassPhraseCur != NULL) {
                cpp = (char **)apr_array_push(aPassPhrase);
                *cpp = cpPassPhraseCur;
                nPassPhrase++;
            }

            /*
             * Insert private key into the global module configuration
             * (we convert it to a stand-alone DER byte sequence
             * because the SSL library uses static variables inside a
             * RSA structure which do not survive DSO reloads!)
             */
            cp = asn1_table_vhost_key(mc, p, cpVHostID, an);
            length = i2d_PrivateKey(pPrivateKey, NULL);
            ucp = ssl_asn1_table_set(mc->tPrivateKey, cp, length);
            (void)i2d_PrivateKey(pPrivateKey, &ucp); /* 2nd arg increments */

            if (nPassPhraseDialogCur != 0) {
                /* remember mtime of encrypted keys */
                asn1 = ssl_asn1_table_get(mc->tPrivateKey, cp);
                asn1->source_mtime = pkey_mtime;
            }

            /*
             * Free the private key structure
             */
            EVP_PKEY_free(pPrivateKey);
        }
    }

    /*
     * Let the user know when we're successful.
     */
    if (nPassPhraseDialog > 0) {
        sc = mySrvConfig(s);
        if (writetty) {
            apr_file_printf(writetty, "\n");
            apr_file_printf(writetty, "Ok: Pass Phrase Dialog successful.\n");
        }
    }

    /*
     * Wipe out the used memory from the
     * pass phrase array and then deallocate it
     */
    if (aPassPhrase->nelts) {
        pphrase_array_clear(aPassPhrase);
        ap_log_error(APLOG_MARK, APLOG_INFO, 0, s,
                     "Init: Wiped out the queried pass phrases from memory");
    }

    /* Close the pipes if they were opened
     */
    if (readtty) {
        apr_file_close(readtty);
        apr_file_close(writetty);
        readtty = writetty = NULL;
    }
    return;
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
        const char *pname;
        
        apr_tokenize_to_argv(progname, &args, p);
        pname = apr_pstrdup(p, args[0]);
        procnew = (apr_proc_t *)apr_pcalloc(p, sizeof(*procnew));
        rc = apr_proc_create(procnew, pname, (const char * const *)args,
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

#ifdef SSLC_VERSION_NUMBER
int ssl_pphrase_Handle_CB(char *buf, int bufsize, int verify)
{
    void *srv = ssl_pphrase_server_rec;
#else
int ssl_pphrase_Handle_CB(char *buf, int bufsize, int verify, void *srv)
{
#endif
    SSLModConfigRec *mc;
    server_rec *s;
    apr_pool_t *p;
    apr_array_header_t *aPassPhrase;
    SSLSrvConfigRec *sc;
    int *pnPassPhraseCur;
    char **cppPassPhraseCur;
    char *cpVHostID;
    char *cpAlgoType;
    int *pnPassPhraseDialog;
    int *pnPassPhraseDialogCur;
    BOOL *pbPassPhraseDialogOnce;
    char *cpp;
    int len = -1;

    mc = myModConfig((server_rec *)srv);

    /*
     * Reconnect to the context of ssl_phrase_Handle()
     */
    s                      = myCtxVarGet(mc,  1, server_rec *);
    p                      = myCtxVarGet(mc,  2, apr_pool_t *);
    aPassPhrase            = myCtxVarGet(mc,  3, apr_array_header_t *);
    pnPassPhraseCur        = myCtxVarGet(mc,  4, int *);
    cppPassPhraseCur       = myCtxVarGet(mc,  5, char **);
    cpVHostID              = myCtxVarGet(mc,  6, char *);
    cpAlgoType             = myCtxVarGet(mc,  7, char *);
    pnPassPhraseDialog     = myCtxVarGet(mc,  8, int *);
    pnPassPhraseDialogCur  = myCtxVarGet(mc,  9, int *);
    pbPassPhraseDialogOnce = myCtxVarGet(mc, 10, BOOL *);
    sc                     = mySrvConfig(s);

    (*pnPassPhraseDialog)++;
    (*pnPassPhraseDialogCur)++;

    /*
     * When remembered pass phrases are available use them...
     */
    if ((cpp = pphrase_array_get(aPassPhrase, *pnPassPhraseCur)) != NULL) {
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
                ap_log_error(APLOG_MARK, APLOG_INFO, 0, s,
                             "Init: Creating pass phrase dialog pipe child "
                             "'%s'", sc->server->pphrase_dialog_path);
	        if (ssl_pipe_child_create(p, sc->server->pphrase_dialog_path)
                        != APR_SUCCESS) {
                    ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                                 "Init: Failed to create pass phrase pipe '%s'",
                                 sc->server->pphrase_dialog_path);
                    PEMerr(PEM_F_DEF_CALLBACK,PEM_R_PROBLEMS_GETTING_PASSWORD);
                    memset(buf, 0, (unsigned int)bufsize);
                    return (-1);
                }
            }
            ap_log_error(APLOG_MARK, APLOG_INFO, 0, s,
                         "Init: Requesting pass phrase via piped dialog");
        }
        else { /* sc->server->pphrase_dialog_type == SSL_PPTYPE_BUILTIN */ 
#ifdef WIN32
            PEMerr(PEM_F_DEF_CALLBACK,PEM_R_PROBLEMS_GETTING_PASSWORD);
            memset(buf, 0, (unsigned int)bufsize);
            return (-1);
#else
            /*
             * stderr has already been redirected to the error_log.
             * rather than attempting to temporarily rehook it to the terminal,
             * we print the prompt to stdout before EVP_read_pw_string turns
             * off tty echo
             */
            apr_file_open_stdout(&writetty, p);

            ap_log_error(APLOG_MARK, APLOG_INFO, 0, s,
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
        if (*pnPassPhraseDialog == 1) {
            apr_file_printf(writetty, "%s mod_ssl/%s (Pass Phrase Dialog)\n",
                            AP_SERVER_BASEVERSION, MOD_SSL_VERSION);
            apr_file_printf(writetty, "Some of your private key files are encrypted for security reasons.\n");
            apr_file_printf(writetty, "In order to read them you have to provide us with the pass phrases.\n");
        }
        if (*pbPassPhraseDialogOnce) {
            *pbPassPhraseDialogOnce = FALSE;
            apr_file_printf(writetty, "\n");
            apr_file_printf(writetty, "Server %s (%s)\n", cpVHostID, cpAlgoType);
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
                PEMerr(PEM_F_DEF_CALLBACK,PEM_R_PROBLEMS_GETTING_PASSWORD);
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
        const char **argv = apr_palloc(p, sizeof(char *) * 4);
        char *result;

        ap_log_error(APLOG_MARK, APLOG_INFO, 0, s,
                     "Init: Requesting pass phrase from dialog filter "
                     "program (%s)", cmd);

        argv[0] = cmd;
        argv[1] = cpVHostID;
        argv[2] = cpAlgoType;
        argv[3] = NULL;

        result = ssl_util_readfilter(s, p, cmd, argv);
        apr_cpystrn(buf, result, bufsize);
        len = strlen(buf);
    }

    /*
     * Ok, we now have the pass phrase, so give it back
     */
    *cppPassPhraseCur = apr_pstrdup(p, buf);

    /*
     * And return it's length to OpenSSL...
     */
    return (len);
}

