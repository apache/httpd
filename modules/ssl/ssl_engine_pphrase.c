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
 * Copyright (c) 1998-2001 Ralf S. Engelschall. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following
 *    disclaimer in the documentation and/or other materials
 *    provided with the distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by
 *     Ralf S. Engelschall <rse@engelschall.com> for use in the
 *     mod_ssl project (http://www.modssl.org/)."
 *
 * 4. The names "mod_ssl" must not be used to endorse or promote
 *    products derived from this software without prior written
 *    permission. For written permission, please contact
 *    rse@engelschall.com.
 *
 * 5. Products derived from this software may not be called "mod_ssl"
 *    nor may "mod_ssl" appear in their names without prior
 *    written permission of Ralf S. Engelschall.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by
 *     Ralf S. Engelschall <rse@engelschall.com> for use in the
 *     mod_ssl project (http://www.modssl.org/)."
 *
 * THIS SOFTWARE IS PROVIDED BY RALF S. ENGELSCHALL ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL RALF S. ENGELSCHALL OR
 * HIS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 */
                             /* ``Treat your password like your
                                  toothbrush. Don't let anybody
                                  else use it, and get a new one
                                  every six months.''
                                           -- Clifford Stoll     */
#include "mod_ssl.h"


/*  _________________________________________________________________
**
**  Pass Phrase and Private Key Handling
**  _________________________________________________________________
*/

#define STDERR_FILENO_STORE 50
#define BUILTIN_DIALOG_BACKOFF 2
#define BUILTIN_DIALOG_RETRIES 5

void ssl_pphrase_Handle(server_rec *s, pool *p)
{
    SSLModConfigRec *mc = myModConfig();
    SSLSrvConfigRec *sc;
    server_rec *pServ;
    char *cpVHostID;
    char szPath[MAX_STRING_LEN];
    EVP_PKEY *pPrivateKey;
    ssl_asn1_t *asn1;
    unsigned char *ucp;
    X509 *pX509Cert;
    FILE *fp;
    BOOL bReadable;
    ssl_ds_array *aPassPhrase;
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

    /*
     * Start with a fresh pass phrase array
     */
    aPassPhrase       = ssl_ds_array_make(p, sizeof(char *));
    nPassPhrase       = 0;
    nPassPhraseDialog = 0;

    /*
     * Walk through all configured servers
     */
    for (pServ = s; pServ != NULL; pServ = pServ->next) {
        sc = mySrvConfig(pServ);

        if (!sc->bEnabled)
            continue;

        cpVHostID = ssl_util_vhostid(p, pServ);
        ssl_log(pServ, SSL_LOG_INFO,
                "Init: Loading certificate & private key of SSL-aware server %s",
                cpVHostID);

        /*
         * Read in server certificate(s): This is the easy part
         * because this file isn't encrypted in any way.
         */
        if (sc->szPublicCertFile[0] == NULL) {
            ssl_log(pServ, SSL_LOG_ERROR,
                    "Init: Server %s should be SSL-aware but has no certificate configured "
                    "[Hint: SSLCertificateFile]", cpVHostID);
            ssl_die();
        }
        algoCert = SSL_ALGO_UNKNOWN;
        algoKey  = SSL_ALGO_UNKNOWN;
        for (i = 0, j = 0; i < SSL_AIDX_MAX && sc->szPublicCertFile[i] != NULL; i++) {

            ap_cpystrn(szPath, sc->szPublicCertFile[i], sizeof(szPath));
            if ((fp = ap_pfopen(p, szPath, "r")) == NULL) {
                ssl_log(s, SSL_LOG_ERROR|SSL_ADD_ERRNO,
                        "Init: Can't open server certificate file %s", szPath);
                ssl_die();
            }
            if ((pX509Cert = SSL_read_X509(fp, NULL, NULL)) == NULL) {
                ssl_log(s, SSL_LOG_ERROR|SSL_ADD_SSLERR,
                        "Init: Unable to read server certificate from file %s", szPath);
                ssl_die();
            }
            ap_pfclose(p, fp);

            /*
             * check algorithm type of certificate and make
             * sure only one certificate per type is used.
             */
            at = ssl_util_algotypeof(pX509Cert, NULL);
            an = ssl_util_algotypestr(at);
            if (algoCert & at) {
                ssl_log(s, SSL_LOG_ERROR|SSL_ADD_SSLERR,
                        "Init: Multiple %s server certificates not allowed", an);
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
            cp = ap_psprintf(mc->pPool, "%s:%s", cpVHostID, an);
            asn1 = (ssl_asn1_t *)ssl_ds_table_push(mc->tPublicCert, cp);
            asn1->nData  = i2d_X509(pX509Cert, NULL);
            asn1->cpData = ap_palloc(mc->pPool, asn1->nData);
            ucp = asn1->cpData; i2d_X509(pX509Cert, &ucp); /* 2nd arg increments */

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
            if (sc->szPrivateKeyFile[j] != NULL)
                ap_cpystrn(szPath, sc->szPrivateKeyFile[j++], sizeof(szPath));

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
                if ((fp = ap_pfopen(p, szPath, "r")) == NULL) {
                    ssl_log(s, SSL_LOG_ERROR|SSL_ADD_ERRNO,
                            "Init: Can't open server private key file %s", szPath);
                    ssl_die();
                }
                cpPassPhraseCur = NULL;
                bReadable = ((pPrivateKey = SSL_read_PrivateKey(fp, NULL,
                             ssl_pphrase_Handle_CB)) != NULL ? TRUE : FALSE);
                ap_pfclose(p, fp);

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
                if (   sc->nPassPhraseDialogType == SSL_PPTYPE_BUILTIN
                    && cpPassPhraseCur != NULL
                    && nPassPhraseRetry < BUILTIN_DIALOG_RETRIES ) {
                    fprintf(stdout, "Apache:mod_ssl:Error: Pass phrase incorrect "
                            "(%d more retr%s permitted).\n",
                            (BUILTIN_DIALOG_RETRIES-nPassPhraseRetry),
                            (BUILTIN_DIALOG_RETRIES-nPassPhraseRetry) == 1 ? "y" : "ies");
                    nPassPhraseRetry++;
                    if (nPassPhraseRetry > BUILTIN_DIALOG_BACKOFF)
                        sleep((nPassPhraseRetry-BUILTIN_DIALOG_BACKOFF)*5);
                    continue;
                }

                /*
                 * Ok, anything else now means a fatal error.
                 */
                if (cpPassPhraseCur == NULL)
                    ssl_log(pServ, SSL_LOG_ERROR|SSL_ADD_SSLERR, "Init: Private key not found");
                    if (sc->nPassPhraseDialogType == SSL_PPTYPE_BUILTIN) {
                        fprintf(stdout, "Apache:mod_ssl:Error: Private key not found.\n");
                        fprintf(stdout, "**Stopped\n");
                    }
                else {
                    ssl_log(pServ, SSL_LOG_ERROR|SSL_ADD_SSLERR, "Init: Pass phrase incorrect");
                    if (sc->nPassPhraseDialogType == SSL_PPTYPE_BUILTIN) {
                        fprintf(stdout, "Apache:mod_ssl:Error: Pass phrase incorrect.\n");
                        fprintf(stdout, "**Stopped\n");
                    }
                }
                ssl_die();
            }

            if (pPrivateKey == NULL) {
                ssl_log(s, SSL_LOG_ERROR|SSL_ADD_SSLERR,
                        "Init: Unable to read server private key from file %s", szPath);
                ssl_die();
            }

            /*
             * check algorithm type of private key and make
             * sure only one private key per type is used.
             */
            at = ssl_util_algotypeof(NULL, pPrivateKey);
            an = ssl_util_algotypestr(at);
            if (algoKey & at) {
                ssl_log(s, SSL_LOG_ERROR|SSL_ADD_SSLERR,
                        "Init: Multiple %s server private keys not allowed", an);
                ssl_die();
            }
            algoKey |= at;

            /*
             * Log the type of reading
             */
            if (nPassPhraseDialogCur == 0)
                ssl_log(pServ, SSL_LOG_TRACE, 
                        "Init: (%s) unencrypted %s private key - pass phrase not required", 
                        cpVHostID, an);
            else {
                if (cpPassPhraseCur != NULL)
                    ssl_log(pServ, SSL_LOG_TRACE, 
                            "Init: (%s) encrypted %s private key - pass phrase requested", 
                            cpVHostID, an);
                else
                    ssl_log(pServ, SSL_LOG_TRACE, 
                            "Init: (%s) encrypted %s private key - pass phrase reused", 
                            cpVHostID, an);
            }

            /*
             * Ok, when we have one more pass phrase store it
             */
            if (cpPassPhraseCur != NULL) {
                cpp = (char **)ssl_ds_array_push(aPassPhrase);
                *cpp = cpPassPhraseCur;
                nPassPhrase++;
            }

            /*
             * Insert private key into the global module configuration
             * (we convert it to a stand-alone DER byte sequence
             * because the SSL library uses static variables inside a
             * RSA structure which do not survive DSO reloads!)
             */
            cp = ap_psprintf(mc->pPool, "%s:%s", cpVHostID, an);
            asn1 = (ssl_asn1_t *)ssl_ds_table_push(mc->tPrivateKey, cp);
            asn1->nData  = i2d_PrivateKey(pPrivateKey, NULL);
            asn1->cpData = ap_palloc(mc->pPool, asn1->nData);
            ucp = asn1->cpData; i2d_PrivateKey(pPrivateKey, &ucp); /* 2nd arg increments */

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
        if (sc->nPassPhraseDialogType == SSL_PPTYPE_BUILTIN) {
            fprintf(stdout, "\n");
            fprintf(stdout, "Ok: Pass Phrase Dialog successful.\n");
        }
    }

    /*
     * Wipe out the used memory from the
     * pass phrase array and then deallocate it
     */
    if (!ssl_ds_array_isempty(aPassPhrase)) {
        ssl_ds_array_wipeout(aPassPhrase);
        ssl_ds_array_kill(aPassPhrase);
        ssl_log(s, SSL_LOG_INFO, "Init: Wiped out the queried pass phrases from memory");
    }

    return;
}

int ssl_pphrase_Handle_CB(char *buf, int bufsize, int verify)
{
    SSLModConfigRec *mc = myModConfig();
    server_rec *s;
    pool *p;
    ssl_ds_array *aPassPhrase;
    SSLSrvConfigRec *sc;
    int *pnPassPhraseCur;
    char **cppPassPhraseCur;
    char *cpVHostID;
    char *cpAlgoType;
    int *pnPassPhraseDialog;
    int *pnPassPhraseDialogCur;
    BOOL *pbPassPhraseDialogOnce;
    int stderr_store;
    char **cpp;
    int len = -1;

    /*
     * Reconnect to the context of ssl_phrase_Handle()
     */
    s                      = myCtxVarGet(mc,  1, server_rec *);
    p                      = myCtxVarGet(mc,  2, pool *);
    aPassPhrase            = myCtxVarGet(mc,  3, ssl_ds_array *);
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
    if ((cpp = (char **)ssl_ds_array_get(aPassPhrase, *pnPassPhraseCur)) != NULL) {
        ap_cpystrn(buf, *cpp, bufsize);
        len = strlen(buf);
        return len;
    }

    /*
     * Builtin dialog
     */
    if (sc->nPassPhraseDialogType == SSL_PPTYPE_BUILTIN) {
        char *prompt;
        int i;
#ifdef WIN32
        FILE *con;
#endif

        ssl_log(s, SSL_LOG_INFO,
                "Init: Requesting pass phrase via builtin terminal dialog");

        /*
         * Reconnect STDERR to terminal (here STDOUT) because
         * at our init stage Apache already connected STDERR
         * to the general error logfile.
         */
#ifdef WIN32
        stderr_store = STDERR_FILENO_STORE;
#else
        if ((stderr_store = open("/dev/null", O_WRONLY)) == -1)
            stderr_store = STDERR_FILENO_STORE;
#endif
        dup2(STDERR_FILENO, stderr_store);
#ifdef WIN32
        if ((con = fopen("con", "w")) != NULL)
            dup2(fileno(con), STDERR_FILENO);
        else
            dup2(STDOUT_FILENO, STDERR_FILENO);
#else
        dup2(STDOUT_FILENO, STDERR_FILENO);
#endif

        /*
         * The first time display a header to inform the user about what
         * program he actually speaks to, which module is responsible for
         * this terminal dialog and why to the hell he has to enter
         * something...
         */
        if (*pnPassPhraseDialog == 1) {
            fprintf(stderr, "%s mod_ssl/%s (Pass Phrase Dialog)\n",
                    SERVER_BASEVERSION, MOD_SSL_VERSION);
            fprintf(stderr, "Some of your private key files are encrypted for security reasons.\n");
            fprintf(stderr, "In order to read them you have to provide us with the pass phrases.\n");
        }
        if (*pbPassPhraseDialogOnce) {
            *pbPassPhraseDialogOnce = FALSE;
            fprintf(stderr, "\n");
            fprintf(stderr, "Server %s (%s)\n", cpVHostID, cpAlgoType);
        }

        /*
         * Emulate the OpenSSL internal pass phrase dialog
         * (see crypto/pem/pem_lib.c:def_callback() for details)
         */
        prompt = "Enter pass phrase:";
        for (;;) {
            if ((i = EVP_read_pw_string(buf, bufsize, prompt, FALSE)) != 0) {
                PEMerr(PEM_F_DEF_CALLBACK,PEM_R_PROBLEMS_GETTING_PASSWORD);
                memset(buf, 0, (unsigned int)bufsize);
                return (-1);
            }
            len = strlen(buf);
            if (len < 1)
                fprintf(stderr, "Apache:mod_ssl:Error: Pass phrase empty (needs to be at least 1 character).\n");
            else
                break;
        }

        /*
         * Restore STDERR to Apache error logfile
         */
        dup2(stderr_store, STDERR_FILENO);
        close(stderr_store);
#ifdef WIN32
        if (con != NULL)
            fclose(con);
#endif
    }

    /*
     * Filter program
     */
    else if (sc->nPassPhraseDialogType == SSL_PPTYPE_FILTER) {
        char *cmd;
        char *result;

        ssl_log(s, SSL_LOG_INFO,
                "Init: Requesting pass phrase from dialog filter program (%s)",
                sc->szPassPhraseDialogPath);

        if (strchr(sc->szPassPhraseDialogPath, ' ') != NULL)
            cmd = ap_psprintf(p, "\"%s\" %s %s", sc->szPassPhraseDialogPath, cpVHostID, cpAlgoType);
        else
            cmd = ap_psprintf(p, "%s %s %s", sc->szPassPhraseDialogPath, cpVHostID, cpAlgoType);
        result = ssl_util_readfilter(s, p, cmd);
        ap_cpystrn(buf, result, bufsize);
        len = strlen(buf);
    }

    /*
     * Ok, we now have the pass phrase, so give it back
     */
    *cppPassPhraseCur = ap_pstrdup(p, buf);

    /*
     * And return it's length to OpenSSL...
     */
    return (len);
}

