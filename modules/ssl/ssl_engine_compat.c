/*                      _             _
**  _ __ ___   ___   __| |    ___ ___| |  mod_ssl
** | '_ ` _ \ / _ \ / _` |   / __/ __| |  Apache Interface to OpenSSL
** | | | | | | (_) | (_| |   \__ \__ \ |  www.modssl.org
** |_| |_| |_|\___/ \__,_|___|___/___/_|  ftp.modssl.org
**                      |_____|
**  ssl_engine_compat.c
**  Backward Compatibility
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

                             /* ``Backward compatibility is for
                                  users who don't want to live
                                  on the bleeding edge.''
                                            -- Unknown          */
#ifdef SSL_COMPAT

#include "mod_ssl.h"


/*  _________________________________________________________________
**
**  Backward Compatibility
**  _________________________________________________________________
*/

/*
 * The mapping of obsolete directives to official ones...
 */

static char *ssl_compat_RequireSSL(pool *, const char *, const char *, const char *);
static char *ssl_compat_SSLSessionLockFile(pool *, const char *, const char *, const char *);
static char *ssl_compat_SSLCacheDisable(pool *, const char *, const char *, const char *);
static char *ssl_compat_SSLRequireCipher(pool *, const char *, const char *, const char *);
static char *ssl_compat_SSLBanCipher(pool *, const char *, const char *, const char *);
static char *ssl_compat_SSL_SessionDir(pool *, const char *, const char *, const char *);
static char *ssl_compat_words2list(pool *, const char *);

#define CRM_BEGIN              /* nop */
#define CRM_ENTRY(what,action) { what, action },
#define CRM_END                { NULL, NULL, NULL, NULL, NULL, NULL }
#define CRM_CMD(cmd)           cmd, NULL, NULL
#define CRM_STR(str)           NULL, str, NULL
#define CRM_PAT(cmd)           NULL, NULL, pat
#define CRM_LOG(msg)           msg, NULL, NULL
#define CRM_SUB(new)           NULL, new, NULL
#define CRM_CAL(fct)           NULL, NULL, fct

static struct {
    char *cpCommand;
    char *cpSubstring;
    char *cpPattern;
    char *cpMessage;
    char *cpSubst;
    char *(*fpSubst)(pool *, const char *, const char *, const char *);
} ssl_cmd_rewrite_map[] = {
    CRM_BEGIN

    /*
     * Apache-SSL 1.x & mod_ssl 2.0.x backward compatibility
     */
    CRM_ENTRY( CRM_CMD("SSLEnable"),                   CRM_SUB("SSLEngine on")                )
    CRM_ENTRY( CRM_CMD("SSLDisable"),                  CRM_SUB("SSLEngine off")               )
    CRM_ENTRY( CRM_CMD("SSLLogFile"),                  CRM_SUB("SSLLog")                      )
    CRM_ENTRY( CRM_CMD("SSLRequiredCiphers"),          CRM_SUB("SSLCipherSuite")              )
    CRM_ENTRY( CRM_CMD("SSLRequireCipher"),            CRM_CAL(ssl_compat_SSLRequireCipher)   )
    CRM_ENTRY( CRM_CMD("SSLBanCipher"),                CRM_CAL(ssl_compat_SSLBanCipher)       )
    CRM_ENTRY( CRM_CMD("SSLFakeBasicAuth"),            CRM_SUB("SSLOptions +FakeBasicAuth")   )
    CRM_ENTRY( CRM_CMD("SSLCacheServerPath"),          CRM_LOG("Use SSLSessionCache instead") )
    CRM_ENTRY( CRM_CMD("SSLCacheServerPort"),          CRM_LOG("Use SSLSessionCache instead") )

    /*
     * Apache-SSL 1.x backward compatibility
     */
    CRM_ENTRY( CRM_CMD("SSLExportClientCertificates"), CRM_SUB("SSLOptions +ExportCertData")  )
    CRM_ENTRY( CRM_CMD("SSLCacheServerRunDir"),        CRM_LOG("Not needed for mod_ssl")      )

    /*
     * Sioux 1.x backward compatibility
     */
    CRM_ENTRY( CRM_CMD("SSL_CertFile"),            CRM_SUB("SSLCertificateFile")              )
    CRM_ENTRY( CRM_CMD("SSL_KeyFile"),             CRM_SUB("SSLCertificateKeyFile")           )
    CRM_ENTRY( CRM_CMD("SSL_CipherSuite"),         CRM_SUB("SSLCipherSuite")                  )
    CRM_ENTRY( CRM_CMD("SSL_X509VerifyDir"),       CRM_SUB("SSLCACertificatePath")            )
    CRM_ENTRY( CRM_CMD("SSL_Log"),                 CRM_SUB("SSLLogFile")                      )
    CRM_ENTRY( CRM_CMD("SSL_Connect"),             CRM_SUB("SSLEngine")                       )
    CRM_ENTRY( CRM_CMD("SSL_ClientAuth"),          CRM_SUB("SSLVerifyClient")                 )
    CRM_ENTRY( CRM_CMD("SSL_X509VerifyDepth"),     CRM_SUB("SSLVerifyDepth")                  )
    CRM_ENTRY( CRM_CMD("SSL_FetchKeyPhraseFrom"),  CRM_LOG("Use SSLPassPhraseDialog instead") )
    CRM_ENTRY( CRM_CMD("SSL_SessionDir"),          CRM_CAL(ssl_compat_SSL_SessionDir)         )
    CRM_ENTRY( CRM_CMD("SSL_Require"),             CRM_LOG("Use SSLRequire instead (Syntax!)"))
    CRM_ENTRY( CRM_CMD("SSL_CertFileType"),        CRM_LOG("Not supported by mod_ssl")        )
    CRM_ENTRY( CRM_CMD("SSL_KeyFileType"),         CRM_LOG("Not supported by mod_ssl")        )
    CRM_ENTRY( CRM_CMD("SSL_X509VerifyPolicy"),    CRM_LOG("Not supported by mod_ssl")        )
    CRM_ENTRY( CRM_CMD("SSL_LogX509Attributes"),   CRM_LOG("Not supported by mod_ssl")        )

    /*
     * Stronghold 2.x backward compatibility
     */
    CRM_ENTRY( CRM_CMD("StrongholdAccelerator"),     CRM_LOG("Not supported by mod_ssl")      )
    CRM_ENTRY( CRM_CMD("StrongholdKey"),             CRM_LOG("Not supported by mod_ssl")      )
    CRM_ENTRY( CRM_CMD("StrongholdLicenseFile"),     CRM_LOG("Not supported by mod_ssl")      )
    CRM_ENTRY( CRM_CMD("SSLFlag"),                   CRM_SUB("SSLEngine")                     )
    CRM_ENTRY( CRM_CMD("SSLClientCAfile"),           CRM_SUB("SSLCACertificateFile")          )
    CRM_ENTRY( CRM_CMD("SSLSessionLockFile"),        CRM_CAL(ssl_compat_SSLSessionLockFile)   )
    CRM_ENTRY( CRM_CMD("SSLCacheDisable"),           CRM_CAL(ssl_compat_SSLCacheDisable)      )
    CRM_ENTRY( CRM_CMD("RequireSSL"),                CRM_CAL(ssl_compat_RequireSSL)           )
    CRM_ENTRY( CRM_CMD("SSLCipherList"),             CRM_SUB("SSLCipherSuite")                )
    CRM_ENTRY( CRM_CMD("SSLErrorFile"),              CRM_LOG("Not needed for mod_ssl")        )
    CRM_ENTRY( CRM_CMD("SSLRoot"),                   CRM_LOG("Not supported by mod_ssl")      )
    CRM_ENTRY( CRM_CMD("SSL_CertificateLogDir"),     CRM_LOG("Not supported by mod_ssl")      )
    CRM_ENTRY( CRM_CMD("AuthCertDir"),               CRM_LOG("Not supported by mod_ssl")      )
    CRM_ENTRY( CRM_CMD("SSL_Group"),                 CRM_LOG("Not supported by mod_ssl")      )
#ifndef SSL_EXPERIMENTAL_PROXY
    CRM_ENTRY( CRM_CMD("SSLProxyMachineCertPath"),   CRM_LOG("Not supported by mod_ssl")      )
    CRM_ENTRY( CRM_CMD("SSLProxyMachineCertFile"),   CRM_LOG("Not supported by mod_ssl")      )
    CRM_ENTRY( CRM_CMD("SSLProxyCACertificatePath"), CRM_LOG("Not supported by mod_ssl")      )
    CRM_ENTRY( CRM_CMD("SSLProxyCACertificateFile"), CRM_LOG("Not supported by mod_ssl")      )
    CRM_ENTRY( CRM_CMD("SSLProxyVerifyDepth"),       CRM_LOG("Not supported by mod_ssl")      )
    CRM_ENTRY( CRM_CMD("SSLProxyCipherList"),        CRM_LOG("Not supported by mod_ssl")      )
#else
    CRM_ENTRY( CRM_CMD("SSLProxyCipherList"),        CRM_SUB("SSLProxyCipherSuite")           )
#endif

    CRM_END
};

static char *ssl_compat_RequireSSL(
    pool *p, const char *oline, const char *cmd, const char *args)
{
    char *cp;
    
    for (cp = (char *)args; ap_isspace(*cp); cp++)
        ;
    if (strcEQ(cp, "on"))
        return "SSLRequireSSL";
    return "";
}

static char *ssl_compat_SSLSessionLockFile(
    pool *p, const char *oline, const char *cmd, const char *args)
{
    char *cp;

    for (cp = (char *)args; ap_isspace(*cp); cp++)
        ;
    return ap_pstrcat(p, "SSLMutex file:", cp, NULL);
}

static char *ssl_compat_SSLCacheDisable(
    pool *p, const char *oline, const char *cmd, const char *args)
{
    char *cp;

    for (cp = (char *)args; ap_isspace(*cp); cp++)
        ;
    if (strcEQ(cp, "on"))
        return "SSLSessionCache none";
    return "";
}

static char *ssl_compat_SSLRequireCipher(pool *p, const char *oline, const char *cmd, const char *args)
{
    return ap_pstrcat(p, "SSLRequire %{SSL_CIPHER} in {",
                          ssl_compat_words2list(p, args),
                          "}", NULL);
}

static char *ssl_compat_SSLBanCipher(pool *p, const char *oline, const char *cmd, const char *args)
{
    return ap_pstrcat(p, "SSLRequire not (%{SSL_CIPHER} in {",
                          ssl_compat_words2list(p, args),
                          "})", NULL);
}

static char *ssl_compat_SSL_SessionDir(
    pool *p, const char *oline, const char *cmd, const char *args)
{
    char *cp;
   
    for (cp = (char *)args; ap_isspace(*cp); cp++)
        ;
    return ap_pstrcat(p, "SSLSessionCache dir:", cp, NULL);
}

static char *ssl_compat_words2list(pool *p, const char *oline)
{
    char *line;
    char *cpB;
    char *cpE;
    char *cpI;
    char *cpO;
    char n;

    /*
     * Step 1: Determine borders
     */
    cpB = (char *)oline;
    while (*cpB == ' ' || *cpB == '\t')
       cpB++;
    cpE = cpB+strlen(cpB);
    while (cpE > cpB && (*(cpE-1) == ' ' || *(cpE-1) == '\t'))
        cpE--;

    /*
     * Step 2: Determine final size and allocate buffer
     */
    for (cpI = cpB, n = 1; cpI < cpE; cpI++)
        if ((*cpI == ' ' || *cpI == '\t') &&
            (cpI > cpB && *(cpI-1) != ' ' && *(cpI-1) != '\t'))
            n++;
    line = ap_palloc(p, (cpE-cpB)+(n*2)+n+1);
    cpI = cpB;
    cpO = line;
    while (cpI < cpE) {
        if (   (*cpI != ' ' && *cpI != '\t')
            && (   cpI == cpB
                || (   cpI > cpB
                    && (*(cpI-1) == ' ' || *(cpI-1) == '\t')))) {
            *cpO++ = '"';
            *cpO++ = *cpI++;
        }
        else if (   (*cpI == ' ' || *cpI == '\t')
                 && (   cpI > cpB
                     && (*(cpI-1) != ' ' && *(cpI-1) != '\t'))) {
            *cpO++ = '"';
            *cpO++ = ',';
            *cpO++ = *cpI++;
        }
        else {
            *cpO++ = *cpI++;
        }
    }
    if (cpI > cpB && (*(cpI-1) != ' ' && *(cpI-1) != '\t'))
        *cpO++ = '"';
    *cpO++ = NUL;
    return line;
}

char *ssl_compat_directive(server_rec *s, pool *p, const char *oline)
{
    int i;
    char *line;
    char *cp;
    char caCmd[1024];
    char *cpArgs;
    int match;

    /*
     * Skip comment lines
     */
    cp = (char *)oline;
    while ((*cp == ' ' || *cp == '\t' || *cp == '\n') && (*cp != NUL))
        cp++;
    if (*cp == '#' || *cp == NUL)
        return NULL;

    /*
     * Extract directive name
     */
    cp = (char *)oline;
    for (i = 0; *cp != ' ' && *cp != '\t' && *cp != NUL && i < 1024; )
        caCmd[i++] = *cp++;
    caCmd[i] = NUL;
    cpArgs = cp;

    /*
     * Apply rewriting map
     */
    line = NULL;
    for (i = 0; !(ssl_cmd_rewrite_map[i].cpCommand == NULL &&
                  ssl_cmd_rewrite_map[i].cpPattern == NULL   ); i++) {
        /*
         * Matching
         */
        match = FALSE;
        if (ssl_cmd_rewrite_map[i].cpCommand != NULL) {
            if (strcEQ(ssl_cmd_rewrite_map[i].cpCommand, caCmd))
                match = TRUE;
        }
        else if (ssl_cmd_rewrite_map[i].cpSubstring != NULL) {
            if (strstr(oline, ssl_cmd_rewrite_map[i].cpSubstring) != NULL)
                match = TRUE;
        }
        else if (ssl_cmd_rewrite_map[i].cpPattern != NULL) {
            if (ap_fnmatch(ssl_cmd_rewrite_map[i].cpPattern, oline, 0))
                match = TRUE;
        }

        /*
         * Action Processing
         */
        if (match) {
            if (ssl_cmd_rewrite_map[i].cpMessage != NULL) {
                ap_log_error(APLOG_MARK, APLOG_WARNING|APLOG_NOERRNO, s,
                             "mod_ssl:Compat: OBSOLETE '%s' => %s",
                             oline, ssl_cmd_rewrite_map[i].cpMessage);
                line = "";
                break;
            }
            else if (ssl_cmd_rewrite_map[i].cpSubst != NULL) {
                if (ssl_cmd_rewrite_map[i].cpCommand != NULL)
                    line = ap_pstrcat(p, ssl_cmd_rewrite_map[i].cpSubst,
                                      cpArgs, NULL);
                else if (ssl_cmd_rewrite_map[i].cpSubstring != NULL)
                    line = ssl_util_ptxtsub(p, oline, ssl_cmd_rewrite_map[i].cpSubstring,
                                            ssl_cmd_rewrite_map[i].cpSubst);
                else
                    line = ssl_cmd_rewrite_map[i].cpSubst;
                break;
            }
            else if (ssl_cmd_rewrite_map[i].fpSubst != NULL) {
                line = ((char *(*)(pool *, const char *, const char *, const char *))
                        (ssl_cmd_rewrite_map[i].fpSubst))(p, oline, caCmd, cpArgs);
                break;
            }
        }
    }
    if (line != NULL && line[0] != NUL)
        ap_log_error(APLOG_MARK, APLOG_INFO|APLOG_NOERRNO, s,
                     "mod_ssl:Compat: MAPPED '%s' => '%s'", oline, line);
    return line;
}

/*
 * The mapping of obsolete environment variables to official ones...
 */

#define VRM_BEGIN              /* nop */
#define VRM_ENTRY(var,action)  { var, action },
#define VRM_END                { NULL, NULL, NULL }
#define VRM_VAR(old)           old
#define VRM_SUB(new)           new, NULL
#define VRM_LOG(msg)           NULL, msg

static struct {
    char *cpOld;
    char *cpNew;
    char *cpMsg;
} ssl_var_rewrite_map[] = {
    VRM_BEGIN

    /*
     * Apache-SSL 1.x, mod_ssl 2.0.x, Sioux 1.x
     * and Stronghold 2.x backward compatibility
     */
    VRM_ENTRY( VRM_VAR("SSL_PROTOCOL_VERSION"),          VRM_SUB("SSL_PROTOCOL")             )
    VRM_ENTRY( VRM_VAR("SSLEAY_VERSION"),                VRM_SUB("SSL_VERSION_LIBRARY")      )
    VRM_ENTRY( VRM_VAR("HTTPS_SECRETKEYSIZE"),           VRM_SUB("SSL_CIPHER_USEKEYSIZE")    )
    VRM_ENTRY( VRM_VAR("HTTPS_KEYSIZE"),                 VRM_SUB("SSL_CIPHER_ALGKEYSIZE")    )
    VRM_ENTRY( VRM_VAR("HTTPS_CIPHER"),                  VRM_SUB("SSL_CIPHER")               )
    VRM_ENTRY( VRM_VAR("HTTPS_EXPORT"),                  VRM_SUB("SSL_CIPHER_EXPORT")        )
    VRM_ENTRY( VRM_VAR("SSL_SERVER_KEY_SIZE"),           VRM_SUB("SSL_CIPHER_ALGKEYSIZE")    )
    VRM_ENTRY( VRM_VAR("SSL_SERVER_CERTIFICATE"),        VRM_SUB("SSL_SERVER_CERT")          )
    VRM_ENTRY( VRM_VAR("SSL_SERVER_CERT_START"),         VRM_SUB("SSL_SERVER_V_START")       )
    VRM_ENTRY( VRM_VAR("SSL_SERVER_CERT_END"),           VRM_SUB("SSL_SERVER_V_END")         )
    VRM_ENTRY( VRM_VAR("SSL_SERVER_CERT_SERIAL"),        VRM_SUB("SSL_SERVER_M_SERIAL")      )
    VRM_ENTRY( VRM_VAR("SSL_SERVER_SIGNATURE_ALGORITHM"),VRM_SUB("SSL_SERVER_A_SIG")         )
    VRM_ENTRY( VRM_VAR("SSL_SERVER_DN"),                 VRM_SUB("SSL_SERVER_S_DN")          )
    VRM_ENTRY( VRM_VAR("SSL_SERVER_CN"),                 VRM_SUB("SSL_SERVER_S_DN_CN")       )
    VRM_ENTRY( VRM_VAR("SSL_SERVER_EMAIL"),              VRM_SUB("SSL_SERVER_S_DN_Email")    )
    VRM_ENTRY( VRM_VAR("SSL_SERVER_O"),                  VRM_SUB("SSL_SERVER_S_DN_O")        )
    VRM_ENTRY( VRM_VAR("SSL_SERVER_OU"),                 VRM_SUB("SSL_SERVER_S_DN_OU")       )
    VRM_ENTRY( VRM_VAR("SSL_SERVER_C"),                  VRM_SUB("SSL_SERVER_S_DN_C")        )
    VRM_ENTRY( VRM_VAR("SSL_SERVER_SP"),                 VRM_SUB("SSL_SERVER_S_DN_SP")       )
    VRM_ENTRY( VRM_VAR("SSL_SERVER_L"),                  VRM_SUB("SSL_SERVER_S_DN_L")        )
    VRM_ENTRY( VRM_VAR("SSL_SERVER_IDN"),                VRM_SUB("SSL_SERVER_I_DN")          )
    VRM_ENTRY( VRM_VAR("SSL_SERVER_ICN"),                VRM_SUB("SSL_SERVER_I_DN_CN")       )
    VRM_ENTRY( VRM_VAR("SSL_SERVER_IEMAIL"),             VRM_SUB("SSL_SERVER_I_DN_Email")    )
    VRM_ENTRY( VRM_VAR("SSL_SERVER_IO"),                 VRM_SUB("SSL_SERVER_I_DN_O")        )
    VRM_ENTRY( VRM_VAR("SSL_SERVER_IOU"),                VRM_SUB("SSL_SERVER_I_DN_OU")       )
    VRM_ENTRY( VRM_VAR("SSL_SERVER_IC"),                 VRM_SUB("SSL_SERVER_I_DN_C")        )
    VRM_ENTRY( VRM_VAR("SSL_SERVER_ISP"),                VRM_SUB("SSL_SERVER_I_DN_SP")       )
    VRM_ENTRY( VRM_VAR("SSL_SERVER_IL"),                 VRM_SUB("SSL_SERVER_I_DN_L")        )
    VRM_ENTRY( VRM_VAR("SSL_CLIENT_CERTIFICATE"),        VRM_SUB("SSL_CLIENT_CERT")          )
    VRM_ENTRY( VRM_VAR("SSL_CLIENT_CERT_START"),         VRM_SUB("SSL_CLIENT_V_START")       )
    VRM_ENTRY( VRM_VAR("SSL_CLIENT_CERT_END"),           VRM_SUB("SSL_CLIENT_V_END")         )
    VRM_ENTRY( VRM_VAR("SSL_CLIENT_CERT_SERIAL"),        VRM_SUB("SSL_CLIENT_M_SERIAL")      )
    VRM_ENTRY( VRM_VAR("SSL_CLIENT_SIGNATURE_ALGORITHM"),VRM_SUB("SSL_CLIENT_A_SIG")         )
    VRM_ENTRY( VRM_VAR("SSL_CLIENT_DN"),                 VRM_SUB("SSL_CLIENT_S_DN")          )
    VRM_ENTRY( VRM_VAR("SSL_CLIENT_CN"),                 VRM_SUB("SSL_CLIENT_S_DN_CN")       )
    VRM_ENTRY( VRM_VAR("SSL_CLIENT_EMAIL"),              VRM_SUB("SSL_CLIENT_S_DN_Email")    )
    VRM_ENTRY( VRM_VAR("SSL_CLIENT_O"),                  VRM_SUB("SSL_CLIENT_S_DN_O")        )
    VRM_ENTRY( VRM_VAR("SSL_CLIENT_OU"),                 VRM_SUB("SSL_CLIENT_S_DN_OU")       )
    VRM_ENTRY( VRM_VAR("SSL_CLIENT_C"),                  VRM_SUB("SSL_CLIENT_S_DN_C")        )
    VRM_ENTRY( VRM_VAR("SSL_CLIENT_SP"),                 VRM_SUB("SSL_CLIENT_S_DN_SP")       )
    VRM_ENTRY( VRM_VAR("SSL_CLIENT_L"),                  VRM_SUB("SSL_CLIENT_S_DN_L")        )
    VRM_ENTRY( VRM_VAR("SSL_CLIENT_IDN"),                VRM_SUB("SSL_CLIENT_I_DN")          )
    VRM_ENTRY( VRM_VAR("SSL_CLIENT_ICN"),                VRM_SUB("SSL_CLIENT_I_DN_CN")       )
    VRM_ENTRY( VRM_VAR("SSL_CLIENT_IEMAIL"),             VRM_SUB("SSL_CLIENT_I_DN_Email")    )
    VRM_ENTRY( VRM_VAR("SSL_CLIENT_IO"),                 VRM_SUB("SSL_CLIENT_I_DN_O")        )
    VRM_ENTRY( VRM_VAR("SSL_CLIENT_IOU"),                VRM_SUB("SSL_CLIENT_I_DN_OU")       )
    VRM_ENTRY( VRM_VAR("SSL_CLIENT_IC"),                 VRM_SUB("SSL_CLIENT_I_DN_C")        )
    VRM_ENTRY( VRM_VAR("SSL_CLIENT_ISP"),                VRM_SUB("SSL_CLIENT_I_DN_SP")       )
    VRM_ENTRY( VRM_VAR("SSL_CLIENT_IL"),                 VRM_SUB("SSL_CLIENT_I_DN_L")        )
    VRM_ENTRY( VRM_VAR("SSL_EXPORT"),                    VRM_SUB("SSL_CIPHER_EXPORT")        )
    VRM_ENTRY( VRM_VAR("SSL_KEYSIZE"),                   VRM_SUB("SSL_CIPHER_ALGKEYSIZE")    )
    VRM_ENTRY( VRM_VAR("SSL_SECRETKEYSIZE"),             VRM_SUB("SSL_CIPHER_USEKEYSIZE")    )
    VRM_ENTRY( VRM_VAR("SSL_SSLEAY_VERSION"),            VRM_SUB("SSL_VERSION_LIBRARY")      )

    VRM_ENTRY( VRM_VAR("SSL_STRONG_CRYPTO"),             VRM_LOG("Not supported by mod_ssl") )
    VRM_ENTRY( VRM_VAR("SSL_SERVER_KEY_EXP"),            VRM_LOG("Not supported by mod_ssl") )
    VRM_ENTRY( VRM_VAR("SSL_SERVER_KEY_SIZE"),           VRM_LOG("Not supported by mod_ssl") )
    VRM_ENTRY( VRM_VAR("SSL_SERVER_KEY_ALGORITHM"),      VRM_LOG("Not supported by mod_ssl") )
    VRM_ENTRY( VRM_VAR("SSL_SERVER_SESSIONDIR"),         VRM_LOG("Not supported by mod_ssl") )
    VRM_ENTRY( VRM_VAR("SSL_SERVER_CERTIFICATELOGDIR"),  VRM_LOG("Not supported by mod_ssl") )
    VRM_ENTRY( VRM_VAR("SSL_SERVER_CERTFILE"),           VRM_LOG("Not supported by mod_ssl") )
    VRM_ENTRY( VRM_VAR("SSL_SERVER_KEYFILE"),            VRM_LOG("Not supported by mod_ssl") )
    VRM_ENTRY( VRM_VAR("SSL_SERVER_KEYFILETYPE"),        VRM_LOG("Not supported by mod_ssl") )
    VRM_ENTRY( VRM_VAR("SSL_CLIENT_KEY_EXP"),            VRM_LOG("Not supported by mod_ssl") )
    VRM_ENTRY( VRM_VAR("SSL_CLIENT_KEY_ALGORITHM"),      VRM_LOG("Not supported by mod_ssl") )
    VRM_ENTRY( VRM_VAR("SSL_CLIENT_KEY_SIZE"),           VRM_LOG("Not supported by mod_ssl") )

    VRM_END
};

void ssl_compat_variables(request_rec *r)
{
    char *cpOld;
    char *cpNew;
    char *cpMsg;
    char *cpVal;
    int i;

    for (i = 0; ssl_var_rewrite_map[i].cpOld != NULL; i++) {
        cpOld = ssl_var_rewrite_map[i].cpOld;
        cpMsg = ssl_var_rewrite_map[i].cpMsg;
        cpNew = ssl_var_rewrite_map[i].cpNew;
        if (cpNew != NULL) {
            cpVal = ssl_var_lookup(r->pool, r->server, r->connection, r, cpNew);
            if (!strIsEmpty(cpVal))
                ap_table_set(r->subprocess_env, cpOld, cpVal);
        }
        else if (cpMsg != NULL) {
#ifdef SSL_VENDOR
           /*
            * something that isn't provided by mod_ssl, so at least
            * let vendor extensions provide a reasonable value first.
            */
            cpVal = NULL;
            ap_hook_use("ap::mod_ssl::vendor::compat_variables_lookup",
                        AP_HOOK_SIG3(ptr,ptr,ptr),
                        AP_HOOK_DECLINE(NULL),
                        &cpVal, r, cpOld);
            if (cpVal != NULL) {
                ap_table_set(r->subprocess_env, cpOld, cpVal);
                continue;
            }
#endif

            /*
             * we cannot print a message, so we set at least
             * the variables content to the compat message
             */
            ap_table_set(r->subprocess_env, cpOld, cpMsg);
        }
    }
    return;
}

#endif /* SSL_COMPAT */
