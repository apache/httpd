/*                      _             _
**  _ __ ___   ___   __| |    ___ ___| |  mod_ssl
** | '_ ` _ \ / _ \ / _` |   / __/ __| |  Apache Interface to OpenSSL
** | | | | | | (_) | (_| |   \__ \__ \ |  www.modssl.org
** |_| |_| |_|\___/ \__,_|___|___/___/_|  ftp.modssl.org
**                      |_____|
**  mod_ssl.c
**  Apache API interface structures
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
                             /* ``I'll be surprised if
                                  others think that what you
                                  are doing is honourable.''
                                    -- Ben Laurie, Apache-SSL author */
#include "mod_ssl.h"

/*  _________________________________________________________________
**
**  Apache API glue structures
**  _________________________________________________________________
*/

/*
 *  identify the module to SCCS `what' and RCS `ident' commands
 */
static char const sccsid[] = "@(#) mod_ssl/" MOD_SSL_VERSION " >";
static char const rcsid[]  = "$Id: mod_ssl.c,v 1.1 2001/05/04 21:54:42 rse Exp $";

/*
 *  the table of configuration directives we provide
 */
static command_rec ssl_config_cmds[] = {
    /*
     * Global (main-server) context configuration directives
     */
    AP_SRV_CMD(Mutex, TAKE1,
               "SSL lock for handling internal mutual exclusions "
               "(`none', `file:/path/to/file')")
    AP_SRV_CMD(PassPhraseDialog, TAKE1,
               "SSL dialog mechanism for the pass phrase query "
               "(`builtin', `exec:/path/to/program')")
    AP_SRV_CMD(SessionCache, TAKE1,
               "SSL Session Cache storage "
               "(`none', `dbm:/path/to/file')")
#ifdef SSL_EXPERIMENTAL_ENGINE
    AP_SRV_CMD(CryptoDevice, TAKE1,
               "SSL external Crypto Device usage "
               "(`builtin', `...')")
#endif
    AP_SRV_CMD(RandomSeed, TAKE23,
               "SSL Pseudo Random Number Generator (PRNG) seeding source "
               "(`startup|connect builtin|file:/path|exec:/path [bytes]')")

    /*
     * Per-server context configuration directives
     */
    AP_SRV_CMD(Engine, FLAG,
               "SSL switch for the protocol engine "
               "(`on', `off')")
    AP_ALL_CMD(CipherSuite, TAKE1,
               "Colon-delimited list of permitted SSL Ciphers "
               "(`XXX:...:XXX' - see manual)")
    AP_SRV_CMD(CertificateFile, TAKE1,
               "SSL Server Certificate file "
               "(`/path/to/file' - PEM or DER encoded)")
    AP_SRV_CMD(CertificateKeyFile, TAKE1,
               "SSL Server Private Key file "
               "(`/path/to/file' - PEM or DER encoded)")
    AP_SRV_CMD(CertificateChainFile, TAKE1,
               "SSL Server CA Certificate Chain file "
               "(`/path/to/file' - PEM encoded)")
#ifdef SSL_EXPERIMENTAL_PERDIRCA
    AP_ALL_CMD(CACertificatePath, TAKE1,
               "SSL CA Certificate path "
               "(`/path/to/dir' - contains PEM encoded files)")
    AP_ALL_CMD(CACertificateFile, TAKE1,
               "SSL CA Certificate file "
               "(`/path/to/file' - PEM encoded)")
#else
    AP_SRV_CMD(CACertificatePath, TAKE1,
               "SSL CA Certificate path "
               "(`/path/to/dir' - contains PEM encoded files)")
    AP_SRV_CMD(CACertificateFile, TAKE1,
               "SSL CA Certificate file "
               "(`/path/to/file' - PEM encoded)")
#endif
    AP_SRV_CMD(CARevocationPath, TAKE1,
               "SSL CA Certificate Revocation List (CRL) path "
               "(`/path/to/dir' - contains PEM encoded files)")
    AP_SRV_CMD(CARevocationFile, TAKE1,
               "SSL CA Certificate Revocation List (CRL) file "
               "(`/path/to/file' - PEM encoded)")
    AP_ALL_CMD(VerifyClient, TAKE1,
               "SSL Client verify type "
               "(`none', `optional', `require', `optional_no_ca')")
    AP_ALL_CMD(VerifyDepth, TAKE1,
               "SSL Client verify depth "
               "(`N' - number of intermediate certificates)")
    AP_SRV_CMD(SessionCacheTimeout, TAKE1,
               "SSL Session Cache object lifetime "
               "(`N' - number of seconds)")
    AP_SRV_CMD(Log, TAKE1,
               "SSL logfile for SSL-related messages "
               "(`/path/to/file', `|/path/to/program')")
    AP_SRV_CMD(LogLevel, TAKE1,
               "SSL logfile verbosity level "
               "(`none', `error', `warn', `info', `debug')")
    AP_SRV_CMD(Protocol, RAW_ARGS,
               "Enable or disable various SSL protocols"
               "(`[+-][SSLv2|SSLv3|TLSv1] ...' - see manual)")

#ifdef SSL_EXPERIMENTAL_PROXY
    /* 
     * Proxy configuration for remote SSL connections
     */
    AP_SRV_CMD(ProxyProtocol, RAW_ARGS,
               "SSL Proxy: enable or disable SSL protocol flavors "
               "(`[+-][SSLv2|SSLv3|TLSv1] ...' - see manual)")
    AP_SRV_CMD(ProxyCipherSuite, TAKE1,
               "SSL Proxy: colon-delimited list of permitted SSL ciphers "
               "(`XXX:...:XXX' - see manual)")
    AP_SRV_CMD(ProxyVerify, FLAG,
               "SSL Proxy: whether to verify the remote certificate "
               "(`on' or `off')")
    AP_SRV_CMD(ProxyVerifyDepth, TAKE1,
               "SSL Proxy: maximum certificate verification depth "
               "(`N' - number of intermediate certificates)")
    AP_SRV_CMD(ProxyCACertificateFile, TAKE1,
               "SSL Proxy: file containing server certificates "
               "(`/path/to/file' - PEM encoded certificates)")
    AP_SRV_CMD(ProxyCACertificatePath, TAKE1,
               "SSL Proxy: directory containing server certificates "
               "(`/path/to/dir' - contains PEM encoded certificates)")
    AP_SRV_CMD(ProxyMachineCertificateFile, TAKE1,
               "SSL Proxy: file containing client certificates "
               "(`/path/to/file' - PEM encoded certificates)")
    AP_SRV_CMD(ProxyMachineCertificatePath, TAKE1,
               "SSL Proxy: directory containing client certificates "
               "(`/path/to/dir' - contains PEM encoded certificates)")
#endif

    /*
     * Per-directory context configuration directives
     */
    AP_DIR_CMD(Options, OPTIONS, RAW_ARGS,
               "Set one of more options to configure the SSL engine"
               "(`[+-]option[=value] ...' - see manual)")
    AP_DIR_CMD(RequireSSL, AUTHCFG, NO_ARGS,
               "Require the SSL protocol for the per-directory context "
               "(no arguments)")
    AP_DIR_CMD(Require, AUTHCFG, RAW_ARGS,
               "Require a boolean expresion to evaluate to true for granting access"
               "(arbitrary complex boolean expression - see manual)")

    AP_END_CMD
};

static const handler_rec ssl_config_handler[] = {
    { "mod_ssl:content-handler", ssl_hook_Handler },
    { NULL, NULL }
};

/*
 *  the main Apache API config structure
 */
module MODULE_VAR_EXPORT ssl_module = {
    STANDARD_MODULE_STUFF,

    /* Standard API (always present) */

    ssl_init_Module,          /* module initializer                  */
    ssl_config_perdir_create, /* create per-dir    config structures */
    ssl_config_perdir_merge,  /* merge  per-dir    config structures */
    ssl_config_server_create, /* create per-server config structures */
    ssl_config_server_merge,  /* merge  per-server config structures */
    ssl_config_cmds,          /* table of config file commands       */
    ssl_config_handler,       /* [#8] MIME-typed-dispatched handlers */
    ssl_hook_Translate,       /* [#1] URI to filename translation    */
    ssl_hook_Auth,            /* [#4] validate user id from request  */
    ssl_hook_UserCheck,       /* [#5] check if the user is ok _here_ */
    ssl_hook_Access,          /* [#3] check access by host address   */
    NULL,                     /* [#6] determine MIME type            */
    ssl_hook_Fixup,           /* [#7] pre-run fixups                 */
    NULL,                     /* [#9] log a transaction              */
    NULL,                     /* [#2] header parser                  */
    ssl_init_Child,           /* child_init                          */
    NULL,                     /* child_exit                          */
    ssl_hook_ReadReq,         /* [#0] post read-request              */

    /* Extended API (forced to be enabled with mod_ssl) */

    ssl_hook_AddModule,       /* after modules was added to core     */
    ssl_hook_RemoveModule,    /* before module is removed from core  */
    ssl_hook_RewriteCommand,  /* configuration command rewriting     */
    ssl_hook_NewConnection,   /* socket connection open              */
    ssl_hook_CloseConnection  /* socket connection close             */
};

