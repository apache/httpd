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
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000-2001 The Apache Software Foundation.  All rights
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

#include "mod_ssl.h"

/*
 *  the table of configuration directives we provide
 */

#define SSL_CMD_ALL(name, args, desc) \
        AP_INIT_##args("SSL"#name, ssl_cmd_SSL##name, NULL, RSRC_CONF|OR_AUTHCFG, desc),
#define SSL_CMD_SRV(name, args, desc) \
        AP_INIT_##args("SSL"#name, ssl_cmd_SSL##name, NULL, RSRC_CONF, desc),
#define SSL_CMD_DIR(name, type, args, desc) \
        AP_INIT_##args("SSL"#name, ssl_cmd_SSL##name, NULL, OR_##type, desc),
#define AP_END_CMD { NULL }

static const command_rec ssl_config_cmds[] = {

    /*
     * Global (main-server) context configuration directives
     */
    SSL_CMD_SRV(Mutex, TAKE1,
                "SSL lock for handling internal mutual exclusions "
                "(`none', `file:/path/to/file')")
    SSL_CMD_SRV(PassPhraseDialog, TAKE1,
                "SSL dialog mechanism for the pass phrase query "
                "(`builtin', `exec:/path/to/program')")
    SSL_CMD_SRV(SessionCache, TAKE1,
                "SSL Session Cache storage "
                "(`none', `dbm:/path/to/file')")
#ifdef SSL_EXPERIMENTAL_ENGINE
    SSL_CMD_SRV(CryptoDevice, TAKE1,
                "SSL external Crypto Device usage "
                "(`builtin', `...')")
#endif
    SSL_CMD_SRV(RandomSeed, TAKE23,
                "SSL Pseudo Random Number Generator (PRNG) seeding source "
                "(`startup|connect builtin|file:/path|exec:/path [bytes]')")

    /*
     * Per-server context configuration directives
     */
    SSL_CMD_SRV(Engine, FLAG,
                "SSL switch for the protocol engine "
                "(`on', `off')")
    SSL_CMD_ALL(CipherSuite, TAKE1,
                "Colon-delimited list of permitted SSL Ciphers "
                "(`XXX:...:XXX' - see manual)")
    SSL_CMD_SRV(CertificateFile, TAKE1,
                "SSL Server Certificate file "
                "(`/path/to/file' - PEM or DER encoded)")
    SSL_CMD_SRV(CertificateKeyFile, TAKE1,
                "SSL Server Private Key file "
                "(`/path/to/file' - PEM or DER encoded)")
    SSL_CMD_SRV(CertificateChainFile, TAKE1,
                "SSL Server CA Certificate Chain file "
                "(`/path/to/file' - PEM encoded)")
#ifdef SSL_EXPERIMENTAL_PERDIRCA
    SSL_CMD_ALL(CACertificatePath, TAKE1,
                "SSL CA Certificate path "
                "(`/path/to/dir' - contains PEM encoded files)")
    SSL_CMD_ALL(CACertificateFile, TAKE1,
                "SSL CA Certificate file "
                "(`/path/to/file' - PEM encoded)")
#else
    SSL_CMD_SRV(CACertificatePath, TAKE1,
                "SSL CA Certificate path "
                "(`/path/to/dir' - contains PEM encoded files)")
    SSL_CMD_SRV(CACertificateFile, TAKE1,
                "SSL CA Certificate file "
                "(`/path/to/file' - PEM encoded)")
#endif
    SSL_CMD_SRV(CARevocationPath, TAKE1,
                "SSL CA Certificate Revocation List (CRL) path "
                "(`/path/to/dir' - contains PEM encoded files)")
    SSL_CMD_SRV(CARevocationFile, TAKE1,
                "SSL CA Certificate Revocation List (CRL) file "
                "(`/path/to/file' - PEM encoded)")
    SSL_CMD_ALL(VerifyClient, TAKE1,
                "SSL Client verify type "
                "(`none', `optional', `require', `optional_no_ca')")
    SSL_CMD_ALL(VerifyDepth, TAKE1,
                "SSL Client verify depth "
                "(`N' - number of intermediate certificates)")
    SSL_CMD_SRV(SessionCacheTimeout, TAKE1,
                "SSL Session Cache object lifetime "
                "(`N' - number of seconds)")
    SSL_CMD_SRV(Log, TAKE1,
                "SSL logfile for SSL-related messages "
                "(`/path/to/file', `|/path/to/program')")
    SSL_CMD_SRV(LogLevel, TAKE1,
                "SSL logfile verbosity level "
                "(`none', `error', `warn', `info', `debug')")
    SSL_CMD_SRV(Protocol, RAW_ARGS,
                "Enable or disable various SSL protocols"
                "(`[+-][SSLv2|SSLv3|TLSv1] ...' - see manual)")

#ifdef SSL_EXPERIMENTAL_PROXY
    /* 
     * Proxy configuration for remote SSL connections
     */
    SSL_CMD_SRV(ProxyProtocol, RAW_ARGS,
               "SSL Proxy: enable or disable SSL protocol flavors "
               "(`[+-][SSLv2|SSLv3|TLSv1] ...' - see manual)")
    SSL_CMD_SRV(ProxyCipherSuite, TAKE1,
               "SSL Proxy: colon-delimited list of permitted SSL ciphers "
               "(`XXX:...:XXX' - see manual)")
    SSL_CMD_SRV(ProxyVerify, FLAG,
               "SSL Proxy: whether to verify the remote certificate "
               "(`on' or `off')")
    SSL_CMD_SRV(ProxyVerifyDepth, TAKE1,
               "SSL Proxy: maximum certificate verification depth "
               "(`N' - number of intermediate certificates)")
    SSL_CMD_SRV(ProxyCACertificateFile, TAKE1,
               "SSL Proxy: file containing server certificates "
               "(`/path/to/file' - PEM encoded certificates)")
    SSL_CMD_SRV(ProxyCACertificatePath, TAKE1,
               "SSL Proxy: directory containing server certificates "
               "(`/path/to/dir' - contains PEM encoded certificates)")
    SSL_CMD_SRV(ProxyMachineCertificateFile, TAKE1,
               "SSL Proxy: file containing client certificates "
               "(`/path/to/file' - PEM encoded certificates)")
    SSL_CMD_SRV(ProxyMachineCertificatePath, TAKE1,
               "SSL Proxy: directory containing client certificates "
               "(`/path/to/dir' - contains PEM encoded certificates)")
#endif

    /*
     * Per-directory context configuration directives
     */
    SSL_CMD_DIR(Options, OPTIONS, RAW_ARGS,
               "Set one or more options to configure the SSL engine"
               "(`[+-]option[=value] ...' - see manual)")
    SSL_CMD_DIR(RequireSSL, AUTHCFG, NO_ARGS,
               "Require the SSL protocol for the per-directory context "
               "(no arguments)")
    SSL_CMD_DIR(Require, AUTHCFG, RAW_ARGS,
               "Require a boolean expression to evaluate to true for granting access"
               "(arbitrary complex boolean expression - see manual)")

    AP_END_CMD
};

/*
 *  the various processing hooks
 */

static void ssl_hook_pre_config(
    apr_pool_t *pconf, apr_pool_t *plog, apr_pool_t *ptemp)
{
    /* unused */
    return;
}


static void ssl_hook_post_config(
    apr_pool_t *pconf, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s)
{
    /* ssl_init_Module() */
    return;
}

static int ssl_hook_pre_connection(conn_rec *r)
{
    /* unused */
    return DECLINED;
}

static int ssl_hook_process_connection(conn_rec *r)
{
    /* call ssl_hook_NewConnection */
    /* hook ssl_hook_CloseConnection() */
    return DECLINED;
}

static int ssl_hook_handler(request_rec *r)
{
    /* ssl_hook_Handler() */
    return DECLINED;
}

static int ssl_hook_translate_name(request_rec *r)
{
    /* ssl_hook_Translate() */
    return DECLINED;
}

static void ssl_hook_init_child(apr_pool_t *pchild, server_rec *s)
{
    /* ssl_init_Child() */
    return;
}

static int ssl_hook_auth_checker(request_rec *r)
{
    /* ssl_hook_Auth() */
    return DECLINED;
}

static int ssl_hook_check_user_id(request_rec *r)
{
    /* ssl_hook_UserCheck */
    return DECLINED;
}

static int ssl_hook_access_checker(request_rec *r)
{
    /* ssl_hook_Access() */
    return DECLINED;
}

static int ssl_hook_fixups(request_rec *r)
{
    /* ssl_hook_Fixup() */
    return DECLINED;
}

static int ssl_hook_post_read_request(request_rec *r)
{
    /* ssl_hook_ReadReq() */
    return DECLINED;
}

static void ssl_hook_child_init(apr_pool_t *pchild, server_rec *s)
{
    /* ssl_init_Child() */
    return;
}

/*
 *  the module registration phase
 */
static void ssl_register_hooks(apr_pool_t *p)
{
    ap_hook_pre_config        (ssl_hook_pre_config,         NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_post_config       (ssl_hook_post_config,        NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_handler           (ssl_hook_handler,            NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_translate_name    (ssl_hook_translate_name,     NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_child_init        (ssl_hook_child_init,         NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_auth_checker      (ssl_hook_auth_checker,       NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_check_user_id     (ssl_hook_check_user_id,      NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_access_checker    (ssl_hook_access_checker,     NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_fixups            (ssl_hook_fixups,             NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_post_read_request (ssl_hook_post_read_request,  NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_pre_connection    (ssl_hook_pre_connection,     NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_process_connection(ssl_hook_process_connection, NULL, NULL, APR_HOOK_MIDDLE);

    ssl_var_register();
    ssl_ext_register();
    ssl_io_register();

    return;
}

/*
 *  the main module structure
 */
module AP_MODULE_DECLARE_DATA ssl_module = {
    STANDARD20_MODULE_STUFF,
    ssl_config_perdir_create,   /* create per-dir    config structures */
    ssl_config_perdir_merge,    /* merge  per-dir    config structures */
    ssl_config_server_create,   /* create per-server config structures */
    ssl_config_server_merge,    /* merge  per-server config structures */
    ssl_config_cmds,            /* table of configuration directives   */
    ssl_register_hooks          /* register hooks */
};

