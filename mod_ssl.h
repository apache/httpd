/*                      _             _
**  _ __ ___   ___   __| |    ___ ___| |  mod_ssl
** | '_ ` _ \ / _ \ / _` |   / __/ __| |  Apache Interface to OpenSSL
** | | | | | | (_) | (_| |   \__ \__ \ |  www.modssl.org
** |_| |_| |_|\___/ \__,_|___|___/___/_|  ftp.modssl.org
**                      |_____|
**  mod_ssl.h
**  Global header
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
                             /* ``The Apache Group: a collection
                                  of talented individuals who are
                                  trying to perfect the art of
                                  never finishing something.''
                                             -- Rob Hartill         */
#ifndef __MOD_SSL_H__
#define __MOD_SSL_H__

#define MOD_SSL_VERSION "3.0a0"

/* 
 * Optionally enable the experimental stuff, but allow the user to
 * override the decision which experimental parts are included by using
 * CFLAGS="-DSSL_EXPERIMENTAL_xxxx_IGNORE".
 */
#ifdef SSL_EXPERIMENTAL
#ifndef SSL_EXPERIMENTAL_PERDIRCA_IGNORE
#define SSL_EXPERIMENTAL_PERDIRCA
#endif
#ifndef SSL_EXPERIMENTAL_PROXY_IGNORE
#define SSL_EXPERIMENTAL_PROXY
#endif
#ifdef SSL_ENGINE
#ifndef SSL_EXPERIMENTAL_ENGINE_IGNORE
#define SSL_EXPERIMENTAL_ENGINE
#endif
#endif
#endif /* SSL_EXPERIMENTAL */

/*
 * Power up our brain...
 */

/* Apache headers */
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_main.h"
#include "http_connection.h"
#include "http_request.h"
#include "http_protocol.h"
#include "util_script.h"
#include "util_filter.h"
#include "mpm.h"
#include "apr.h"
#include "apr_strings.h"
#include "apr_tables.h"
#include "apr_lib.h"
#include "apr_fnmatch.h"
#include "apr_strings.h"
#include "apr_dbm.h"
#include "apr_optional.h"

/* OpenSSL headers */
#include <ssl.h>
#include <err.h>
#include <x509.h>
#include <x509v3.h>
#include <pem.h>
#include <crypto.h>
#include <evp.h>
#include <rand.h>
#ifdef SSL_EXPERIMENTAL_ENGINE
#include <engine.h>
#endif

/* mod_ssl headers */
#include "ssl_expr.h"
#include "ssl_util_ssl.h"
#include "ssl_util_table.h"

/* The #ifdef macros are only defined AFTER including the above
 * therefore we cannot include these system files at the top  :-(
 */
#if APR_HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#if APR_HAVE_UNISTD_H
#include <unistd.h> /* needed for STDIN_FILENO et.al., at least on FreeBSD */
#endif

/*
 * Provide reasonable default for some defines
 */
#ifndef FALSE
#define FALSE (0)
#endif
#ifndef TRUE
#define TRUE (!FALSE)
#endif
#ifndef PFALSE
#define PFALSE ((void *)FALSE)
#endif
#ifndef PTRUE
#define PTRUE ((void *)TRUE)
#endif
#ifndef UNSET
#define UNSET (-1)
#endif
#ifndef NUL
#define NUL '\0'
#endif
#ifndef RAND_MAX
#include <limits.h>
#define RAND_MAX INT_MAX
#endif

/*
 * Provide reasonable defines for some types
 */
#ifndef BOOL
#define BOOL unsigned int
#endif
#ifndef UCHAR
#define UCHAR unsigned char
#endif

/*
 * Provide useful shorthands
 */
#define strEQ(s1,s2)     (strcmp(s1,s2)        == 0)
#define strNE(s1,s2)     (strcmp(s1,s2)        != 0)
#define strEQn(s1,s2,n)  (strncmp(s1,s2,n)     == 0)
#define strNEn(s1,s2,n)  (strncmp(s1,s2,n)     != 0)

#define strcEQ(s1,s2)    (strcasecmp(s1,s2)    == 0)
#define strcNE(s1,s2)    (strcasecmp(s1,s2)    != 0)
#define strcEQn(s1,s2,n) (strncasecmp(s1,s2,n) == 0)
#define strcNEn(s1,s2,n) (strncasecmp(s1,s2,n) != 0)

#define strIsEmpty(s)    (s == NULL || s[0] == NUL)

#define cfgMerge(el,unset)  new->el = (add->el == (unset)) ? base->el : add->el
#define cfgMergeArray(el)   new->el = apr_array_append(p, add->el, base->el)
#define cfgMergeTable(el)   new->el = apr_table_overlay(p, add->el, base->el)
#define cfgMergeCtx(el)     new->el = apr_table_overlay(p, add->el, base->el)
#define cfgMergeString(el)  cfgMerge(el, NULL)
#define cfgMergeBool(el)    cfgMerge(el, UNSET)
#define cfgMergeInt(el)     cfgMerge(el, UNSET)

#define myConnConfig(c) \
(SSLConnRec *)ap_get_module_config(c->conn_config, &ssl_module)
#define myConnConfigSet(c, val) \
ap_set_module_config(c->conn_config, &ssl_module, val)
#define mySrvConfig(srv) (SSLSrvConfigRec *)ap_get_module_config(srv->module_config,  &ssl_module)
#define myDirConfig(req) (SSLDirConfigRec *)ap_get_module_config(req->per_dir_config, &ssl_module)
#define myModConfig(srv) (mySrvConfig((srv)))->mc

#define myCtxVarSet(mc,num,val)  mc->rCtx.pV##num = val
#define myCtxVarGet(mc,num,type) (type)(mc->rCtx.pV##num)

/*
 * SSL Logging
 */
#define SSL_LOG_NONE    (1<<0)
#define SSL_LOG_ERROR   (1<<1)
#define SSL_LOG_WARN    (1<<2)
#define SSL_LOG_INFO    (1<<3)
#define SSL_LOG_TRACE   (1<<4)
#define SSL_LOG_DEBUG   (1<<5)
#define SSL_LOG_MASK    (SSL_LOG_ERROR|SSL_LOG_WARN|SSL_LOG_INFO|SSL_LOG_TRACE|SSL_LOG_DEBUG)

#define SSL_ADD_NONE     (1<<8)
#define SSL_ADD_ERRNO    (1<<9)
#define SSL_ADD_SSLERR   (1<<10)
#define SSL_NO_TIMESTAMP (1<<11)
#define SSL_NO_LEVELID   (1<<12)
#define SSL_NO_NEWLINE   (1<<13)

/*
 * Defaults for the configuration
 */
#ifndef SSL_SESSION_CACHE_TIMEOUT
#define SSL_SESSION_CACHE_TIMEOUT  300
#endif

/*
 * Support for MM library
 */
#define SSL_MM_FILE_MODE ( APR_UREAD | APR_UWRITE | APR_GREAD | APR_WREAD )

/*
 * Support for DBM library
 */
#define SSL_DBM_FILE_MODE ( APR_UREAD | APR_UWRITE | APR_GREAD | APR_WREAD )

#if !defined(SSL_DBM_FILE_SUFFIX_DIR) && !defined(SSL_DBM_FILE_SUFFIX_PAG)
#if defined(DBM_SUFFIX)
#define SSL_DBM_FILE_SUFFIX_DIR DBM_SUFFIX
#define SSL_DBM_FILE_SUFFIX_PAG DBM_SUFFIX
#elif defined(__FreeBSD__) || (defined(DB_LOCK) && defined(DB_SHMEM))
#define SSL_DBM_FILE_SUFFIX_DIR ".db"
#define SSL_DBM_FILE_SUFFIX_PAG ".db"
#else
#define SSL_DBM_FILE_SUFFIX_DIR ".dir"
#define SSL_DBM_FILE_SUFFIX_PAG ".pag"
#endif
#endif

/*
 * Check for OpenSSL version 
 */
#if SSL_LIBRARY_VERSION < 0x00903100
#error "mod_ssl requires OpenSSL 0.9.3 or higher"
#endif

/*
 * The own data structures
 */
typedef struct {
    apr_pool_t *pPool;
    apr_pool_t *pSubPool;
    apr_array_header_t *aData;
} ssl_ds_array;

typedef struct {
    apr_pool_t *pPool;
    apr_pool_t *pSubPool;
    apr_array_header_t *aKey;
    apr_array_header_t *aData;
} ssl_ds_table;

/*
 * Define the certificate algorithm types
 */

typedef int ssl_algo_t;

#define SSL_ALGO_UNKNOWN (0)
#define SSL_ALGO_RSA     (1<<0)
#define SSL_ALGO_DSA     (1<<1)
#define SSL_ALGO_ALL     (SSL_ALGO_RSA|SSL_ALGO_DSA)

#define SSL_AIDX_RSA     (0)
#define SSL_AIDX_DSA     (1)
#define SSL_AIDX_MAX     (2)


/*
 * Define IDs for the temporary RSA keys and DH params
 */

#define SSL_TKP_GEN        (0)
#define SSL_TKP_ALLOC      (1)
#define SSL_TKP_FREE       (2)

#define SSL_TKPIDX_RSA512  (0)
#define SSL_TKPIDX_RSA1024 (1)
#define SSL_TKPIDX_DH512   (2)
#define SSL_TKPIDX_DH1024  (3)
#define SSL_TKPIDX_MAX     (4)

/*
 * Define the SSL options
 */
#define SSL_OPT_NONE           (0)
#define SSL_OPT_RELSET         (1<<0)
#define SSL_OPT_STDENVVARS     (1<<1)
#define SSL_OPT_COMPATENVVARS  (1<<2)
#define SSL_OPT_EXPORTCERTDATA (1<<3)
#define SSL_OPT_FAKEBASICAUTH  (1<<4)
#define SSL_OPT_STRICTREQUIRE  (1<<5)
#define SSL_OPT_OPTRENEGOTIATE (1<<6)
#define SSL_OPT_ALL            (SSL_OPT_STDENVVARS|SSL_OPT_COMPATENVVAR|SSL_OPT_EXPORTCERTDATA|SSL_OPT_FAKEBASICAUTH|SSL_OPT_STRICTREQUIRE|SSL_OPT_OPTRENEGOTIATE)
typedef int ssl_opt_t;

/*
 * Define the SSL Protocol options
 */
#define SSL_PROTOCOL_NONE  (0)
#define SSL_PROTOCOL_SSLV2 (1<<0)
#define SSL_PROTOCOL_SSLV3 (1<<1)
#define SSL_PROTOCOL_TLSV1 (1<<2)
#define SSL_PROTOCOL_ALL   (SSL_PROTOCOL_SSLV2|SSL_PROTOCOL_SSLV3|SSL_PROTOCOL_TLSV1)
typedef int ssl_proto_t;

/*
 * Define the SSL verify levels
 */
typedef enum {
    SSL_CVERIFY_UNSET           = UNSET,
    SSL_CVERIFY_NONE            = 0,
    SSL_CVERIFY_OPTIONAL        = 1,
    SSL_CVERIFY_REQUIRE         = 2,
    SSL_CVERIFY_OPTIONAL_NO_CA  = 3
} ssl_verify_t;

#ifndef X509_V_ERR_CERT_UNTRUSTED
#define X509_V_ERR_CERT_UNTRUSTED 27

#endif

#ifdef OPENSSL_VERSION_NUMBER

#define EVP_PKEY_key_type(k)              (EVP_PKEY_type(k->type))

#define X509_NAME_get_entries(xs)         (xs->entries)
#define X509_REVOKED_get_serialNumber(xs) (xs->serialNumber)

#define X509_get_signature_algorithm(xs) (xs->cert_info->signature->algorithm)
#define X509_get_key_algorithm(xs)       (xs->cert_info->key->algor->algorithm)

#define X509_NAME_ENTRY_get_data_ptr(xs) (xs->value->data)
#define X509_NAME_ENTRY_get_data_len(xs) (xs->value->length)

#define SSL_CTX_get_extra_certs(ctx)       (ctx->extra_certs)
#define SSL_CTX_set_extra_certs(ctx,value) {ctx->extra_certs = value;}

#define SSL_CIPHER_get_name(s)             (s->name)
#define SSL_CIPHER_get_valid(s)            (s->valid)

#define SSL_SESSION_get_session_id(s)      (s->session_id)
#define SSL_SESSION_get_session_id_length(s) (s->session_id_length)

/*
 * Support for retrieving/overriding states
 */
#ifndef SSL_get_state
#define SSL_get_state(ssl) SSL_state(ssl)
#endif

#define SSL_set_state(ssl,val) (ssl)->state = val

#endif

#define ssl_verify_error_is_optional(errnum) \
   ((errnum == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT) \
    || (errnum == X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN) \
    || (errnum == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY) \
    || (errnum == X509_V_ERR_CERT_UNTRUSTED) \
    || (errnum == X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE))

/*
 * Define the SSL pass phrase dialog types
 */
typedef enum {
    SSL_PPTYPE_UNSET   = UNSET,
    SSL_PPTYPE_BUILTIN = 0,
    SSL_PPTYPE_FILTER  = 1,
	SSL_PPTYPE_PIPE    = 2
} ssl_pphrase_t;

/*
 * Define the Path Checking modes
 */
#define SSL_PCM_EXISTS     1
#define SSL_PCM_ISREG      2
#define SSL_PCM_ISDIR      4
#define SSL_PCM_ISNONZERO  8
typedef unsigned int ssl_pathcheck_t;

/*
 * Define the SSL session cache modes and structures
 */
typedef enum {
    SSL_SCMODE_UNSET = UNSET,
    SSL_SCMODE_NONE  = 0,
    SSL_SCMODE_DBM   = 1,
    SSL_SCMODE_SHMHT = 2,
    SSL_SCMODE_SHMCB = 3
} ssl_scmode_t;

/*
 * Define the SSL mutex modes
 */
typedef enum {
    SSL_MUTEXMODE_UNSET  = UNSET,
    SSL_MUTEXMODE_NONE   = 0,
    SSL_MUTEXMODE_USED   = 1
} ssl_mutexmode_t;

/*
 * Define the SSL requirement structure
 */
typedef struct {
    char     *cpExpr;
    ssl_expr *mpExpr;
} ssl_require_t;

/*
 * Define the SSL random number generator seeding source
 */
typedef enum {
    SSL_RSCTX_STARTUP = 1,
    SSL_RSCTX_CONNECT = 2
} ssl_rsctx_t;
typedef enum {
    SSL_RSSRC_BUILTIN = 1,
    SSL_RSSRC_FILE    = 2,
    SSL_RSSRC_EXEC    = 3
#if SSL_LIBRARY_VERSION >= 0x00905100
   ,SSL_RSSRC_EGD     = 4
#endif
} ssl_rssrc_t;
typedef struct {
    ssl_rsctx_t  nCtx;
    ssl_rssrc_t  nSrc;
    char        *cpPath;
    int          nBytes;
} ssl_randseed_t;

/*
 * Define the structure of an ASN.1 anything
 */
typedef struct {
    long int       nData;
    unsigned char *cpData;
    apr_time_t     source_mtime;
} ssl_asn1_t;

/*
 * Define the mod_ssl per-module configuration structure
 * (i.e. the global configuration for each httpd process)
 */

typedef struct {
    SSL                *pssl;
    BIO                *pbioRead;
    BIO                *pbioWrite;
    ap_filter_t        *pInputFilter;
    ap_filter_t        *pOutputFilter;
} SSLFilterRec;

typedef enum {
    SSL_SHUTDOWN_TYPE_UNSET,
    SSL_SHUTDOWN_TYPE_STANDARD,
    SSL_SHUTDOWN_TYPE_UNCLEAN,
    SSL_SHUTDOWN_TYPE_ACCURATE
} ssl_shutdown_type_e;

typedef struct {
    SSL *ssl;
    const char *client_dn;
    X509 *client_cert;
    ssl_shutdown_type_e shutdown_type;
    const char *verify_info;
    const char *verify_error;
    int verify_depth;
    int log_level; /* for avoiding expensive logging */
} SSLConnRec;

#define SSLConnLogApplies(sslconn, level) (sslconn->log_level >= level)

typedef struct {
    pid_t           pid;
    apr_pool_t     *pPool;
    BOOL            bFixed;
    int             nSessionCacheMode;
    char           *szSessionCacheDataFile;
    int             nSessionCacheDataSize;
#if 0 /* XXX */
    AP_MM          *pSessionCacheDataMM;
#endif
    apr_table_t    *tSessionCacheDataTable;
    ssl_mutexmode_t nMutexMode;
    char           *szMutexFile;
    apr_lock_t     *pMutex;
    apr_array_header_t   *aRandSeed;
    int             nScoreboardSize; /* used for builtin random seed */
    apr_hash_t     *tTmpKeys;
    void           *pTmpKeys[SSL_TKPIDX_MAX];
    ssl_ds_table   *tPublicCert;
    apr_hash_t     *tPrivateKey;
#ifdef SSL_EXPERIMENTAL_ENGINE
    char           *szCryptoDevice;
#endif
    struct {
        void *pV1, *pV2, *pV3, *pV4, *pV5, *pV6, *pV7, *pV8, *pV9, *pV10;
    } rCtx;
} SSLModConfigRec;

/*
 * Define the mod_ssl per-server configuration structure
 * (i.e. the configuration for the main server
 *  and all <VirtualHost> contexts)
 */
typedef struct {
    SSLModConfigRec *mc;
    const char  *szVHostID;
    int          nVHostID_length;
    BOOL         bEnabled;
    apr_table_t *ap_server_ctx;
    const char  *szPublicCertFile[SSL_AIDX_MAX];
    const char  *szPrivateKeyFile[SSL_AIDX_MAX];
    const char  *szCertificateChain;
    const char  *szCACertificatePath;
    const char  *szCACertificateFile;
    const char  *szLogFile;
    const char  *szCipherSuite;
    apr_file_t  *fileLogFile;
    int          nLogLevel;
    int          nVerifyDepth;
    ssl_verify_t nVerifyClient;
    X509        *pPublicCert[SSL_AIDX_MAX];
    EVP_PKEY    *pPrivateKey[SSL_AIDX_MAX];
    SSL_CTX     *pSSLCtx;
    int          nSessionCacheTimeout;
    int          nPassPhraseDialogType;
    const char  *szPassPhraseDialogPath;
    ssl_proto_t  nProtocol;
    const char  *szCARevocationPath;
    const char  *szCARevocationFile;
    X509_STORE  *pRevocationStore;
#ifdef SSL_EXPERIMENTAL_PROXY
    /* Configuration details for proxy operation */
    ssl_proto_t  nProxyProtocol;
    int          bProxyVerify;
    int          nProxyVerifyDepth;
    const char  *szProxyCACertificatePath;
    const char  *szProxyCACertificateFile;
    const char  *szProxyClientCertificateFile;
    const char  *szProxyClientCertificatePath;
    const char  *szProxyCipherSuite;
    SSL_CTX     *pSSLProxyCtx;
    STACK_OF(X509_INFO) *skProxyClientCerts;
#endif
} SSLSrvConfigRec;

/*
 * Define the mod_ssl per-directory configuration structure
 * (i.e. the local configuration for all <Directory>
 *  and .htaccess contexts)
 */
typedef struct {
    BOOL          bSSLRequired;
    apr_array_header_t *aRequirement;
    ssl_opt_t     nOptions;
    ssl_opt_t     nOptionsAdd;
    ssl_opt_t     nOptionsDel;
    char         *szCipherSuite;
    ssl_verify_t  nVerifyClient;
    int           nVerifyDepth;
#ifdef SSL_EXPERIMENTAL_PERDIRCA
    char         *szCACertificatePath;
    char         *szCACertificateFile;
#endif
} SSLDirConfigRec;

/*
 *  function prototypes
 */

/*  API glue structures  */
extern module AP_MODULE_DECLARE_DATA ssl_module;

/*  configuration handling   */
SSLModConfigRec *ssl_config_global_create(server_rec *);
void         ssl_config_global_fix(SSLModConfigRec *);
BOOL         ssl_config_global_isfixed(SSLModConfigRec *);
void        *ssl_config_server_create(apr_pool_t *, server_rec *);
void        *ssl_config_server_merge(apr_pool_t *, void *, void *);
void        *ssl_config_perdir_create(apr_pool_t *, char *);
void        *ssl_config_perdir_merge(apr_pool_t *, void *, void *);
const char  *ssl_cmd_SSLMutex(cmd_parms *, void *, const char *);
const char  *ssl_cmd_SSLPassPhraseDialog(cmd_parms *, void *, const char *);
const char  *ssl_cmd_SSLCryptoDevice(cmd_parms *, void *, const char *);
const char  *ssl_cmd_SSLRandomSeed(cmd_parms *, void *, const char *, const char *, const char *);
const char  *ssl_cmd_SSLEngine(cmd_parms *, void *, int);
const char  *ssl_cmd_SSLCipherSuite(cmd_parms *, void *, const char *);
const char  *ssl_cmd_SSLCertificateFile(cmd_parms *, void *, const char *);
const char  *ssl_cmd_SSLCertificateKeyFile(cmd_parms *, void *, const char *);
const char  *ssl_cmd_SSLCertificateChainFile(cmd_parms *, void *, const char *);
const char  *ssl_cmd_SSLCACertificatePath(cmd_parms *, void *, const char *);
const char  *ssl_cmd_SSLCACertificateFile(cmd_parms *, void *, const char *);
const char  *ssl_cmd_SSLCARevocationPath(cmd_parms *, void *, const char *);
const char  *ssl_cmd_SSLCARevocationFile(cmd_parms *, void *, const char *);
const char  *ssl_cmd_SSLVerifyClient(cmd_parms *, void *, const char *);
const char  *ssl_cmd_SSLVerifyDepth(cmd_parms *, void *, const char *);
const char  *ssl_cmd_SSLSessionCache(cmd_parms *, void *, const char *);
const char  *ssl_cmd_SSLSessionCacheTimeout(cmd_parms *, void *, const char *);
const char  *ssl_cmd_SSLLog(cmd_parms *, void *, const char *);
const char  *ssl_cmd_SSLLogLevel(cmd_parms *, void *, const char *);
const char  *ssl_cmd_SSLProtocol(cmd_parms *, void *, const char *);
const char  *ssl_cmd_SSLOptions(cmd_parms *, void *, const char *);
const char  *ssl_cmd_SSLRequireSSL(cmd_parms *, void *);
const char  *ssl_cmd_SSLRequire(cmd_parms *, void *, const char *);
#ifdef SSL_EXPERIMENTAL_PROXY
const char  *ssl_cmd_SSLProxyProtocol(cmd_parms *, char *, const char *);
const char  *ssl_cmd_SSLProxyCipherSuite(cmd_parms *, char *, char *);
const char  *ssl_cmd_SSLProxyVerify(cmd_parms *, char *, int);
const char  *ssl_cmd_SSLProxyVerifyDepth(cmd_parms *, char *, char *);
const char  *ssl_cmd_SSLProxyCACertificatePath(cmd_parms *, char *, char *);
const char  *ssl_cmd_SSLProxyCACertificateFile(cmd_parms *, char *, char *);
const char  *ssl_cmd_SSLProxyMachineCertificatePath(cmd_parms *, char *, char *);
const char  *ssl_cmd_SSLProxyMachineCertificateFile(cmd_parms *, char *, char *);
#endif

/*  module initialization  */
int          ssl_init_Module(apr_pool_t *, apr_pool_t *, apr_pool_t *, server_rec *);
void         ssl_init_SSLLibrary(void);
void         ssl_init_Engine(server_rec *, apr_pool_t *);
void         ssl_init_TmpKeysHandle(int, server_rec *, apr_pool_t *);
void         ssl_init_ConfigureServer(server_rec *, apr_pool_t *, SSLSrvConfigRec *);
void         ssl_init_CheckServers(server_rec *, apr_pool_t *);
STACK_OF(X509_NAME) 
            *ssl_init_FindCAList(server_rec *, apr_pool_t *, const char *, const char *);
void         ssl_init_Child(apr_pool_t *, server_rec *);
apr_status_t ssl_init_ChildKill(void *data);
apr_status_t ssl_init_ModuleKill(void *data);

/*  Apache API hooks  */
void         ssl_hook_NewConnection(conn_rec *);
void         ssl_hook_TimeoutConnection(int);
int          ssl_hook_process_connection(SSLFilterRec *pRec);
apr_status_t ssl_hook_CloseConnection(SSLFilterRec *);
int          ssl_hook_Translate(request_rec *);
int          ssl_hook_Auth(request_rec *);
int          ssl_hook_UserCheck(request_rec *);
int          ssl_hook_Access(request_rec *);
int          ssl_hook_Fixup(request_rec *);
int          ssl_hook_ReadReq(request_rec *);
int          ssl_hook_Handler(request_rec *);

/*  OpenSSL callbacks */
RSA         *ssl_callback_TmpRSA(SSL *, int, int);
DH          *ssl_callback_TmpDH(SSL *, int, int);
int          ssl_callback_SSLVerify(int, X509_STORE_CTX *);
int          ssl_callback_SSLVerify_CRL(int, X509_STORE_CTX *, server_rec *);
int          ssl_callback_NewSessionCacheEntry(SSL *, SSL_SESSION *);
SSL_SESSION *ssl_callback_GetSessionCacheEntry(SSL *, unsigned char *, int, int *);
void         ssl_callback_DelSessionCacheEntry(SSL_CTX *, SSL_SESSION *);
#if SSL_LIBRARY_VERSION >= 0x00907000
void         ssl_callback_LogTracingState(const SSL *, int, int);
#else
void         ssl_callback_LogTracingState(SSL *, int, int);
#endif

/*  Session Cache Support  */
void         ssl_scache_init(server_rec *, apr_pool_t *);
#if 0 /* XXX */
void         ssl_scache_status_register(apr_pool_t *p);
#endif
void         ssl_scache_kill(server_rec *);
BOOL         ssl_scache_store(server_rec *, UCHAR *, int, time_t, SSL_SESSION *);
SSL_SESSION *ssl_scache_retrieve(server_rec *, UCHAR *, int);
void         ssl_scache_remove(server_rec *, UCHAR *, int);
void         ssl_scache_expire(server_rec *);
void         ssl_scache_status(server_rec *, apr_pool_t *, void (*)(char *, void *), void *);
char        *ssl_scache_id2sz(UCHAR *, int);
void         ssl_scache_dbm_init(server_rec *, apr_pool_t *);
void         ssl_scache_dbm_kill(server_rec *);
BOOL         ssl_scache_dbm_store(server_rec *, UCHAR *, int, time_t, SSL_SESSION *);
SSL_SESSION *ssl_scache_dbm_retrieve(server_rec *, UCHAR *, int);
void         ssl_scache_dbm_remove(server_rec *, UCHAR *, int);
void         ssl_scache_dbm_expire(server_rec *);
void         ssl_scache_dbm_status(server_rec *, apr_pool_t *, void (*)(char *, void *), void *);
#if 0 /* XXX */
void         ssl_scache_shmht_init(server_rec *, pool *);
void         ssl_scache_shmht_kill(server_rec *);
BOOL         ssl_scache_shmht_store(server_rec *, UCHAR *, int, time_t, SSL_SESSION *);
SSL_SESSION *ssl_scache_shmht_retrieve(server_rec *, UCHAR *, int);
void         ssl_scache_shmht_remove(server_rec *, UCHAR *, int);
void         ssl_scache_shmht_expire(server_rec *);
void         ssl_scache_shmht_status(server_rec *, pool *, void (*)(char *, void *), void *);
void         ssl_scache_shmcb_init(server_rec *, pool *);
void         ssl_scache_shmcb_kill(server_rec *);
BOOL         ssl_scache_shmcb_store(server_rec *, UCHAR *, int, time_t, SSL_SESSION *);
SSL_SESSION *ssl_scache_shmcb_retrieve(server_rec *, UCHAR *, int);
void         ssl_scache_shmcb_remove(server_rec *, UCHAR *, int);
void         ssl_scache_shmcb_expire(server_rec *);
void         ssl_scache_shmcb_status(server_rec *, pool *, void (*)(char *, void *), void *);
#endif

/*  Pass Phrase Support  */
void         ssl_pphrase_Handle(server_rec *, apr_pool_t *);

/*  Diffie-Hellman Parameter Support  */
DH           *ssl_dh_GetTmpParam(int);
DH           *ssl_dh_GetParamFromFile(char *);

/*  Data Structures */
ssl_ds_array *ssl_ds_array_make(apr_pool_t *, int);
BOOL          ssl_ds_array_isempty(ssl_ds_array *);
void         *ssl_ds_array_push(ssl_ds_array *);
void         *ssl_ds_array_get(ssl_ds_array *, int);
void          ssl_ds_array_wipeout(ssl_ds_array *);
void          ssl_ds_array_kill(ssl_ds_array *);
ssl_ds_table *ssl_ds_table_make(apr_pool_t *, int);
BOOL          ssl_ds_table_isempty(ssl_ds_table *);
void         *ssl_ds_table_push(ssl_ds_table *, char *);
void         *ssl_ds_table_get(ssl_ds_table *, char *);
void          ssl_ds_table_wipeout(ssl_ds_table *);
void          ssl_ds_table_kill(ssl_ds_table *);

unsigned char *ssl_asn1_table_set(apr_hash_t *table,
                                  const void *key,
                                  long int length);

ssl_asn1_t *ssl_asn1_table_get(apr_hash_t *table,
                               const void *key);

void ssl_asn1_table_unset(apr_hash_t *table,
                          const void *key);

/*  Mutex Support  */
int          ssl_mutex_init(server_rec *, apr_pool_t *);
int          ssl_mutex_reinit(server_rec *, apr_pool_t *);
int          ssl_mutex_on(server_rec *);
int          ssl_mutex_off(server_rec *);

/*  Logfile Support  */
void         ssl_log_open(server_rec *, server_rec *, apr_pool_t *);
void         ssl_log(server_rec *, int, const char *, ...);
void         ssl_die(void);

/*  Variables  */
void         ssl_var_register(void);
char        *ssl_var_lookup(apr_pool_t *, server_rec *, conn_rec *, request_rec *, char *);
void         ssl_var_log_config_register(apr_pool_t *p);

APR_DECLARE_OPTIONAL_FN(char *, ssl_var_lookup,
                        (apr_pool_t *, server_rec *,
                         conn_rec *, request_rec *,
                         char *));

/*  Proxy Extensions  */
#if 0 /* XXX */
void         ssl_ext_proxy_register(apr_pool_t *p);
#endif /* -0- */

/*  I/O  */
void         ssl_io_filter_init(conn_rec *, SSL *);
void         ssl_io_filter_register(apr_pool_t *);
long         ssl_io_data_cb(BIO *, int, const char *, int, long, long);

/*  PRNG  */
int          ssl_rand_seed(server_rec *, apr_pool_t *, ssl_rsctx_t, char *);

/*  Utility Functions  */
char        *ssl_util_vhostid(apr_pool_t *, server_rec *);
void         ssl_util_strupper(char *);
void         ssl_util_uuencode(char *, const char *, BOOL);
void         ssl_util_uuencode_binary(unsigned char *, const unsigned char *, int, BOOL);
apr_file_t  *ssl_util_ppopen(server_rec *, apr_pool_t *, const char *,
                             const char * const *);
void         ssl_util_ppclose(server_rec *, apr_pool_t *, apr_file_t *);
char        *ssl_util_readfilter(server_rec *, apr_pool_t *, const char *,
                                 const char * const *);
BOOL         ssl_util_path_check(ssl_pathcheck_t, const char *, apr_pool_t *);
ssl_algo_t   ssl_util_algotypeof(X509 *, EVP_PKEY *); 
char        *ssl_util_algotypestr(ssl_algo_t);
char        *ssl_util_ptxtsub(apr_pool_t *, const char *, const char *, char *);
void         ssl_util_thread_setup(server_rec *, apr_pool_t *);

#endif /* __MOD_SSL_H__ */
