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
 
#include <assert.h>

#include <apr_strings.h>
#include <apr_optional.h>
#include <apr_optional_hooks.h>

#include <httpd.h>
#include <http_core.h>
#include <http_config.h>
#include <http_connection.h>
#include <http_protocol.h>
#include <http_request.h>
#include <http_ssl.h>
#include <http_log.h>

#include "mod_http2.h"
#include "h2_private.h"

#include "h2_bucket_beam.h"
#include "h2_stream.h"
#include "h2_c2.h"
#include "h2_config.h"
#include "h2_conn_ctx.h"
#include "h2_c1.h"
#include "h2_request.h"
#include "h2_headers.h"
#include "h2_session.h"
#include "h2_util.h"
#include "h2_protocol.h"
#include "mod_http2.h"

const char *h2_protocol_ids_tls[] = {
    "h2", NULL
};

const char *h2_protocol_ids_clear[] = {
    "h2c", NULL
};

const char *H2_MAGIC_TOKEN = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/*******************************************************************************
 * HTTP/2 error stuff
 */
static const char *h2_err_descr[] = {
    "no error",                    /* 0x0 */
    "protocol error",
    "internal error",
    "flow control error",
    "settings timeout",
    "stream closed",               /* 0x5 */
    "frame size error",
    "refused stream",
    "cancel",
    "compression error",
    "connect error",               /* 0xa */
    "enhance your calm",
    "inadequate security",
    "http/1.1 required",
};

const char *h2_protocol_err_description(unsigned int h2_error)
{
    if (h2_error < (sizeof(h2_err_descr)/sizeof(h2_err_descr[0]))) {
        return h2_err_descr[h2_error];
    }
    return "unknown http/2 error code";
}

/*******************************************************************************
 * Check connection security requirements of RFC 7540
 */

/*
 * Black Listed Ciphers from RFC 7549 Appendix A
 *
 */
static const char *RFC7540_names[] = {
    /* ciphers with NULL encrpytion */
    "NULL-MD5",                         /* TLS_NULL_WITH_NULL_NULL */
    /* same */                          /* TLS_RSA_WITH_NULL_MD5 */
    "NULL-SHA",                         /* TLS_RSA_WITH_NULL_SHA */
    "NULL-SHA256",                      /* TLS_RSA_WITH_NULL_SHA256 */
    "PSK-NULL-SHA",                     /* TLS_PSK_WITH_NULL_SHA */
    "DHE-PSK-NULL-SHA",                 /* TLS_DHE_PSK_WITH_NULL_SHA */
    "RSA-PSK-NULL-SHA",                 /* TLS_RSA_PSK_WITH_NULL_SHA */
    "PSK-NULL-SHA256",                  /* TLS_PSK_WITH_NULL_SHA256 */
    "PSK-NULL-SHA384",                  /* TLS_PSK_WITH_NULL_SHA384 */
    "DHE-PSK-NULL-SHA256",              /* TLS_DHE_PSK_WITH_NULL_SHA256 */
    "DHE-PSK-NULL-SHA384",              /* TLS_DHE_PSK_WITH_NULL_SHA384 */
    "RSA-PSK-NULL-SHA256",              /* TLS_RSA_PSK_WITH_NULL_SHA256 */
    "RSA-PSK-NULL-SHA384",              /* TLS_RSA_PSK_WITH_NULL_SHA384 */
    "ECDH-ECDSA-NULL-SHA",              /* TLS_ECDH_ECDSA_WITH_NULL_SHA */
    "ECDHE-ECDSA-NULL-SHA",             /* TLS_ECDHE_ECDSA_WITH_NULL_SHA */
    "ECDH-RSA-NULL-SHA",                /* TLS_ECDH_RSA_WITH_NULL_SHA */
    "ECDHE-RSA-NULL-SHA",               /* TLS_ECDHE_RSA_WITH_NULL_SHA */
    "AECDH-NULL-SHA",                   /* TLS_ECDH_anon_WITH_NULL_SHA */
    "ECDHE-PSK-NULL-SHA",               /* TLS_ECDHE_PSK_WITH_NULL_SHA */
    "ECDHE-PSK-NULL-SHA256",            /* TLS_ECDHE_PSK_WITH_NULL_SHA256 */
    "ECDHE-PSK-NULL-SHA384",            /* TLS_ECDHE_PSK_WITH_NULL_SHA384 */
    
    /* DES/3DES ciphers */
    "PSK-3DES-EDE-CBC-SHA",             /* TLS_PSK_WITH_3DES_EDE_CBC_SHA */
    "DHE-PSK-3DES-EDE-CBC-SHA",         /* TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA */
    "RSA-PSK-3DES-EDE-CBC-SHA",         /* TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA */
    "ECDH-ECDSA-DES-CBC3-SHA",          /* TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA */
    "ECDHE-ECDSA-DES-CBC3-SHA",         /* TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA */
    "ECDH-RSA-DES-CBC3-SHA",            /* TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA */
    "ECDHE-RSA-DES-CBC3-SHA",           /* TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA */
    "AECDH-DES-CBC3-SHA",               /* TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA */
    "SRP-3DES-EDE-CBC-SHA",             /* TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA */
    "SRP-RSA-3DES-EDE-CBC-SHA",         /* TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA */
    "SRP-DSS-3DES-EDE-CBC-SHA",         /* TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA */
    "ECDHE-PSK-3DES-EDE-CBC-SHA",       /* TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA */
    "DES-CBC-SHA",                      /* TLS_RSA_WITH_DES_CBC_SHA */
    "DES-CBC3-SHA",                     /* TLS_RSA_WITH_3DES_EDE_CBC_SHA */
    "DHE-DSS-DES-CBC3-SHA",             /* TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA */
    "DHE-RSA-DES-CBC-SHA",              /* TLS_DHE_RSA_WITH_DES_CBC_SHA */
    "DHE-RSA-DES-CBC3-SHA",             /* TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA */
    "ADH-DES-CBC-SHA",                  /* TLS_DH_anon_WITH_DES_CBC_SHA */
    "ADH-DES-CBC3-SHA",                 /* TLS_DH_anon_WITH_3DES_EDE_CBC_SHA */
    "EXP-DH-DSS-DES-CBC-SHA",           /* TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA */
    "DH-DSS-DES-CBC-SHA",               /* TLS_DH_DSS_WITH_DES_CBC_SHA */
    "DH-DSS-DES-CBC3-SHA",              /* TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA */
    "EXP-DH-RSA-DES-CBC-SHA",           /* TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA */
    "DH-RSA-DES-CBC-SHA",               /* TLS_DH_RSA_WITH_DES_CBC_SHA */
    "DH-RSA-DES-CBC3-SHA",              /* TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA */

    /* blacklisted EXPORT ciphers */
    "EXP-RC4-MD5",                      /* TLS_RSA_EXPORT_WITH_RC4_40_MD5 */
    "EXP-RC2-CBC-MD5",                  /* TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5 */
    "EXP-DES-CBC-SHA",                  /* TLS_RSA_EXPORT_WITH_DES40_CBC_SHA */
    "EXP-DHE-DSS-DES-CBC-SHA",          /* TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA */
    "EXP-DHE-RSA-DES-CBC-SHA",          /* TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA */
    "EXP-ADH-DES-CBC-SHA",              /* TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA */
    "EXP-ADH-RC4-MD5",                  /* TLS_DH_anon_EXPORT_WITH_RC4_40_MD5 */

    /* blacklisted RC4 encryption */
    "RC4-MD5",                          /* TLS_RSA_WITH_RC4_128_MD5 */
    "RC4-SHA",                          /* TLS_RSA_WITH_RC4_128_SHA */
    "ADH-RC4-MD5",                      /* TLS_DH_anon_WITH_RC4_128_MD5 */
    "KRB5-RC4-SHA",                     /* TLS_KRB5_WITH_RC4_128_SHA */
    "KRB5-RC4-MD5",                     /* TLS_KRB5_WITH_RC4_128_MD5 */
    "EXP-KRB5-RC4-SHA",                 /* TLS_KRB5_EXPORT_WITH_RC4_40_SHA */
    "EXP-KRB5-RC4-MD5",                 /* TLS_KRB5_EXPORT_WITH_RC4_40_MD5 */
    "PSK-RC4-SHA",                      /* TLS_PSK_WITH_RC4_128_SHA */
    "DHE-PSK-RC4-SHA",                  /* TLS_DHE_PSK_WITH_RC4_128_SHA */
    "RSA-PSK-RC4-SHA",                  /* TLS_RSA_PSK_WITH_RC4_128_SHA */
    "ECDH-ECDSA-RC4-SHA",               /* TLS_ECDH_ECDSA_WITH_RC4_128_SHA */
    "ECDHE-ECDSA-RC4-SHA",              /* TLS_ECDHE_ECDSA_WITH_RC4_128_SHA */
    "ECDH-RSA-RC4-SHA",                 /* TLS_ECDH_RSA_WITH_RC4_128_SHA */
    "ECDHE-RSA-RC4-SHA",                /* TLS_ECDHE_RSA_WITH_RC4_128_SHA */
    "AECDH-RC4-SHA",                    /* TLS_ECDH_anon_WITH_RC4_128_SHA */
    "ECDHE-PSK-RC4-SHA",                /* TLS_ECDHE_PSK_WITH_RC4_128_SHA */

    /* blacklisted AES128 encrpytion ciphers */
    "AES128-SHA256",                    /* TLS_RSA_WITH_AES_128_CBC_SHA */
    "DH-DSS-AES128-SHA",                /* TLS_DH_DSS_WITH_AES_128_CBC_SHA */
    "DH-RSA-AES128-SHA",                /* TLS_DH_RSA_WITH_AES_128_CBC_SHA */
    "DHE-DSS-AES128-SHA",               /* TLS_DHE_DSS_WITH_AES_128_CBC_SHA */
    "DHE-RSA-AES128-SHA",               /* TLS_DHE_RSA_WITH_AES_128_CBC_SHA */
    "ADH-AES128-SHA",                   /* TLS_DH_anon_WITH_AES_128_CBC_SHA */
    "AES128-SHA256",                    /* TLS_RSA_WITH_AES_128_CBC_SHA256 */
    "DH-DSS-AES128-SHA256",             /* TLS_DH_DSS_WITH_AES_128_CBC_SHA256 */
    "DH-RSA-AES128-SHA256",             /* TLS_DH_RSA_WITH_AES_128_CBC_SHA256 */
    "DHE-DSS-AES128-SHA256",            /* TLS_DHE_DSS_WITH_AES_128_CBC_SHA256 */
    "DHE-RSA-AES128-SHA256",            /* TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 */
    "ECDH-ECDSA-AES128-SHA",            /* TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA */
    "ECDHE-ECDSA-AES128-SHA",           /* TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA */
    "ECDH-RSA-AES128-SHA",              /* TLS_ECDH_RSA_WITH_AES_128_CBC_SHA */
    "ECDHE-RSA-AES128-SHA",             /* TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA */
    "AECDH-AES128-SHA",                 /* TLS_ECDH_anon_WITH_AES_128_CBC_SHA */
    "ECDHE-ECDSA-AES128-SHA256",        /* TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 */
    "ECDH-ECDSA-AES128-SHA256",         /* TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256 */
    "ECDHE-RSA-AES128-SHA256",          /* TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 */
    "ECDH-RSA-AES128-SHA256",           /* TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256 */
    "ADH-AES128-SHA256",                /* TLS_DH_anon_WITH_AES_128_CBC_SHA256 */
    "PSK-AES128-CBC-SHA",               /* TLS_PSK_WITH_AES_128_CBC_SHA */
    "DHE-PSK-AES128-CBC-SHA",           /* TLS_DHE_PSK_WITH_AES_128_CBC_SHA */
    "RSA-PSK-AES128-CBC-SHA",           /* TLS_RSA_PSK_WITH_AES_128_CBC_SHA */
    "PSK-AES128-CBC-SHA256",            /* TLS_PSK_WITH_AES_128_CBC_SHA256 */
    "DHE-PSK-AES128-CBC-SHA256",        /* TLS_DHE_PSK_WITH_AES_128_CBC_SHA256 */
    "RSA-PSK-AES128-CBC-SHA256",        /* TLS_RSA_PSK_WITH_AES_128_CBC_SHA256 */
    "ECDHE-PSK-AES128-CBC-SHA",         /* TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA */
    "ECDHE-PSK-AES128-CBC-SHA256",      /* TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256 */
    "AES128-CCM",                       /* TLS_RSA_WITH_AES_128_CCM */
    "AES128-CCM8",                      /* TLS_RSA_WITH_AES_128_CCM_8 */
    "PSK-AES128-CCM",                   /* TLS_PSK_WITH_AES_128_CCM */
    "PSK-AES128-CCM8",                  /* TLS_PSK_WITH_AES_128_CCM_8 */
    "AES128-GCM-SHA256",                /* TLS_RSA_WITH_AES_128_GCM_SHA256 */
    "DH-RSA-AES128-GCM-SHA256",         /* TLS_DH_RSA_WITH_AES_128_GCM_SHA256 */
    "DH-DSS-AES128-GCM-SHA256",         /* TLS_DH_DSS_WITH_AES_128_GCM_SHA256 */
    "ADH-AES128-GCM-SHA256",            /* TLS_DH_anon_WITH_AES_128_GCM_SHA256 */
    "PSK-AES128-GCM-SHA256",            /* TLS_PSK_WITH_AES_128_GCM_SHA256 */
    "RSA-PSK-AES128-GCM-SHA256",        /* TLS_RSA_PSK_WITH_AES_128_GCM_SHA256 */
    "ECDH-ECDSA-AES128-GCM-SHA256",     /* TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256 */
    "ECDH-RSA-AES128-GCM-SHA256",       /* TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256 */
    "SRP-AES-128-CBC-SHA",              /* TLS_SRP_SHA_WITH_AES_128_CBC_SHA */
    "SRP-RSA-AES-128-CBC-SHA",          /* TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA */
    "SRP-DSS-AES-128-CBC-SHA",          /* TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA */
    
    /* blacklisted AES256 encrpytion ciphers */
    "AES256-SHA",                       /* TLS_RSA_WITH_AES_256_CBC_SHA */
    "DH-DSS-AES256-SHA",                /* TLS_DH_DSS_WITH_AES_256_CBC_SHA */
    "DH-RSA-AES256-SHA",                /* TLS_DH_RSA_WITH_AES_256_CBC_SHA */
    "DHE-DSS-AES256-SHA",               /* TLS_DHE_DSS_WITH_AES_256_CBC_SHA */
    "DHE-RSA-AES256-SHA",               /* TLS_DHE_RSA_WITH_AES_256_CBC_SHA */
    "ADH-AES256-SHA",                   /* TLS_DH_anon_WITH_AES_256_CBC_SHA */
    "AES256-SHA256",                    /* TLS_RSA_WITH_AES_256_CBC_SHA256 */
    "DH-DSS-AES256-SHA256",             /* TLS_DH_DSS_WITH_AES_256_CBC_SHA256 */
    "DH-RSA-AES256-SHA256",             /* TLS_DH_RSA_WITH_AES_256_CBC_SHA256 */
    "DHE-DSS-AES256-SHA256",            /* TLS_DHE_DSS_WITH_AES_256_CBC_SHA256 */
    "DHE-RSA-AES256-SHA256",            /* TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 */
    "ADH-AES256-SHA256",                /* TLS_DH_anon_WITH_AES_256_CBC_SHA256 */
    "ECDH-ECDSA-AES256-SHA",            /* TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA */
    "ECDHE-ECDSA-AES256-SHA",           /* TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA */
    "ECDH-RSA-AES256-SHA",              /* TLS_ECDH_RSA_WITH_AES_256_CBC_SHA */
    "ECDHE-RSA-AES256-SHA",             /* TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA */
    "AECDH-AES256-SHA",                 /* TLS_ECDH_anon_WITH_AES_256_CBC_SHA */
    "ECDHE-ECDSA-AES256-SHA384",        /* TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 */
    "ECDH-ECDSA-AES256-SHA384",         /* TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384 */
    "ECDHE-RSA-AES256-SHA384",          /* TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 */
    "ECDH-RSA-AES256-SHA384",           /* TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384 */
    "PSK-AES256-CBC-SHA",               /* TLS_PSK_WITH_AES_256_CBC_SHA */
    "DHE-PSK-AES256-CBC-SHA",           /* TLS_DHE_PSK_WITH_AES_256_CBC_SHA */
    "RSA-PSK-AES256-CBC-SHA",           /* TLS_RSA_PSK_WITH_AES_256_CBC_SHA */
    "PSK-AES256-CBC-SHA384",            /* TLS_PSK_WITH_AES_256_CBC_SHA384 */
    "DHE-PSK-AES256-CBC-SHA384",        /* TLS_DHE_PSK_WITH_AES_256_CBC_SHA384 */
    "RSA-PSK-AES256-CBC-SHA384",        /* TLS_RSA_PSK_WITH_AES_256_CBC_SHA384 */
    "ECDHE-PSK-AES256-CBC-SHA",         /* TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA */
    "ECDHE-PSK-AES256-CBC-SHA384",      /* TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384 */
    "SRP-AES-256-CBC-SHA",              /* TLS_SRP_SHA_WITH_AES_256_CBC_SHA */
    "SRP-RSA-AES-256-CBC-SHA",          /* TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA */
    "SRP-DSS-AES-256-CBC-SHA",          /* TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA */
    "AES256-CCM",                       /* TLS_RSA_WITH_AES_256_CCM */
    "AES256-CCM8",                      /* TLS_RSA_WITH_AES_256_CCM_8 */
    "PSK-AES256-CCM",                   /* TLS_PSK_WITH_AES_256_CCM */
    "PSK-AES256-CCM8",                  /* TLS_PSK_WITH_AES_256_CCM_8 */
    "AES256-GCM-SHA384",                /* TLS_RSA_WITH_AES_256_GCM_SHA384 */
    "DH-RSA-AES256-GCM-SHA384",         /* TLS_DH_RSA_WITH_AES_256_GCM_SHA384 */
    "DH-DSS-AES256-GCM-SHA384",         /* TLS_DH_DSS_WITH_AES_256_GCM_SHA384 */
    "ADH-AES256-GCM-SHA384",            /* TLS_DH_anon_WITH_AES_256_GCM_SHA384 */
    "PSK-AES256-GCM-SHA384",            /* TLS_PSK_WITH_AES_256_GCM_SHA384 */
    "RSA-PSK-AES256-GCM-SHA384",        /* TLS_RSA_PSK_WITH_AES_256_GCM_SHA384 */
    "ECDH-ECDSA-AES256-GCM-SHA384",     /* TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384 */
    "ECDH-RSA-AES256-GCM-SHA384",       /* TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384 */
    
    /* blacklisted CAMELLIA128 encrpytion ciphers */
    "CAMELLIA128-SHA",                  /* TLS_RSA_WITH_CAMELLIA_128_CBC_SHA */
    "DH-DSS-CAMELLIA128-SHA",           /* TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA */
    "DH-RSA-CAMELLIA128-SHA",           /* TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA */
    "DHE-DSS-CAMELLIA128-SHA",          /* TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA */
    "DHE-RSA-CAMELLIA128-SHA",          /* TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA */
    "ADH-CAMELLIA128-SHA",              /* TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA */
    "ECDHE-ECDSA-CAMELLIA128-SHA256",   /* TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 */
    "ECDH-ECDSA-CAMELLIA128-SHA256",    /* TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 */
    "ECDHE-RSA-CAMELLIA128-SHA256",     /* TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 */
    "ECDH-RSA-CAMELLIA128-SHA256",      /* TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256 */
    "PSK-CAMELLIA128-SHA256",           /* TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256 */
    "DHE-PSK-CAMELLIA128-SHA256",       /* TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256 */
    "RSA-PSK-CAMELLIA128-SHA256",       /* TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256 */
    "ECDHE-PSK-CAMELLIA128-SHA256",     /* TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256 */
    "CAMELLIA128-GCM-SHA256",           /* TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256 */
    "DH-RSA-CAMELLIA128-GCM-SHA256",    /* TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256 */
    "DH-DSS-CAMELLIA128-GCM-SHA256",    /* TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256 */
    "ADH-CAMELLIA128-GCM-SHA256",       /* TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256 */
    "ECDH-ECDSA-CAMELLIA128-GCM-SHA256",/* TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256 */
    "ECDH-RSA-CAMELLIA128-GCM-SHA256",  /* TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256 */
    "PSK-CAMELLIA128-GCM-SHA256",       /* TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256 */
    "RSA-PSK-CAMELLIA128-GCM-SHA256",   /* TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256 */
    "CAMELLIA128-SHA256",               /* TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256 */
    "DH-DSS-CAMELLIA128-SHA256",        /* TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256 */
    "DH-RSA-CAMELLIA128-SHA256",        /* TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256 */
    "DHE-DSS-CAMELLIA128-SHA256",       /* TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256 */
    "DHE-RSA-CAMELLIA128-SHA256",       /* TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 */
    "ADH-CAMELLIA128-SHA256",           /* TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256 */
    
    /* blacklisted CAMELLIA256 encrpytion ciphers */
    "CAMELLIA256-SHA",                  /* TLS_RSA_WITH_CAMELLIA_256_CBC_SHA */
    "DH-RSA-CAMELLIA256-SHA",           /* TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA */
    "DH-DSS-CAMELLIA256-SHA",           /* TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA */
    "DHE-DSS-CAMELLIA256-SHA",          /* TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA */
    "DHE-RSA-CAMELLIA256-SHA",          /* TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA */
    "ADH-CAMELLIA256-SHA",              /* TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA */
    "ECDHE-ECDSA-CAMELLIA256-SHA384",   /* TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 */
    "ECDH-ECDSA-CAMELLIA256-SHA384",    /* TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 */
    "ECDHE-RSA-CAMELLIA256-SHA384",     /* TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384 */
    "ECDH-RSA-CAMELLIA256-SHA384",      /* TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384 */
    "PSK-CAMELLIA256-SHA384",           /* TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384 */
    "DHE-PSK-CAMELLIA256-SHA384",       /* TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384 */
    "RSA-PSK-CAMELLIA256-SHA384",       /* TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384 */
    "ECDHE-PSK-CAMELLIA256-SHA384",     /* TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384 */
    "CAMELLIA256-SHA256",               /* TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256 */
    "DH-DSS-CAMELLIA256-SHA256",        /* TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256 */
    "DH-RSA-CAMELLIA256-SHA256",        /* TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256 */
    "DHE-DSS-CAMELLIA256-SHA256",       /* TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256 */
    "DHE-RSA-CAMELLIA256-SHA256",       /* TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256 */
    "ADH-CAMELLIA256-SHA256",           /* TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256 */
    "CAMELLIA256-GCM-SHA384",           /* TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384 */
    "DH-RSA-CAMELLIA256-GCM-SHA384",    /* TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384 */
    "DH-DSS-CAMELLIA256-GCM-SHA384",    /* TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384 */
    "ADH-CAMELLIA256-GCM-SHA384",       /* TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384 */
    "ECDH-ECDSA-CAMELLIA256-GCM-SHA384",/* TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384 */
    "ECDH-RSA-CAMELLIA256-GCM-SHA384",  /* TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384 */
    "PSK-CAMELLIA256-GCM-SHA384",       /* TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384 */
    "RSA-PSK-CAMELLIA256-GCM-SHA384",   /* TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384 */
    
    /* The blacklisted ARIA encrpytion ciphers */
    "ARIA128-SHA256",                   /* TLS_RSA_WITH_ARIA_128_CBC_SHA256 */
    "ARIA256-SHA384",                   /* TLS_RSA_WITH_ARIA_256_CBC_SHA384 */
    "DH-DSS-ARIA128-SHA256",            /* TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256 */
    "DH-DSS-ARIA256-SHA384",            /* TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384 */
    "DH-RSA-ARIA128-SHA256",            /* TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256 */
    "DH-RSA-ARIA256-SHA384",            /* TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384 */
    "DHE-DSS-ARIA128-SHA256",           /* TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256 */
    "DHE-DSS-ARIA256-SHA384",           /* TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384 */
    "DHE-RSA-ARIA128-SHA256",           /* TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256 */
    "DHE-RSA-ARIA256-SHA384",           /* TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384 */
    "ADH-ARIA128-SHA256",               /* TLS_DH_anon_WITH_ARIA_128_CBC_SHA256 */
    "ADH-ARIA256-SHA384",               /* TLS_DH_anon_WITH_ARIA_256_CBC_SHA384 */
    "ECDHE-ECDSA-ARIA128-SHA256",       /* TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256 */
    "ECDHE-ECDSA-ARIA256-SHA384",       /* TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384 */
    "ECDH-ECDSA-ARIA128-SHA256",        /* TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256 */
    "ECDH-ECDSA-ARIA256-SHA384",        /* TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384 */
    "ECDHE-RSA-ARIA128-SHA256",         /* TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256 */
    "ECDHE-RSA-ARIA256-SHA384",         /* TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384 */
    "ECDH-RSA-ARIA128-SHA256",          /* TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256 */
    "ECDH-RSA-ARIA256-SHA384",          /* TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384 */
    "ARIA128-GCM-SHA256",               /* TLS_RSA_WITH_ARIA_128_GCM_SHA256 */
    "ARIA256-GCM-SHA384",               /* TLS_RSA_WITH_ARIA_256_GCM_SHA384 */
    "DH-DSS-ARIA128-GCM-SHA256",        /* TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256 */
    "DH-DSS-ARIA256-GCM-SHA384",        /* TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384 */
    "DH-RSA-ARIA128-GCM-SHA256",        /* TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256 */
    "DH-RSA-ARIA256-GCM-SHA384",        /* TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384 */
    "ADH-ARIA128-GCM-SHA256",           /* TLS_DH_anon_WITH_ARIA_128_GCM_SHA256 */
    "ADH-ARIA256-GCM-SHA384",           /* TLS_DH_anon_WITH_ARIA_256_GCM_SHA384 */
    "ECDH-ECDSA-ARIA128-GCM-SHA256",    /* TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256 */
    "ECDH-ECDSA-ARIA256-GCM-SHA384",    /* TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384 */
    "ECDH-RSA-ARIA128-GCM-SHA256",      /* TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256 */
    "ECDH-RSA-ARIA256-GCM-SHA384",      /* TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384 */
    "PSK-ARIA128-SHA256",               /* TLS_PSK_WITH_ARIA_128_CBC_SHA256 */
    "PSK-ARIA256-SHA384",               /* TLS_PSK_WITH_ARIA_256_CBC_SHA384 */
    "DHE-PSK-ARIA128-SHA256",           /* TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256 */
    "DHE-PSK-ARIA256-SHA384",           /* TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384 */
    "RSA-PSK-ARIA128-SHA256",           /* TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256 */
    "RSA-PSK-ARIA256-SHA384",           /* TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384 */
    "ARIA128-GCM-SHA256",               /* TLS_PSK_WITH_ARIA_128_GCM_SHA256 */
    "ARIA256-GCM-SHA384",               /* TLS_PSK_WITH_ARIA_256_GCM_SHA384 */
    "RSA-PSK-ARIA128-GCM-SHA256",       /* TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256 */
    "RSA-PSK-ARIA256-GCM-SHA384",       /* TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384 */
    "ECDHE-PSK-ARIA128-SHA256",         /* TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256 */
    "ECDHE-PSK-ARIA256-SHA384",         /* TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384 */

    /* blacklisted SEED encryptions */
    "SEED-SHA",                         /*TLS_RSA_WITH_SEED_CBC_SHA */
    "DH-DSS-SEED-SHA",                  /* TLS_DH_DSS_WITH_SEED_CBC_SHA */
    "DH-RSA-SEED-SHA",                  /* TLS_DH_RSA_WITH_SEED_CBC_SHA */
    "DHE-DSS-SEED-SHA",                 /* TLS_DHE_DSS_WITH_SEED_CBC_SHA */
    "DHE-RSA-SEED-SHA",                 /* TLS_DHE_RSA_WITH_SEED_CBC_SHA */               
    "ADH-SEED-SHA",                     /* TLS_DH_anon_WITH_SEED_CBC_SHA */

    /* blacklisted KRB5 ciphers */
    "KRB5-DES-CBC-SHA",                 /* TLS_KRB5_WITH_DES_CBC_SHA */
    "KRB5-DES-CBC3-SHA",                /* TLS_KRB5_WITH_3DES_EDE_CBC_SHA */
    "KRB5-IDEA-CBC-SHA",                /* TLS_KRB5_WITH_IDEA_CBC_SHA */
    "KRB5-DES-CBC-MD5",                 /* TLS_KRB5_WITH_DES_CBC_MD5 */
    "KRB5-DES-CBC3-MD5",                /* TLS_KRB5_WITH_3DES_EDE_CBC_MD5 */
    "KRB5-IDEA-CBC-MD5",                /* TLS_KRB5_WITH_IDEA_CBC_MD5 */
    "EXP-KRB5-DES-CBC-SHA",             /* TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA */
    "EXP-KRB5-DES-CBC-MD5",             /* TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5 */
    "EXP-KRB5-RC2-CBC-SHA",             /* TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA */
    "EXP-KRB5-RC2-CBC-MD5",             /* TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5 */
  
    /* blacklisted exoticas */
    "DHE-DSS-CBC-SHA",                  /* TLS_DHE_DSS_WITH_DES_CBC_SHA */
    "IDEA-CBC-SHA",                     /* TLS_RSA_WITH_IDEA_CBC_SHA */
    
    /* not really sure if the following names are correct */
    "SSL3_CK_SCSV",                     /* TLS_EMPTY_RENEGOTIATION_INFO_SCSV */
    "SSL3_CK_FALLBACK_SCSV"
};
static size_t RFC7540_names_LEN = sizeof(RFC7540_names)/sizeof(RFC7540_names[0]);


static apr_hash_t *BLCNames;

static void cipher_init(apr_pool_t *pool)
{
    apr_hash_t *hash = apr_hash_make(pool);
    const char *source;
    unsigned int i;
    
    source = "rfc7540";
    for (i = 0; i < RFC7540_names_LEN; ++i) {
        apr_hash_set(hash, RFC7540_names[i], APR_HASH_KEY_STRING, source);
    }
    
    BLCNames = hash;
}

static int cipher_is_blacklisted(const char *cipher, const char **psource)
{   
    *psource = apr_hash_get(BLCNames, cipher, APR_HASH_KEY_STRING);
    return !!*psource;
}

apr_status_t h2_protocol_init(apr_pool_t *pool, server_rec *s)
{
    (void)pool;
    ap_log_error(APLOG_MARK, APLOG_TRACE1, 0, s, "h2_h2, child_init");
    cipher_init(pool);
    
    return APR_SUCCESS;
}

int h2_protocol_is_acceptable_c1(conn_rec *c, request_rec *r, int require_all)
{
    int is_tls = ap_ssl_conn_is_ssl(c);

    if (is_tls && h2_config_cgeti(c, H2_CONF_MODERN_TLS_ONLY) > 0) {
        /* Check TLS connection for modern TLS parameters, as defined in
         * RFC 7540 and https://wiki.mozilla.org/Security/Server_Side_TLS#Modern_compatibility
         */
        apr_pool_t *pool = c->pool;
        server_rec *s = c->base_server;
        const char *val;

        /* Need Tlsv1.2 or higher, rfc 7540, ch. 9.2
         */
        val = ap_ssl_var_lookup(pool, s, c, NULL, "SSL_PROTOCOL");
        if (val && *val) {
            if (strncmp("TLS", val, 3) 
                || !strcmp("TLSv1", val) 
                || !strcmp("TLSv1.1", val)) {
                ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c, APLOGNO(03050)
                              "h2_h2(%ld): tls protocol not suitable: %s", 
                              (long)c->id, val);
                return 0;
            }
        }
        else if (require_all) {
            ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c, APLOGNO(03051)
                          "h2_h2(%ld): tls protocol is indetermined", (long)c->id);
            return 0;
        }

        if (!strcmp("TLSv1.2", val)) {
            /* Check TLS cipher blacklist, defined pre-TLSv1.3, so only
             * checking for 1.2 */
            val = ap_ssl_var_lookup(pool, s, c, NULL, "SSL_CIPHER");
            if (val && *val) {
                const char *source;
                if (cipher_is_blacklisted(val, &source)) {
                    ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c, APLOGNO(03052)
                                  "h2_h2(%ld): tls cipher %s blacklisted by %s",
                                  (long)c->id, val, source);
                    return 0;
                }
            }
            else if (require_all) {
                ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c, APLOGNO(03053)
                              "h2_h2(%ld): tls cipher is indetermined", (long)c->id);
                return 0;
            }
        }
    }
    return 1;
}

