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
#include <apr_lib.h>
#include <apr_strings.h>

#include <httpd.h>
#include <http_connection.h>
#include <http_core.h>
#include <http_log.h>

#include <rustls.h>

#include "tls_proto.h"
#include "tls_conf.h"
#include "tls_util.h"

extern module AP_MODULE_DECLARE_DATA tls_module;
APLOG_USE_MODULE(tls);



/**
 * Known cipher as registered in
 * <https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4>
 */
static tls_cipher_t KNOWN_CIPHERS[] = {
    { 0x0000, "TLS_NULL_WITH_NULL_NULL", NULL },
    { 0x0001, "TLS_RSA_WITH_NULL_MD5", NULL },
    { 0x0002, "TLS_RSA_WITH_NULL_SHA", NULL },
    { 0x0003, "TLS_RSA_EXPORT_WITH_RC4_40_MD5", NULL },
    { 0x0004, "TLS_RSA_WITH_RC4_128_MD5", NULL },
    { 0x0005, "TLS_RSA_WITH_RC4_128_SHA", NULL },
    { 0x0006, "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5", NULL },
    { 0x0007, "TLS_RSA_WITH_IDEA_CBC_SHA", NULL },
    { 0x0008, "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA", NULL },
    { 0x0009, "TLS_RSA_WITH_DES_CBC_SHA", NULL },
    { 0x000a, "TLS_RSA_WITH_3DES_EDE_CBC_SHA", NULL },
    { 0x000b, "TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA", NULL },
    { 0x000c, "TLS_DH_DSS_WITH_DES_CBC_SHA", NULL },
    { 0x000d, "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA", NULL },
    { 0x000e, "TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA", NULL },
    { 0x000f, "TLS_DH_RSA_WITH_DES_CBC_SHA", NULL },
    { 0x0010, "TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA", NULL },
    { 0x0011, "TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA", NULL },
    { 0x0012, "TLS_DHE_DSS_WITH_DES_CBC_SHA", NULL },
    { 0x0013, "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA", NULL },
    { 0x0014, "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA", NULL },
    { 0x0015, "TLS_DHE_RSA_WITH_DES_CBC_SHA", NULL },
    { 0x0016, "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA", NULL },
    { 0x0017, "TLS_DH_anon_EXPORT_WITH_RC4_40_MD5", NULL },
    { 0x0018, "TLS_DH_anon_WITH_RC4_128_MD5", NULL },
    { 0x0019, "TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA", NULL },
    { 0x001a, "TLS_DH_anon_WITH_DES_CBC_SHA", NULL },
    { 0x001b, "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA", NULL },
    { 0x001c, "SSL_FORTEZZA_KEA_WITH_NULL_SHA", NULL },
    { 0x001d, "SSL_FORTEZZA_KEA_WITH_FORTEZZA_CBC_SHA", NULL },
    { 0x001e, "TLS_KRB5_WITH_DES_CBC_SHA_or_SSL_FORTEZZA_KEA_WITH_RC4_128_SHA", NULL },
    { 0x001f, "TLS_KRB5_WITH_3DES_EDE_CBC_SHA", NULL },
    { 0x0020, "TLS_KRB5_WITH_RC4_128_SHA", NULL },
    { 0x0021, "TLS_KRB5_WITH_IDEA_CBC_SHA", NULL },
    { 0x0022, "TLS_KRB5_WITH_DES_CBC_MD5", NULL },
    { 0x0023, "TLS_KRB5_WITH_3DES_EDE_CBC_MD5", NULL },
    { 0x0024, "TLS_KRB5_WITH_RC4_128_MD5", NULL },
    { 0x0025, "TLS_KRB5_WITH_IDEA_CBC_MD5", NULL },
    { 0x0026, "TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA", NULL },
    { 0x0027, "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA", NULL },
    { 0x0028, "TLS_KRB5_EXPORT_WITH_RC4_40_SHA", NULL },
    { 0x0029, "TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5", NULL },
    { 0x002a, "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5", NULL },
    { 0x002b, "TLS_KRB5_EXPORT_WITH_RC4_40_MD5", NULL },
    { 0x002c, "TLS_PSK_WITH_NULL_SHA", NULL },
    { 0x002d, "TLS_DHE_PSK_WITH_NULL_SHA", NULL },
    { 0x002e, "TLS_RSA_PSK_WITH_NULL_SHA", NULL },
    { 0x002f, "TLS_RSA_WITH_AES_128_CBC_SHA", NULL },
    { 0x0030, "TLS_DH_DSS_WITH_AES_128_CBC_SHA", NULL },
    { 0x0031, "TLS_DH_RSA_WITH_AES_128_CBC_SHA", NULL },
    { 0x0032, "TLS_DHE_DSS_WITH_AES_128_CBC_SHA", NULL },
    { 0x0033, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA", NULL },
    { 0x0034, "TLS_DH_anon_WITH_AES_128_CBC_SHA", NULL },
    { 0x0035, "TLS_RSA_WITH_AES_256_CBC_SHA", NULL },
    { 0x0036, "TLS_DH_DSS_WITH_AES_256_CBC_SHA", NULL },
    { 0x0037, "TLS_DH_RSA_WITH_AES_256_CBC_SHA", NULL },
    { 0x0038, "TLS_DHE_DSS_WITH_AES_256_CBC_SHA", NULL },
    { 0x0039, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA", NULL },
    { 0x003a, "TLS_DH_anon_WITH_AES_256_CBC_SHA", NULL },
    { 0x003b, "TLS_RSA_WITH_NULL_SHA256", "NULL-SHA256" },
    { 0x003c, "TLS_RSA_WITH_AES_128_CBC_SHA256", "AES128-SHA256" },
    { 0x003d, "TLS_RSA_WITH_AES_256_CBC_SHA256", "AES256-SHA256" },
    { 0x003e, "TLS_DH_DSS_WITH_AES_128_CBC_SHA256", "DH-DSS-AES128-SHA256" },
    { 0x003f, "TLS_DH_RSA_WITH_AES_128_CBC_SHA256", "DH-RSA-AES128-SHA256" },
    { 0x0040, "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256", "DHE-DSS-AES128-SHA256" },
    { 0x0041, "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA", NULL },
    { 0x0042, "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA", NULL },
    { 0x0043, "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA", NULL },
    { 0x0044, "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA", NULL },
    { 0x0045, "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA", NULL },
    { 0x0046, "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA", NULL },
    { 0x0047, "TLS_ECDH_ECDSA_WITH_NULL_SHA_draft", NULL },
    { 0x0048, "TLS_ECDH_ECDSA_WITH_RC4_128_SHA_draft", NULL },
    { 0x0049, "TLS_ECDH_ECDSA_WITH_DES_CBC_SHA_draft", NULL },
    { 0x004a, "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA_draft", NULL },
    { 0x004b, "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA_draft", NULL },
    { 0x004c, "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA_draft", NULL },
    { 0x004d, "TLS_ECDH_ECNRA_WITH_DES_CBC_SHA_draft", NULL },
    { 0x004e, "TLS_ECDH_ECNRA_WITH_3DES_EDE_CBC_SHA_draft", NULL },
    { 0x004f, "TLS_ECMQV_ECDSA_NULL_SHA_draft", NULL },
    { 0x0050, "TLS_ECMQV_ECDSA_WITH_RC4_128_SHA_draft", NULL },
    { 0x0051, "TLS_ECMQV_ECDSA_WITH_DES_CBC_SHA_draft", NULL },
    { 0x0052, "TLS_ECMQV_ECDSA_WITH_3DES_EDE_CBC_SHA_draft", NULL },
    { 0x0053, "TLS_ECMQV_ECNRA_NULL_SHA_draft", NULL },
    { 0x0054, "TLS_ECMQV_ECNRA_WITH_RC4_128_SHA_draft", NULL },
    { 0x0055, "TLS_ECMQV_ECNRA_WITH_DES_CBC_SHA_draft", NULL },
    { 0x0056, "TLS_ECMQV_ECNRA_WITH_3DES_EDE_CBC_SHA_draft", NULL },
    { 0x0057, "TLS_ECDH_anon_NULL_WITH_SHA_draft", NULL },
    { 0x0058, "TLS_ECDH_anon_WITH_RC4_128_SHA_draft", NULL },
    { 0x0059, "TLS_ECDH_anon_WITH_DES_CBC_SHA_draft", NULL },
    { 0x005a, "TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA_draft", NULL },
    { 0x005b, "TLS_ECDH_anon_EXPORT_WITH_DES40_CBC_SHA_draft", NULL },
    { 0x005c, "TLS_ECDH_anon_EXPORT_WITH_RC4_40_SHA_draft", NULL },
    { 0x0060, "TLS_RSA_EXPORT1024_WITH_RC4_56_MD5", NULL },
    { 0x0061, "TLS_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5", NULL },
    { 0x0062, "TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA", NULL },
    { 0x0063, "TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA", NULL },
    { 0x0064, "TLS_RSA_EXPORT1024_WITH_RC4_56_SHA", NULL },
    { 0x0065, "TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA", NULL },
    { 0x0066, "TLS_DHE_DSS_WITH_RC4_128_SHA", NULL },
    { 0x0067, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256", "DHE-RSA-AES128-SHA256" },
    { 0x0068, "TLS_DH_DSS_WITH_AES_256_CBC_SHA256", "DH-DSS-AES256-SHA256" },
    { 0x0069, "TLS_DH_RSA_WITH_AES_256_CBC_SHA256", "DH-RSA-AES256-SHA256" },
    { 0x006a, "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256", "DHE-DSS-AES256-SHA256" },
    { 0x006b, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256", "DHE-RSA-AES256-SHA256" },
    { 0x006c, "TLS_DH_anon_WITH_AES_128_CBC_SHA256", "ADH-AES128-SHA256" },
    { 0x006d, "TLS_DH_anon_WITH_AES_256_CBC_SHA256", "ADH-AES256-SHA256" },
    { 0x0072, "TLS_DHE_DSS_WITH_3DES_EDE_CBC_RMD", NULL },
    { 0x0073, "TLS_DHE_DSS_WITH_AES_128_CBC_RMD", NULL },
    { 0x0074, "TLS_DHE_DSS_WITH_AES_256_CBC_RMD", NULL },
    { 0x0077, "TLS_DHE_RSA_WITH_3DES_EDE_CBC_RMD", NULL },
    { 0x0078, "TLS_DHE_RSA_WITH_AES_128_CBC_RMD", NULL },
    { 0x0079, "TLS_DHE_RSA_WITH_AES_256_CBC_RMD", NULL },
    { 0x007c, "TLS_RSA_WITH_3DES_EDE_CBC_RMD", NULL },
    { 0x007d, "TLS_RSA_WITH_AES_128_CBC_RMD", NULL },
    { 0x007e, "TLS_RSA_WITH_AES_256_CBC_RMD", NULL },
    { 0x0080, "TLS_GOSTR341094_WITH_28147_CNT_IMIT", NULL },
    { 0x0081, "TLS_GOSTR341001_WITH_28147_CNT_IMIT", NULL },
    { 0x0082, "TLS_GOSTR341094_WITH_NULL_GOSTR3411", NULL },
    { 0x0083, "TLS_GOSTR341001_WITH_NULL_GOSTR3411", NULL },
    { 0x0084, "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA", NULL },
    { 0x0085, "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA", NULL },
    { 0x0086, "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA", NULL },
    { 0x0087, "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA", NULL },
    { 0x0088, "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA", NULL },
    { 0x0089, "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA", NULL },
    { 0x008a, "TLS_PSK_WITH_RC4_128_SHA", "PSK-RC4-SHA" },
    { 0x008b, "TLS_PSK_WITH_3DES_EDE_CBC_SHA", "PSK-3DES-EDE-CBC-SHA" },
    { 0x008c, "TLS_PSK_WITH_AES_128_CBC_SHA", NULL },
    { 0x008d, "TLS_PSK_WITH_AES_256_CBC_SHA", NULL },
    { 0x008e, "TLS_DHE_PSK_WITH_RC4_128_SHA", NULL },
    { 0x008f, "TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA", NULL },
    { 0x0090, "TLS_DHE_PSK_WITH_AES_128_CBC_SHA", NULL },
    { 0x0091, "TLS_DHE_PSK_WITH_AES_256_CBC_SHA", NULL },
    { 0x0092, "TLS_RSA_PSK_WITH_RC4_128_SHA", NULL },
    { 0x0093, "TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA", NULL },
    { 0x0094, "TLS_RSA_PSK_WITH_AES_128_CBC_SHA", NULL },
    { 0x0095, "TLS_RSA_PSK_WITH_AES_256_CBC_SHA", NULL },
    { 0x0096, "TLS_RSA_WITH_SEED_CBC_SHA", NULL },
    { 0x0097, "TLS_DH_DSS_WITH_SEED_CBC_SHA", NULL },
    { 0x0098, "TLS_DH_RSA_WITH_SEED_CBC_SHA", NULL },
    { 0x0099, "TLS_DHE_DSS_WITH_SEED_CBC_SHA", NULL },
    { 0x009a, "TLS_DHE_RSA_WITH_SEED_CBC_SHA", NULL },
    { 0x009b, "TLS_DH_anon_WITH_SEED_CBC_SHA", NULL },
    { 0x009c, "TLS_RSA_WITH_AES_128_GCM_SHA256", "AES128-GCM-SHA256" },
    { 0x009d, "TLS_RSA_WITH_AES_256_GCM_SHA384", "AES256-GCM-SHA384" },
    { 0x009e, "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", "DHE-RSA-AES128-GCM-SHA256" },
    { 0x009f, "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384", "DHE-RSA-AES256-GCM-SHA384" },
    { 0x00a0, "TLS_DH_RSA_WITH_AES_128_GCM_SHA256", "DH-RSA-AES128-GCM-SHA256" },
    { 0x00a1, "TLS_DH_RSA_WITH_AES_256_GCM_SHA384", "DH-RSA-AES256-GCM-SHA384" },
    { 0x00a2, "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256", "DHE-DSS-AES128-GCM-SHA256" },
    { 0x00a3, "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384", "DHE-DSS-AES256-GCM-SHA384" },
    { 0x00a4, "TLS_DH_DSS_WITH_AES_128_GCM_SHA256", "DH-DSS-AES128-GCM-SHA256" },
    { 0x00a5, "TLS_DH_DSS_WITH_AES_256_GCM_SHA384", "DH-DSS-AES256-GCM-SHA384" },
    { 0x00a6, "TLS_DH_anon_WITH_AES_128_GCM_SHA256", "ADH-AES128-GCM-SHA256" },
    { 0x00a7, "TLS_DH_anon_WITH_AES_256_GCM_SHA384", "ADH-AES256-GCM-SHA384" },
    { 0x00a8, "TLS_PSK_WITH_AES_128_GCM_SHA256", NULL },
    { 0x00a9, "TLS_PSK_WITH_AES_256_GCM_SHA384", NULL },
    { 0x00aa, "TLS_DHE_PSK_WITH_AES_128_GCM_SHA256", NULL },
    { 0x00ab, "TLS_DHE_PSK_WITH_AES_256_GCM_SHA384", NULL },
    { 0x00ac, "TLS_RSA_PSK_WITH_AES_128_GCM_SHA256", NULL },
    { 0x00ad, "TLS_RSA_PSK_WITH_AES_256_GCM_SHA384", NULL },
    { 0x00ae, "TLS_PSK_WITH_AES_128_CBC_SHA256", "PSK-AES128-CBC-SHA" },
    { 0x00af, "TLS_PSK_WITH_AES_256_CBC_SHA384", "PSK-AES256-CBC-SHA" },
    { 0x00b0, "TLS_PSK_WITH_NULL_SHA256", NULL },
    { 0x00b1, "TLS_PSK_WITH_NULL_SHA384", NULL },
    { 0x00b2, "TLS_DHE_PSK_WITH_AES_128_CBC_SHA256", NULL },
    { 0x00b3, "TLS_DHE_PSK_WITH_AES_256_CBC_SHA384", NULL },
    { 0x00b4, "TLS_DHE_PSK_WITH_NULL_SHA256", NULL },
    { 0x00b5, "TLS_DHE_PSK_WITH_NULL_SHA384", NULL },
    { 0x00b6, "TLS_RSA_PSK_WITH_AES_128_CBC_SHA256", NULL },
    { 0x00b7, "TLS_RSA_PSK_WITH_AES_256_CBC_SHA384", NULL },
    { 0x00b8, "TLS_RSA_PSK_WITH_NULL_SHA256", NULL },
    { 0x00b9, "TLS_RSA_PSK_WITH_NULL_SHA384", NULL },
    { 0x00ba, "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256", NULL },
    { 0x00bb, "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256", NULL },
    { 0x00bc, "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256", NULL },
    { 0x00bd, "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256", NULL },
    { 0x00be, "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256", NULL },
    { 0x00bf, "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256", NULL },
    { 0x00c0, "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256", NULL },
    { 0x00c1, "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256", NULL },
    { 0x00c2, "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256", NULL },
    { 0x00c3, "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256", NULL },
    { 0x00c4, "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256", NULL },
    { 0x00c5, "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256", NULL },
    { 0x00ff, "TLS_EMPTY_RENEGOTIATION_INFO_SCSV", NULL },
    { 0x1301, "TLS_AES_128_GCM_SHA256", "TLS13_AES_128_GCM_SHA256" },
    { 0x1302, "TLS_AES_256_GCM_SHA384", "TLS13_AES_256_GCM_SHA384" },
    { 0x1303, "TLS_CHACHA20_POLY1305_SHA256", "TLS13_CHACHA20_POLY1305_SHA256" },
    { 0x1304, "TLS_AES_128_CCM_SHA256", "TLS13_AES_128_CCM_SHA256" },
    { 0x1305, "TLS_AES_128_CCM_8_SHA256", "TLS13_AES_128_CCM_8_SHA256" },
    { 0xc001, "TLS_ECDH_ECDSA_WITH_NULL_SHA", NULL },
    { 0xc002, "TLS_ECDH_ECDSA_WITH_RC4_128_SHA", NULL },
    { 0xc003, "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA", NULL },
    { 0xc004, "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA", NULL },
    { 0xc005, "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA", NULL },
    { 0xc006, "TLS_ECDHE_ECDSA_WITH_NULL_SHA", NULL },
    { 0xc007, "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA", NULL },
    { 0xc008, "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA", NULL },
    { 0xc009, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", NULL },
    { 0xc00a, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA", NULL },
    { 0xc00b, "TLS_ECDH_RSA_WITH_NULL_SHA", NULL },
    { 0xc00c, "TLS_ECDH_RSA_WITH_RC4_128_SHA", NULL },
    { 0xc00d, "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA", NULL },
    { 0xc00e, "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA", NULL },
    { 0xc00f, "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA", NULL },
    { 0xc010, "TLS_ECDHE_RSA_WITH_NULL_SHA", NULL },
    { 0xc011, "TLS_ECDHE_RSA_WITH_RC4_128_SHA", NULL },
    { 0xc012, "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA", NULL },
    { 0xc013, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", NULL },
    { 0xc014, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", NULL },
    { 0xc015, "TLS_ECDH_anon_WITH_NULL_SHA", NULL },
    { 0xc016, "TLS_ECDH_anon_WITH_RC4_128_SHA", NULL },
    { 0xc017, "TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA", NULL },
    { 0xc018, "TLS_ECDH_anon_WITH_AES_128_CBC_SHA", NULL },
    { 0xc019, "TLS_ECDH_anon_WITH_AES_256_CBC_SHA", NULL },
    { 0xc01a, "TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA", NULL },
    { 0xc01b, "TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA", NULL },
    { 0xc01c, "TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA", NULL },
    { 0xc01d, "TLS_SRP_SHA_WITH_AES_128_CBC_SHA", NULL },
    { 0xc01e, "TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA", NULL },
    { 0xc01f, "TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA", NULL },
    { 0xc020, "TLS_SRP_SHA_WITH_AES_256_CBC_SHA", NULL },
    { 0xc021, "TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA", NULL },
    { 0xc022, "TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA", NULL },
    { 0xc023, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", "ECDHE-ECDSA-AES128-SHA256" },
    { 0xc024, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384", "ECDHE-ECDSA-AES256-SHA384" },
    { 0xc025, "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256", "ECDH-ECDSA-AES128-SHA256" },
    { 0xc026, "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384", "ECDH-ECDSA-AES256-SHA384" },
    { 0xc027, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", "ECDHE-RSA-AES128-SHA256" },
    { 0xc028, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384", "ECDHE-RSA-AES256-SHA384" },
    { 0xc029, "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256", "ECDH-RSA-AES128-SHA256" },
    { 0xc02a, "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384", "ECDH-RSA-AES256-SHA384" },
    { 0xc02b, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "ECDHE-ECDSA-AES128-GCM-SHA256" },
    { 0xc02c, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", "ECDHE-ECDSA-AES256-GCM-SHA384" },
    { 0xc02d, "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256", "ECDH-ECDSA-AES128-GCM-SHA256" },
    { 0xc02e, "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384", "ECDH-ECDSA-AES256-GCM-SHA384" },
    { 0xc02f, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "ECDHE-RSA-AES128-GCM-SHA256" },
    { 0xc030, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "ECDHE-RSA-AES256-GCM-SHA384" },
    { 0xc031, "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256", "ECDH-RSA-AES128-GCM-SHA256" },
    { 0xc032, "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384", "ECDH-RSA-AES256-GCM-SHA384" },
    { 0xc033, "TLS_ECDHE_PSK_WITH_RC4_128_SHA", NULL },
    { 0xc034, "TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA", NULL },
    { 0xc035, "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA", NULL },
    { 0xc036, "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA", NULL },
    { 0xc037, "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256", NULL },
    { 0xc038, "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384", NULL },
    { 0xc039, "TLS_ECDHE_PSK_WITH_NULL_SHA", NULL },
    { 0xc03a, "TLS_ECDHE_PSK_WITH_NULL_SHA256", NULL },
    { 0xc03b, "TLS_ECDHE_PSK_WITH_NULL_SHA384", NULL },
    { 0xc03c, "TLS_RSA_WITH_ARIA_128_CBC_SHA256", NULL },
    { 0xc03d, "TLS_RSA_WITH_ARIA_256_CBC_SHA384", NULL },
    { 0xc03e, "TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256", NULL },
    { 0xc03f, "TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384", NULL },
    { 0xc040, "TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256", NULL },
    { 0xc041, "TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384", NULL },
    { 0xc042, "TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256", NULL },
    { 0xc043, "TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384", NULL },
    { 0xc044, "TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256", NULL },
    { 0xc045, "TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384", NULL },
    { 0xc046, "TLS_DH_anon_WITH_ARIA_128_CBC_SHA256", NULL },
    { 0xc047, "TLS_DH_anon_WITH_ARIA_256_CBC_SHA384", NULL },
    { 0xc048, "TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256", NULL },
    { 0xc049, "TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384", NULL },
    { 0xc04a, "TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256", NULL },
    { 0xc04b, "TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384", NULL },
    { 0xc04c, "TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256", NULL },
    { 0xc04d, "TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384", NULL },
    { 0xc04e, "TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256", NULL },
    { 0xc04f, "TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384", NULL },
    { 0xc050, "TLS_RSA_WITH_ARIA_128_GCM_SHA256", NULL },
    { 0xc051, "TLS_RSA_WITH_ARIA_256_GCM_SHA384", NULL },
    { 0xc052, "TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256", NULL },
    { 0xc053, "TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384", NULL },
    { 0xc054, "TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256", NULL },
    { 0xc055, "TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384", NULL },
    { 0xc056, "TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256", NULL },
    { 0xc057, "TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384", NULL },
    { 0xc058, "TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256", NULL },
    { 0xc059, "TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384", NULL },
    { 0xc05a, "TLS_DH_anon_WITH_ARIA_128_GCM_SHA256", NULL },
    { 0xc05b, "TLS_DH_anon_WITH_ARIA_256_GCM_SHA384", NULL },
    { 0xc05c, "TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256", NULL },
    { 0xc05d, "TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384", NULL },
    { 0xc05e, "TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256", NULL },
    { 0xc05f, "TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384", NULL },
    { 0xc060, "TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256", NULL },
    { 0xc061, "TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384", NULL },
    { 0xc062, "TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256", NULL },
    { 0xc063, "TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384", NULL },
    { 0xc064, "TLS_PSK_WITH_ARIA_128_CBC_SHA256", NULL },
    { 0xc065, "TLS_PSK_WITH_ARIA_256_CBC_SHA384", NULL },
    { 0xc066, "TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256", NULL },
    { 0xc067, "TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384", NULL },
    { 0xc068, "TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256", NULL },
    { 0xc069, "TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384", NULL },
    { 0xc06a, "TLS_PSK_WITH_ARIA_128_GCM_SHA256", NULL },
    { 0xc06b, "TLS_PSK_WITH_ARIA_256_GCM_SHA384", NULL },
    { 0xc06c, "TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256", NULL },
    { 0xc06d, "TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384", NULL },
    { 0xc06e, "TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256", NULL },
    { 0xc06f, "TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384", NULL },
    { 0xc070, "TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256", NULL },
    { 0xc071, "TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384", NULL },
    { 0xc072, "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256", NULL },
    { 0xc073, "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384", NULL },
    { 0xc074, "TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256", NULL },
    { 0xc075, "TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384", NULL },
    { 0xc076, "TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256", NULL },
    { 0xc077, "TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384", NULL },
    { 0xc078, "TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256", NULL },
    { 0xc079, "TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384", NULL },
    { 0xc07a, "TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256", NULL },
    { 0xc07b, "TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384", NULL },
    { 0xc07c, "TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256", NULL },
    { 0xc07d, "TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384", NULL },
    { 0xc07e, "TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256", NULL },
    { 0xc07f, "TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384", NULL },
    { 0xc080, "TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256", NULL },
    { 0xc081, "TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384", NULL },
    { 0xc082, "TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256", NULL },
    { 0xc083, "TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384", NULL },
    { 0xc084, "TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256", NULL },
    { 0xc085, "TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384", NULL },
    { 0xc086, "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256", NULL },
    { 0xc087, "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384", NULL },
    { 0xc088, "TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256", NULL },
    { 0xc089, "TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384", NULL },
    { 0xc08a, "TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256", NULL },
    { 0xc08b, "TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384", NULL },
    { 0xc08c, "TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256", NULL },
    { 0xc08d, "TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384", NULL },
    { 0xc08e, "TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256", NULL },
    { 0xc08f, "TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384", NULL },
    { 0xc090, "TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256", NULL },
    { 0xc091, "TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384", NULL },
    { 0xc092, "TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256", NULL },
    { 0xc093, "TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384", NULL },
    { 0xc094, "TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256", NULL },
    { 0xc095, "TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384", NULL },
    { 0xc096, "TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256", NULL },
    { 0xc097, "TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384", NULL },
    { 0xc098, "TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256", NULL },
    { 0xc099, "TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384", NULL },
    { 0xc09a, "TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256", NULL },
    { 0xc09b, "TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384", NULL },
    { 0xc09c, "TLS_RSA_WITH_AES_128_CCM", NULL },
    { 0xc09d, "TLS_RSA_WITH_AES_256_CCM", NULL },
    { 0xc09e, "TLS_DHE_RSA_WITH_AES_128_CCM", NULL },
    { 0xc09f, "TLS_DHE_RSA_WITH_AES_256_CCM", NULL },
    { 0xc0a0, "TLS_RSA_WITH_AES_128_CCM_8", NULL },
    { 0xc0a1, "TLS_RSA_WITH_AES_256_CCM_8", NULL },
    { 0xc0a2, "TLS_DHE_RSA_WITH_AES_128_CCM_8", NULL },
    { 0xc0a3, "TLS_DHE_RSA_WITH_AES_256_CCM_8", NULL },
    { 0xc0a4, "TLS_PSK_WITH_AES_128_CCM", NULL },
    { 0xc0a5, "TLS_PSK_WITH_AES_256_CCM", NULL },
    { 0xc0a6, "TLS_DHE_PSK_WITH_AES_128_CCM", NULL },
    { 0xc0a7, "TLS_DHE_PSK_WITH_AES_256_CCM", NULL },
    { 0xc0a8, "TLS_PSK_WITH_AES_128_CCM_8", NULL },
    { 0xc0a9, "TLS_PSK_WITH_AES_256_CCM_8", NULL },
    { 0xc0aa, "TLS_PSK_DHE_WITH_AES_128_CCM_8", NULL },
    { 0xc0ab, "TLS_PSK_DHE_WITH_AES_256_CCM_8", NULL },
    { 0xcca8, "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", "ECDHE-RSA-CHACHA20-POLY1305" },
    { 0xcca9, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", "ECDHE-ECDSA-CHACHA20-POLY1305" },
    { 0xccaa, "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256", "DHE-RSA-CHACHA20-POLY1305" },
    { 0xccab, "TLS_PSK_WITH_CHACHA20_POLY1305_SHA256", "PSK-CHACHA20-POLY1305" },
    { 0xccac, "TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256", "ECDHE-PSK-CHACHA20-POLY1305" },
    { 0xccad, "TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256", "DHE-PSK-CHACHA20-POLY1305" },
    { 0xccae, "TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256", "RSA-PSK-CHACHA20-POLY1305" },
    { 0xfefe, "SSL_RSA_FIPS_WITH_DES_CBC_SHA", NULL },
    { 0xfeff, "SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA", NULL },
};

typedef struct {
    apr_uint16_t id;
    const rustls_supported_ciphersuite *rustls_suite;
} rustls_cipher_t;

tls_proto_conf_t *tls_proto_init(apr_pool_t *pool, server_rec *s)
{
    tls_proto_conf_t *conf;
    tls_cipher_t *cipher;
    const rustls_supported_ciphersuite *rustls_suite;
    rustls_cipher_t *rcipher;
    apr_uint16_t id;
    apr_size_t i;

    (void)s;
    conf = apr_pcalloc(pool, sizeof(*conf));

    conf->supported_versions = apr_array_make(pool, 3, sizeof(apr_uint16_t));
    /* Until we can look that up at crustls, we assume what we currently know */
    APR_ARRAY_PUSH(conf->supported_versions, apr_uint16_t) = TLS_VERSION_1_2;
    APR_ARRAY_PUSH(conf->supported_versions, apr_uint16_t) = TLS_VERSION_1_3;

    conf->known_ciphers_by_name = apr_hash_make(pool);
    conf->known_ciphers_by_id = apr_hash_make(pool);
    for (i = 0; i < TLS_DIM(KNOWN_CIPHERS); ++i) {
        cipher = &KNOWN_CIPHERS[i];
        apr_hash_set(conf->known_ciphers_by_id, &cipher->id, sizeof(apr_uint16_t), cipher);
        apr_hash_set(conf->known_ciphers_by_name, cipher->name, APR_HASH_KEY_STRING, cipher);
        if (cipher->alias) {
            apr_hash_set(conf->known_ciphers_by_name, cipher->alias, APR_HASH_KEY_STRING, cipher);
        }
    }

    conf->supported_cipher_ids = apr_array_make(pool, 10, sizeof(apr_uint16_t));
    conf->rustls_ciphers_by_id = apr_hash_make(pool);
    i = 0;
    while ((rustls_suite = rustls_all_ciphersuites_get_entry(i++))) {
        id = rustls_supported_ciphersuite_get_suite(rustls_suite);
        rcipher = apr_pcalloc(pool, sizeof(*rcipher));
        rcipher->id = id;
        rcipher->rustls_suite = rustls_suite;
        APR_ARRAY_PUSH(conf->supported_cipher_ids, apr_uint16_t) = id;
        apr_hash_set(conf->rustls_ciphers_by_id, &rcipher->id, sizeof(apr_uint16_t), rcipher);

    }

    return conf;
}

const char *tls_proto_get_cipher_names(
    tls_proto_conf_t *conf, const apr_array_header_t *ciphers, apr_pool_t *pool)
{
    apr_array_header_t *names;
    int n;

    names = apr_array_make(pool, ciphers->nelts, sizeof(const char*));
    for (n = 0; n < ciphers->nelts; ++n) {
        apr_uint16_t id = APR_ARRAY_IDX(ciphers, n, apr_uint16_t);
        APR_ARRAY_PUSH(names, const char *) = tls_proto_get_cipher_name(conf, id, pool);
    }
    return apr_array_pstrcat(pool, names, ':');
}

apr_status_t tls_proto_pre_config(apr_pool_t *pool, apr_pool_t *ptemp)
{
    (void)pool;
    (void)ptemp;
    return APR_SUCCESS;
}

apr_status_t tls_proto_post_config(apr_pool_t *pool, apr_pool_t *ptemp, server_rec *s)
{
    tls_conf_server_t *sc = tls_conf_server_get(s);
    tls_proto_conf_t *conf = sc->global->proto;

    (void)pool;
    if (APLOGdebug(s)) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO(10314)
                     "tls ciphers supported: %s",
                     tls_proto_get_cipher_names(conf, conf->supported_cipher_ids, ptemp));
    }
    return APR_SUCCESS;
}

static apr_status_t get_uint16_from(const char *name, const char *prefix, apr_uint16_t *pint)
{
    apr_size_t plen = strlen(prefix);
    if (strlen(name) == plen+4 && !strncmp(name, prefix, plen)) {
        /* may be a hex notation cipher id */
        char *end = NULL;
        apr_int64_t code = apr_strtoi64(name + plen, &end, 16);
        if ((!end || !*end) && code && code <= APR_UINT16_MAX) {
            *pint = (apr_uint16_t)code;
            return APR_SUCCESS;
        }
    }
    return APR_ENOENT;
}

apr_uint16_t tls_proto_get_version_by_name(tls_proto_conf_t *conf, const char *name)
{
    apr_uint16_t version;
    (void)conf;
    if (!apr_strnatcasecmp(name, "TLSv1.2")) {
        return TLS_VERSION_1_2;
    }
    else if (!apr_strnatcasecmp(name, "TLSv1.3")) {
        return TLS_VERSION_1_3;
    }
    if (APR_SUCCESS == get_uint16_from(name, "TLSv0x", &version)) {
        return version;
    }
    return 0;
}

const char *tls_proto_get_version_name(
    tls_proto_conf_t *conf, apr_uint16_t id, apr_pool_t *pool)
{
    (void)conf;
    switch (id) {
    case TLS_VERSION_1_2:
        return "TLSv1.2";
    case TLS_VERSION_1_3:
        return "TLSv1.3";
    default:
        return apr_psprintf(pool, "TLSv0x%04x", id);
    }
}

apr_array_header_t *tls_proto_create_versions_plus(
    tls_proto_conf_t *conf, apr_uint16_t min_version, apr_pool_t *pool)
{
    apr_array_header_t *versions = apr_array_make(pool, 3, sizeof(apr_uint16_t));
    apr_uint16_t version;
    int i;

    for (i = 0; i < conf->supported_versions->nelts; ++i) {
        version = APR_ARRAY_IDX(conf->supported_versions, i, apr_uint16_t);
        if (version >= min_version) {
            APR_ARRAY_PUSH(versions, apr_uint16_t) = version;
        }
    }
    return versions;
}

int tls_proto_is_cipher_supported(tls_proto_conf_t *conf, apr_uint16_t cipher)
{
    return tls_util_array_uint16_contains(conf->supported_cipher_ids, cipher);
}

apr_status_t tls_proto_get_cipher_by_name(
    tls_proto_conf_t *conf, const char *name, apr_uint16_t *pcipher)
{
    tls_cipher_t *cipher = apr_hash_get(conf->known_ciphers_by_name, name, APR_HASH_KEY_STRING);
    if (cipher) {
        *pcipher = cipher->id;
        return APR_SUCCESS;
    }
    return get_uint16_from(name, "TLS_CIPHER_0x", pcipher);
}

const char *tls_proto_get_cipher_name(
    tls_proto_conf_t *conf, apr_uint16_t id, apr_pool_t *pool)
{
    tls_cipher_t *cipher = apr_hash_get(conf->known_ciphers_by_id, &id, sizeof(apr_uint16_t));
    if (cipher) {
        return cipher->name;
    }
    return apr_psprintf(pool, "TLS_CIPHER_0x%04x", id);
}

apr_array_header_t *tls_proto_get_rustls_suites(
    tls_proto_conf_t *conf, const apr_array_header_t *ids, apr_pool_t *pool)
{
    apr_array_header_t *suites;
    rustls_cipher_t *rcipher;
    apr_uint16_t id;
    int i;

    suites = apr_array_make(pool, ids->nelts, sizeof(const rustls_supported_ciphersuite*));
    for (i = 0; i < ids->nelts; ++i) {
        id = APR_ARRAY_IDX(ids, i, apr_uint16_t);
        rcipher = apr_hash_get(conf->rustls_ciphers_by_id, &id, sizeof(apr_uint16_t));
        if (rcipher) {
            APR_ARRAY_PUSH(suites, const rustls_supported_ciphersuite *) = rcipher->rustls_suite;
        }
    }
    return suites;
}
