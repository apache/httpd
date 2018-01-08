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

#include "ap_config.h"

#if APR_CHARSET_EBCDIC

#include "apr_strings.h"
#include "httpd.h"
#include "http_log.h"
#include "http_core.h"
#include "util_ebcdic.h"

/* we know core's module_index is 0 */
#undef APLOG_MODULE_INDEX
#define APLOG_MODULE_INDEX AP_CORE_MODULE_INDEX

apr_status_t ap_init_ebcdic(apr_pool_t *pool)
{
    apr_status_t rv;

    rv = apr_xlate_open(&ap_hdrs_to_ascii, "ISO-8859-1", APR_DEFAULT_CHARSET, pool);
    if (rv) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, NULL, APLOGNO(00040)
                     "apr_xlate_open() failed");
        return rv;
    }

    rv = apr_xlate_open(&ap_hdrs_from_ascii, APR_DEFAULT_CHARSET, "ISO-8859-1", pool);
    if (rv) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, NULL, APLOGNO(00041)
                     "apr_xlate_open() failed");
        return rv;
    }

    rv = apr_MD5InitEBCDIC(ap_hdrs_to_ascii);
    if (rv) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, NULL, APLOGNO(00042)
                     "apr_MD5InitEBCDIC() failed");
        return rv;
    }

    rv = apr_base64init_ebcdic(ap_hdrs_to_ascii, ap_hdrs_from_ascii);
    if (rv) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, NULL, APLOGNO(00043)
                     "apr_base64init_ebcdic() failed");
        return rv;
    }

    rv = apr_SHA1InitEBCDIC(ap_hdrs_to_ascii);
    if (rv) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, NULL, APLOGNO(00044)
                     "apr_SHA1InitEBCDIC() failed");
        return rv;
    }

    return APR_SUCCESS;
}

void ap_xlate_proto_to_ascii(char *buffer, apr_size_t len)
{
    apr_size_t inbytes_left, outbytes_left;

    inbytes_left = outbytes_left = len;
    apr_xlate_conv_buffer(ap_hdrs_to_ascii, buffer, &inbytes_left,
                          buffer, &outbytes_left);
}

void ap_xlate_proto_from_ascii(char *buffer, apr_size_t len)
{
    apr_size_t inbytes_left, outbytes_left;

    inbytes_left = outbytes_left = len;
    apr_xlate_conv_buffer(ap_hdrs_from_ascii, buffer, &inbytes_left,
                          buffer, &outbytes_left);
}

int ap_rvputs_proto_in_ascii(request_rec *r, ...)
{
    va_list va;
    const char *s;
    char *ascii_s;
    apr_size_t len;
    apr_size_t written = 0;

    va_start(va, r);
    while (1) {
        s = va_arg(va, const char *);
        if (s == NULL)
            break;
        len = strlen(s);
        ascii_s = apr_pstrmemdup(r->pool, s, len);
        ap_xlate_proto_to_ascii(ascii_s, len);
        if (ap_rputs(ascii_s, r) < 0) {
            va_end(va);
            return -1;
        }
        written += len;
    }
    va_end(va);

    return written;
}
#endif /* APR_CHARSET_EBCDIC */
