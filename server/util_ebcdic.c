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
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Software Foundation.  For more
 * information on the Apache Software Foundation, please see
 * <http://www.apache.org/>.
 *
 * Portions of this software are based upon public domain software
 * originally written at the National Center for Supercomputing Applications,
 * University of Illinois, Urbana-Champaign.
 */

#include "ap_config.h"

#if APR_CHARSET_EBCDIC

#include "apr_strings.h"
#include "httpd.h"
#include "http_log.h"
#include "http_core.h"
#include "util_ebcdic.h"

apr_status_t ap_init_ebcdic(apr_pool_t *pool)
{
    apr_status_t rv;
    char buf[80];

    rv = apr_xlate_open(&ap_hdrs_to_ascii, "ISO8859-1", APR_DEFAULT_CHARSET, pool);
    if (rv) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, NULL,
                     "apr_xlate_open() failed");
        return rv;
    }

    rv = apr_xlate_open(&ap_hdrs_from_ascii, APR_DEFAULT_CHARSET, "ISO8859-1", pool);
    if (rv) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, NULL,
                     "apr_xlate_open() failed");
        return rv;
    }

    rv = apr_xlate_open(&ap_locale_to_ascii, "ISO8859-1", APR_LOCALE_CHARSET, pool);
    if (rv) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, NULL,
                     "apr_xlate_open() failed");
        return rv;
    }

    rv = apr_xlate_open(&ap_locale_from_ascii, APR_LOCALE_CHARSET, "ISO8859-1", pool);
    if (rv) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, NULL,
                     "apr_xlate_open() failed");
        return rv;
    }

    rv = apr_MD5InitEBCDIC(ap_hdrs_to_ascii);
    if (rv) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, NULL,
                     "apr_MD5InitEBCDIC() failed");
        return rv;
    }
    
    rv = apr_base64init_ebcdic(ap_hdrs_to_ascii, ap_hdrs_from_ascii);
    if (rv) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, NULL,
                     "apr_base64init_ebcdic() failed");
        return rv;
    }
    
    rv = apr_SHA1InitEBCDIC(ap_hdrs_to_ascii);
    if (rv) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, NULL,
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
        ascii_s = apr_pstrndup(r->pool, s, len);
        ap_xlate_proto_to_ascii(ascii_s, len);
        if (ap_rputs(ascii_s, r) < 0)
            return -1;
        written += len;
    }
    va_end(va);
 
    return written;
}    
#endif /* APR_CHARSET_EBCDIC */
