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
 */

#include "apr_xml.h"

#include "httpd.h"
#include "http_protocol.h"
#include "http_log.h"
#include "http_core.h"

#include "util_xml.h"


/* used for reading input blocks */
#define READ_BLOCKSIZE 2048


AP_DECLARE(int) ap_xml_parse_input(request_rec * r, apr_xml_doc **pdoc)
{
    apr_xml_parser *parser;
    apr_bucket_brigade *brigade;
    int seen_eos;
    apr_status_t status;
    char errbuf[200];
    apr_size_t total_read = 0;
    apr_size_t limit_xml_body = ap_get_limit_xml_body(r);

    parser = apr_xml_parser_create(r->pool);
    brigade = apr_brigade_create(r->pool, r->connection->bucket_alloc);

    seen_eos = 0;
    total_read = 0;

    do {
        apr_bucket *bucket;

        /* read the body, stuffing it into the parser */
        status = ap_get_brigade(r->input_filters, brigade,
                                AP_MODE_READBYTES, APR_BLOCK_READ,
                                READ_BLOCKSIZE);

        if (status != APR_SUCCESS) {
            goto read_error;
        }

        for (bucket = APR_BRIGADE_FIRST(brigade);
             bucket != APR_BRIGADE_SENTINEL(brigade);
             bucket = APR_BUCKET_NEXT(bucket))
        {
            const char *data;
            apr_size_t len;

            if (APR_BUCKET_IS_EOS(bucket)) {
                seen_eos = 1;
                break;
            }

            if (APR_BUCKET_IS_METADATA(bucket)) {
                continue;
            }

            status = apr_bucket_read(bucket, &data, &len, APR_BLOCK_READ);
            if (status != APR_SUCCESS) {
                goto read_error;
            }

            total_read += len;
            if (limit_xml_body && total_read > limit_xml_body) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                              "XML request body is larger than the configured "
                              "limit of %lu", (unsigned long)limit_xml_body);
                goto read_error;
            }

            status = apr_xml_parser_feed(parser, data, len);
            if (status) {
                goto parser_error;
            }
        }

        apr_brigade_cleanup(brigade);
    } while (!seen_eos);

    apr_brigade_destroy(brigade);

    /* tell the parser that we're done */
    status = apr_xml_parser_done(parser, pdoc);
    if (status) {
        /* Some parsers are stupid and return an error on blank documents. */
        if (!total_read) {
            *pdoc = NULL;
            return OK;
        }
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "XML parser error (at end). status=%d", status);
        return HTTP_BAD_REQUEST;
    }

    return OK;

  parser_error:
    (void) apr_xml_parser_geterror(parser, errbuf, sizeof(errbuf));
    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                  "%s", errbuf);

    /* FALLTHRU */

  read_error:
    /* make sure the parser is terminated */
    (void) apr_xml_parser_done(parser, NULL);

    apr_brigade_destroy(brigade);

    /* Apache will supply a default error, plus the error log above. */
    return HTTP_BAD_REQUEST;
}
