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

#include "apr_xml.h"

#include "httpd.h"
#include "http_protocol.h"
#include "http_log.h"
#include "http_core.h"

#include "util_charset.h"
#include "util_xml.h"


/* used for reading input blocks */
#define READ_BLOCKSIZE 2048


/* we know core's module_index is 0 */
#undef APLOG_MODULE_INDEX
#define APLOG_MODULE_INDEX AP_CORE_MODULE_INDEX

AP_DECLARE(int) ap_xml_parse_input(request_rec * r, apr_xml_doc **pdoc)
{
    apr_xml_parser *parser;
    apr_bucket_brigade *brigade;
    int seen_eos;
    apr_status_t status;
    char errbuf[200];
    apr_size_t total_read = 0;
    apr_size_t limit_xml_body = ap_get_limit_xml_body(r);
    int result = HTTP_BAD_REQUEST;

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
            result = ap_map_http_request_error(status, HTTP_BAD_REQUEST);
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
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(00539)
                              "XML request body is larger than the configured "
                              "limit of %lu", (unsigned long)limit_xml_body);
                result = HTTP_REQUEST_ENTITY_TOO_LARGE;
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
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(00540)
                      "XML parser error (at end). status=%d", status);
        return HTTP_BAD_REQUEST;
    }

#if APR_CHARSET_EBCDIC
    apr_xml_parser_convert_doc(r->pool, *pdoc, ap_hdrs_from_ascii);
#endif
    return OK;

  parser_error:
    (void) apr_xml_parser_geterror(parser, errbuf, sizeof(errbuf));
    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(00541)
                  "XML Parser Error: %s", errbuf);

    /* FALLTHRU */

  read_error:
    /* make sure the parser is terminated */
    (void) apr_xml_parser_done(parser, NULL);

    apr_brigade_destroy(brigade);

    /* Apache will supply a default error, plus the error log above. */
    return result;
}
