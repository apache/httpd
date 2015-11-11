/* Copyright 2015 greenbytes GmbH (https://www.greenbytes.de)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <assert.h>
#include <stdio.h>

#include <apr_strings.h>

#include <httpd.h>
#include <http_core.h>
#include <http_log.h>

#include "h2_private.h"
#include "h2_h2.h"
#include "h2_util.h"
#include "h2_push.h"
#include "h2_request.h"
#include "h2_response.h"


typedef struct {
    apr_array_header_t *pushes;
    apr_pool_t *pool;
    const h2_request *req;
} link_ctx;

static size_t skip_ws(const char *s, size_t i, size_t max)
{
    char c;
    while (i < max && (((c = s[i]) == ' ') || (c == '\t'))) {
        ++i;
    }
    return i;
}

static void inspect_link(link_ctx *ctx, const char *s, size_t slen)
{
    /* RFC 5988 <https://tools.ietf.org/html/rfc5988#section-6.2.1>
      Link           = "Link" ":" #link-value
      link-value     = "<" URI-Reference ">" *( ";" link-param )
      link-param     = ( ( "rel" "=" relation-types )
                     | ( "anchor" "=" <"> URI-Reference <"> )
                     | ( "rev" "=" relation-types )
                     | ( "hreflang" "=" Language-Tag )
                     | ( "media" "=" ( MediaDesc | ( <"> MediaDesc <"> ) ) )
                     | ( "title" "=" quoted-string )
                     | ( "title*" "=" ext-value )
                     | ( "type" "=" ( media-type | quoted-mt ) )
                     | ( link-extension ) )
      link-extension = ( parmname [ "=" ( ptoken | quoted-string ) ] )
                     | ( ext-name-star "=" ext-value )
      ext-name-star  = parmname "*" ; reserved for RFC2231-profiled
                                    ; extensions.  Whitespace NOT
                                    ; allowed in between.
      ptoken         = 1*ptokenchar
      ptokenchar     = "!" | "#" | "$" | "%" | "&" | "'" | "("
                     | ")" | "*" | "+" | "-" | "." | "/" | DIGIT
                     | ":" | "<" | "=" | ">" | "?" | "@" | ALPHA
                     | "[" | "]" | "^" | "_" | "`" | "{" | "|"
                     | "}" | "~"
      media-type     = type-name "/" subtype-name
      quoted-mt      = <"> media-type <">
      relation-types = relation-type
                     | <"> relation-type *( 1*SP relation-type ) <">
      relation-type  = reg-rel-type | ext-rel-type
      reg-rel-type   = LOALPHA *( LOALPHA | DIGIT | "." | "-" )
      ext-rel-type   = URI
     */
     /* TODO */
     (void)skip_ws;
}

apr_array_header_t *h2_push_collect(apr_pool_t *p, const h2_request *req, 
                                    const h2_response *res)
{
    link_ctx ctx;
    
    ctx.pushes = NULL;
    ctx.pool = p;
    ctx.req = req;
    
    /* Collect push candidates from the request/response pair.
     * 
     * One source for pushes are "rel=preload" link headers
     * in the response.
     * 
     * TODO: This may be extended in the future by hooks or callbacks
     * where other modules can provide push information directly.
     */
    if (res->ngheader) {
        int i;
        for (i = 0; i < res->ngheader->nvlen; ++i) {
            nghttp2_nv *nv = &res->ngheader->nv[i];
            if (nv->namelen == 4 
                && apr_strnatcasecmp("link", (const char *)nv->name)) {
                inspect_link(&ctx, (const char *)nv->value, nv->valuelen);
            }
        }
    }
    
    return ctx.pushes;
}
