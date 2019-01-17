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

#ifndef __mod_h2__h2_alt_svc__
#define __mod_h2__h2_alt_svc__

typedef struct h2_alt_svc h2_alt_svc;

struct h2_alt_svc {
    const char *alpn;
    const char *host;
    int port;
};

void h2_alt_svc_register_hooks(void);

/**
 * Parse an Alt-Svc specifier as described in "HTTP Alternative Services"
 * (https://tools.ietf.org/html/draft-ietf-httpbis-alt-svc-04)
 * with the following changes:
 * - do not percent encode token values
 * - do not use quotation marks
 */
h2_alt_svc *h2_alt_svc_parse(const char *s, apr_pool_t *pool);


#endif /* defined(__mod_h2__h2_alt_svc__) */
