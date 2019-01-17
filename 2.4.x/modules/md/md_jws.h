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

#ifndef mod_md_md_jws_h
#define mod_md_md_jws_h

struct apr_table_t;
struct md_json_t;
struct md_pkey_t;

apr_status_t md_jws_sign(md_json_t **pmsg, apr_pool_t *p,
                         const char *payload, size_t len, struct apr_table_t *protected, 
                         struct md_pkey_t *pkey, const char *key_id);

apr_status_t md_jws_pkey_thumb(const char **pthumb, apr_pool_t *p, struct md_pkey_t *pkey);

#endif /* md_jws_h */
