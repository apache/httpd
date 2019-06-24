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

#ifndef mod_md_md_drive_h
#define mod_md_md_drive_h

struct md_mod_conf_t;
struct md_reg_t;

typedef struct md_drive_ctx md_drive_ctx;

int md_will_renew_cert(const md_t *md);

/**
 * Start driving the certificate procotol for the domains mentioned in mc->watched_names.
 */
apr_status_t md_start_watching(struct md_mod_conf_t *mc, server_rec *s, apr_pool_t *p);




#endif /* mod_md_md_drive_h */
