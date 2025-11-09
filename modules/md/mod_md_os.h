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

#ifndef mod_md_md_os_h
#define mod_md_md_os_h

/**
 * Try chown'ing the file/directory. Give id -1 to not change uid/gid.
 * Will return APR_ENOTIMPL on platforms not supporting this operation.
 */
apr_status_t md_try_chown(const char *fname, unsigned int uid, int gid, apr_pool_t *p);

/**
 * Make a file or directory read/write(/searchable) by httpd workers.
 */
apr_status_t md_make_worker_accessible(const char *fname, apr_pool_t *p);

/**
 * Trigger a graceful restart of the server. Depending on the architecture, may
 * return APR_ENOTIMPL.
 */
apr_status_t md_server_graceful(apr_pool_t *p, server_rec *s);

#endif /* mod_md_md_os_h */
