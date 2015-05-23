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

#ifndef MOD_AUTHZ_OWNER_H
#define MOD_AUTHZ_OWNER_H

#include "http_request.h"

/* mod_authz_owner exports an optional function which retrieves the
 * group name of the file identified by r->filename, if available, or
 * else returns NULL. */
APR_DECLARE_OPTIONAL_FN(char*, authz_owner_get_file_group, (request_rec *r));

#endif /* MOD_AUTHZ_OWNER_H */
