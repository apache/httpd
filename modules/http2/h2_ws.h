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

#ifndef __mod_h2__h2_ws__
#define __mod_h2__h2_ws__

#include "h2.h"

/**
 * Rewrite a websocket request.
 *
 * @param req the h2 request to rewrite
 * @param c2 the connection to process the request on
 * @param no_body != 0 iff the request is known to have no body
 * @return the websocket request for internal submit
 */
const h2_request *h2_ws_rewrite_request(const h2_request *req,
                                        conn_rec *c2, int no_body);

void h2_ws_register_hooks(void);

#endif /* defined(__mod_h2__h2_ws__) */
