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

/**
 * @file mod_proxy_fdpass.h
 * @brief FD Passing interfaces
 *
 * @ingroup APACHE_INTERNAL
 * @{
 */

#include "mod_proxy.h"

#ifndef _PROXY_FDPASS_H_
#define _PROXY_FDPASS_H_

#define PROXY_FDPASS_FLUSHER "proxy_fdpass_flusher"

typedef struct proxy_fdpass_flush proxy_fdpass_flush;
struct proxy_fdpass_flush {
    const char *name;
    int (*flusher)(request_rec *r);
    void *context;
};

#endif /* _PROXY_FDPASS_H_ */
/** @} */

