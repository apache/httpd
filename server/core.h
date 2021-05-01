/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * @file  server/core.h
 * @brief core private declarations
 *
 * @addtogroup APACHE_CORE
 * @{
 */

#ifndef CORE_H
#define CORE_H

/**
 * @brief A structure to contain connection state information
 */
typedef struct conn_config_t {
    /** Socket belonging to the connection */
    apr_socket_t *socket;
} conn_config_t;

#endif /* CORE_H */
/** @} */

