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

#ifndef MOD_AUTHZ_DBD_H
#define MOD_AUTHZ_DBD_H
#include "httpd.h"

/* Create a set of AUTHZ_DBD_DECLARE(type), AUTHZ_DBD_DECLARE_NONSTD(type) and
 * AUTHZ_DBD_DECLARE_DATA with appropriate export and import tags
 */
#if !defined(WIN32)
#define AUTHZ_DBD_DECLARE(type)            type
#define AUTHZ_DBD_DECLARE_NONSTD(type)     type
#define AUTHZ_DBD_DECLARE_DATA
#elif defined(AUTHZ_DBD_DECLARE_STATIC)
#define AUTHZ_DBD_DECLARE(type)            type __stdcall
#define AUTHZ_DBD_DECLARE_NONSTD(type)     type
#define AUTHZ_DBD_DECLARE_DATA
#elif defined(AUTHZ_DBD_DECLARE_EXPORT)
#define AUTHZ_DBD_DECLARE(type)            __declspec(dllexport) type __stdcall
#define AUTHZ_DBD_DECLARE_NONSTD(type)     __declspec(dllexport) type
#define AUTHZ_DBD_DECLARE_DATA             __declspec(dllexport)
#else
#define AUTHZ_DBD_DECLARE(type)            __declspec(dllimport) type __stdcall
#define AUTHZ_DBD_DECLARE_NONSTD(type)     __declspec(dllimport) type
#define AUTHZ_DBD_DECLARE_DATA             __declspec(dllimport)
#endif

APR_DECLARE_EXTERNAL_HOOK(authz_dbd, AUTHZ_DBD, int, client_login,
                          (request_rec *r, int code, const char *action))
#endif
