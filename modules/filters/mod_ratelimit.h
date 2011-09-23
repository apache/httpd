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

#ifndef _MOD_RATELIMIT_H_
#define _MOD_RATELIMIT_H_

/* Create a set of AP_RL_DECLARE(type), AP_RL_DECLARE_NONSTD(type) and
 * AP_RL_DECLARE_DATA with appropriate export and import tags for the platform
 */
#if !defined(WIN32)
#define AP_RL_DECLARE(type)            type
#define AP_RL_DECLARE_NONSTD(type)     type
#define AP_RL_DECLARE_DATA
#elif defined(AP_RL_DECLARE_STATIC)
#define AP_RL_DECLARE(type)            type __stdcall
#define AP_RL_DECLARE_NONSTD(type)     type
#define AP_RL_DECLARE_DATA
#elif defined(AP_RL_DECLARE_EXPORT)
#define AP_RL_DECLARE(type)            __declspec(dllexport) type __stdcall
#define AP_RL_DECLARE_NONSTD(type)     __declspec(dllexport) type
#define AP_RL_DECLARE_DATA             __declspec(dllexport)
#else
#define AP_RL_DECLARE(type)            __declspec(dllimport) type __stdcall
#define AP_RL_DECLARE_NONSTD(type)     __declspec(dllimport) type
#define AP_RL_DECLARE_DATA             __declspec(dllimport)
#endif

AP_RL_DECLARE_DATA extern const apr_bucket_type_t ap_rl_bucket_type_end;
AP_RL_DECLARE_DATA extern const apr_bucket_type_t ap_rl_bucket_type_start;

#define AP_RL_BUCKET_IS_END(e)         (e->type == &ap_rl_bucket_type_end)
#define AP_RL_BUCKET_IS_START(e)         (e->type == &ap_rl_bucket_type_start)

/* TODO: Make these Optional Functions, so that module load order doesn't matter. */
AP_RL_DECLARE(apr_bucket*) ap_rl_end_create(apr_bucket_alloc_t *list);
AP_RL_DECLARE(apr_bucket*) ap_rl_start_create(apr_bucket_alloc_t *list);

#endif
