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

AP_DECLARE_DATA extern const apr_bucket_type_t rl_bucket_type_end;
AP_DECLARE_DATA extern const apr_bucket_type_t rl_bucket_type_start;

#define RL_BUCKET_IS_END(e)         (e->type == &rl_bucket_type_end)
#define RL_BUCKET_IS_START(e)         (e->type == &rl_bucket_type_start)

/* TODO: Make these Optional Functions, so that module load order doesn't matter. */
apr_bucket* rl_end_create(apr_bucket_alloc_t *list);
apr_bucket* rl_start_create(apr_bucket_alloc_t *list);

#endif
