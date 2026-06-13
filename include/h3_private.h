/*
 * Copyright (c) 2026 The mod_http3 Project Authors. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef H3_PRIVATE_H
#define H3_PRIVATE_H

#include <httpd.h>

#include <http_config.h>
#include <http_log.h>

// TI: AP_MODULE_DECLARE_DATA is unset (ap_config.h:167, ~26y). GCC visibility support introduced in GCC 4.0 (~2005)

#if defined(_WIN32)
    #define HTTP3_PUBLIC __declspec(dllexport)
#elif defined(__GNUC__) || defined(__clang__)
    #define HTTP3_PUBLIC __attribute__((visibility("default")))
#else
    #define HTTP3_PUBLIC AP_MODULE_DECLARE_DATA
#endif

// See mod_http3.c:128
HTTP3_PUBLIC extern module http3_module;
AP_MAYBE_UNUSED(static int* const aplog_module_index) = &(http3_module.module_index);

#endif /* H3_PRIVATE_H */
