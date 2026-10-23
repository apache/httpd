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

#ifndef H3_CHECK_H
#define H3_CHECK_H

#include <httpd.h>

#include <http_log.h>
#include <stdlib.h>

/* clang-format off */

/**
 * Assertion macro for validating runtime invariants.
 *
 * Evaluates @p expr_; on failure, logs the failed expression via
 * ap_log_perror at APLOG_ERR, runs the optional cleanup statement
 * (a single statement), then aborts. The condition is branch-predicted
 * unlikely on GCC/Clang so the happy path is essentially free.
 *
 * Usage:
 *   CHECK(ptr != NULL);                     // assert and abort
 *   CHECK(conn != NULL, mtx_unlock(&m));   // release before aborting
 *   CHECK(buf != NULL, return APR_EINVAL);  // bail out of the function
 *
 * @param expr_ Expression to validate.
 * @param ...   Optional single statement run before abort() on failure.
 */
#if defined(_WIN32)
    #define CHECK(expr_, ...)                                                              \
        do                                                                                 \
        {                                                                                  \
            if (!(expr_))                                                                  \
            {                                                                              \
                ap_log_perror(APLOG_MARK, APLOG_ERR, 0, NULL, "check failed: %s", #expr_); \
                __VA_ARGS__;                                                               \
                abort();                                                                   \
            }                                                                              \
        } while (0)
#else
    #define CHECK(expr_, ...)                                                              \
        do                                                                                 \
        {                                                                                  \
            if (__builtin_expect(!(expr_), 0))                                             \
            {                                                                              \
                ap_log_perror(APLOG_MARK, APLOG_ERR, 0, NULL, "check failed: %s", #expr_); \
                __VA_ARGS__;                                                               \
                abort();                                                                   \
            }                                                                              \
        } while (0)
#endif

#endif /* H3_CHECK_H */
