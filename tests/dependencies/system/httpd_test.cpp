/*
 * Copyright (c) 2026 The mod_http3 Project Authors. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * This file is derived from code originally distributed as part of
 * the OpenSSL project and has been modified for use in mod_http3.
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

#include <gtest/gtest.h>

extern "C"
{
#include <httpd.h>

#include <apr_pools.h>
#include <http_config.h>
#include <http_log.h>
#include <http_protocol.h>
}

TEST(Dependencies, Httpd_VersionAtLeast2_5)
{
    // Apache HTTP Server version should be >= 2.5.x
    EXPECT_EQ(AP_SERVER_MAJORVERSION_NUMBER, 2);
    EXPECT_EQ(AP_SERVER_MINORVERSION_NUMBER, 5);
    EXPECT_GE(AP_SERVER_PATCHLEVEL_NUMBER, 0);
}

TEST(Dependencies, Httpd_HTTPStatusCodes)
{
    EXPECT_EQ(HTTP_OK, 200);
    EXPECT_EQ(HTTP_NOT_FOUND, 404);
    EXPECT_EQ(HTTP_INTERNAL_SERVER_ERROR, 500);
}

TEST(Dependencies, Httpd_LogLevelMacros)
{
    EXPECT_GE(APLOG_EMERG, 0);
    EXPECT_GT(APLOG_DEBUG, APLOG_EMERG);
}
