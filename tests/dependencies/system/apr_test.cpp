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
#include <ap_mmn.h>
#include <apr_general.h>
#include <apr_pools.h>
#include <apr_strings.h>
#include <apr_version.h>
}

class APREnvironment : public ::testing::Environment
{
  public:
    void SetUp() override
    {
        apr_status_t rc = apr_initialize();
        ASSERT_EQ(rc, APR_SUCCESS);
    }
    void TearDown() override
    {
        apr_terminate();
    }
};

namespace
{
::testing::Environment* const aprEnv = ::testing::AddGlobalTestEnvironment(new APREnvironment);
}

TEST(Dependencies, APR_VersionAtLeast1_7)
{
    // APR version should be >= 1.7.x
    EXPECT_EQ(APR_MAJOR_VERSION, 1);
    EXPECT_EQ(APR_MINOR_VERSION, 7);
    EXPECT_GE(APR_PATCH_VERSION, 0);

    // MODULE_MAGIC_NUMBER_MAJOR should be >= 20211221
    EXPECT_GE(MODULE_MAGIC_NUMBER_MAJOR, 20211221);
}

TEST(Dependencies, APR_PoolCreateDestroy)
{
    apr_pool_t* pool = nullptr;
    apr_status_t rv = apr_pool_create(&pool, nullptr);
    ASSERT_EQ(rv, APR_SUCCESS);
    ASSERT_NE(pool, nullptr);
    apr_pool_destroy(pool);
}

TEST(Dependencies, APR_StringDup)
{
    apr_pool_t* pool = nullptr;
    apr_status_t rv = apr_pool_create(&pool, nullptr);
    ASSERT_EQ(rv, APR_SUCCESS);
    ASSERT_NE(pool, nullptr);

    const char* original = "mod_http3 test string";
    char* copy = apr_pstrdup(pool, original);
    ASSERT_NE(copy, nullptr);
    EXPECT_STREQ(copy, original);
    EXPECT_NE(copy, original);

    apr_pool_destroy(pool);
}
