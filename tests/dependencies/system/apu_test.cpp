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
#include <apr_base64.h>
#include <apr_md5.h>
#include <apu.h>
#include <apu_version.h>
}

class APUEnvironment : public ::testing::Environment
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
::testing::Environment* const apuEnv = ::testing::AddGlobalTestEnvironment(new APUEnvironment);
}

TEST(Dependencies, APU_VersionAtLeast1_6)
{
    // APU version should be >= 1.6.x
    EXPECT_EQ(APU_MAJOR_VERSION, 1);
    EXPECT_EQ(APU_MINOR_VERSION, 6);
    EXPECT_GE(APU_PATCH_VERSION, 0);
}

TEST(Dependencies, APU_Base64EncodeDecodee)
{
    const char input[] = "mod_http3 apr-util test";
    const int input_len = static_cast<int>(sizeof(input) - 1);

    const int enc_buf_len = apr_base64_encode_len(input_len);
    ASSERT_GT(enc_buf_len, 0);

    std::string encoded(enc_buf_len, '\0');

    const int enc_len = apr_base64_encode(encoded.data(), input, input_len);
    ASSERT_GT(enc_len, 0);
    ASSERT_LE(enc_len, enc_buf_len);

    encoded[enc_len] = '\0';

    const int dec_buf_len = apr_base64_decode_len(encoded.c_str());
    ASSERT_GT(dec_buf_len, 0);

    std::string decoded(dec_buf_len, '\0');

    const int dec_len = apr_base64_decode(decoded.data(), encoded.c_str());
    ASSERT_EQ(dec_len, input_len);
    ASSERT_LE(dec_len + 1, dec_buf_len);

    EXPECT_EQ(memcmp(decoded.data(), input, input_len), 0);
}

TEST(Dependencies, APU_MD5Digest)
{
    apr_pool_t* pool = nullptr;
    apr_status_t rv = apr_pool_create(&pool, nullptr);
    ASSERT_EQ(rv, APR_SUCCESS);
    ASSERT_NE(pool, nullptr);

    const unsigned char input[] = "mod_http3 apr-util md5";
    const int input_len = static_cast<int>(sizeof(input) - 1);

    unsigned char digest[APR_MD5_DIGESTSIZE];
    rv = apr_md5(digest, input, input_len);
    ASSERT_EQ(rv, APR_SUCCESS);

    // MD5 digest should not be all zeros
    bool any_non_zero = false;
    for (unsigned char b : digest)
    {
        if (b != 0)
        {
            any_non_zero = true;
            break;
        }
    }
    EXPECT_TRUE(any_non_zero);

    apr_pool_destroy(pool);
}