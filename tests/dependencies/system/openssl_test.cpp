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
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/opensslv.h>
#include <openssl/ssl.h>
}

TEST(Dependencies, OpenSSL_VersionAtLeast3_5)
{

    // OpenSSL version should be >= 3.5.x
    EXPECT_EQ(OPENSSL_VERSION_MAJOR, 3);
    EXPECT_EQ(OPENSSL_VERSION_MINOR, 5);
    EXPECT_GE(OPENSSL_VERSION_PATCH, 0);
}

TEST(Dependencies, OpenSSL_QuicClientMethod)
{
    const SSL_METHOD* method = OSSL_QUIC_client_method();
    ASSERT_NE(method, nullptr) << "QUIC not available";
}

TEST(Dependencies, OpenSSL_QuicSSLContextCreation)
{
    SSL_CTX* ctx = SSL_CTX_new(OSSL_QUIC_client_method());
    ASSERT_NE(ctx, nullptr) << "Failed to create QUIC SSL_CTX";
    SSL_CTX_free(ctx);
}

TEST(Dependencies, OpenSSL_EVPDigestSHA256)
{
    const EVP_MD* sha256 = EVP_sha256();
    ASSERT_NE(sha256, nullptr);
    EXPECT_EQ(EVP_MD_size(sha256), 32);
}
