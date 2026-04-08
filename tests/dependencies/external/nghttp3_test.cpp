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
#include <nghttp3/nghttp3.h>
}

TEST(Dependencies, Nghttp3_VersionAtLeast1_15_90)
{
    const int v = NGHTTP3_VERSION_NUM;

    const int major = (v >> 16) & 0xff;
    const int minor = (v >> 8) & 0xff;
    const int patch = v & 0xff;

    // nghttp3 version should be >= 1.15.90
    EXPECT_EQ(major, 1);
    EXPECT_EQ(minor, 15);
    EXPECT_GE(patch, 90);
}

TEST(Dependencies, Nghttp3_SettingsDefault)
{
    nghttp3_settings settings;
    nghttp3_settings_default(&settings);
    EXPECT_GT(settings.max_field_section_size, 0u);
}

TEST(Dependencies, Nghttp3_DefaultAllocator)
{
    const nghttp3_mem* mem = nghttp3_mem_default();
    ASSERT_NE(mem, nullptr);
    EXPECT_NE(mem->malloc, nullptr);
    EXPECT_NE(mem->free, nullptr);
    EXPECT_NE(mem->realloc, nullptr);
}
