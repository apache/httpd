// Copyright 2010 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "mod_spdy/common/protocol_util.h"

#include "testing/gtest/include/gtest/gtest.h"

namespace {

TEST(ProtocolUtilTest, InvalidSpdyResponseHeaders) {
  // Forbidden headers should be rejected regardless of capitalization.
  EXPECT_TRUE(mod_spdy::IsInvalidSpdyResponseHeader("connection"));
  EXPECT_TRUE(mod_spdy::IsInvalidSpdyResponseHeader("Connection"));
  EXPECT_TRUE(mod_spdy::IsInvalidSpdyResponseHeader("cOnNeCtIoN"));
  EXPECT_TRUE(mod_spdy::IsInvalidSpdyResponseHeader("transfer-encoding"));
  EXPECT_TRUE(mod_spdy::IsInvalidSpdyResponseHeader("Transfer-Encoding"));
}

TEST(ProtocolUtilTest, ValidSpdyResponseHeaders) {
  // Permitted headers should be accepted regardless of capitalization (SPDY
  // requires header names to be lowercase, but this function shouldn't be
  // checking that).
  EXPECT_FALSE(mod_spdy::IsInvalidSpdyResponseHeader("content-length"));
  EXPECT_FALSE(mod_spdy::IsInvalidSpdyResponseHeader("Content-Length"));
  EXPECT_FALSE(mod_spdy::IsInvalidSpdyResponseHeader(
      "x-header-we-have-never-heard-of"));
  EXPECT_FALSE(mod_spdy::IsInvalidSpdyResponseHeader(
      "X-HEADER-WE-HAVE-NEVER-HEARD-OF"));
}

TEST(ProtocolUtilTest, MergeIntoEmpty) {
  net::SpdyHeaderBlock headers;
  ASSERT_EQ(0u, headers.size());

  mod_spdy::MergeInHeader("content-length", "256", &headers);
  ASSERT_EQ(1u, headers.size());
  ASSERT_EQ("256", headers["content-length"]);
}

TEST(ProtocolUtilTest, MakeLowerCase) {
  net::SpdyHeaderBlock headers;
  ASSERT_EQ(0u, headers.size());

  mod_spdy::MergeInHeader("Content-Length", "256", &headers);
  ASSERT_EQ(1u, headers.size());
  ASSERT_EQ(0u, headers.count("Content-Length"));
  ASSERT_EQ("256", headers["content-length"]);
}

TEST(ProtocolUtilTest, MergeDifferentHeaders) {
  net::SpdyHeaderBlock headers;
  ASSERT_EQ(0u, headers.size());

  mod_spdy::MergeInHeader("x-foo", "bar", &headers);
  ASSERT_EQ(1u, headers.size());
  ASSERT_EQ("bar", headers["x-foo"]);

  mod_spdy::MergeInHeader("x-baz", "quux", &headers);
  ASSERT_EQ(2u, headers.size());
  ASSERT_EQ("bar", headers["x-foo"]);
  ASSERT_EQ("quux", headers["x-baz"]);
}

TEST(ProtocolUtilTest, MergeRepeatedHeader) {
  net::SpdyHeaderBlock headers;
  ASSERT_EQ(0u, headers.size());

  mod_spdy::MergeInHeader("x-foo", "bar", &headers);
  ASSERT_EQ(1u, headers.size());
  const std::string expected1("bar");
  ASSERT_EQ(expected1, headers["x-foo"]);

  mod_spdy::MergeInHeader("x-foo", "baz", &headers);
  ASSERT_EQ(1u, headers.size());
  const std::string expected2("bar\0baz", 7);
  ASSERT_EQ(expected2, headers["x-foo"]);

  mod_spdy::MergeInHeader("x-foo", "quux", &headers);
  ASSERT_EQ(1u, headers.size());
  const std::string expected3("bar\0baz\0quux", 12);
  ASSERT_EQ(expected3, headers["x-foo"]);
}

}  // namespace
