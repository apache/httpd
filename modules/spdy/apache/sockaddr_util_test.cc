// Copyright 2012 Google Inc.
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

#include "mod_spdy/apache/sockaddr_util.h"

#include "apr_strings.h"

#include "base/basictypes.h"
#include "mod_spdy/apache/pool_util.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace {

void VerifySameAddr(apr_sockaddr_t* exp, apr_sockaddr_t* actual) {
  // apr_sockaddr_equal checks the actual IP (4 or 6) portion of the address,
  // and nothing else.
  EXPECT_NE(0, apr_sockaddr_equal(exp, actual));

  // Annoyingly this means we have to touch other fields directly.
  EXPECT_STREQ(exp->hostname, actual->hostname);
  EXPECT_STREQ(exp->servname, actual->servname);
  EXPECT_EQ(exp->port, actual->port);
  EXPECT_EQ(exp->salen, actual->salen);
  EXPECT_EQ(exp->ipaddr_len, actual->ipaddr_len);
  EXPECT_EQ(exp->addr_str_len, actual->addr_str_len);

  // next fields must both be either null or non-null.
  EXPECT_TRUE((exp->next == NULL) == (actual->next == NULL));
  if (exp->next != NULL) {
    VerifySameAddr(exp->next, actual->next);
  }
}

TEST(SockAddrUtilTest, CloneIpv4) {
  mod_spdy::LocalPool local, other;

  apr_sockaddr_t* original = NULL;
  ASSERT_EQ(APR_SUCCESS,
            apr_sockaddr_info_get(
                &original, "127.1.2.3", APR_INET, 80, 0, local.pool()));
  original->hostname = apr_pstrdup(local.pool(), "localhost");
  original->servname = apr_pstrdup(local.pool(), "http");

  apr_sockaddr_t* clone = mod_spdy::DeepCopySockAddr(original, other.pool());
  EXPECT_EQ(other.pool(), clone->pool);
  VerifySameAddr(original, clone);
}

TEST(SockAddrUtilTest, CloneIpv6) {
  mod_spdy::LocalPool local, other;

  // The IPv6 address below was that of example.com on 2012-07-20.
  apr_sockaddr_t* original = NULL;
  ASSERT_EQ(APR_SUCCESS,
            apr_sockaddr_info_get(
                &original, "2001:500:88:200::10", APR_INET6,
                443, 0, local.pool()));
  original->hostname = apr_pstrdup(local.pool(), "example.com");
  original->servname = apr_pstrdup(local.pool(), "https");

  apr_sockaddr_t* clone = mod_spdy::DeepCopySockAddr(original, other.pool());
  EXPECT_EQ(other.pool(), clone->pool);
  VerifySameAddr(original, clone);
}

TEST(SockAddrUtilTest, Clone2Records) {
  // Test where ->next links an IpV4 record from IPv6 one.
  mod_spdy::LocalPool local, other;

  // Both addresses are of example.com as of 2012-07-20.
  apr_sockaddr_t* original = NULL;
  ASSERT_EQ(APR_SUCCESS,
            apr_sockaddr_info_get(
                &original, "2001:500:88:200::10", APR_INET6,
                443, 0, local.pool()));
  original->hostname = apr_pstrdup(local.pool(), "example.com");
  original->servname = apr_pstrdup(local.pool(), "https");

  apr_sockaddr_t* original4 = NULL;
  ASSERT_EQ(APR_SUCCESS,
            apr_sockaddr_info_get(
                &original4, "192.0.43.10", APR_INET,
                443, 0, local.pool()));
  original4->hostname = apr_pstrdup(local.pool(), "example.com");
  original4->servname = apr_pstrdup(local.pool(), "https");
  original->next = original4;

  apr_sockaddr_t* clone = mod_spdy::DeepCopySockAddr(original, other.pool());
  EXPECT_EQ(other.pool(), clone->pool);
  VerifySameAddr(original, clone);
}

}  // namespace
