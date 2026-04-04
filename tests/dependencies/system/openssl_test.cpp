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
