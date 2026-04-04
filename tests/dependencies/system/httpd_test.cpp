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
