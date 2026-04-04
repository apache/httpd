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
