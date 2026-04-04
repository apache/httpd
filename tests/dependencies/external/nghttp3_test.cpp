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
