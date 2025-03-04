#include <gtest/gtest.h>

extern "C"
{
#include "hw2.h"
}

#include "tests_utils.h"

class expand_key_tests : public testing::Test
{
private:
    void SetUp() override {}
};

TEST_F(expand_key_tests, KeyZero)
{
    const sbu_key_t key = 0;
    const block_t expected[EXPANDED_KEYS_LENGTH]{
        0x5be0cd18, 0x629a2929, 0x7b0e80ee, 0x6a09e667, 0x269527d7, 0xcbd72830, 0x80dd2739, 0x558b17e2,
        0xaff87bda, 0x563f5d21, 0x71146d5c, 0xcd738a73, 0x0893cf4e, 0x946027bb, 0x9f0320f2, 0xf4f1a9ea,
        0xef4ae164, 0xe2fc2f68, 0xc5db5004, 0xce90cb2d, 0x34f73f04, 0x5379d2bd, 0x2dbcae7a, 0x82421cd9,
        0xe55e3296, 0xfedaa947, 0x7d6e1e1a, 0xc7d2c989, 0x3ab830cc, 0xc86d9e08, 0x6f17f21c, 0x1abe0b00
    };
    block_t output[EXPANDED_KEYS_LENGTH]{ 0 };
    sbu_expand_keys(key, output);
    for (auto i = 0; i < EXPANDED_KEYS_LENGTH; ++i)
        ASSERT_EQ(output[i], expected[i]) << "Failed for key " RED_MSG << std::hex << key << std::dec << COLOR_END;
}

TEST_F(expand_key_tests, KeyExample1)
{
    const sbu_key_t key = 0xab6176446f0c280aULL;
    const block_t expected[EXPANDED_KEYS_LENGTH]{
        0x1aa5d116, 0x053ee712, 0x12f77161, 0xb5c58cf1, 0x1182a238, 0xbef32f47, 0x395896b6, 0x00398652,
        0x6dbb53a7, 0xa3b51fe2, 0x422652d6, 0x091366c1, 0xe292e8a5, 0x706d5848, 0xfa4b0a36, 0xe254b8ba,
        0x9ab5a35b, 0x4030c0d5, 0x6d1660fc, 0x681c1732, 0x01ee49dc, 0x734b81a6, 0xfcecfbc3, 0xac39d0ab,
        0xb5027aae, 0xa80197ef, 0x2dc29bd1, 0x1da18d9b, 0x9fabb720, 0xb90585ce, 0xc58deb27, 0x12406a54
    };
    block_t output[EXPANDED_KEYS_LENGTH]{ 0 };
    sbu_expand_keys(key, output);
    for (auto i = 0; i < EXPANDED_KEYS_LENGTH; ++i)
        ASSERT_EQ(output[i], expected[i]) << "Failed for key " RED_MSG << std::hex << key << std::dec << COLOR_END;
} 

TEST_F(expand_key_tests, KeyExample2)
{
    const sbu_key_t key = 0x02908278d78913b9ULL;
    const block_t expected[EXPANDED_KEYS_LENGTH]{
        0x9e4eca04, 0xd55d030b, 0x7aa0a0e8, 0x4a628c5d, 0x6b992f26, 0x89300399, 0x0e9bba68, 0x37faaa8c,
        0x5a787f79, 0x9476333c, 0x75e57e08, 0x3ed04a1f, 0xd551c47b, 0x47ae7496, 0xcd8826e8, 0xd5979464,
        0xad768f85, 0x77f3ec0b, 0x5ad54c22, 0x5fdf3bec, 0x362d6502, 0x4488ad78, 0xcb2fd71d, 0x9bfafc75,
        0x82c15670, 0x9fc2bb31, 0x1a01b70f, 0x2a62a145, 0xa8689bfe, 0x8ec6a910, 0xf24ec7f9, 0x2583468a
    };
    block_t output[EXPANDED_KEYS_LENGTH]{ 0 };
    sbu_expand_keys(key, output);
    for (auto i = 0; i < EXPANDED_KEYS_LENGTH; ++i)
        ASSERT_EQ(output[i], expected[i]) << "Failed for key " RED_MSG << std::hex << key << std::dec << COLOR_END;
}

TEST_F(expand_key_tests, KeyExample3)
{
    const sbu_key_t key = 0x0f814f4be3ad7eddULL;
    const block_t expected[EXPANDED_KEYS_LENGTH]{
        0x20faf2c9, 0x60982c7b, 0x02c349c0, 0x088da357, 0x0e9b6aa7, 0xe3d96540, 0xa8d36a49, 0x7d855a92,
        0x87f636aa, 0x7e311051, 0x591a202c, 0xe57dc703, 0x209d823e, 0xbc6e6acb, 0xb70d6d82, 0xdcffe49a,
        0xc744ac14, 0xcaf26218, 0xedd51d74, 0xe69e865d, 0x1cf97274, 0x7b779fcd, 0x05b2e30a, 0xaa4c51a9,
        0xcd507fe6, 0xd6d4e437, 0x5560536a, 0xefdc84f9, 0x12b67dbc, 0xe063d378, 0x4719bf6c, 0x32b04670
    };
    block_t output[EXPANDED_KEYS_LENGTH]{ 0 };
    sbu_expand_keys(key, output);
    for (auto i = 0; i < EXPANDED_KEYS_LENGTH; ++i)
        ASSERT_EQ(output[i], expected[i]) << "Failed for key " RED_MSG << std::hex << key << std::dec << COLOR_END;
}

TEST_F(expand_key_tests, KeyExample4)
{
    const sbu_key_t key = 0x38f5cbea610b4c80ULL;
    const block_t expected[EXPANDED_KEYS_LENGTH]{
        0x22a0d335, 0x4ebf73a8, 0xf54d21da, 0x4446f023, 0x62ed86b5, 0x1de84ada, 0xdd3fbe5c, 0x2b778097,
        0xf7279f94, 0x6d84e17d, 0x23df5ae0, 0xb8cbc586, 0xbc019033, 0x61184331, 0x1ff47637, 0x41007fbf,
        0x9c077ef6, 0x2afecd15, 0xd0ebc0be, 0xf7f19acd, 0x9b0bb8a3, 0xb045e2da, 0xb8d1450d, 0xdce9662f,
        0x08c7a602, 0xad88533b, 0xfd0b3088, 0x4312540b, 0x4771c575, 0xa69c5de3, 0xf412db93, 0x84a536f4
    };
    block_t output[EXPANDED_KEYS_LENGTH]{ 0 };
    sbu_expand_keys(key, output);
    for (auto i = 0; i < EXPANDED_KEYS_LENGTH; ++i)
        ASSERT_EQ(output[i], expected[i]) << "Failed for key " RED_MSG << std::hex << key << std::dec << COLOR_END;
}