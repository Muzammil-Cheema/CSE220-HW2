#include <gtest/gtest.h>
#include "tests_utils.h"

extern "C"
{
#include "hw2.h"
}

class encryption_tests : public testing::Test
{
private:
    void SetUp() override {}
};

constexpr inline std::size_t OVERFLOW_BUFFER_SIZE = 256;

TEST_F(encryption_tests, EncryptMessage1)
{
    char message[] = "We the People of the United States, in Order to form a more perfect Union, establish Justice, \
insure domestic Tranquility, provide for the common defence, promote the general Welfare, and secure the Blessings of \
Liberty to ourselves and our Posterity, do ordain and establish this Constitution for the United States of America.";
    
    const block_t expected[] = {
        0xf64cfba0, 0x1d6159a0, 0xd6797b1e, 0x5b9cb3ba, 0x08796d0e, 0xa7b734f5, 0x9bb50531, 0xf53cf1b6, 
        0x44e6ce33, 0x00b98b4e, 0x6dab9155, 0x1892e76e, 0x0100edf5, 0xdeb7c528, 0x5a20082a, 0xfc1b3fca, 
        0x09322c16, 0x952a0a5f, 0xab574a3b, 0xa974cb53, 0x969c33c7, 0xb81656c7, 0x720c5dd4, 0xc01e4416, 
        0xf3d73934, 0xb4615510, 0x12ec8681, 0x796cb12e, 0x8f1cab05, 0x2bb58262, 0x8fdf0ab9, 0x5d1eef06, 
        0x0768bebd, 0x78e60e39, 0xd8b6c43a, 0x3798e765, 0xbbcbc6a7, 0x21d21774, 0x6d7b7557, 0xca7a3d40, 
        0xc1f666d8, 0x2551e451, 0x53a27661, 0x07b7c0c2, 0x70fcdb20, 0xcaa4079c, 0x2db60470, 0x55265254, 
        0x07cf2971, 0x07072978, 0xd2773dfe, 0x48918640, 0x20bce669, 0xc3107379, 0x4ff51bff, 0xf80c6393, 
        0x4c81da38, 0xd5d3c702, 0xe2ec31fa, 0x588078b1, 0xfbea1bc2, 0xa1635824, 0x49b07a09, 0x5981f763, 
        0x5924046f, 0x7f96dccd, 0x40f2ca79, 0xd8d24d70, 0x838b3871, 0x852ea7d1, 0xf1ecb768, 0x1e6e3ed7, 
        0xbdfdecbc, 0xf1e57706, 0x25c8a479, 0xcd2a9175, 0x2709d7ef, 0x155d692a, 0x9b103e07, 0xe3bdcf7b, 
        0x3387907b, 0x72ca8e95, 0x00000000 // this last 0 is not actually part of the encryption. used in testing 
    };
    constexpr auto expected_size = std::size(expected);
    const sbu_key_t key = 0x17880621;
    
    block_t key_sched[EXPANDED_KEYS_LENGTH]{ 0 };
    block_t output[expected_size + OVERFLOW_BUFFER_SIZE]{ 0 };

    sbu_expand_keys(key, key_sched);
    sbu_encrypt(reinterpret_cast<uint8_t*>(message), output, sizeof(message), key_sched);

    size_t idx = 0;
    for (; idx < expected_size; ++idx)
        ASSERT_EQ(output[idx], expected[idx]) << "Incorrect for block index " RED_MSG << idx << COLOR_END;
    for (size_t i = 0; i < OVERFLOW_BUFFER_SIZE;  ++i, ++idx)
        ASSERT_EQ(output[idx], 0) << "Overflow buffer is not 0. Likely because `sbu_encrypt` writes too many blocks.";
}

TEST_F(encryption_tests, EncryptMessage2)
{
    char message[] = "Arma virumque cano, Troiae qui primus ab oris \
Italiam, fato profugus, Laviniaque venit \
litora, multum ille et terris iactatus et alto \
vi superum saevae memorem Iunonis ob iram; \
multa quoque et bello passus, dum conderet urbem, \
inferretque deos Latio, genus unde Latinum, \
Albanique patres, atque altae moenia Romae.";
    
    const block_t expected[] = {
        0x788f1389, 0x2a6579f0, 0x267ba904, 0xf3193167, 0x4f739e05, 0xe945ca94, 0x8bd68de5, 0x07ff441a, 
        0x5c8f3594, 0x5080ee03, 0x8c56bf48, 0xf6fff5e9, 0x83a98418, 0x4ebc09cc, 0x61fbfd35, 0xa04aea9c, 
        0x1704bfa5, 0x90ab1630, 0x6c88a5eb, 0x78398895, 0xc3379b68, 0xb6630b16, 0x5766fe26, 0x11ef59a4, 
        0xd4942e5f, 0x22f116f8, 0xc69dacf1, 0x16569f77, 0xcfa93ae7, 0xd058a06e, 0xdd799877, 0x43853bba, 
        0x472982ff, 0x28329725, 0x76364a7a, 0x53263194, 0x56e9f19d, 0xf95e44fc, 0xad46b897, 0x83d8b27e, 
        0x82bf4aad, 0xc50caf67, 0x08012db7, 0xad4c9542, 0x6301eb19, 0xc83135f8, 0x65ff9b41, 0x507bef46, 
        0x6a97c487, 0xaa7b0b42, 0x056e01a3, 0x4c730034, 0x4ede180c, 0xe835accc, 0x3e199d5b, 0x46237758, 
        0xfe38306d, 0xcc84c857, 0x81e2d872, 0xe6b128b7, 0x67bd9371, 0x913f2467, 0x4f4613c9, 0x02d9abc4, 
        0xf1fdf58d, 0xe712cea3, 0x68ef580d, 0x45887109, 0x21d7a80c, 0x8b30b389, 0xdbcb1d81, 0x78e9a437, 
        0x0c087b1e, 0x930c8530, 0xbb6153b1, 0xf3b3573a, 0x0a851f85, 0x0ba79ff6, 0xeb0baebb, 0x00000000
    };
    constexpr auto expected_size = std::size(expected);
    const sbu_key_t key = 0xDEAD0AE17EA5ULL;
    
    block_t key_sched[EXPANDED_KEYS_LENGTH]{ 0 };
    block_t output[expected_size + OVERFLOW_BUFFER_SIZE]{ 0 };

    sbu_expand_keys(key, key_sched);
    sbu_encrypt(reinterpret_cast<uint8_t*>(message), output, sizeof(message), key_sched);

    size_t idx = 0;
    for (; idx < expected_size; ++idx)
        ASSERT_EQ(output[idx], expected[idx]) << "Incorrect for block index " RED_MSG << idx << "/" << expected_size << COLOR_END;
    for (size_t i = 0; i < OVERFLOW_BUFFER_SIZE;  ++i, ++idx)
        ASSERT_EQ(output[idx], 0) << "Overflow buffer is not 0. Likely because `sbu_encrypt` writes too many blocks.";
}

TEST_F(encryption_tests, EncryptMessage3)
{
    char message[] = "Introduces systems-level programming concepts using the C language and assembly language, \
and explores the correspondence of programming constructs in these languages. Topics include internal data representation, \
basic instructions and control structures, bitwise operations, arithmetic operations, memory management, pointers, function \
calls and parameter passing, linking, and loading. Included is an overview of computer architecture and organization topics, \
including von Neumann architecture, the memory hierarchy, and basics of pipelining.";
    
    const block_t expected[] = {
        0x58695f03, 0x8374c0cf, 0x1b34f334, 0x3cc0849e, 0x7248f822, 0x6a350e79, 0x22624bcf, 0x0ce238af, 
        0x73927a37, 0x66d4cf52, 0x62bad7ef, 0xf62a9d10, 0xb000a5b9, 0x96551c89, 0xff9d2401, 0x9f41bd51, 
        0xf0e58ff0, 0xced43057, 0x5fdc51ea, 0x35d07c98, 0x69807553, 0xb664f4de, 0xbdc22a66, 0x3bf7c9af, 
        0x0fef65bd, 0x7e855f0a, 0x4796d8cb, 0x655e0672, 0x7dcf54c4, 0xd7ca6f07, 0x47339640, 0x22624bcf, 
        0x0ce238af, 0x73927a37, 0x66d4cf52, 0xb07b894f, 0x42371e64, 0xea62bea5, 0xf4f0675b, 0x170ac192, 
        0xe396abf8, 0x479b56f0, 0x7d4ab43a, 0x27b019b6, 0xde5091ac, 0x194f4b8f, 0xd5fdeb04, 0x1913459d, 
        0x1dfa6d33, 0x7057b929, 0xfad44b66, 0x04b0ab3c, 0x1346b7c0, 0x53a2c700, 0x4dc38bc9, 0x1c6f4c79, 
        0xbc1c8c29, 0x58d952d9, 0xa374d581, 0x3241432f, 0x68a6c864, 0xb07b894f, 0x81289c4b, 0xb78d4673, 
        0x1b26e1ab, 0xfbde677a, 0x38bac5dc, 0x98729f11, 0x79aa837c, 0x2edf322f, 0x8f2b7bf7, 0x1cd2a988, 
        0x589dab2c, 0x7b08539a, 0x5306a7dd, 0x1306516c, 0x224ba36e, 0x8be928ae, 0x829b0b1e, 0x0e789dbc, 
        0xdf10c8dc, 0x5ddd2d47, 0x2c3d720c, 0x7b08539a, 0x5e8d2225, 0x170bcc5d, 0x8adde9de, 0x70fbc1b3, 
        0x060cc6bd, 0x26ff30b9, 0xf018a36a, 0xd93dd35a, 0x23482cbe, 0x869c3b61, 0x2998f2b4, 0x611bf5a6, 
        0x3920ab37, 0x798f5294, 0x6c2da88a, 0x2b2e1da3, 0x046cb356, 0x1ac10094, 0xf8d80c13, 0x48226b68, 
        0x13d0f869, 0x30d95426, 0xd675f757, 0x2bac0bd6, 0x01d2fb25, 0x866ec4d5, 0x1bc1b7f4, 0x976ab3d1, 
        0x98729f11, 0x103f8b4a, 0xd9573029, 0xb937441b, 0xe79b1f2d, 0xb000a5b9, 0x7bfb75eb, 0xf508081b, 
        0x581726a5, 0xd675f757, 0x2bac0bd6, 0x01d2fb25, 0x4b40e753, 0x6572d678, 0x37638067, 0x784b1108, 
        0xe96c3f3f, 0x6b98326e, 0xa374d581, 0xac831fea, 0x060878f8, 0x857ea2a5, 0x501c52d9, 0x8da7de04, 
        0xa966228c, 0x00000000, 0x00000000, 0x00000000
    };
    constexpr auto expected_size = std::size(expected);
    const sbu_key_t key = 0x8a21febe813b224aULL;
    
    block_t key_sched[EXPANDED_KEYS_LENGTH]{ 0 };
    block_t output[expected_size + OVERFLOW_BUFFER_SIZE]{ 0 };

    sbu_expand_keys(key, key_sched);
    sbu_encrypt(reinterpret_cast<uint8_t*>(message), output, sizeof(message), key_sched);

    size_t idx = 0;
    for (; idx < expected_size; ++idx)
        ASSERT_EQ(output[idx], expected[idx]) << "Incorrect for block index " RED_MSG << idx << "/" << expected_size << COLOR_END;
    for (size_t i = 0; i < OVERFLOW_BUFFER_SIZE;  ++i, ++idx)
        ASSERT_EQ(output[idx], 0) << "Overflow buffer is not 0. Likely because `sbu_encrypt` writes too many blocks.";
}

TEST_F(encryption_tests, DecryptMessage1)
{
    block_t encrypted[] = {
        0xf16e342a, 0x7ad6e054, 0xed8ed386, 0x72ef3533, 0xce2167ca, 0xa4783098, 0x1a3a126c, 0xbdb092a6, 
        0x874e3cea, 0xc9fdecd5, 0x800941e8, 0x7527680a, 0x96d28e4a, 0x7cb7d882, 0x4994b3d5, 0x6c7166c5, 
        0x2d47c60b, 0x777fcfc0, 0x2a76abf9, 0x825927c0, 0x4423de3b, 0x58787c68, 0xd7014626, 0xff86195c, 
        0xed8ed386, 0x72ef3533, 0xce2167ca, 0xc93dd14c, 0xfaafb16c, 0x9a244ec5, 0xd578af42, 0x4aef944b, 
        0xcc80ca96, 0x93870bc7, 0xb463c040, 0x7175629f, 0xf7155ffb, 0x52f5712a, 0x5578c4c4, 0x71af8792, 
        0x2b301817, 0xf676644e, 0x1e9046bd, 0xc5aaf15a, 0xc61b447e, 0x586e6512, 0x8b98839a, 0x5e9cf506, 
        0x7532eb9c, 0x128b3e15, 0x84c654bb, 0x87e9df24, 0xb74c112c, 0x9ada7570, 0x2c8e0ac9, 0x170d1522, 
        0xa1375bf2, 0x9c435d70, 0xccf5c99b, 0xec5f92c5, 0xb290f914, 0x57b869b0, 0x7ac37d30, 0x2a32484b, 
        0xf9ccee2e, 0xe416b2d6, 0x88395158, 0xf9bd5fe4, 0x128eaf81, 0xf0e56df4, 0x31c92e5b, 0x6b35e772, 
        0x5400c97e, 0x16386c82, 0x1936ec5d, 0x249894da, 0xce311dc5, 0x1357ac80, 0x8cd4d8c6, 0x06f189db, 
        0x08bd6924, 0x46de7d07, 0x93031a84, 0x90c7c9c2, 0x8c0ffc5b, 0x67d90c3d, 0xf2e13af7, 0x998f8919, 
        0xa4557ce0, 0x01fa0c4c, 0x9c435d70, 0xccf5c99b, 0x5b72b4e1, 0x4a4f72bb, 0xf3e3d9c6, 0xe26f4ccf, 
        0xe416b2d6, 0x88395158, 0xf9bd5fe4, 0x128eaf81, 0xf0e56df4, 0x56ff0c20, 0x800941e8, 0xf42f1afa, 
        0x2ad9d488, 0xb280e10a, 0x245e1bc9
    };
    const char *expected = "Homework assignments consist of programming projects in C or MIPS assembly language. \
Programming assignments are graded primarily or exclusively on correctness. Students are required to have an \
active GitHub account to submit assignments that will be distributed by the instructor using CodeGrade. Detailed \
instructions for accessing and submitting homework assignments will be provided by the instructor during the semester.";

    constexpr size_t expected_string_size = 425;
    uint8_t output[expected_string_size + OVERFLOW_BUFFER_SIZE]{ 0 };

    sbu_key_t key = 0x1ce30458e44aULL; // encode in base64 :)
    block_t key_sched[EXPANDED_KEYS_LENGTH]{ 0 };
    sbu_expand_keys(key, key_sched);
    sbu_decrypt(encrypted, output, expected_string_size, key_sched);

    size_t idx = 0;
    for (; idx < expected_string_size; ++idx)
        ASSERT_EQ(output[idx], expected[idx]) << "Incorrect for byte index " RED_MSG << idx << "/" << expected_string_size << COLOR_END;
    for (size_t i = 0; i < OVERFLOW_BUFFER_SIZE; ++i, ++idx)
        ASSERT_EQ(output[idx], 0) << "Overflow buffer is not 0. Likely because `sbu_decrypt` writes too many bytes.";
}

TEST_F(encryption_tests, DecryptMessage2)
{
    block_t encrypted[] = {
        0x73851aba, 0xf5fe88b5, 0xd95c99e9, 0x84d8a4e7, 0x68b2e4f7, 0x59164370, 0xb84e2c4f, 0xbcc54d1f, 
        0xb7b2c935, 0x918551fa, 0x7539d003, 0xaaeefe06, 0x6a2d3714, 0x73b47cfd, 0x726696e4, 0xf0f0d0af, 
        0xb21e18f4, 0x553996e9, 0x3df9dcf1, 0x5abaeb26, 0x1d7ec3c5, 0x12b1e67f, 0x14044129, 0x20dea6f1, 
        0xabf647f1, 0x7a7d3b9c, 0x19fb381d, 0x15728add, 0x4cb276e8, 0x330116d6, 0x80077dfc, 0x314c64bb, 
        0x69c29e1c, 0xe4f4b571, 0xf326aab2, 0xc3d52fad, 0x8e17f89e, 0x3ed406c8, 0x8c733f3c, 0xac8cad81, 
        0x09392913, 0x2cd1f677, 0x1e1900af, 0x92832143, 0xde08877a, 0xaf3016c3, 0x6948a207, 0x68784233, 
        0xbd55f144, 0x8ff861f8, 0x4087bb55, 0xe3af0f3c, 0x652ceff2, 0x2864bddf, 0x12e95942, 0x68784233, 
        0xcaea41f8, 0xe3af0f3c, 0x652ceff2, 0x2864bddf, 0x4ea6034e, 0xc77c1d9d, 0x11a21990, 0x4be3f2d0, 
        0x9206cac3, 0xfce83884, 0xebca3a83, 0x9f30aa8b, 0xc682ad2f, 0x4087bb55, 0x7eb00a1a, 0xe1c30ebe, 
        0x306140cc, 0x19f03492, 0xdc171801, 0xc4aea919, 0xa9ffc0f8, 0xc77c1d9d, 0xc15fe5d9, 0xe3af0f3c, 
        0x652ceff2, 0x2864bddf, 0xd6ab4f0c, 0x962f0b18, 0x102f514f, 0xe3af0f3c, 0x652ceff2, 0x2864bddf, 
        0xeb455ea1, 0xa40ec0d2, 0xe2f82c2e, 0x58f5c25d, 0xe63e0941, 0x496f03b7
    };
    const char *expected = "We're no strangers to love \
You know the rules and so do I \
A full commitment's what I'm thinkin' of \
You wouldn't get this from any other guy \
I just wanna tell you how I'm feeling \
Gotta make you understand \
Never gonna give you up \
Never gonna let you down \
Never gonna run around and desert you \
Never gonna make you cry \
Never gonna say goodbye \
Never gonna tell a lie and hurt you";

    constexpr size_t expected_string_size = 375;
    uint8_t output[expected_string_size + OVERFLOW_BUFFER_SIZE]{ 0 };

    sbu_key_t key = 0xae2724ae8965ULL; // encode to base64
    block_t key_sched[EXPANDED_KEYS_LENGTH]{ 0 };
    sbu_expand_keys(key, key_sched);
    sbu_decrypt(encrypted, output, expected_string_size, key_sched);

    size_t idx = 0;
    for (; idx < expected_string_size; ++idx)
        ASSERT_EQ(output[idx], expected[idx]) << "Incorrect for byte index " RED_MSG << idx << "/" << expected_string_size << COLOR_END;
    for (size_t i = 0; i < OVERFLOW_BUFFER_SIZE; ++i, ++idx)
        ASSERT_EQ(output[idx], 0) << "Overflow buffer is not 0. Likely because `sbu_decrypt` writes too many bytes.";
}

TEST_F(encryption_tests, DecryptMessage3)
{
    block_t encrypted[] = {
        0x48153f61, 0x463a0664, 0x5f73289c, 0xa20d9d1c, 0xd3f9b1b2, 0x1a637656, 0xee284049, 0xd8c3c145, 
        0xecba30e0, 0x641e0118, 0xae56c389, 0x4e7fb757, 0xcb2cf72f, 0x2c11800c, 0x5d004d04, 0x53720bab, 
        0xdd7e3b7c, 0xe04e9b5d, 0xb7025d92, 0x03ceb723, 0x454a6978, 0x8d75ed12, 0xe30031fc, 0x40602888, 
        0x9a455cc0, 0x52911b3b, 0x3972e841, 0x6d1f22b1, 0x0da83df9, 0x7d1c4b3c, 0x4716690c, 0x979a274b, 
        0xbf0ac119, 0x00f76adf, 0x5460b7ac, 0x3444aefd, 0x1ceb56d4, 0x93886827, 0xb297ae48, 0x42bce487, 
        0x9a318be7, 0x5751b722, 0xe4ac995e, 0x245a47c5, 0x0ca86bc7, 0x5db3c9e4, 0x2b99bc17, 0x71f5a023, 
        0x47975358, 0xb297ae48, 0xa05ae47b, 0x781b89f3, 0x23e030f6, 0x0ad3fbf9, 0xbb8054b0, 0x4d6fa6c9, 
        0xff324868, 0x0abfd6a0, 0xbe5b10bc, 0xd83adc5d, 0x217a8d4e, 0xefa55e25, 0x2512c8fa, 0xc34b4bac, 
        0xb25bd86f, 0xfea04fa9, 0x93886827, 0xa6b124c5, 0x48153f61, 0x3376bbf7, 0xb8187419, 0x183db924, 
        0x247a3c0a, 0x832c6026, 0x73c72e66, 0x5e0edfe5, 0x9244eb17, 0x1fce0e76, 0x832c6026, 0x73c72e66, 
        0x40f6b4ec, 0x57cc0fba, 0x0cdd2f76, 0x755f054a, 0xd5ecde8c, 0x35c0b2e5, 0x525b1595, 0x478b9a84, 
        0x245a47c5, 0x830d0eef, 0xe79d38de, 0x587f28bd, 0x37d71c4c, 0x247a3c0a, 0x832c6026, 0x73c72e66, 
        0xaa8ab616, 0x183db924, 0x247a3c0a, 0x832c6026, 0xe53dc91e, 0x6b46557d, 0x6289bbec, 0x19b3c791, 
        0x19a7eacb, 0xf15478ac, 0x3085504b, 0xc27db8a6
    };
    const char *expected = "And so I cry sometimes when I'm lying in bed \
Just to get it all out what's in my head \
And I \
I am feeling a little peculiar \
And so I wake in the morning and I step outside \
And I take a deep breath and I get real high, and I \
Scream from the top of my lungs \
What's going on? \
And I say, hey-yeah-yeah-yeah-yeah, hey-yeah-yeah \
I said hey, what's going on? \
And I say, hey-yeah-yeah-yeah-yeah, hey-yeah-yeah \
I said hey, what's going on?";

    constexpr size_t expected_string_size = 429;
    uint8_t output[expected_string_size + OVERFLOW_BUFFER_SIZE]{ 0 };

    sbu_key_t key = 0x1de31a9d2a27ULL;
    block_t key_sched[EXPANDED_KEYS_LENGTH]{ 0 };
    sbu_expand_keys(key, key_sched);
    sbu_decrypt(encrypted, output, expected_string_size, key_sched);

    size_t idx = 0;
    for (; idx < expected_string_size; ++idx)
        ASSERT_EQ(output[idx], expected[idx]) << "Incorrect for byte index " RED_MSG << idx << "/" << expected_string_size << COLOR_END;
    for (size_t i = 0; i < OVERFLOW_BUFFER_SIZE; ++i, ++idx)
        ASSERT_EQ(output[idx], 0) << "Overflow buffer is not 0. Likely because `sbu_decrypt` writes too many bytes.";
}