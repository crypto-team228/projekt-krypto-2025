#include <gtest/gtest.h>

#include "cipher/TDES/tdes.hpp"
#include "mode/ECB.hpp"
#include "KATHarness.hpp"

TEST(TDES, KAT_ECB_FromFile)
{
    auto cases = LoadKATFile("tests/data/tdes_ecb_kat.csv");

    ASSERT_FALSE(cases.empty()) << "No TDES KAT cases loaded";

    for (const auto& tc : cases) {
        ASSERT_EQ(tc.plaintext.size(), 8u) << "3DES block size must be 8 bytes";

        TDES tdes(tc.key);
        ECB ecb;

        auto cipher = ecb.encrypt(tc.plaintext, tdes);
        EXPECT_EQ(cipher, tc.ciphertext) << "Encrypt mismatch for KAT: " << tc.name;

        auto decrypted = ecb.decrypt(cipher, tdes);
        EXPECT_EQ(decrypted, tc.plaintext) << "Decrypt mismatch for KAT: " << tc.name;
    }
}
