#include <gtest/gtest.h>
#include "cipher/AES/aes.hpp"
#include "KATHarness.hpp"

TEST(AES, KAT_ECB_FromFile)
{
    // ścieżka względna względem katalogu uruchomienia –
    // jeśli używasz CTest/CMake, ustaw working directory na root projektu
    auto cases = LoadKATFile("tests/data/aes_ecb_kat.csv");

    ASSERT_FALSE(cases.empty()) << "No AES KAT cases loaded";

    for (const auto& tc : cases) {
        ASSERT_EQ(tc.plaintext.size(), 16u) << "AES ECB KAT requires 16‑byte block";

        AES aes(tc.key);

        std::vector<uint8_t> buf = tc.plaintext;

        aes.encryptBlock(buf.data(), buf.data());
        EXPECT_EQ(buf, tc.ciphertext) << "Encrypt mismatch for KAT: " << tc.name;

        aes.decryptBlock(buf.data(), buf.data());
        EXPECT_EQ(buf, tc.plaintext) << "Decrypt mismatch for KAT: " << tc.name;
    }
}
