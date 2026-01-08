#include <gtest/gtest.h>

#include "cipher/TDES/tdes.hpp"
#include "mode/ECB.hpp"
#include "utils/DataConverter.hpp"

// Helper: build 24‑byte 3DES key from 3 hex strings
static std::vector<uint8_t> Build3DESKey(
    const std::string& k1,
    const std::string& k2,
    const std::string& k3)
{
    auto b1 = DataConverter::HexToBytes(k1);
    auto b2 = DataConverter::HexToBytes(k2);
    auto b3 = DataConverter::HexToBytes(k3);

    std::vector<uint8_t> key;
    key.insert(key.end(), b1.begin(), b1.end());
    key.insert(key.end(), b2.begin(), b2.end());
    key.insert(key.end(), b3.begin(), b3.end());
    return key;
}

// ------------------------------------------------------------
// 1. Test jednego bloku — podstawowy test poprawności
// ------------------------------------------------------------
TEST(TDES, SingleBlockEncryptDecrypt)
{
    std::string plaintextHex = "0123456789abcdef";
    std::string expectedHex = "37d174403fc04f1a";

    auto plaintext = DataConverter::HexToBytes(plaintextHex);
    auto key = Build3DESKey(
        "033457799bbcdff1",
        "133457799bbcdff1",
        "233457799bbcdff1"
    );

    TDES tdes(key);
    ECB ecb;

    auto cipher = ecb.encrypt(plaintext, tdes);
    EXPECT_EQ(DataConverter::BytesToHex(cipher), expectedHex);
	std::cout << "Cipher: " << DataConverter::BytesToHex(cipher) << std::endl;
    auto decrypted = ecb.decrypt(cipher, tdes);
    EXPECT_EQ(DataConverter::BytesToHex(decrypted), plaintextHex);
}

// ------------------------------------------------------------
// 2. Test wielu bloków — ECB powinien szyfrować blok po bloku
// ------------------------------------------------------------
TEST(TDES, MultiBlockECB)
{
    std::string plaintextHex =
        "0123456789abcdef"
        "0123456789abcdef";

    std::string expectedHex =
        "37d174403fc04f1a"
        "37d174403fc04f1a";

    auto plaintext = DataConverter::HexToBytes(plaintextHex);
    auto key = Build3DESKey(
        "033457799bbcdff1",
        "133457799bbcdff1",
        "233457799bbcdff1"
    );

    TDES tdes(key);
    ECB ecb;

    auto cipher = ecb.encrypt(plaintext, tdes);
    EXPECT_EQ(DataConverter::BytesToHex(cipher), expectedHex);

    auto decrypted = ecb.decrypt(cipher, tdes);
    EXPECT_EQ(DataConverter::BytesToHex(decrypted), plaintextHex);
}

// ------------------------------------------------------------
// 3. Test vectors — kilka przypadków w jednej pętli
// ------------------------------------------------------------
TEST(TDES, TestVectors)
{
    struct TestCase {
        std::string plaintextHex;
        std::string k1, k2, k3;
        std::string expectedHex;
    };

    std::vector<TestCase> cases = {
        {"0123456789abcdef", "033457799bbcdff1", "133457799bbcdff1", "233457799bbcdff1", "37d174403fc04f1a"},
        {"fedcba9876543210", "233457799bbcdff1", "133457799bbcdff1", "033457799bbcdff1", "473eeb07b08f7d13"},
        {"0123456789abcdef0123456789abcdef",
         "033457799bbcdff1", "133457799bbcdff1", "233457799bbcdff1",
         "37d174403fc04f1a37d174403fc04f1a"}
    };


    for (const auto& tc : cases) {
        auto plaintext = DataConverter::HexToBytes(tc.plaintextHex);
        auto key = Build3DESKey(tc.k1, tc.k2, tc.k3);

        TDES tdes(key);
        ECB ecb;

        auto cipher = ecb.encrypt(plaintext, tdes);
        EXPECT_EQ(DataConverter::BytesToHex(cipher), tc.expectedHex);

        auto decrypted = ecb.decrypt(cipher, tdes);
        EXPECT_EQ(DataConverter::BytesToHex(decrypted), tc.plaintextHex);
    }
}

// ------------------------------------------------------------
// 4. Test błędnych kluczy — TDES powinien odrzucać złe długości
// ------------------------------------------------------------
TEST(TDES, InvalidKeyLength)
{
    std::vector<uint8_t> tooShort(5);
    EXPECT_THROW(TDES tdes(tooShort), std::invalid_argument);

    std::vector<uint8_t> tooLong(40);
    EXPECT_THROW(TDES tdes(tooLong), std::invalid_argument);
}
