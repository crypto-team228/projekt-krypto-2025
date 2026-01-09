#include <gtest/gtest.h>
#include "cipher/AES/aes.hpp"
#include <vector>
#include <array>
#include <iomanip>

// Helper: compare two byte vectors
static bool bytesEqual(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b)
{
    return a.size() == b.size() && std::equal(a.begin(), a.end(), b.begin());
}

// Helper: portable popcount for uint8_t
static int popcount8(uint8_t x)
{
    // Kernighan's method
    int count = 0;
    while (x)
    {
        x &= (x - 1);
        ++count;
    }
    return count;
}

// ------------------------------------------------------------
// NIST C.1 Test Vector
// ------------------------------------------------------------
TEST(AES, NIST_C1)
{
    std::vector<uint8_t> key = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f };

    std::vector<uint8_t> plaintext = {
        0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
        0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff };

    std::vector<uint8_t> expected = {
        0x69,0xc4,0xe0,0xd8,0x6a,0x7b,0x04,0x30,
        0xd8,0xcd,0xb7,0x80,0x70,0xb4,0xc5,0x5a };

    AES aes;
    aes.setKey(key);

    std::vector<uint8_t> result = plaintext;
    aes.encryptBlock(result.data(), result.data());

    EXPECT_TRUE(bytesEqual(result, expected));

    aes.decryptBlock(result.data(), result.data());
    EXPECT_TRUE(bytesEqual(result, plaintext));
}

// ------------------------------------------------------------
// All zeros test
// ------------------------------------------------------------
TEST(AES, AllZeros)
{
    std::vector<uint8_t> key(16, 0);
    std::vector<uint8_t> plaintext(16, 0);

    std::vector<uint8_t> expected = {
        0x66,0xe9,0x4b,0xd4,0xef,0x8a,0x2c,0x3b,
        0x88,0x4c,0xfa,0x59,0xca,0x34,0x2b,0x2e };

    AES aes;
    aes.setKey(key);

    std::vector<uint8_t> result = plaintext;
    aes.encryptBlock(result.data(), result.data());
    EXPECT_TRUE(bytesEqual(result, expected));

    aes.decryptBlock(result.data(), result.data());
    EXPECT_TRUE(bytesEqual(result, plaintext));
}

// ------------------------------------------------------------
// NIST SP 800‑38A
// ------------------------------------------------------------
TEST(AES, NIST_SP800_38A)
{
    std::vector<uint8_t> key = {
        0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
        0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c };

    std::vector<uint8_t> plaintext = {
        0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,
        0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a };

    std::vector<uint8_t> expected = {
        0x3a,0xd7,0x7b,0xb4,0x0d,0x7a,0x36,0x60,
        0xa8,0x9e,0xca,0xf3,0x24,0x66,0xef,0x97 };

    AES aes;
    aes.setKey(key);

    std::vector<uint8_t> result = plaintext;
    aes.encryptBlock(result.data(), result.data());
    EXPECT_TRUE(bytesEqual(result, expected));

    aes.decryptBlock(result.data(), result.data());
    EXPECT_TRUE(bytesEqual(result, plaintext));
}

// ------------------------------------------------------------
// All 0xFF test
// ------------------------------------------------------------
TEST(AES, AllOnes)
{
    std::vector<uint8_t> key(16, 0xFF);
    std::vector<uint8_t> plaintext(16, 0xFF);

    AES aes;
    aes.setKey(key);

    std::vector<uint8_t> encrypted = plaintext;
    aes.encryptBlock(encrypted.data(), encrypted.data());

    EXPECT_FALSE(bytesEqual(encrypted, plaintext));

    aes.decryptBlock(encrypted.data(), encrypted.data());
    EXPECT_TRUE(bytesEqual(encrypted, plaintext));
}

// ------------------------------------------------------------
// Multiple blocks (roundtrip)
// ------------------------------------------------------------
TEST(AES, MultipleBlocksRoundtrip)
{
    std::vector<uint8_t> key = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f };

    AES aes;
    aes.setKey(key);

    std::vector<uint8_t> data = {
        0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
        0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,
        0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
        0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10,
        0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x00,0x11,
        0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99 };

    std::vector<uint8_t> original = data;

    aes.encryptBlock(data.data(), data.data());
    aes.decryptBlock(data.data(), data.data());

    EXPECT_TRUE(bytesEqual(data, original));
}

// ------------------------------------------------------------
// Different keys produce different ciphertexts
// ------------------------------------------------------------
TEST(AES, DifferentKeys)
{
    std::vector<uint8_t> plaintext = {
        0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
        0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff };

    std::vector<uint8_t> key1 = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f };

    std::vector<uint8_t> key2 = {
        0x0f,0x0e,0x0d,0x0c,0x0b,0x0a,0x09,0x08,
        0x07,0x06,0x05,0x04,0x03,0x02,0x01,0x00 };

    AES aes1, aes2;
    aes1.setKey(key1);
    aes2.setKey(key2);

    std::vector<uint8_t> cipher1 = plaintext;
    std::vector<uint8_t> cipher2 = plaintext;

    aes1.encryptBlock(cipher1.data(), cipher1.data());
    aes2.encryptBlock(cipher2.data(), cipher2.data());

    EXPECT_FALSE(bytesEqual(cipher1, cipher2));
}

// ------------------------------------------------------------
// Avalanche effect
// ------------------------------------------------------------
TEST(AES, AvalancheEffect)
{
    std::vector<uint8_t> key = {
        0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
        0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c };

    AES aes;
    aes.setKey(key);

    std::vector<uint8_t> p1 = {
        0x32,0x43,0xf6,0xa8,0x88,0x5a,0x30,0x8d,
        0x31,0x31,0x98,0xa2,0xe0,0x37,0x07,0x34 };

    std::vector<uint8_t> p2 = p1;
    p2[0] ^= 0x01;

    std::vector<uint8_t> c1 = p1;
    std::vector<uint8_t> c2 = p2;

    aes.encryptBlock(c1.data(), c1.data());
    aes.encryptBlock(c2.data(), c2.data());

    int diff_bits = 0;
    for (size_t i = 0; i < 16; i++)
    {
        uint8_t x = c1[i] ^ c2[i];
        diff_bits += popcount8(x);
    }

    EXPECT_GE(diff_bits, 40);
    EXPECT_LE(diff_bits, 90);
}

// ------------------------------------------------------------
// Inverse property (100 random-ish patterns)
// ------------------------------------------------------------
TEST(AES, InverseProperty)
{
    std::vector<uint8_t> key = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f };

    AES aes;
    aes.setKey(key);

    for (int t = 0; t < 100; t++)
    {
        std::vector<uint8_t> original(16);
        for (int i = 0; i < 16; i++)
            original[i] = (uint8_t)((t * 17 + i * 13) & 0xFF);

        std::vector<uint8_t> working = original;

        aes.encryptBlock(working.data(), working.data());
        aes.decryptBlock(working.data(), working.data());

        EXPECT_TRUE(bytesEqual(working, original));
    }
}

// ------------------------------------------------------------
// Key change test
// ------------------------------------------------------------
TEST(AES, KeyChange)
{
    std::vector<uint8_t> plaintext = {
        0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
        0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff };

    std::vector<uint8_t> key1 = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f };

    std::vector<uint8_t> key2 = {
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
        0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f };

    AES aes;
    aes.setKey(key1);

    std::vector<uint8_t> c1 = plaintext;
    aes.encryptBlock(c1.data(), c1.data());

    aes.setKey(key2);

    std::vector<uint8_t> c2 = plaintext;
    aes.encryptBlock(c2.data(), c2.data());

    EXPECT_FALSE(bytesEqual(c1, c2));

    aes.decryptBlock(c2.data(), c2.data());
    EXPECT_TRUE(bytesEqual(c2, plaintext));
}
