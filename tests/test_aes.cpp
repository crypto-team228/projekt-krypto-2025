#include <iostream>
#include <iomanip>
#include <string>
#include <vector>
#include "cipher/AES/aes.hpp"

// Test result tracking
int tests_passed = 0;
int tests_failed = 0;

// Helper to compare two states
bool compareStates(const AES::State &a, const AES::State &b)
{
    for (int i = 0; i < 16; i++)
    {
        if (a[i] != b[i])
            return false;
    }
    return true;
}

// Helper to print a state
void printState(const AES::State &st)
{
    for (int i = 0; i < 16; i++)
    {
        std::cout << std::hex << std::setfill('0') << std::setw(2) << (int)st[i];
        if (i < 15)
            std::cout << " ";
    }
}

// Test helper
void runTest(const std::string &name, bool passed)
{
    if (passed)
    {
        std::cout << "✓ " << name << " PASSED\n";
        tests_passed++;
    }
    else
    {
        std::cout << "✗ " << name << " FAILED\n";
        tests_failed++;
    }
}

// NIST Test Vector 1 - FIPS 197 Appendix C.1
void testNISTVector1()
{
    std::cout << "\n=== NIST FIPS 197 Appendix C.1 Test ===\n";

    AES::Key128 key = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

    AES::State plaintext = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};

    AES::State expected_ciphertext = {
        0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
        0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a};

    AES::State result = plaintext;

    // Test encryption
    std::cout << "Plaintext:  ";
    printState(plaintext);
    std::cout << "\nCiphertext: ";
    printState(result);
    std::cout << "\nExpected:   ";
    printState(expected_ciphertext);
    std::cout << "\n";

    bool encrypt_pass = compareStates(result, expected_ciphertext);
    runTest("NIST C.1 Encryption", encrypt_pass);

    // Test decryption
    bool decrypt_pass = compareStates(result, plaintext);
    runTest("NIST C.1 Decryption", decrypt_pass);
}

// NIST Test Vector 2 - All zeros
void testAllZeros()
{
    std::cout << "\n=== All Zeros Test ===\n";

    AES::Key128 key = {0};
    AES::State plaintext = {0};

    AES::State expected_ciphertext = {
        0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b,
        0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34, 0x2b, 0x2e};

    AES::State result = plaintext;

    bool encrypt_pass = compareStates(result, expected_ciphertext);
    runTest("All Zeros Encryption", encrypt_pass);

    bool decrypt_pass = compareStates(result, plaintext);
    runTest("All Zeros Decryption", decrypt_pass);
}

// NIST Test Vector 3 - From NIST SP 800-38A
void testNISTSP800()
{
    std::cout << "\n=== NIST SP 800-38A Test ===\n";

    AES::Key128 key = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};

    AES::State plaintext = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a};

    AES::State expected_ciphertext = {
        0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60,
        0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97};

    AES::State result = plaintext;

    bool encrypt_pass = compareStates(result, expected_ciphertext);
    runTest("NIST SP 800-38A Encryption", encrypt_pass);

    bool decrypt_pass = compareStates(result, plaintext);
    runTest("NIST SP 800-38A Decryption", decrypt_pass);
}

// Test with all 0xFF
void testAllOnes()
{
    std::cout << "\n=== All Ones (0xFF) Test ===\n";

    AES::Key128 key;
    key.fill(0xFF);

    AES::State plaintext;
    plaintext.fill(0xFF);

    AES::State encrypted = plaintext;

    // Check that encryption changed the data
    bool changed = !compareStates(encrypted, plaintext);
    runTest("All 0xFF changes on encryption", changed);

    // Test roundtrip
    bool roundtrip = compareStates(encrypted, plaintext);
    runTest("All 0xFF roundtrip", roundtrip);
}

// Test multiple blocks with same key
void testMultipleBlocks()
{
    std::cout << "\n=== Multiple Blocks Test ===\n";

    AES::Key128 key = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};


    // Test 3 different blocks
    std::vector<AES::State> blocks = {
        {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
         0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
        {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
         0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10},
        {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
         0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99}};

    bool all_passed = true;
    for (size_t i = 0; i < blocks.size(); i++)
    {
        AES::State original = blocks[i];
        AES::State encrypted = original;


        if (!compareStates(encrypted, original))
        {
            all_passed = false;
            std::cout << "  Block " << i << " failed roundtrip\n";
        }
    }

    runTest("Multiple blocks roundtrip", all_passed);
}

// Test that different keys produce different ciphertexts
void testDifferentKeys()
{
    std::cout << "\n=== Different Keys Test ===\n";

    AES::State plaintext = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};

    AES::Key128 key1 = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

    AES::Key128 key2 = {
        0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08,
        0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00};


    AES::State cipher1 = plaintext;
    AES::State cipher2 = plaintext;

    bool different = !compareStates(cipher1, cipher2);
    runTest("Different keys produce different ciphertexts", different);
}

// Test avalanche effect - small change in plaintext causes large change in ciphertext
void testAvalancheEffect()
{
    std::cout << "\n=== Avalanche Effect Test ===\n";

    AES::Key128 key = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};


    AES::State plaintext1 = {
        0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
        0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34};

    AES::State plaintext2 = plaintext1;
    plaintext2[0] ^= 0x01; // Flip one bit

    AES::State cipher1 = plaintext1;
    AES::State cipher2 = plaintext2;

    // Count different bits
    int diff_bits = 0;
    for (int i = 0; i < 16; i++)
    {
        uint8_t xor_val = cipher1[i] ^ cipher2[i];
        for (int bit = 0; bit < 8; bit++)
        {
            if (xor_val & (1 << bit))
                diff_bits++;
        }
    }

    std::cout << "  1-bit plaintext change caused " << diff_bits << " bit changes in ciphertext\n";
    bool good_avalanche = (diff_bits >= 40 && diff_bits <= 90);
    runTest("Avalanche effect (40-90 bits changed)", good_avalanche);
}

// Test that encryption and decryption are inverses
void testInverseProperty()
{
    std::cout << "\n=== Inverse Property Test ===\n";

    AES::Key128 key = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

    bool all_passed = true;

    for (int test = 0; test < 100; test++)
    {
        AES::State original;
        for (int i = 0; i < 16; i++)
        {
            original[i] = (uint8_t)((test * 17 + i * 13) & 0xFF);
        }

        AES::State working = original;

        if (!compareStates(working, original))
        {
            all_passed = false;
            std::cout << "  Failed on test pattern " << test << "\n";
            break;
        }
    }

    runTest("100 roundtrip tests", all_passed);
}

int main()
{
    std::cout << "========================================\n";
    std::cout << "         AES Implementation Tests       \n";
    std::cout << "========================================\n";

    testNISTVector1();
    testAllZeros();
    testNISTSP800();
    testAllOnes();
    testMultipleBlocks();
    testDifferentKeys();
    testAvalancheEffect();
    testInverseProperty();

    std::cout << "\n========================================\n";
    std::cout << "              Test Summary              \n";
    std::cout << "========================================\n";
    std::cout << "Tests passed: " << tests_passed << "\n";
    std::cout << "Tests failed: " << tests_failed << "\n";
    std::cout << "Total tests:  " << (tests_passed + tests_failed) << "\n";

    if (tests_failed == 0)
    {
        std::cout << "\nAll tests PASSED!\n";
        return 0;
    }
    else
    {
        std::cout << "\nSome tests FAILED\n";
        return 1;
    }
}
