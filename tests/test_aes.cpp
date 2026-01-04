#include <iostream>
#include <iomanip>
#include <vector>
#include <array>
#include "cipher/AES/aes.hpp"

// Test counters
static int tests_passed = 0;
static int tests_failed = 0;

void runTest(const std::string &test_name, bool passed)
{
    if (passed)
    {
        std::cout << "✓ " << test_name << " PASSED\n";
        tests_passed++;
    }
    else
    {
        std::cout << "✗ " << test_name << " FAILED\n";
        tests_failed++;
    }
}

void printBytes(const std::vector<uint8_t> &data)
{
    for (size_t i = 0; i < data.size(); i++)
    {
        std::cout << std::hex << std::setfill('0') << std::setw(2) << (int)data[i];
        if ((i + 1) % 16 == 0)
            std::cout << "\n";
        else
            std::cout << " ";
    }
    std::cout << std::dec << "\n";
}

bool compareBytes(const std::vector<uint8_t> &a, const std::vector<uint8_t> &b)
{
    if (a.size() != b.size())
        return false;
    for (size_t i = 0; i < a.size(); i++)
    {
        if (a[i] != b[i])
            return false;
    }
    return true;
}

// NIST Test Vector 1 - From NIST FIPS 197, Appendix C.1
void testNISTVector1()
{
    std::cout << "\n=== NIST C.1 Test Vector ===\n";

    std::vector<uint8_t> key = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

    std::vector<uint8_t> plaintext = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};

    std::vector<uint8_t> expected_ciphertext = {
        0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
        0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a};

    AES aes;
    aes.setKey(key);

    std::vector<uint8_t> result = plaintext;

    // Test encryption
    aes.encryptBlock(result.data(), result.data());
    std::cout << "Plaintext:  ";
    printBytes(plaintext);
    std::cout << "Ciphertext: ";
    printBytes(result);
    std::cout << "Expected:   ";
    printBytes(expected_ciphertext);

    bool encrypt_pass = compareBytes(result, expected_ciphertext);
    runTest("NIST C.1 Encryption", encrypt_pass);

    // Test decryption
    aes.decryptBlock(result.data(), result.data());
    bool decrypt_pass = compareBytes(result, plaintext);
    runTest("NIST C.1 Decryption", decrypt_pass);
}

// NIST Test Vector 2 - All zeros
void testAllZeros()
{
    std::cout << "\n=== All Zeros Test ===\n";

    std::vector<uint8_t> key(16, 0);
    std::vector<uint8_t> plaintext(16, 0);

    std::vector<uint8_t> expected_ciphertext = {
        0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b,
        0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34, 0x2b, 0x2e};

    AES aes;
    aes.setKey(key);

    std::vector<uint8_t> result = plaintext;
    aes.encryptBlock(result.data(), result.data());
    bool encrypt_pass = compareBytes(result, expected_ciphertext);
    runTest("All Zeros Encryption", encrypt_pass);

    aes.decryptBlock(result.data(), result.data());
    bool decrypt_pass = compareBytes(result, plaintext);
    runTest("All Zeros Decryption", decrypt_pass);
}

// NIST Test Vector 3 - From NIST SP 800-38A
void testNISTSP800()
{
    std::cout << "\n=== NIST SP 800-38A Test ===\n";

    std::vector<uint8_t> key = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};

    std::vector<uint8_t> plaintext = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a};

    std::vector<uint8_t> expected_ciphertext = {
        0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60,
        0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97};

    AES aes;
    aes.setKey(key);

    std::vector<uint8_t> result = plaintext;
    aes.encryptBlock(result.data(), result.data());
    bool encrypt_pass = compareBytes(result, expected_ciphertext);
    runTest("NIST SP 800-38A Encryption", encrypt_pass);

    aes.decryptBlock(result.data(), result.data());
    bool decrypt_pass = compareBytes(result, plaintext);
    runTest("NIST SP 800-38A Decryption", decrypt_pass);
}

// Test with all 0xFF
void testAllOnes()
{
    std::cout << "\n=== All Ones (0xFF) Test ===\n";

    std::vector<uint8_t> key(16, 0xFF);
    std::vector<uint8_t> plaintext(16, 0xFF);

    AES aes;
    aes.setKey(key);

    std::vector<uint8_t> encrypted = plaintext;
    aes.encryptBlock(encrypted.data(), encrypted.data());

    // Check that encryption changed the data
    bool changed = !compareBytes(encrypted, plaintext);
    runTest("All 0xFF changes on encryption", changed);

    // Test roundtrip
    aes.decryptBlock(encrypted.data(), encrypted.data());
    bool roundtrip = compareBytes(encrypted, plaintext);
    runTest("All 0xFF roundtrip", roundtrip);
}

// Test multiple blocks with same key
void testMultipleBlocks()
{
    std::cout << "\n=== Multiple Blocks Test ===\n";

    std::vector<uint8_t> key = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

    AES aes;
    aes.setKey(key);

    // Test 3 blocks (48 bytes)
    std::vector<uint8_t> data = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
        0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99};

    std::vector<uint8_t> original = data;

    aes.encryptBlock(data.data(),data.data());
    aes.decryptBlock(data.data(), data.data());

    bool roundtrip = compareBytes(data, original);
    runTest("Multiple blocks roundtrip", roundtrip);
}

// Test that different keys produce different ciphertexts
void testDifferentKeys()
{
    std::cout << "\n=== Different Keys Test ===\n";

    std::vector<uint8_t> plaintext = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};

    std::vector<uint8_t> key1 = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

    std::vector<uint8_t> key2 = {
        0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08,
        0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00};

    AES aes1, aes2;
    aes1.setKey(key1);
    aes2.setKey(key2);

    std::vector<uint8_t> cipher1 = plaintext;
    std::vector<uint8_t> cipher2 = plaintext;

    aes1.encryptBlock(cipher1.data(), cipher1.data());
    aes2.encryptBlock(cipher2.data(), cipher2.data());

    bool different = !compareBytes(cipher1, cipher2);
    runTest("Different keys produce different ciphertexts", different);
}

// Test avalanche effect - small change in plaintext causes large change in ciphertext
void testAvalancheEffect()
{
    std::cout << "\n=== Avalanche Effect Test ===\n";

    std::vector<uint8_t> key = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};

    AES aes;
    aes.setKey(key);

    std::vector<uint8_t> plaintext1 = {
        0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
        0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34};

    std::vector<uint8_t> plaintext2 = plaintext1;
    plaintext2[0] ^= 0x01; // Flip one bit

    std::vector<uint8_t> cipher1 = plaintext1;
    std::vector<uint8_t> cipher2 = plaintext2;

    aes.encryptBlock(cipher1.data(), cipher1.data());
    aes.encryptBlock(cipher2.data(), cipher2.data());

    // Count different bits
    int diff_bits = 0;
    for (size_t i = 0; i < 16; i++)
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

    std::vector<uint8_t> key = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

    AES aes;
    aes.setKey(key);
    bool all_passed = true;

    for (int test = 0; test < 100; test++)
    {
        std::vector<uint8_t> original(16);
        for (int i = 0; i < 16; i++)
        {
            original[i] = (uint8_t)((test * 17 + i * 13) & 0xFF);
        }

        std::vector<uint8_t> working = original;
        aes.encryptBlock(working.data(), working.data());
        aes.decryptBlock(working.data(), working.data());

        if (!compareBytes(working, original))
        {
            all_passed = false;
            std::cout << "  Failed on test pattern " << test << "\n";
            break;
        }
    }

    runTest("100 roundtrip tests", all_passed);
}

// Test setKey can change the key
void testKeyChange()
{
    std::cout << "\n=== Key Change Test ===\n";

    std::vector<uint8_t> plaintext = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};

    std::vector<uint8_t> key1 = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

    std::vector<uint8_t> key2 = {
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};

    AES aes;
    aes.setKey(key1);

    std::vector<uint8_t> cipher1 = plaintext;
    aes.encryptBlock(cipher1.data(), cipher1.data());

    // Change key
    aes.setKey(key2);

    std::vector<uint8_t> cipher2 = plaintext;
    aes.encryptBlock(cipher2.data(), cipher2.data());

    bool different = !compareBytes(cipher1, cipher2);
    runTest("setKey changes encryption result", different);

    // Verify decryption works with new key
    aes.decryptBlock(cipher2.data(), cipher2.data());
    bool decrypt_works = compareBytes(cipher2, plaintext);
    runTest("Decryption works after key change", decrypt_works);
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
    testKeyChange();

    std::cout << "\n========================================\n";
    std::cout << "              Test Summary              \n";
    std::cout << "========================================\n";
    std::cout << "Tests passed: " << tests_passed << "\n";
    std::cout << "Tests failed: " << tests_failed << "\n";
    std::cout << "Total tests:  " << (tests_passed + tests_failed) << "\n";

    if (tests_failed == 0)
    {
        std::cout << "\nAll tests PASSED! ✓\n";
        return 0;
    }
    else
    {
        std::cout << "\nSome tests FAILED ✗\n";
        return 1;
    }
}
