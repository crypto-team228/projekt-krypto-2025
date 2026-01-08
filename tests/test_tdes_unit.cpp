#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#include <cctype>

#include "cipher/TDES/tdes.hpp"

static std::string ToLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c){ return static_cast<char>(std::tolower(c)); });
    return s;
}

int main() {
    // Construct TDES with an empty key vector - string-based APIs derive subkeys from provided hex keys.
    TDES tdes(std::vector<uint8_t>{});

    struct TestCase {
        std::string plaintext; // 8-byte blocks in hex-like ASCII (existing API expects this format)
        std::string key1;
        std::string key2;
        std::string key3;
        std::string expectedCipherHex; // expected hex (lowercase accepted)
    };

    std::vector<TestCase> cases = {
        // Single block test vectors (from existing tests)
        {"0123456789ABCDEF", "033457799BBCDFF1", "133457799BBCDFF1", "233457799BBCDFF1", "37d174403fc04f1a"},
        {"FEDCBA9876543210", "233457799BBCDFF1", "133457799BBCDFF1", "033457799BBCDFF1", "473eeb07b08f7d13"},
        // Two-block repeated plaintext expected result
        {"0123456789ABCDEF0123456789ABCDEF", "033457799BBCDFF1", "133457799BBCDFF1", "233457799BBCDFF1", "37d174403fc04f1a37d174403fc04f1a"},
    };

    bool all_ok = true;
    for (const auto &tc : cases) {
        // Encrypt
        std::string cipher = tdes.EncryptBlock(tc.plaintext, tc.key1, tc.key2, tc.key3);
        // Convert raw cipher bytes -> hex using helper functions
        auto cipherBits = tdes.StringToBitArray<64>(cipher);
        std::string cipherHex = tdes.BitArrayToHexString(cipherBits);
        if (ToLower(cipherHex) != ToLower(tc.expectedCipherHex)) {
            std::cerr << "Encrypt FAIL\n";
            std::cerr << " Plaintext      : " << tc.plaintext << "\n";
            std::cerr << " Keys           : " << tc.key1 << " " << tc.key2 << " " << tc.key3 << "\n";
            std::cerr << " Expected (hex) : " << tc.expectedCipherHex << "\n";
            std::cerr << " Got (hex)      : " << cipherHex << "\n\n";
            all_ok = false;
        } else {
            std::cout << "Encrypt OK: expected " << tc.expectedCipherHex << " got " << cipherHex << "\n";
        }

        // Decrypt: call DecryptBlock and verify it matches original plaintext
        std::string decrypted = tdes.DecryptBlock(cipher, tc.key1, tc.key2, tc.key3);
        // decrypted is returned as raw bytes; convert to hex or compare raw depending on test case length
        // convert decrypted back to hex and compare to plaintext hex string(s)
        // plaintext contains ASCII hex digits representing original 8-byte blocks; to compare, transform decrypted bytes into hex
        auto decryptedBits = tdes.StringToBitArray<64>(decrypted);
        std::string decryptedHex = tdes.BitArrayToHexString(decryptedBits);

        // For multi-block plaintexts (32 hex chars), decryptBlock should be applied per-block by caller.
        // The existing string-based API returns concatenated raw blocks; compare in 64-bit chunks.
        // Compare first-block hex against first 16 hex chars of plaintext for single-block test cases.
        std::string expectedPlainHex;
        if (tc.plaintext.size() >= 16) {
            // first 8 bytes represented by first 16 characters
            expectedPlainHex = tc.plaintext.substr(0, 16);
        } else {
            expectedPlainHex = tc.plaintext;
        }

        // The BitArrayToHexString gives uppercase letters; normalize
        if (ToLower(decryptedHex).find(ToLower(expectedPlainHex)) == std::string::npos) {
            std::cerr << "Decrypt FAIL\n";
            std::cerr << " Plaintext (hex) : " << tc.plaintext << "\n";
            std::cerr << " Decrypted (hex) : " << decryptedHex << "\n\n";
            all_ok = false;
        } else {
            std::cout << "Decrypt OK: recovered block (hex) " << decryptedHex << "\n";
        }
    }

    // Basic negative test: malformed/short key3 should not crash and should return some result.
    try {
        std::string plaintext = "0123456789ABCDEF";
        std::string key1 = "033457799BBCDFF1";
        std::string key2 = "133457799BBCDFF1";
        std::string key3 = "23345779"; // intentionally short
        std::string cipher = tdes.EncryptBlock(plaintext, key1, key2, key3);
        auto hex = tdes.BitArrayToHexString(tdes.StringToBitArray<64>(cipher));
        std::cout << "Short-key test produced (hex): " << hex << "\n";
    } catch (...) {
        std::cerr << "Short-key test threw exception\n";
        all_ok = false;
    }

    if (all_ok) {
        std::cout << "\nAll TDES 3DES tests passed.\n";
        return 0;
    } else {
        std::cerr << "\nSome TDES 3DES tests failed.\n";
        return 1;
    }
}