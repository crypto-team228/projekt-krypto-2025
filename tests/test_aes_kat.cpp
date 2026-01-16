#include <gtest/gtest.h>
#include "cipher/AES/aes.hpp"
#include "mode/CBC.hpp"
#include "mode/CTR.hpp"
#include "mode/GCM.hpp"
#include "mode/ECB.hpp"
#include "KATHarness.hpp"

// Pomocnicze predykaty na nazwie test case
static bool IsEncryptCase(const std::string& name) {
    return name.rfind("ENC_", 0) == 0; // zaczyna się od "ENC_"
}

static bool IsDecryptCase(const std::string& name) {
    return name.rfind("DEC_", 0) == 0; // zaczyna się od "DEC_"
}

// =======================
// AES ECB
// =======================

TEST(AES, KAT_ECB)
{
    auto cases = LoadKATFile("tests/nist/aesavs/ecb/ECB.csv");
    ASSERT_FALSE(cases.empty());

    // ENCRYPT
    for (auto& tc : cases) {
        if (!IsEncryptCase(tc.name))
            continue;

        try {
            AES aes(tc.key);
            ECB ecb;
			ecb.setPadding(PaddingMode::None);

            auto ct = ecb.encrypt(tc.plaintext, aes);

            EXPECT_EQ(ct, tc.ciphertext)
                << "ENC failed: " << tc.name
                << "\nKey:        " << BytesToHex(tc.key)
                << "\nPlaintext:  " << BytesToHex(tc.plaintext)
                << "\nExpected CT:" << BytesToHex(tc.ciphertext)
                << "\nActual CT:  " << BytesToHex(ct);
        }
        catch (const std::exception& ex) {
            ADD_FAILURE() << "Exception in ENC case " << tc.name << ": " << ex.what();
        }
    }

    // DECRYPT
    for (auto& tc : cases) {
        if (!IsDecryptCase(tc.name))
            continue;

        try {
            AES aes(tc.key);
            ECB ecb;
			ecb.setPadding(PaddingMode::None);

            auto pt =  ecb.decrypt(tc.ciphertext,aes);

            EXPECT_EQ(pt, tc.plaintext)
                << "DEC failed: " << tc.name
                << "\nKey:        " << BytesToHex(tc.key)
                << "\nCiphertext: " << BytesToHex(tc.ciphertext)
                << "\nExpected PT:" << BytesToHex(tc.plaintext)
                << "\nActual PT:  " << BytesToHex(pt);
        }
        catch (const std::exception& ex) {
            ADD_FAILURE() << "Exception in DEC case " << tc.name << ": " << ex.what();
        }
    }
}

// =======================
// AES CBC
// =======================

TEST(AES, KAT_CBC)
{
    auto cases = LoadKATFile("tests/nist/aesavs/cbc/CBC.csv");
    ASSERT_FALSE(cases.empty());

    // ENCRYPT
    for (auto& tc : cases) {
        if (!IsEncryptCase(tc.name))
            continue;

        try {
            AES aes(tc.key);
            CBC cbc;
            cbc.setIV(tc.iv);
			cbc.setPadding(PaddingMode::None);

            auto ct = cbc.encrypt(tc.plaintext, aes);

            EXPECT_EQ(ct, tc.ciphertext)
                << "ENC failed: " << tc.name
                << "\nKey:        " << BytesToHex(tc.key)
                << "\nIV:         " << BytesToHex(tc.iv)
                << "\nPlaintext:  " << BytesToHex(tc.plaintext)
                << "\nExpected CT:" << BytesToHex(tc.ciphertext)
                << "\nActual CT:  " << BytesToHex(ct);
        }
        catch (const std::exception& ex) {
            ADD_FAILURE() << "Exception in ENC case " << tc.name << ": " << ex.what();
        }
    }

    // DECRYPT
    for (auto& tc : cases) {
        if (!IsDecryptCase(tc.name))
            continue;

        try {
            AES aes(tc.key);
            CBC cbc;
            cbc.setIV(tc.iv);
			cbc.setPadding(PaddingMode::None);

            auto pt = cbc.decrypt(tc.ciphertext, aes);

            EXPECT_EQ(pt, tc.plaintext)
                << "DEC failed: " << tc.name
                << "\nKey:        " << BytesToHex(tc.key)
                << "\nIV:         " << BytesToHex(tc.iv)
                << "\nCiphertext: " << BytesToHex(tc.ciphertext)
                << "\nExpected PT:" << BytesToHex(tc.plaintext)
                << "\nActual PT:  " << BytesToHex(pt);
        }
        catch (const std::exception& ex) {
            ADD_FAILURE() << "Exception in DEC case " << tc.name << ": " << ex.what();
        }
    }
}

// =======================
// AES CTR
// =======================

TEST(AES, KAT_CTR)
{
    auto cases = LoadKATFile("tests/nist/aesavs/ctr/CTR.csv");
    ASSERT_FALSE(cases.empty());

    // ENCRYPT
    for (auto& tc : cases) {
        if (!IsEncryptCase(tc.name))
            continue;

        try {
            AES aes(tc.key);
            CTR ctr;
            ctr.setIV(tc.iv);
			ctr.setPadding(PaddingMode::None);

            auto ct = ctr.encrypt(tc.plaintext, aes);

            EXPECT_EQ(ct, tc.ciphertext)
                << "ENC failed: " << tc.name
                << "\nKey:        " << BytesToHex(tc.key)
                << "\nIV:         " << BytesToHex(tc.iv)
                << "\nPlaintext:  " << BytesToHex(tc.plaintext)
                << "\nExpected CT:" << BytesToHex(tc.ciphertext)
                << "\nActual CT:  " << BytesToHex(ct);
        }
        catch (const std::exception& ex) {
            ADD_FAILURE() << "Exception in ENC case " << tc.name << ": " << ex.what();
        }
    }

    // DECRYPT (CTR jest symetryczny, ale testujemy osobno)
    for (auto& tc : cases) {
        if (!IsDecryptCase(tc.name))
            continue;

        try {
            AES aes(tc.key);
            CTR ctr;
            ctr.setIV(tc.iv);
			ctr.setPadding(PaddingMode::None);

            auto pt = ctr.decrypt(tc.ciphertext, aes);

            EXPECT_EQ(pt, tc.plaintext)
                << "DEC failed: " << tc.name
                << "\nKey:        " << BytesToHex(tc.key)
                << "\nIV:         " << BytesToHex(tc.iv)
                << "\nCiphertext: " << BytesToHex(tc.ciphertext)
                << "\nExpected PT:" << BytesToHex(tc.plaintext)
                << "\nActual PT:  " << BytesToHex(pt);
        }
        catch (const std::exception& ex) {
            ADD_FAILURE() << "Exception in DEC case " << tc.name << ": " << ex.what();
        }
    }
}

// =======================
// AES GCM
// =======================

TEST(AES, KAT_GCM)
{
    auto cases = LoadKATFile("tests/nist/gcmvs/gcm/GCM.csv");
    ASSERT_FALSE(cases.empty());

    for (auto& tc : cases) {
        try {
            AES aes(tc.key);

            // ENCRYPT
            GCM gcm_enc;
            if (!tc.iv.empty())
                gcm_enc.setIV(tc.iv);
            if (!tc.aad.empty())
                gcm_enc.setAAD(tc.aad);

            auto ct = gcm_enc.encrypt(tc.plaintext, aes);
            auto tag = gcm_enc.getTag();

            if (!tc.ciphertext.empty()) {
                EXPECT_EQ(ct, tc.ciphertext)
                    << "ENC failed: " << tc.name
                    << "\nKey:        " << BytesToHex(tc.key)
                    << "\nIV:         " << BytesToHex(tc.iv)
                    << "\nAAD:        " << BytesToHex(tc.aad)
                    << "\nPlaintext:  " << BytesToHex(tc.plaintext)
                    << "\nExpected CT:" << BytesToHex(tc.ciphertext)
                    << "\nActual CT:  " << BytesToHex(ct);
            }

            if (!tc.tag.empty()) {
                EXPECT_EQ(std::vector<uint8_t>(tag.begin(), tag.end()), tc.tag)
                    << "TAG mismatch in ENC: " << tc.name;
            }

            // DECRYPT
            GCM gcm_dec;
            if (!tc.iv.empty())
                gcm_dec.setIV(tc.iv);
            if (!tc.aad.empty())
                gcm_dec.setAAD(tc.aad);

            auto pt = gcm_dec.decrypt(ct, aes);
            EXPECT_EQ(pt, tc.plaintext)
                << "DEC failed: " << tc.name;

            EXPECT_TRUE(gcm_dec.verifyTag(tag))
                << "TAG verify failed in DEC: " << tc.name;
        }
        catch (const std::exception& ex) {
            ADD_FAILURE() << "Exception in GCM case " << tc.name << ": " << ex.what();
        }
    }
}

TEST(AES, SingleVector_AES256_ECB_Manual)
{
    // NIST AES-256 ECB KAT (przykład z Twojego logu, ale bez CBC)
    const std::string key_hex = "0000000000000000000000000000000000000000000000000000000000000000";
    const std::string pt_hex = "fffffffffffffffffffffffffffffffc";
    const std::string ct_hex = "0f59cb5a4b522e2ac56c1a64f558ad9a";

    auto key = HexToBytes(key_hex);
    auto pt = HexToBytes(pt_hex);
    auto ct_expected = HexToBytes(ct_hex);

    ASSERT_EQ(key.size(), 32u);
    ASSERT_EQ(pt.size(), 16u);
    ASSERT_EQ(ct_expected.size(), 16u);

    AES aes(key);

    std::vector<uint8_t> out(16);
    aes.encryptBlock(pt.data(), out.data());

    EXPECT_EQ(out, ct_expected)
        << "Key: " << BytesToHex(key)
        << "\nPT: " << BytesToHex(pt)
        << "\nCT: " << BytesToHex(out);
}

