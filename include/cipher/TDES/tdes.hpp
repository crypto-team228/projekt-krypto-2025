#pragma once
#include <array>
#include <cstdint>
#include <vector>
#include "cipher/cipher.hpp"

// =======================
//  TDES – szybka wersja
// =======================

class TDES : public Cipher
{
public:
    static constexpr std::size_t BLOCK_SIZE = 8;

    using Bit64 = uint64_t;   // 64-bit block
    using Bit48 = uint64_t;   // 48-bit subkey
    using Bit32 = uint32_t;   // 32-bit half-block

    using SubkeySchedule = std::array<Bit48, 16>;

public:
    explicit TDES(const std::vector<uint8_t>& key);
    TDES() = default;

    ~TDES() override;

    std::size_t blockSize() const override;

    void setKey(const std::vector<uint8_t>& key) override;

    void encryptBlock(const uint8_t* in, uint8_t* out) const override;
    void decryptBlock(const uint8_t* in, uint8_t* out) const override;

private:
    // 3DES EDE
    Bit64 TripleDESEncrypt(Bit64 bits) const;
    Bit64 TripleDESDecrypt(Bit64 bits) const;

    // DES
    Bit64 DESEncryptBlock(Bit64 block, const SubkeySchedule& subkeys) const;
    Bit64 DESDecryptBlock(Bit64 block, const SubkeySchedule& subkeys) const;

    // Feistel
    Bit32 FeistelFunction(Bit32 right, Bit48 subkey) const;

    // Subkeys
    SubkeySchedule GenerateSubkeys(Bit64 key64);

private:
    SubkeySchedule subkeys1{};
    SubkeySchedule subkeys2{};
    SubkeySchedule subkeys3{};
};

// =======================
//  LUT-y DES (extern)
// =======================

// IP / FP
extern uint64_t ip_lut[8][256];
extern uint64_t fp_lut[8][256];

// E-expansion
extern uint64_t e_lut[4][256];

// P-permutation
extern uint32_t p_lut[4][256];

// PC-1 / PC-2
extern uint64_t pc1_lut[8][256];
extern uint64_t pc2_lut[7][256];

// S-box LUT (8 × 64)
extern uint8_t sbox_lut[8][64];

// Key shifts (16)
extern const int keyShiftTable[16];
