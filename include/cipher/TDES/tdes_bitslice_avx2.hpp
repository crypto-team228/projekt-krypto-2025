#pragma once
#include <immintrin.h>
#include <cstdint>
#include <array>
#include <vector>
#include <stdexcept>
#include <cstring>
#include <iostream>
#include <iomanip>
#include "cipher/cipher.hpp"

struct FeistelTrace {
    uint64_t E;      // 48 bitów po ekspansji
    uint64_t X;      // 48 bitów po XOR z kluczem
    uint32_t S;      // 32 bity po S-boksach
    uint32_t P;      // 32 bity po permutacji P (czyli F)
};

class TDES_Bitslice_AVX2 final : public Cipher {
public:
    static constexpr std::size_t BLOCK_SIZE = 8;   // 64-bit block
    static constexpr std::size_t BS_BLOCKS = 32;   // liczba bloków przetwarzanych równolegle
    static constexpr std::size_t BS_PLANES = 64;   // 64 bity na blok

    using Bit64 = uint64_t;
    using Bit48 = uint64_t;
    using Bit32 = uint32_t;
    using SubkeyScheduleScalar = std::array<Bit48, 16>;

    // 64 bit-planes, ka¿dy jako maska 32-bitowa w __m256i
    using BitSliceState = std::array<__m256i, BS_PLANES>;

    // bitslice subkeys: [key_index][round][48 bit-planes]
    using SubkeyBitsliceRound = std::array<__m256i, 48>;
    using SubkeyBitslice = std::array<std::array<SubkeyBitsliceRound, 16>, 3>;

    TDES_Bitslice_AVX2() = default;
    explicit TDES_Bitslice_AVX2(const std::vector<uint8_t>& key) { setKey(key); }

    ~TDES_Bitslice_AVX2() override;

    std::size_t blockSize() const override { return BLOCK_SIZE; }
    std::size_t batchSize() const override { return BS_BLOCKS; }

    void setKey(const std::vector<uint8_t>& key) override;

    void encryptBlocks(const uint8_t* in, uint8_t* out, size_t blocks) const override {
        encryptBlocks_bitslice(in, out, blocks);
    }

    void decryptBlocks(const uint8_t* in, uint8_t* out, size_t blocks) const override {
        decryptBlocks_bitslice(in, out, blocks);
    }

    void encryptBlock(const uint8_t* in, uint8_t* out) const override;
    void decryptBlock(const uint8_t* in, uint8_t* out) const override;

    void encryptBlock_bitslice_single(const uint8_t* in, uint8_t* out) const;

    void decryptBlock_bitslice_single(const uint8_t* in, uint8_t* out) const;


    void encryptBlocks_bitslice(const uint8_t* in, uint8_t* out, std::size_t blocks) const;
    void decryptBlocks_bitslice(const uint8_t* in, uint8_t* out, std::size_t blocks) const;

private:
    // scalar key schedule
    static SubkeyScheduleScalar GenerateSubkeysScalar(uint64_t key64);
    void expand_subkeys_to_bitslice();

    // scalar key schedule (3 klucze)
    SubkeyScheduleScalar subkeys1_scalar{};
    SubkeyScheduleScalar subkeys2_scalar{};
    SubkeyScheduleScalar subkeys3_scalar{};

    // bitslice subkeys
    SubkeyBitslice subkeys_bitslice{};

    // layout danych
    static void blocks_to_bitslice(const uint8_t* in,
        std::size_t blocks,
        BitSliceState& bs);

    static void bitslice_to_blocks(const BitSliceState& bs,
        uint8_t* out,
        std::size_t blocks);

    // IP/FP
    static void IP_bitslice(BitSliceState& bs);
    static void FP_bitslice(BitSliceState& bs);

    // Feistel F
    void feistel_bitslice(const BitSliceState& bs_R,
        BitSliceState& bs_F,
        int round,
        int key_index) const;

    void DES_encrypt_bitslice_block(BitSliceState& bs, int key_index) const;

    void DES_decrypt_bitslice_block(BitSliceState& bs, int key_index) const;

    // DES / 3DES na bitslice
    void DES_encrypt_bitslice(BitSliceState& bs, int key_index) const;
    void DES_decrypt_bitslice(BitSliceState& bs, int key_index) const;

    void TripleDES_encrypt_bitslice(BitSliceState& bs) const;
    void TripleDES_decrypt_bitslice(BitSliceState& bs) const;

    void debug_des_rounds(const uint8_t* in) const;
    uint8_t scalar_S(int box, uint8_t x) const;

    void bitslice_S(int box, const uint64_t in[6], uint64_t out[4]) const;

    uint64_t DES_encrypt_scalar_block(uint64_t block, int key_index) const;

    void test_des_single(const TDES_Bitslice_AVX2& tdes, uint64_t block);

    static void load_block_to_bitslice(BitSliceState& bs, uint64_t block);

    static uint64_t extract_block_from_bitslice(const BitSliceState& bs);

    void selftest_scalar_vs_bitslice(uint64_t block, int key_index) const;

    uint32_t feistel_scalar(uint32_t R, int round, int key_index) const;

    static uint32_t extract_L32_lane0(const BitSliceState& bs);

    static uint32_t extract_R32_lane0(const BitSliceState& bs);

    static uint32_t extract_F32_lane0(const BitSliceState& F);

    uint64_t subkey_scalar_from_bitslice(int key_index, int round) const;

    FeistelTrace feistel_scalar_trace(uint32_t R, int round, int key_index) const;

    FeistelTrace feistel_bitslice_trace_lane0(const BitSliceState& bs_R, int round, int key_index) const;

    void test_feistel_round(uint32_t R, int round, int key_index) const;

    static const uint8_t SBOXES[8][64];


    inline __m256i or_bit(__m256i v, int lane, int bit) const {
        uint64_t mask = 1ULL << bit;
        __m256i lane_mask = _mm256_set_epi64x(
            lane == 3 ? mask : 0,
            lane == 2 ? mask : 0,
            lane == 1 ? mask : 0,
            lane == 0 ? mask : 0
        );
        return _mm256_or_si256(v, lane_mask);
    }




};
