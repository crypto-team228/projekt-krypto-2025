#include <immintrin.h>
#include <cstdint>
#include <array>
#include <vector>
#include <stdexcept>
#include <cstring>
#include "cipher/cipher.hpp"

class TDES_Bitslice_AVX512 final : public Cipher {
public:
    static constexpr std::size_t BLOCK_SIZE = 8;   // 64-bit block
    static constexpr std::size_t BS_BLOCKS = 32;  // liczba bloków przetwarzanych równolegle (do ustalenia)
    static constexpr std::size_t BS_PLANES = 64;  // 64 bity na blok

    using BitSliceState = std::array<__m512i, BS_PLANES>;
    using SubkeyScheduleScalar = std::array<uint64_t, 16>;







    explicit TDES_Bitslice_AVX512(const std::vector<uint8_t>& key);
    ~TDES_Bitslice_AVX512();

    size_t blockSize() const override { return BLOCK_SIZE; }

    void encryptBlock(const uint8_t* in, uint8_t* out) const override {
        encryptBlocks_bitslice(in, out, 1);
    }

    void decryptBlock(const uint8_t* in, uint8_t* out) const override {
        decryptBlocks_bitslice(in, out, 1);
    }

    void setKey(const std::vector<uint8_t>& key);

    // API wysokiego poziomu – bitslice
    void encryptBlocks_bitslice(const uint8_t* in, uint8_t* out, std::size_t blocks) const;
    void decryptBlocks_bitslice(const uint8_t* in, uint8_t* out, std::size_t blocks) const;

private:
    // scalar key schedule (jak w klasycznym DES)
    SubkeyScheduleScalar subkeys1_scalar{};
    SubkeyScheduleScalar subkeys2_scalar{};
    SubkeyScheduleScalar subkeys3_scalar{};

    // bitsliceowe subkeys: [key_index][round][48 bit-planes]
    using SubkeyBitsliceRound = std::array<__m512i, 48>;
    using SubkeyBitslice = std::array<std::array<SubkeyBitsliceRound, 16>, 3>;
    SubkeyBitslice subkeys_bitslice{};


    // --- Warstwa layoutu danych ---

    // 1) Bloki -> bitslice
    static void blocks_to_bitslice(const uint8_t* in,
        std::size_t blocks,
        BitSliceState& bs);

    // 2) Bitslice -> bloki
    static void bitslice_to_blocks(const BitSliceState& bs,
        uint8_t* out,
        std::size_t blocks);

    // --- Warstwa klucza / subkeys ---

    // scalar key schedule (jak w klasycznym DES)
    static SubkeyScheduleScalar GenerateSubkeysScalar(uint64_t key64);

    // rozszerzenie scalar subkeys do bitslice (szkielet)
    void expand_subkeys_to_bitslice();

    // --- Warstwa permutacji IP/FP w bitslice ---

    static void IP_bitslice(BitSliceState& bs);
    static void FP_bitslice(BitSliceState& bs);

    // --- Warstwa rdzenia DES w bitslice ---

    // Feistel F: E-expansion + S-boxy + P-permutation w bitslice
    // R_in: 32 bit-planes prawej po³owy
    // F_out: 32 bit-planes wyniku F
    void feistel_bitslice(const BitSliceState& bs_R,
        BitSliceState& bs_F,
        int round,
        int key_index /* 0,1,2 dla K1,K2,K3 */) const;

    // --- Warstwa rund DES / 3DES w bitslice ---

    // DES encrypt/decrypt na bitslice (jedna instancja DES)
    void DES_encrypt_bitslice(BitSliceState& bs,
        int key_index /* 0,1,2 */) const;
    void DES_decrypt_bitslice(BitSliceState& bs,
        int key_index /* 0,1,2 */) const;

    // Triple DES EDE na bitslice
    void TripleDES_encrypt_bitslice(BitSliceState& bs) const;
    void TripleDES_decrypt_bitslice(BitSliceState& bs) const;
};