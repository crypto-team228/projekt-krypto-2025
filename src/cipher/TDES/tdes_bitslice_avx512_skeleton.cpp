#include "cipher/TDES/tdes_bitslice_avx512_skeleton.hpp"

static inline void secure_memzero(void* p, std::size_t n) noexcept {
    volatile uint8_t* v = static_cast<volatile uint8_t*>(p);
    while (n--) *v++ = 0;
}

static const uint8_t DES_PC1[56] = {
    57,49,41,33,25,17,9,
    1,58,50,42,34,26,18,
    10,2,59,51,43,35,27,
    19,11,3,60,52,44,36,
    63,55,47,39,31,23,15,
    7,62,54,46,38,30,22,
    14,6,61,53,45,37,29,
    21,13,5,28,20,12,4
};

static const uint8_t DES_PC2[48] = {
    14,17,11,24,1,5,
    3,28,15,6,21,10,
    23,19,12,4,26,8,
    16,7,27,20,13,2,
    41,52,31,37,47,55,
    30,40,51,45,33,48,
    44,49,39,56,34,53,
    46,42,50,36,29,32
};

static const uint8_t DES_KEY_SHIFTS[16] = {
    1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1
};



TDES_Bitslice_AVX512::TDES_Bitslice_AVX512(const std::vector<uint8_t>& key) {
    setKey(key);
}

TDES_Bitslice_AVX512::~TDES_Bitslice_AVX512() {
    secure_memzero(subkeys1_scalar.data(), subkeys1_scalar.size() * sizeof(uint64_t));
    secure_memzero(subkeys2_scalar.data(), subkeys2_scalar.size() * sizeof(uint64_t));
    secure_memzero(subkeys3_scalar.data(), subkeys3_scalar.size() * sizeof(uint64_t));
}



void TDES_Bitslice_AVX512::setKey(const std::vector<uint8_t>& key) {
    if (key.size() != 8 && key.size() != 16 && key.size() != 24)
        throw std::invalid_argument("TDES_Bitslice_AVX512::setKey: expected 8, 16 or 24 bytes");

    auto load_be64 = [](const uint8_t* in) noexcept -> uint64_t {
        return (uint64_t(in[0]) << 56) |
               (uint64_t(in[1]) << 48) |
               (uint64_t(in[2]) << 40) |
               (uint64_t(in[3]) << 32) |
               (uint64_t(in[4]) << 24) |
               (uint64_t(in[5]) << 16) |
               (uint64_t(in[6]) <<  8) |
               (uint64_t(in[7]) <<  0);
    };

    if (key.size() == 8) {
        uint64_t k1 = load_be64(key.data());
        subkeys1_scalar = GenerateSubkeysScalar(k1);
        subkeys2_scalar = subkeys1_scalar;
        subkeys3_scalar = subkeys1_scalar;
    } else if (key.size() == 16) {
        uint64_t k1 = load_be64(key.data());
        uint64_t k2 = load_be64(key.data() + 8);
        subkeys1_scalar = GenerateSubkeysScalar(k1);
        subkeys2_scalar = GenerateSubkeysScalar(k2);
        subkeys3_scalar = subkeys1_scalar;
    } else {
        uint64_t k1 = load_be64(key.data());
        uint64_t k2 = load_be64(key.data() + 8);
        uint64_t k3 = load_be64(key.data() + 16);
        subkeys1_scalar = GenerateSubkeysScalar(k1);
        subkeys2_scalar = GenerateSubkeysScalar(k2);
        subkeys3_scalar = GenerateSubkeysScalar(k3);
    }

    expand_subkeys_to_bitslice();
}



void TDES_Bitslice_AVX512::encryptBlocks_bitslice(const uint8_t* in, uint8_t* out, std::size_t blocks) const {
    if (!in || !out) return;
    if (blocks == 0) return;
    if (blocks % BS_BLOCKS != 0)
        throw std::invalid_argument("TDES_Bitslice_AVX512::encryptBlocks_bitslice: blocks must be multiple of BS_BLOCKS");

    for (std::size_t i = 0; i < blocks; i += BS_BLOCKS) {
        BitSliceState bs{};
        blocks_to_bitslice(in + i * BLOCK_SIZE, BS_BLOCKS, bs);
        IP_bitslice(bs);
        TripleDES_encrypt_bitslice(bs);
        FP_bitslice(bs);
        bitslice_to_blocks(bs, out + i * BLOCK_SIZE, BS_BLOCKS);
    }
}

void TDES_Bitslice_AVX512::decryptBlocks_bitslice(const uint8_t* in, uint8_t* out, std::size_t blocks) const {
    if (!in || !out) return;
    if (blocks == 0) return;
    if (blocks % BS_BLOCKS != 0)
        throw std::invalid_argument("TDES_Bitslice_AVX512::decryptBlocks_bitslice: blocks must be multiple of BS_BLOCKS");

    for (std::size_t i = 0; i < blocks; i += BS_BLOCKS) {
        BitSliceState bs{};
        blocks_to_bitslice(in + i * BLOCK_SIZE, BS_BLOCKS, bs);
        IP_bitslice(bs);
        TripleDES_decrypt_bitslice(bs);
        FP_bitslice(bs);
        bitslice_to_blocks(bs, out + i * BLOCK_SIZE, BS_BLOCKS);
    }
}



// --- Warstwa layoutu danych: hard-core bit-matrix transpose 32x64 ---

// Założenie: BS_BLOCKS == 32
// Wejście: 32 bloków po 64 bity (big-endian w bajtach)
// Wyjście: 64 bit-planes, każdy jako maska 32-bitowa w dolnym lane __m512i

static inline void transpose_32x32(uint32_t x[32]) {
    for (int i = 0; i < 16; ++i) {
        uint32_t t = (x[i] ^ (x[i + 16] >> 16)) & 0x0000FFFFu;
        x[i]      ^= t;
        x[i + 16] ^= (t << 16);
    }

    for (int i = 0; i < 8; ++i) {
        uint32_t t0 = (x[i] ^ (x[i + 8] >> 8)) & 0x00FF00FFu;
        x[i]      ^= t0;
        x[i + 8]  ^= (t0 << 8);

        uint32_t t1 = (x[i + 16] ^ (x[i + 24] >> 8)) & 0x00FF00FFu;
        x[i + 16] ^= t1;
        x[i + 24] ^= (t1 << 8);
    }

    for (int i = 0; i < 4; ++i) {
        uint32_t t0 = (x[i] ^ (x[i + 4] >> 4)) & 0x0F0F0F0Fu;
        x[i]      ^= t0;
        x[i + 4]  ^= (t0 << 4);

        uint32_t t1 = (x[i + 8] ^ (x[i + 12] >> 4)) & 0x0F0F0F0Fu;
        x[i + 8]  ^= t1;
        x[i + 12] ^= (t1 << 4);

        uint32_t t2 = (x[i + 16] ^ (x[i + 20] >> 4)) & 0x0F0F0F0Fu;
        x[i + 16] ^= t2;
        x[i + 20] ^= (t2 << 4);

        uint32_t t3 = (x[i + 24] ^ (x[i + 28] >> 4)) & 0x0F0F0F0Fu;
        x[i + 24] ^= t3;
        x[i + 28] ^= (t3 << 4);
    }

    for (int i = 0; i < 2; ++i) {
        uint32_t t0 = (x[i] ^ (x[i + 2] >> 2)) & 0x33333333u;
        x[i]      ^= t0;
        x[i + 2]  ^= (t0 << 2);

        uint32_t t1 = (x[i + 4] ^ (x[i + 6] >> 2)) & 0x33333333u;
        x[i + 4]  ^= t1;
        x[i + 6]  ^= (t1 << 2);

        uint32_t t2 = (x[i + 8] ^ (x[i + 10] >> 2)) & 0x33333333u;
        x[i + 8]  ^= t2;
        x[i + 10] ^= (t2 << 2);

        uint32_t t3 = (x[i + 12] ^ (x[i + 14] >> 2)) & 0x33333333u;
        x[i + 12] ^= t3;
        x[i + 14] ^= (t3 << 2);

        uint32_t t4 = (x[i + 16] ^ (x[i + 18] >> 2)) & 0x33333333u;
        x[i + 16] ^= t4;
        x[i + 18] ^= (t4 << 2);

        uint32_t t5 = (x[i + 20] ^ (x[i + 22] >> 2)) & 0x33333333u;
        x[i + 20] ^= t5;
        x[i + 22] ^= (t5 << 2);

        uint32_t t6 = (x[i + 24] ^ (x[i + 26] >> 2)) & 0x33333333u;
        x[i + 24] ^= t6;
        x[i + 26] ^= (t6 << 2);

        uint32_t t7 = (x[i + 28] ^ (x[i + 30] >> 2)) & 0x33333333u;
        x[i + 28] ^= t7;
        x[i + 30] ^= (t7 << 2);
    }

    for (int i = 0; i < 32; i += 2) {
        uint32_t t = (x[i] ^ (x[i + 1] >> 1)) & 0x55555555u;
        x[i]      ^= t;
        x[i + 1]  ^= (t << 1);
    }
}

void TDES_Bitslice_AVX512::blocks_to_bitslice(const uint8_t* in,
                                              std::size_t blocks,
                                              BitSliceState& bs) {
    if (!in) return;
    if (blocks == 0) return;
    if (blocks != BS_BLOCKS)
        throw std::invalid_argument("blocks_to_bitslice: blocks must equal BS_BLOCKS (32)");

    uint64_t rows[32];

    for (std::size_t i = 0; i < 32; ++i) {
        uint64_t v0 = uint64_t(in[i * 8 + 0]);
        uint64_t v1 = uint64_t(in[i * 8 + 1]);
        uint64_t v2 = uint64_t(in[i * 8 + 2]);
        uint64_t v3 = uint64_t(in[i * 8 + 3]);
        uint64_t v4 = uint64_t(in[i * 8 + 4]);
        uint64_t v5 = uint64_t(in[i * 8 + 5]);
        uint64_t v6 = uint64_t(in[i * 8 + 6]);
        uint64_t v7 = uint64_t(in[i * 8 + 7]);

        uint64_t v =
            (v0 << 56) |
            (v1 << 48) |
            (v2 << 40) |
            (v3 << 32) |
            (v4 << 24) |
            (v5 << 16) |
            (v6 <<  8) |
            (v7 <<  0);

        rows[i] = v;
    }

    uint32_t hi[32];
    uint32_t lo[32];

    for (int i = 0; i < 32; ++i) {
        hi[i] = uint32_t(rows[i] >> 32);
        lo[i] = uint32_t(rows[i] & 0xFFFFFFFFu);
    }

    transpose_32x32(hi);
    transpose_32x32(lo);

    for (int bit = 0; bit < 32; ++bit) {
        uint32_t mask_hi = hi[bit];
        uint32_t mask_lo = lo[bit];

        bs[bit]      = _mm512_set1_epi32(int32_t(mask_hi));
        bs[bit + 32] = _mm512_set1_epi32(int32_t(mask_lo));
    }
}

void TDES_Bitslice_AVX512::bitslice_to_blocks(const BitSliceState& bs,
                                              uint8_t* out,
                                              std::size_t blocks) {
    if (!out) return;
    if (blocks == 0) return;
    if (blocks != BS_BLOCKS)
        throw std::invalid_argument("bitslice_to_blocks: blocks must equal BS_BLOCKS (32)");

    uint32_t hi[32];
    uint32_t lo[32];

    for (int bit = 0; bit < 32; ++bit) {
        int32_t v_hi = _mm512_cvtsi512_si32(bs[bit]);
        int32_t v_lo = _mm512_cvtsi512_si32(bs[bit + 32]);

        hi[bit] = uint32_t(v_hi);
        lo[bit] = uint32_t(v_lo);
    }

    transpose_32x32(hi);
    transpose_32x32(lo);

    for (int i = 0; i < 32; ++i) {
        uint64_t v = (uint64_t(hi[i]) << 32) | uint64_t(lo[i]);

        out[i * 8 + 0] = uint8_t(v >> 56);
        out[i * 8 + 1] = uint8_t(v >> 48);
        out[i * 8 + 2] = uint8_t(v >> 40);
        out[i * 8 + 3] = uint8_t(v >> 32);
        out[i * 8 + 4] = uint8_t(v >> 24);
        out[i * 8 + 5] = uint8_t(v >> 16);
        out[i * 8 + 6] = uint8_t(v >>  8);
        out[i * 8 + 7] = uint8_t(v >>  0);
    }
}



// --- Warstwa klucza: szkielet ---

TDES_Bitslice_AVX512::SubkeyScheduleScalar
TDES_Bitslice_AVX512::GenerateSubkeysScalar(uint64_t key64) {
    SubkeyScheduleScalar sk{};

    // PC-1: 64-bit key -> 56-bit permutacja (C||D)
    uint64_t perm = 0;
    for (int i = 0; i < 56; ++i) {
        uint64_t bit = (key64 >> (64 - DES_PC1[i])) & 1ULL;
        perm |= (bit << (55 - i));
    }

    uint32_t C = uint32_t((perm >> 28) & 0x0FFFFFFFu);
    uint32_t D = uint32_t( perm        & 0x0FFFFFFFu);

    auto rotl28 = [](uint32_t v, int s) -> uint32_t {
        v &= 0x0FFFFFFFu;
        return ((v << s) | (v >> (28 - s))) & 0x0FFFFFFFu;
    };

    // 16 rund: rotacje C/D, PC-2 -> 48-bit subkey (w 64-bit)
    for (int round = 0; round < 16; ++round) {
        int s = DES_KEY_SHIFTS[round];
        C = rotl28(C, s);
        D = rotl28(D, s);

        uint64_t CD = (uint64_t(C) << 28) | uint64_t(D);

        uint64_t sub = 0;
        for (int i = 0; i < 48; ++i) {
            uint64_t bit = (CD >> (56 - DES_PC2[i])) & 1ULL;
            sub |= (bit << (47 - i));
        }

        sk[round] = sub;
    }

    return sk;
}


void TDES_Bitslice_AVX512::expand_subkeys_to_bitslice() {
    auto expand_one = [this](const SubkeyScheduleScalar& sk_scalar, int key_index) {
        __m512i all1 = _mm512_set1_epi32(-1);
        __m512i zero = _mm512_setzero_si512();

        for (int round = 0; round < 16; ++round) {
            uint64_t sub = sk_scalar[round]; // 48-bit subkey w dolnych bitach

            for (int bit = 0; bit < 48; ++bit) {
                uint64_t mask = (sub >> (47 - bit)) & 1ULL;
                subkeys_bitslice[key_index][round][bit] = mask ? all1 : zero;
            }
        }
    };

    expand_one(subkeys1_scalar, 0);
    expand_one(subkeys2_scalar, 1);
    expand_one(subkeys3_scalar, 2);
}




// --- IP / FP w bitslice ---

static const uint8_t DES_IP[64] = {
    58,50,42,34,26,18,10, 2,
    60,52,44,36,28,20,12, 4,
    62,54,46,38,30,22,14, 6,
    64,56,48,40,32,24,16, 8,
    57,49,41,33,25,17, 9, 1,
    59,51,43,35,27,19,11, 3,
    61,53,45,37,29,21,13, 5,
    63,55,47,39,31,23,15, 7
};

static const uint8_t DES_FP[64] = {
    40, 8,48,16,56,24,64,32,
    39, 7,47,15,55,23,63,31,
    38, 6,46,14,54,22,62,30,
    37, 5,45,13,53,21,61,29,
    36, 4,44,12,52,20,60,28,
    35, 3,43,11,51,19,59,27,
    34, 2,42,10,50,18,58,26,
    33, 1,41, 9,49,17,57,25
};

void TDES_Bitslice_AVX512::IP_bitslice(BitSliceState& bs) {
    BitSliceState tmp;

    for (int i = 0; i < 64; ++i) {
        int src = int(DES_IP[i]) - 1;
        tmp[i] = bs[src];
    }

    for (int i = 0; i < 64; ++i) {
        bs[i] = tmp[i];
    }
}

void TDES_Bitslice_AVX512::FP_bitslice(BitSliceState& bs) {
    BitSliceState tmp;

    for (int i = 0; i < 64; ++i) {
        int src = int(DES_FP[i]) - 1;
        tmp[i] = bs[src];
    }

    for (int i = 0; i < 64; ++i) {
        bs[i] = tmp[i];
    }
}



// --- Feistel F w bitslice: E-expansion + S-boxy + P ---

// E-expansion: 32 -> 48 bitów
static const uint8_t DES_E[48] = {
    32,  1,  2,  3,  4,  5,
     4,  5,  6,  7,  8,  9,
     8,  9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32,  1
};

// P-permutation: 32 -> 32 bitów
static const uint8_t DES_P[32] = {
    16,  7, 20, 21,
    29, 12, 28, 17,
     1, 15, 23, 26,
     5, 18, 31, 10,
     2,  8, 24, 14,
    32, 27,  3,  9,
    19, 13, 30,  6,
    22, 11,  4, 25
};

void TDES_Bitslice_AVX512::feistel_bitslice(const BitSliceState& bs_R,
                                            BitSliceState& bs_F,
                                            int round,
                                            int key_index) const{
    (void)round;
    (void)key_index;

    // 1) E-expansion: 32 -> 48 bit-planes
    __m512i Ebits[48];

    for (int i = 0; i < 48; ++i) {
        int src = int(DES_E[i]) - 1; // R[0..31] -> R[1..32] w tabeli
        Ebits[i] = bs_R[32 + src];   // prawa połowa w bs: bity 32..63
    }

    // 2) Dodanie klucza rundy (bitslice / maski)
    for (int i = 0; i < 48; ++i) {
        Ebits[i] = _mm512_xor_si512(Ebits[i], subkeys_bitslice[key_index][round][i]);
    }

     


    // 3) S-boxy bitslice: 8 x (6 -> 4) bit-planes
    // Wejście: Ebits[0..47] (8 grup po 6 bitów)
    // Wyjście: 32 bit-planes S_out[0..31]
    __m512i S_out[32];

    {
    // S1: Ebits[0..5] -> S_out[0..3]
    __m512i a0 = Ebits[0];
    __m512i a1 = Ebits[1];
    __m512i a2 = Ebits[2];
    __m512i a3 = Ebits[3];
    __m512i a4 = Ebits[4];
    __m512i a5 = Ebits[5];
    __m512i all1 = _mm512_set1_epi32(-1);
// --- S1 (ANF) ---
__m512i y0 = _mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(all1, a5), a4), _mm512_and_si512(_mm512_and_si512(a3, a4), a5)), a2), _mm512_and_si512(a2, a3)), _mm512_and_si512(_mm512_and_si512(a2, a3), a5)), _mm512_and_si512(_mm512_and_si512(a2, a3), a4)), a1), _mm512_and_si512(a1, a2)), _mm512_and_si512(_mm512_and_si512(a1, a2), a3)), a0), _mm512_and_si512(a0, a4)), _mm512_and_si512(a0, a3)), _mm512_and_si512(_mm512_and_si512(a0, a3), a5)), _mm512_and_si512(_mm512_and_si512(a0, a2), a4)), _mm512_and_si512(_mm512_and_si512(a0, a2), a3)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a2), a3), a5)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a2), a3), a4)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a4), a5)), _mm512_and_si512(_mm512_and_si512(a0, a1), a3)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a3), a5)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a3), a4)), _mm512_and_si512(_mm512_and_si512(a0, a1), a2)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a2), a4), a5)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a2), a3)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a2), a3), a5));
__m512i y1 = _mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(all1, a5), _mm512_and_si512(a4, a5)), _mm512_and_si512(a3, a5)), _mm512_and_si512(a3, a4)), a2), _mm512_and_si512(a2, a4)), _mm512_and_si512(_mm512_and_si512(a2, a4), a5)), _mm512_and_si512(_mm512_and_si512(a2, a3), a5)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a2, a3), a4), a5)), a1), _mm512_and_si512(a1, a5)), _mm512_and_si512(a1, a3)), _mm512_and_si512(_mm512_and_si512(a1, a3), a5)), _mm512_and_si512(_mm512_and_si512(a1, a3), a4)), _mm512_and_si512(_mm512_and_si512(a1, a2), a5)), _mm512_and_si512(a0, a5)), _mm512_and_si512(a0, a4)), _mm512_and_si512(_mm512_and_si512(a0, a3), a4)), _mm512_and_si512(a0, a2)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a2), a4), a5)), _mm512_and_si512(_mm512_and_si512(a0, a2), a3)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a2), a3), a4), a5)), _mm512_and_si512(a0, a1)), _mm512_and_si512(_mm512_and_si512(a0, a1), a5)), _mm512_and_si512(_mm512_and_si512(a0, a1), a4)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a3), a4), a5)), _mm512_and_si512(_mm512_and_si512(a0, a1), a2)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a2), a5)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a2), a4)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a2), a4), a5)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a2), a3)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a2), a3), a5));
__m512i y2 = _mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(all1, a5), a4), a3), _mm512_and_si512(a3, a4)), _mm512_and_si512(_mm512_and_si512(a3, a4), a5)), _mm512_and_si512(a2, a5)), _mm512_and_si512(a2, a4)), _mm512_and_si512(a2, a3)), _mm512_and_si512(_mm512_and_si512(a2, a3), a5)), _mm512_and_si512(a1, a5)), _mm512_and_si512(a1, a4)), _mm512_and_si512(a1, a3)), _mm512_and_si512(_mm512_and_si512(a1, a3), a5)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a1, a3), a4), a5)), _mm512_and_si512(a1, a2)), _mm512_and_si512(_mm512_and_si512(a1, a2), a5)), _mm512_and_si512(_mm512_and_si512(a1, a2), a4)), _mm512_and_si512(_mm512_and_si512(a1, a2), a3)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a1, a2), a3), a5)), a0), _mm512_and_si512(a0, a4)), _mm512_and_si512(_mm512_and_si512(a0, a4), a5)), _mm512_and_si512(_mm512_and_si512(a0, a2), a3)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a2), a3), a4), a5)), _mm512_and_si512(a0, a1)), _mm512_and_si512(_mm512_and_si512(a0, a1), a5)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a4), a5)), _mm512_and_si512(_mm512_and_si512(a0, a1), a3)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a3), a5)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a3), a4)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a3), a4), a5)), _mm512_and_si512(_mm512_and_si512(a0, a1), a2)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a2), a5)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a2), a4)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a2), a4), a5)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a2), a3)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a2), a3), a5));
__m512i y3 = _mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_and_si512(a4, a5), a3), _mm512_and_si512(a2, a4)), a1), _mm512_and_si512(a1, a5)), _mm512_and_si512(a1, a4)), _mm512_and_si512(_mm512_and_si512(a1, a3), a5)), _mm512_and_si512(_mm512_and_si512(a1, a3), a4)), _mm512_and_si512(_mm512_and_si512(a1, a2), a5)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a1, a2), a4), a5)), _mm512_and_si512(a0, a5)), _mm512_and_si512(a0, a4)), _mm512_and_si512(_mm512_and_si512(a0, a4), a5)), _mm512_and_si512(a0, a3)), _mm512_and_si512(_mm512_and_si512(a0, a3), a5)), _mm512_and_si512(_mm512_and_si512(a0, a3), a4)), _mm512_and_si512(a0, a2)), _mm512_and_si512(_mm512_and_si512(a0, a2), a4)), _mm512_and_si512(_mm512_and_si512(a0, a2), a3)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a2), a3), a5)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a2), a3), a4)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a2), a3), a4), a5)), _mm512_and_si512(_mm512_and_si512(a0, a1), a4)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a4), a5)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a3), a4)), _mm512_and_si512(_mm512_and_si512(a0, a1), a2)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a2), a4), a5)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a2), a3)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a2), a3), a5));
    S_out[0] = y0;
    S_out[1] = y1;
    S_out[2] = y2;
    S_out[3] = y3;
}
{
    // S2: Ebits[6..11] -> S_out[4..7]
    __m512i a0 = Ebits[6];
    __m512i a1 = Ebits[7];
    __m512i a2 = Ebits[8];
    __m512i a3 = Ebits[9];
    __m512i a4 = Ebits[10];
    __m512i a5 = Ebits[11];
    __m512i all1 = _mm512_set1_epi32(-1);
// --- S2 (ANF) ---
__m512i y0 = _mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(all1, a5), a4), _mm512_and_si512(a3, a4)), a2), _mm512_and_si512(a1, a5)), _mm512_and_si512(a1, a3)), _mm512_and_si512(_mm512_and_si512(a1, a3), a4)), _mm512_and_si512(a1, a2)), _mm512_and_si512(_mm512_and_si512(a1, a2), a5)), a0), _mm512_and_si512(_mm512_and_si512(a0, a4), a5)), _mm512_and_si512(_mm512_and_si512(a0, a3), a4)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a3), a4), a5)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a2), a4), a5)), _mm512_and_si512(_mm512_and_si512(a0, a1), a5)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a4), a5)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a3), a4)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a3), a4), a5)), _mm512_and_si512(_mm512_and_si512(a0, a1), a2)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a2), a5));
__m512i y1 = _mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(all1, a5), a4), a3), _mm512_and_si512(_mm512_and_si512(a3, a4), a5)), _mm512_and_si512(a2, a5)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a2, a3), a4), a5)), a1), _mm512_and_si512(a1, a3)), _mm512_and_si512(_mm512_and_si512(a1, a3), a5)), _mm512_and_si512(a1, a2)), a0), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a3), a4)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a3), a4), a5)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a2), a4)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a2), a4), a5));
__m512i y2 = _mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(all1, a4), a3), _mm512_and_si512(a2, a4)), _mm512_and_si512(a2, a3)), _mm512_and_si512(_mm512_and_si512(a2, a3), a5)), _mm512_and_si512(_mm512_and_si512(a2, a3), a4)), a1), _mm512_and_si512(_mm512_and_si512(a1, a4), a5)), _mm512_and_si512(_mm512_and_si512(a1, a3), a5)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a1, a3), a4), a5)), _mm512_and_si512(_mm512_and_si512(a1, a2), a5)), a0), _mm512_and_si512(_mm512_and_si512(a0, a4), a5)), _mm512_and_si512(_mm512_and_si512(a0, a3), a4)), _mm512_and_si512(a0, a2)), _mm512_and_si512(_mm512_and_si512(a0, a2), a4)), _mm512_and_si512(_mm512_and_si512(a0, a2), a3)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a2), a3), a5)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a2), a3), a4)), _mm512_and_si512(a0, a1)), _mm512_and_si512(_mm512_and_si512(a0, a1), a5)), _mm512_and_si512(_mm512_and_si512(a0, a1), a4)), _mm512_and_si512(_mm512_and_si512(a0, a1), a3)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a3), a5)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a3), a4), a5)), _mm512_and_si512(_mm512_and_si512(a0, a1), a2)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a2), a4)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a2), a4), a5)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a2), a3));
__m512i y3 = _mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(all1, a3), _mm512_and_si512(_mm512_and_si512(a3, a4), a5)), a2), _mm512_and_si512(a2, a5)), _mm512_and_si512(a2, a4)), _mm512_and_si512(a1, a5)), _mm512_and_si512(_mm512_and_si512(a1, a3), a4)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a1, a3), a4), a5)), _mm512_and_si512(_mm512_and_si512(a1, a2), a4)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a1, a2), a4), a5)), a0), _mm512_and_si512(a0, a5)), _mm512_and_si512(_mm512_and_si512(a0, a4), a5)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a3), a4), a5)), _mm512_and_si512(a0, a2)), _mm512_and_si512(_mm512_and_si512(a0, a2), a5)), _mm512_and_si512(_mm512_and_si512(a0, a2), a4)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a2), a4), a5)), _mm512_and_si512(a0, a1)), _mm512_and_si512(_mm512_and_si512(a0, a1), a4)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a4), a5)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a3), a5)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a2), a5)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a2), a4), a5));
    S_out[4] = y0;
    S_out[5] = y1;
    S_out[6] = y2;
    S_out[7] = y3;
}
{
    // S3: Ebits[12..17] -> S_out[8..11]
    __m512i a0 = Ebits[12];
    __m512i a1 = Ebits[13];
    __m512i a2 = Ebits[14];
    __m512i a3 = Ebits[15];
    __m512i a4 = Ebits[16];
    __m512i a5 = Ebits[17];
    __m512i all1 = _mm512_set1_epi32(-1);
// --- S3 (ANF) ---
__m512i y0 = _mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(all1, a4), _mm512_and_si512(a3, a5)), _mm512_and_si512(a3, a4)), _mm512_and_si512(_mm512_and_si512(a3, a4), a5)), a2), _mm512_and_si512(a2, a4)), _mm512_and_si512(a2, a3)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a2, a3), a4), a5)), a1), _mm512_and_si512(a1, a3)), _mm512_and_si512(_mm512_and_si512(a1, a3), a4)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a1, a3), a4), a5)), _mm512_and_si512(_mm512_and_si512(a1, a2), a4)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a1, a2), a4), a5)), _mm512_and_si512(_mm512_and_si512(a1, a2), a3)), _mm512_and_si512(a0, a5)), _mm512_and_si512(a0, a3)), _mm512_and_si512(_mm512_and_si512(a0, a3), a5)), _mm512_and_si512(_mm512_and_si512(a0, a3), a4)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a3), a4), a5)), _mm512_and_si512(a0, a2)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a2), a4), a5)), _mm512_and_si512(_mm512_and_si512(a0, a2), a3)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a2), a3), a4), a5)), _mm512_and_si512(a0, a1)), _mm512_and_si512(_mm512_and_si512(a0, a1), a3)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a3), a4)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a3), a4), a5)), _mm512_and_si512(_mm512_and_si512(a0, a1), a2)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a2), a3));
__m512i y1 = _mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(a5, _mm512_and_si512(a3, a5)), _mm512_and_si512(a3, a4)), _mm512_and_si512(_mm512_and_si512(a3, a4), a5)), a2), _mm512_and_si512(a2, a4)), _mm512_and_si512(a1, a5)), _mm512_and_si512(a1, a4)), _mm512_and_si512(_mm512_and_si512(a1, a4), a5)), _mm512_and_si512(a1, a3)), _mm512_and_si512(_mm512_and_si512(a1, a3), a5)), _mm512_and_si512(a1, a2)), _mm512_and_si512(_mm512_and_si512(a1, a2), a5)), _mm512_and_si512(_mm512_and_si512(a1, a2), a4)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a1, a2), a4), a5)), _mm512_and_si512(_mm512_and_si512(a1, a2), a3)), a0), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a3), a4), a5)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a2), a3), a4), a5)), _mm512_and_si512(a0, a1)), _mm512_and_si512(_mm512_and_si512(a0, a1), a5)), _mm512_and_si512(_mm512_and_si512(a0, a1), a4)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a4), a5)), _mm512_and_si512(_mm512_and_si512(a0, a1), a3)), _mm512_and_si512(_mm512_and_si512(a0, a1), a2)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a2), a5)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a2), a4)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a2), a4), a5)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a2), a3));
__m512i y2 = _mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(all1, a5), a4), a3), _mm512_and_si512(a3, a5)), _mm512_and_si512(_mm512_and_si512(a3, a4), a5)), _mm512_and_si512(a2, a5)), _mm512_and_si512(a2, a4)), _mm512_and_si512(_mm512_and_si512(a2, a4), a5)), _mm512_and_si512(a2, a3)), _mm512_and_si512(_mm512_and_si512(a2, a3), a5)), _mm512_and_si512(_mm512_and_si512(a2, a3), a4)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a2, a3), a4), a5)), a1), _mm512_and_si512(a1, a4)), _mm512_and_si512(_mm512_and_si512(a1, a4), a5)), _mm512_and_si512(a1, a3)), _mm512_and_si512(_mm512_and_si512(a1, a3), a4)), _mm512_and_si512(a1, a2)), _mm512_and_si512(_mm512_and_si512(a1, a2), a5)), _mm512_and_si512(_mm512_and_si512(a1, a2), a3)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a1, a2), a3), a5)), a0), _mm512_and_si512(a0, a5)), _mm512_and_si512(a0, a3)), _mm512_and_si512(_mm512_and_si512(a0, a3), a5)), _mm512_and_si512(_mm512_and_si512(a0, a3), a4)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a3), a4), a5)), _mm512_and_si512(_mm512_and_si512(a0, a2), a4)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a2), a4), a5)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a2), a3), a5)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a2), a3), a4), a5)), _mm512_and_si512(_mm512_and_si512(a0, a1), a5)), _mm512_and_si512(_mm512_and_si512(a0, a1), a4)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a4), a5)), _mm512_and_si512(_mm512_and_si512(a0, a1), a3)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a3), a5)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a3), a4), a5)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a2), a3)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a2), a3), a5));
__m512i y3 = _mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(a5, a3), _mm512_and_si512(a3, a4)), _mm512_and_si512(a2, a4)), a1), a0), _mm512_and_si512(a0, a5)), _mm512_and_si512(a0, a4)), _mm512_and_si512(_mm512_and_si512(a0, a3), a5)), _mm512_and_si512(_mm512_and_si512(a0, a3), a4)), _mm512_and_si512(a0, a2)), _mm512_and_si512(_mm512_and_si512(a0, a2), a4)), _mm512_and_si512(a0, a1)), _mm512_and_si512(_mm512_and_si512(a0, a1), a5)), _mm512_and_si512(_mm512_and_si512(a0, a1), a4)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a4), a5)), _mm512_and_si512(_mm512_and_si512(a0, a1), a2)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a2), a5)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a2), a4)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a2), a3), a5));
    S_out[8] = y0;
    S_out[9] = y1;
    S_out[10] = y2;
    S_out[11] = y3;
}
{
    // S4: Ebits[18..23] -> S_out[12..15]
    __m512i a0 = Ebits[18];
    __m512i a1 = Ebits[19];
    __m512i a2 = Ebits[20];
    __m512i a3 = Ebits[21];
    __m512i a4 = Ebits[22];
    __m512i a5 = Ebits[23];
    __m512i all1 = _mm512_set1_epi32(-1);
// --- S4 (ANF) ---
__m512i y0 = _mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(a5, a4), _mm512_and_si512(a4, a5)), a3), _mm512_and_si512(a3, a5)), _mm512_and_si512(_mm512_and_si512(a3, a4), a5)), _mm512_and_si512(a2, a5)), _mm512_and_si512(a2, a4)), _mm512_and_si512(a1, a5)), _mm512_and_si512(a1, a4)), _mm512_and_si512(_mm512_and_si512(a1, a4), a5)), _mm512_and_si512(_mm512_and_si512(a1, a3), a4)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a1, a3), a4), a5)), _mm512_and_si512(a1, a2)), _mm512_and_si512(_mm512_and_si512(a1, a2), a4)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a1, a2), a4), a5)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a1, a2), a3), a5)), a0), _mm512_and_si512(_mm512_and_si512(a0, a4), a5)), _mm512_and_si512(a0, a3)), _mm512_and_si512(_mm512_and_si512(a0, a3), a5)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a2), a4), a5)), _mm512_and_si512(_mm512_and_si512(a0, a2), a3)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a2), a3), a5)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a2), a3), a4)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a2), a3), a4), a5)), _mm512_and_si512(_mm512_and_si512(a0, a1), a4)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a4), a5)), _mm512_and_si512(_mm512_and_si512(a0, a1), a3)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a3), a4)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a2), a4)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a2), a4), a5)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a2), a3));
__m512i y1 = _mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(all1, _mm512_and_si512(a4, a5)), _mm512_and_si512(a3, a5)), _mm512_and_si512(a3, a4)), _mm512_and_si512(_mm512_and_si512(a3, a4), a5)), a2), _mm512_and_si512(a2, a5)), _mm512_and_si512(a2, a4)), a1), _mm512_and_si512(a1, a5)), _mm512_and_si512(_mm512_and_si512(a1, a4), a5)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a1, a3), a4), a5)), _mm512_and_si512(a1, a2)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a1, a2), a4), a5)), _mm512_and_si512(_mm512_and_si512(a1, a2), a3)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a1, a2), a3), a5)), a0), _mm512_and_si512(a0, a4)), _mm512_and_si512(_mm512_and_si512(a0, a4), a5)), _mm512_and_si512(_mm512_and_si512(a0, a3), a5)), _mm512_and_si512(_mm512_and_si512(a0, a2), a4)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a2), a4), a5)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a2), a3), a5)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a2), a3), a4), a5)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a4), a5)), _mm512_and_si512(_mm512_and_si512(a0, a1), a3)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a3), a4)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a2), a4), a5)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a2), a3));
__m512i y2 = _mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(all1, a5), a4), _mm512_and_si512(a4, a5)), _mm512_and_si512(a3, a5)), _mm512_and_si512(a3, a4)), a2), _mm512_and_si512(_mm512_and_si512(a2, a3), a4)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a2, a3), a4), a5)), a1), _mm512_and_si512(a1, a5)), _mm512_and_si512(_mm512_and_si512(a1, a4), a5)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a1, a3), a4), a5)), _mm512_and_si512(_mm512_and_si512(a1, a2), a5)), _mm512_and_si512(_mm512_and_si512(a1, a2), a3)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a1, a2), a3), a5)), _mm512_and_si512(a0, a5)), _mm512_and_si512(a0, a4)), _mm512_and_si512(_mm512_and_si512(a0, a4), a5)), _mm512_and_si512(a0, a3)), _mm512_and_si512(_mm512_and_si512(a0, a3), a5)), _mm512_and_si512(_mm512_and_si512(a0, a3), a4)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a3), a4), a5)), _mm512_and_si512(_mm512_and_si512(a0, a2), a5)), _mm512_and_si512(_mm512_and_si512(a0, a2), a4)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a2), a3), a4)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a2), a3), a4), a5)), _mm512_and_si512(a0, a1)), _mm512_and_si512(_mm512_and_si512(a0, a1), a4)), _mm512_and_si512(_mm512_and_si512(a0, a1), a3)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a3), a4)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a2), a5)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a2), a4)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a2), a4), a5)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a2), a3));
__m512i y3 = _mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(all1, _mm512_and_si512(a4, a5)), a3), _mm512_and_si512(a3, a5)), _mm512_and_si512(a3, a4)), a2), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a2, a3), a4), a5)), _mm512_and_si512(a1, a5)), _mm512_and_si512(a1, a4)), _mm512_and_si512(_mm512_and_si512(a1, a4), a5)), _mm512_and_si512(_mm512_and_si512(a1, a3), a4)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a1, a3), a4), a5)), _mm512_and_si512(a1, a2)), _mm512_and_si512(_mm512_and_si512(a1, a2), a5)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a1, a2), a3), a5)), a0), _mm512_and_si512(a0, a5)), _mm512_and_si512(_mm512_and_si512(a0, a4), a5)), _mm512_and_si512(_mm512_and_si512(a0, a3), a5)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a3), a4), a5)), _mm512_and_si512(a0, a2)), _mm512_and_si512(_mm512_and_si512(a0, a2), a5)), _mm512_and_si512(_mm512_and_si512(a0, a2), a4)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a2), a3), a4), a5)), _mm512_and_si512(a0, a1)), _mm512_and_si512(_mm512_and_si512(a0, a1), a4)), _mm512_and_si512(_mm512_and_si512(a0, a1), a3)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a3), a4)), _mm512_and_si512(_mm512_and_si512(a0, a1), a2)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a2), a5)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a2), a4), a5)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a2), a3));
    S_out[12] = y0;
    S_out[13] = y1;
    S_out[14] = y2;
    S_out[15] = y3;
}
{
    // S5: Ebits[24..29] -> S_out[16..19]
    __m512i a0 = Ebits[24];
    __m512i a1 = Ebits[25];
    __m512i a2 = Ebits[26];
    __m512i a3 = Ebits[27];
    __m512i a4 = Ebits[28];
    __m512i a5 = Ebits[29];
    __m512i all1 = _mm512_set1_epi32(-1);
// --- S5 (ANF) ---
__m512i y0 = _mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(a5, a4), _mm512_and_si512(a4, a5)), _mm512_and_si512(a3, a5)), _mm512_and_si512(a3, a4)), _mm512_and_si512(a2, a5)), _mm512_and_si512(a2, a3)), _mm512_and_si512(_mm512_and_si512(a2, a3), a5)), _mm512_and_si512(_mm512_and_si512(a2, a3), a4)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a2, a3), a4), a5)), a1), _mm512_and_si512(a1, a3)), _mm512_and_si512(_mm512_and_si512(a1, a3), a5)), _mm512_and_si512(_mm512_and_si512(a1, a3), a4)), _mm512_and_si512(_mm512_and_si512(a1, a2), a5)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a1, a2), a4), a5)), _mm512_and_si512(a0, a4)), _mm512_and_si512(_mm512_and_si512(a0, a4), a5)), _mm512_and_si512(_mm512_and_si512(a0, a3), a5)), _mm512_and_si512(a0, a2)), _mm512_and_si512(_mm512_and_si512(a0, a2), a5)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a2), a4), a5)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a2), a3), a4)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a4), a5)), _mm512_and_si512(_mm512_and_si512(a0, a1), a3)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a3), a5)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a3), a4)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a3), a4), a5)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a2), a5)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a2), a3));
__m512i y1 = _mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(a5, a4), a3), a2), _mm512_and_si512(a2, a5)), _mm512_and_si512(_mm512_and_si512(a2, a4), a5)), _mm512_and_si512(_mm512_and_si512(a2, a3), a5)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a2, a3), a4), a5)), _mm512_and_si512(a1, a3)), _mm512_and_si512(_mm512_and_si512(a1, a2), a5)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a1, a2), a3), a5)), a0), _mm512_and_si512(_mm512_and_si512(a0, a4), a5)), _mm512_and_si512(_mm512_and_si512(a0, a3), a4)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a3), a4), a5)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a2), a3), a4)), _mm512_and_si512(_mm512_and_si512(a0, a1), a5)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a3), a5)), _mm512_and_si512(_mm512_and_si512(a0, a1), a2)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a2), a5)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a2), a3)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a2), a3), a5));
__m512i y2 = _mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(all1, a4), _mm512_and_si512(a4, a5)), a3), _mm512_and_si512(a3, a5)), _mm512_and_si512(a3, a4)), _mm512_and_si512(a2, a5)), _mm512_and_si512(a2, a4)), _mm512_and_si512(a2, a3)), _mm512_and_si512(_mm512_and_si512(a2, a3), a5)), _mm512_and_si512(_mm512_and_si512(a2, a3), a4)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a2, a3), a4), a5)), a1), _mm512_and_si512(a1, a4)), _mm512_and_si512(_mm512_and_si512(a1, a4), a5)), _mm512_and_si512(_mm512_and_si512(a1, a3), a5)), _mm512_and_si512(_mm512_and_si512(a1, a3), a4)), _mm512_and_si512(_mm512_and_si512(a1, a2), a4)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a1, a2), a4), a5)), _mm512_and_si512(_mm512_and_si512(a1, a2), a3)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a1, a2), a3), a5)), a0), _mm512_and_si512(a0, a5)), _mm512_and_si512(_mm512_and_si512(a0, a4), a5)), _mm512_and_si512(a0, a3)), _mm512_and_si512(_mm512_and_si512(a0, a3), a4)), _mm512_and_si512(a0, a2)), _mm512_and_si512(_mm512_and_si512(a0, a2), a5)), _mm512_and_si512(_mm512_and_si512(a0, a2), a4)), _mm512_and_si512(_mm512_and_si512(a0, a2), a3)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a2), a3), a5)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a2), a3), a4)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a2), a3), a4), a5)), _mm512_and_si512(_mm512_and_si512(a0, a1), a5)), _mm512_and_si512(_mm512_and_si512(a0, a1), a4)), _mm512_and_si512(_mm512_and_si512(a0, a1), a3)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a3), a4), a5)), _mm512_and_si512(_mm512_and_si512(a0, a1), a2)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a2), a4), a5)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a2), a3)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a2), a3), a5));
__m512i y3 = _mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_and_si512(a4, a5), _mm512_and_si512(a3, a4)), a2), _mm512_and_si512(a2, a5)), _mm512_and_si512(a2, a4)), _mm512_and_si512(_mm512_and_si512(a2, a4), a5)), _mm512_and_si512(_mm512_and_si512(a2, a3), a5)), _mm512_and_si512(_mm512_and_si512(a2, a3), a4)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a2, a3), a4), a5)), _mm512_and_si512(a1, a5)), _mm512_and_si512(a1, a4)), _mm512_and_si512(_mm512_and_si512(a1, a4), a5)), _mm512_and_si512(a1, a3)), _mm512_and_si512(_mm512_and_si512(a1, a3), a5)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a1, a3), a4), a5)), _mm512_and_si512(_mm512_and_si512(a1, a2), a4)), _mm512_and_si512(a0, a5)), _mm512_and_si512(a0, a3)), _mm512_and_si512(_mm512_and_si512(a0, a3), a4)), _mm512_and_si512(a0, a2)), _mm512_and_si512(_mm512_and_si512(a0, a2), a5)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a2), a3), a5)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a2), a3), a4)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a2), a3), a4), a5)), _mm512_and_si512(a0, a1)), _mm512_and_si512(_mm512_and_si512(a0, a1), a5)), _mm512_and_si512(_mm512_and_si512(a0, a1), a4)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a4), a5)), _mm512_and_si512(_mm512_and_si512(a0, a1), a3)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a3), a4)), _mm512_and_si512(_mm512_and_si512(a0, a1), a2)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a2), a5)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a2), a4)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a2), a4), a5)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a2), a3));
    S_out[16] = y0;
    S_out[17] = y1;
    S_out[18] = y2;
    S_out[19] = y3;
}
{
    // S6: Ebits[30..35] -> S_out[20..23]
    __m512i a0 = Ebits[30];
    __m512i a1 = Ebits[31];
    __m512i a2 = Ebits[32];
    __m512i a3 = Ebits[33];
    __m512i a4 = Ebits[34];
    __m512i a5 = Ebits[35];
    __m512i all1 = _mm512_set1_epi32(-1);
// --- S6 (ANF) ---
__m512i y0 = _mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(all1, a4), _mm512_and_si512(a4, a5)), _mm512_and_si512(a3, a5)), _mm512_and_si512(a3, a4)), _mm512_and_si512(_mm512_and_si512(a3, a4), a5)), _mm512_and_si512(a2, a5)), _mm512_and_si512(_mm512_and_si512(a2, a4), a5)), _mm512_and_si512(a2, a3)), _mm512_and_si512(_mm512_and_si512(a2, a3), a5)), _mm512_and_si512(_mm512_and_si512(a2, a3), a4)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a2, a3), a4), a5)), a1), _mm512_and_si512(a1, a2)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a1, a2), a3), a5)), _mm512_and_si512(a0, a5)), _mm512_and_si512(a0, a4)), _mm512_and_si512(_mm512_and_si512(a0, a4), a5)), _mm512_and_si512(_mm512_and_si512(a0, a3), a5)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a3), a4), a5)), _mm512_and_si512(a0, a2)), _mm512_and_si512(_mm512_and_si512(a0, a2), a5)), _mm512_and_si512(_mm512_and_si512(a0, a2), a4)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a2), a4), a5)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a3), a5)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a3), a4), a5)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a2), a5)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a2), a4), a5)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a2), a3), a5));
__m512i y1 = _mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(all1, a5), a4), a3), a2), _mm512_and_si512(a2, a4)), _mm512_and_si512(_mm512_and_si512(a2, a3), a4)), a1), _mm512_and_si512(a1, a3)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a1, a3), a4), a5)), a0), _mm512_and_si512(_mm512_and_si512(a0, a3), a4)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a3), a4), a5)), _mm512_and_si512(a0, a2)), _mm512_and_si512(_mm512_and_si512(a0, a2), a5)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a2), a4), a5)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a2), a3), a4)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a3), a4)), _mm512_and_si512(_mm512_and_si512(a0, a1), a2)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a2), a5)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a2), a4)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a2), a4), a5)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a2), a3), a5));
__m512i y2 = _mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(a5, a3), _mm512_and_si512(_mm512_and_si512(a3, a4), a5)), _mm512_and_si512(a2, a4)), _mm512_and_si512(_mm512_and_si512(a1, a4), a5)), _mm512_and_si512(_mm512_and_si512(a1, a3), a4)), _mm512_and_si512(a1, a2)), _mm512_and_si512(_mm512_and_si512(a1, a2), a4)), _mm512_and_si512(a0, a5)), _mm512_and_si512(a0, a4)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a3), a4), a5)), _mm512_and_si512(a0, a2)), _mm512_and_si512(_mm512_and_si512(a0, a2), a5)), _mm512_and_si512(_mm512_and_si512(a0, a2), a4)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a2), a4), a5)), _mm512_and_si512(a0, a1)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a3), a4)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a3), a4), a5)), _mm512_and_si512(_mm512_and_si512(a0, a1), a2)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a2), a4), a5));
__m512i y3 = _mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(a4, _mm512_and_si512(_mm512_and_si512(a3, a4), a5)), a2), _mm512_and_si512(a2, a3)), _mm512_and_si512(_mm512_and_si512(a2, a3), a5)), _mm512_and_si512(_mm512_and_si512(a2, a3), a4)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a2, a3), a4), a5)), _mm512_and_si512(a1, a3)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a1, a3), a4), a5)), _mm512_and_si512(a1, a2)), _mm512_and_si512(_mm512_and_si512(a1, a2), a3)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a1, a2), a3), a5)), a0), _mm512_and_si512(a0, a5)), _mm512_and_si512(_mm512_and_si512(a0, a3), a4)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a3), a4), a5)), _mm512_and_si512(_mm512_and_si512(a0, a2), a4)), _mm512_and_si512(_mm512_and_si512(a0, a2), a3)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a2), a3), a5)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a2), a3), a4)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a2), a3), a4), a5)), _mm512_and_si512(_mm512_and_si512(a0, a1), a5)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a3), a5)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a3), a4), a5)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a2), a5));
    S_out[20] = y0;
    S_out[21] = y1;
    S_out[22] = y2;
    S_out[23] = y3;
}
{
    // S7: Ebits[36..41] -> S_out[24..27]
    __m512i a0 = Ebits[36];
    __m512i a1 = Ebits[37];
    __m512i a2 = Ebits[38];
    __m512i a3 = Ebits[39];
    __m512i a4 = Ebits[40];
    __m512i a5 = Ebits[41];
    __m512i all1 = _mm512_set1_epi32(-1);
// --- S7 (ANF) ---
__m512i y0 = _mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(a5, a4), a2), _mm512_and_si512(_mm512_and_si512(a2, a3), a4)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a2, a3), a4), a5)), _mm512_and_si512(a1, a3)), _mm512_and_si512(a1, a2)), _mm512_and_si512(_mm512_and_si512(a1, a2), a5)), _mm512_and_si512(_mm512_and_si512(a1, a2), a3)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a1, a2), a3), a5)), _mm512_and_si512(a0, a5)), _mm512_and_si512(a0, a4)), _mm512_and_si512(_mm512_and_si512(a0, a4), a5)), _mm512_and_si512(a0, a3)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a3), a4), a5)), _mm512_and_si512(_mm512_and_si512(a0, a2), a5)), _mm512_and_si512(_mm512_and_si512(a0, a2), a4)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a2), a3), a4)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a2), a3), a4), a5)), _mm512_and_si512(a0, a1)), _mm512_and_si512(_mm512_and_si512(a0, a1), a3)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a3), a4)), _mm512_and_si512(_mm512_and_si512(a0, a1), a2)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a2), a5)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a2), a4)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a2), a3)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a2), a3), a5));
__m512i y1 = _mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(all1, a4), a3), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a2, a3), a4), a5)), a1), _mm512_and_si512(a1, a5)), _mm512_and_si512(a1, a3)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a1, a3), a4), a5)), _mm512_and_si512(a1, a2)), a0), _mm512_and_si512(a0, a5)), _mm512_and_si512(a0, a3)), _mm512_and_si512(a0, a2)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a2), a3), a4)), _mm512_and_si512(a0, a1)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a3), a5)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a3), a4), a5)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a2), a5)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a2), a3));
__m512i y2 = _mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(a4, _mm512_and_si512(a4, a5)), a3), _mm512_and_si512(a3, a4)), _mm512_and_si512(_mm512_and_si512(a3, a4), a5)), a2), _mm512_and_si512(a2, a5)), _mm512_and_si512(_mm512_and_si512(a2, a3), a5)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a2, a3), a4), a5)), a1), _mm512_and_si512(_mm512_and_si512(a1, a3), a4)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a1, a3), a4), a5)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a1, a2), a3), a5)), _mm512_and_si512(a0, a5)), _mm512_and_si512(a0, a4)), _mm512_and_si512(_mm512_and_si512(a0, a4), a5)), _mm512_and_si512(a0, a2)), _mm512_and_si512(_mm512_and_si512(a0, a2), a4)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a2), a4), a5)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a2), a3), a5)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a2), a3), a4), a5)), _mm512_and_si512(_mm512_and_si512(a0, a1), a3)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a3), a4)), _mm512_and_si512(_mm512_and_si512(a0, a1), a2)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a2), a5)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a2), a4)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a2), a4), a5)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a2), a3), a5));
__m512i y3 = _mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(a5, a4), _mm512_and_si512(a3, a4)), a2), _mm512_and_si512(a2, a3)), _mm512_and_si512(_mm512_and_si512(a2, a3), a4)), a1), _mm512_and_si512(_mm512_and_si512(a1, a3), a5)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a1, a3), a4), a5)), _mm512_and_si512(a1, a2)), a0), _mm512_and_si512(_mm512_and_si512(a0, a3), a5)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a3), a4), a5)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a2), a3), a5)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a2), a3), a4), a5)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a4), a5)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a3), a5)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a2), a5));
    S_out[24] = y0;
    S_out[25] = y1;
    S_out[26] = y2;
    S_out[27] = y3;
}
{
    // S8: Ebits[42..47] -> S_out[28..31]
    __m512i a0 = Ebits[42];
    __m512i a1 = Ebits[43];
    __m512i a2 = Ebits[44];
    __m512i a3 = Ebits[45];
    __m512i a4 = Ebits[46];
    __m512i a5 = Ebits[47];
    __m512i all1 = _mm512_set1_epi32(-1);
// --- S8 (ANF) ---
__m512i y0 = _mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(all1, a5), a4), _mm512_and_si512(a3, a5)), _mm512_and_si512(_mm512_and_si512(a3, a4), a5)), a2), _mm512_and_si512(a2, a3)), _mm512_and_si512(_mm512_and_si512(a2, a3), a5)), _mm512_and_si512(a1, a5)), _mm512_and_si512(a1, a4)), _mm512_and_si512(_mm512_and_si512(a1, a4), a5)), _mm512_and_si512(a1, a3)), _mm512_and_si512(_mm512_and_si512(a1, a3), a5)), _mm512_and_si512(_mm512_and_si512(a1, a3), a4)), _mm512_and_si512(_mm512_and_si512(a1, a2), a3)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a1, a2), a3), a5)), a0), _mm512_and_si512(a0, a5)), _mm512_and_si512(_mm512_and_si512(a0, a4), a5)), _mm512_and_si512(_mm512_and_si512(a0, a3), a4)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a3), a4), a5)), _mm512_and_si512(_mm512_and_si512(a0, a2), a5)), _mm512_and_si512(_mm512_and_si512(a0, a2), a4)), _mm512_and_si512(_mm512_and_si512(a0, a2), a3)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a2), a3), a5)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a3), a5)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a3), a4), a5)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a2), a5)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a2), a4), a5)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a2), a3)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a2), a3), a5));
__m512i y1 = _mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(all1, a5), a4), a3), _mm512_and_si512(a2, a4)), a1), _mm512_and_si512(a1, a4)), _mm512_and_si512(a1, a3)), _mm512_and_si512(_mm512_and_si512(a1, a3), a4)), _mm512_and_si512(a1, a2)), _mm512_and_si512(_mm512_and_si512(a0, a4), a5)), _mm512_and_si512(a0, a3)), _mm512_and_si512(_mm512_and_si512(a0, a3), a5)), _mm512_and_si512(a0, a2)), _mm512_and_si512(_mm512_and_si512(a0, a2), a4)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a2), a4), a5)), _mm512_and_si512(_mm512_and_si512(a0, a2), a3)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a2), a3), a5)), _mm512_and_si512(_mm512_and_si512(a0, a1), a4)), _mm512_and_si512(_mm512_and_si512(a0, a1), a3)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a3), a4)), _mm512_and_si512(_mm512_and_si512(a0, a1), a2)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a2), a3)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a2), a3), a5));
__m512i y2 = _mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(a4, _mm512_and_si512(a3, a4)), a2), _mm512_and_si512(a2, a4)), a1), _mm512_and_si512(a1, a5)), _mm512_and_si512(_mm512_and_si512(a1, a4), a5)), _mm512_and_si512(_mm512_and_si512(a1, a3), a5)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a1, a3), a4), a5)), _mm512_and_si512(_mm512_and_si512(a1, a2), a5)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a1, a2), a3), a5)), a0), _mm512_and_si512(a0, a4)), _mm512_and_si512(_mm512_and_si512(a0, a4), a5)), _mm512_and_si512(a0, a3)), _mm512_and_si512(_mm512_and_si512(a0, a3), a5)), _mm512_and_si512(_mm512_and_si512(a0, a3), a4)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a3), a4), a5)), _mm512_and_si512(_mm512_and_si512(a0, a2), a4)), _mm512_and_si512(_mm512_and_si512(a0, a1), a4)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a3), a4), a5)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a2), a4)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a2), a4), a5));
__m512i y3 = _mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(all1, a4), _mm512_and_si512(a4, a5)), a3), _mm512_and_si512(a3, a5)), _mm512_and_si512(a3, a4)), a2), _mm512_and_si512(_mm512_and_si512(a2, a4), a5)), _mm512_and_si512(_mm512_and_si512(a2, a3), a5)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a2, a3), a4), a5)), a1), _mm512_and_si512(_mm512_and_si512(a1, a4), a5)), _mm512_and_si512(_mm512_and_si512(a1, a3), a4)), _mm512_and_si512(_mm512_and_si512(a1, a2), a5)), _mm512_and_si512(a0, a5)), _mm512_and_si512(a0, a4)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a3), a4), a5)), _mm512_and_si512(a0, a2)), _mm512_and_si512(_mm512_and_si512(a0, a2), a4)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a2), a4), a5)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a2), a3), a5)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a4), a5)), _mm512_and_si512(_mm512_and_si512(a0, a1), a3)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a3), a5)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a3), a4)), _mm512_and_si512(_mm512_and_si512(a0, a1), a2)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a2), a4)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a2), a4), a5)), _mm512_and_si512(_mm512_and_si512(_mm512_and_si512(_mm512_and_si512(a0, a1), a2), a3), a5));
    S_out[28] = y0;
    S_out[29] = y1;
    S_out[30] = y2;
    S_out[31] = y3;
}



    // 4) P-permutation: S_out[0..31] -> bs_F[32..63] (prawa połowa wyniku F)
    for (int i = 0; i < 32; ++i) {
        int src = int(DES_P[i]) - 1;
        bs_F[32 + i] = S_out[src];
    }

    // Lewa połowa F (bity 0..31) nie jest używana jako osobna część,
    // bo w DES F działa tylko na prawej połowie i jest XORowana z L.
    // Dla przejrzystości wyzerujemy bs_F[0..31].
    for (int i = 0; i < 32; ++i) {
        bs_F[i] = _mm512_setzero_si512();
    }
}



// --- Rundy DES / 3DES w bitslice ---

void TDES_Bitslice_AVX512::DES_encrypt_bitslice(BitSliceState& bs,
                                                int key_index) const{
    (void)key_index; // na razie tylko przekazujemy dalej do feistel_bitslice

    // bs[0..31]  – lewa połowa (L)
    // bs[32..63] – prawa połowa (R)

    for (int round = 0; round < 16; ++round) {
        BitSliceState F;

        // F(L,R,K_round): wynik w F[32..63] (prawa połowa)
        feistel_bitslice(bs, F, round, key_index);

        // L ^= F (tylko prawa połowa F, czyli F[32..63])
        for (int i = 0; i < 32; ++i) {
            bs[i] = _mm512_xor_si512(bs[i], F[32 + i]);
        }

        // swap(L, R)
        for (int i = 0; i < 32; ++i) {
            __m512i tmp = bs[i];
            bs[i]       = bs[32 + i];
            bs[32 + i]  = tmp;
        }
    }

    // Po 16 rundach w DES jest jeszcze finalny swap L/R,
    // ale w klasycznym schemacie Feistela często robi się go
    // przez zamianę kolejności w IP/FP. My trzymamy się
    // standardowego: po rundach wykonujemy swap jeszcze raz.
    for (int i = 0; i < 32; ++i) {
        __m512i tmp = bs[i];
        bs[i]       = bs[32 + i];
        bs[32 + i]  = tmp;
    }
}

void TDES_Bitslice_AVX512::DES_decrypt_bitslice(BitSliceState& bs,
                                                int key_index) const{
    (void)key_index;

    // bs[0..31]  – lewa połowa (L)
    // bs[32..63] – prawa połowa (R)

    for (int round = 15; round >= 0; --round) {
        BitSliceState F;

        feistel_bitslice(bs, F, round, key_index);

        for (int i = 0; i < 32; ++i) {
            bs[i] = _mm512_xor_si512(bs[i], F[32 + i]);
        }

        for (int i = 0; i < 32; ++i) {
            __m512i tmp = bs[i];
            bs[i]       = bs[32 + i];
            bs[32 + i]  = tmp;
        }
    }

    for (int i = 0; i < 32; ++i) {
        __m512i tmp = bs[i];
        bs[i]       = bs[32 + i];
        bs[32 + i]  = tmp;
    }
}

void TDES_Bitslice_AVX512::TripleDES_encrypt_bitslice(BitSliceState& bs) const{
    // K1: key_index = 0
    DES_encrypt_bitslice(bs, 0);

    // K2: key_index = 1 (decrypt)
    DES_decrypt_bitslice(bs, 1);

    // K3: key_index = 2
    DES_encrypt_bitslice(bs, 2);
}

void TDES_Bitslice_AVX512::TripleDES_decrypt_bitslice(BitSliceState& bs) const{
    // K3: key_index = 2 (decrypt)
    DES_decrypt_bitslice(bs, 2);

    // K2: key_index = 1 (encrypt)
    DES_encrypt_bitslice(bs, 1);

    // K1: key_index = 0 (decrypt)
    DES_decrypt_bitslice(bs, 0);
}

