#include "cipher/TDES/tdes_bitslice_avx2.hpp"

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


TDES_Bitslice_AVX2::~TDES_Bitslice_AVX2() {
    secure_memzero(subkeys1_scalar.data(), subkeys1_scalar.size() * sizeof(uint64_t));
    secure_memzero(subkeys2_scalar.data(), subkeys2_scalar.size() * sizeof(uint64_t));
    secure_memzero(subkeys3_scalar.data(), subkeys3_scalar.size() * sizeof(uint64_t));
}



void TDES_Bitslice_AVX2::setKey(const std::vector<uint8_t>& key)
{
    if (key.size() != 8 && key.size() != 16 && key.size() != 24)
        throw std::invalid_argument("TDES_Bitslice_AVX2::setKey: expected 8, 16 or 24 bytes");

    auto load_be64 = [](const uint8_t* in) noexcept -> uint64_t {
        return (uint64_t(in[0]) << 56) |
            (uint64_t(in[1]) << 48) |
            (uint64_t(in[2]) << 40) |
            (uint64_t(in[3]) << 32) |
            (uint64_t(in[4]) << 24) |
            (uint64_t(in[5]) << 16) |
            (uint64_t(in[6]) << 8) |
            (uint64_t(in[7]) << 0);
        };

    if (key.size() == 8) {
        uint64_t k1 = load_be64(key.data());
        subkeys1_scalar = GenerateSubkeysScalar(k1);
        subkeys2_scalar = subkeys1_scalar;
        subkeys3_scalar = subkeys1_scalar;
    }
    else if (key.size() == 16) {
        uint64_t k1 = load_be64(key.data());
        uint64_t k2 = load_be64(key.data() + 8);
        subkeys1_scalar = GenerateSubkeysScalar(k1);
        subkeys2_scalar = GenerateSubkeysScalar(k2);
        subkeys3_scalar = subkeys1_scalar;
    }
    else {
        uint64_t k1 = load_be64(key.data());
        uint64_t k2 = load_be64(key.data() + 8);
        uint64_t k3 = load_be64(key.data() + 16);
        subkeys1_scalar = GenerateSubkeysScalar(k1);
        subkeys2_scalar = GenerateSubkeysScalar(k2);
        subkeys3_scalar = GenerateSubkeysScalar(k3);
    }

    expand_subkeys_to_bitslice();
}




void TDES_Bitslice_AVX2::encryptBlocks_bitslice(const uint8_t* in, uint8_t* out, std::size_t blocks) const {
    if (!in || !out || blocks == 0) return;

    std::size_t full = blocks / BS_BLOCKS;
    std::size_t rem = blocks % BS_BLOCKS;

    // pełne paczki po 32 bloki
    for (std::size_t i = 0; i < full * BS_BLOCKS; i += BS_BLOCKS) {
        BitSliceState bs{};
        blocks_to_bitslice(in + i * BLOCK_SIZE, BS_BLOCKS, bs);
        TripleDES_encrypt_bitslice(bs);
        bitslice_to_blocks(bs, out + i * BLOCK_SIZE, BS_BLOCKS);
    }

    // ogon: single‑block bitslice, bez rekurencji
    if (rem) {
        std::size_t offset = full * BS_BLOCKS;
        for (std::size_t i = 0; i < rem; ++i) {
            encryptBlock_bitslice_single(in + (offset + i) * BLOCK_SIZE,
                out + (offset + i) * BLOCK_SIZE);
        }
    }
}

void TDES_Bitslice_AVX2::decryptBlocks_bitslice(const uint8_t* in, uint8_t* out, std::size_t blocks) const {
    if (!in || !out || blocks == 0) return;

    std::size_t full = blocks / BS_BLOCKS;
    std::size_t rem = blocks % BS_BLOCKS;

    for (std::size_t i = 0; i < full * BS_BLOCKS; i += BS_BLOCKS) {
        BitSliceState bs{};
        blocks_to_bitslice(in + i * BLOCK_SIZE, BS_BLOCKS, bs);
        TripleDES_decrypt_bitslice(bs);
        bitslice_to_blocks(bs, out + i * BLOCK_SIZE, BS_BLOCKS);
    }

    if (rem) {
        std::size_t offset = full * BS_BLOCKS;
        for (std::size_t i = 0; i < rem; ++i) {
            decryptBlock_bitslice_single(in + (offset + i) * BLOCK_SIZE,
                out + (offset + i) * BLOCK_SIZE);
        }
    }
}





// --- Warstwa layoutu danych: hard-core bit-matrix transpose 32x64 ---

// Zalozenie: BS_BLOCKS == 32
// Wejscie: 32 blokow po 64 bity (big-endian w bajtach)
// Wyjscie: 64 bit-planes, kazdy jako maska 32-bitowa w dolnym lane __m256i

static inline void transpose_32x32(uint32_t x[32]) {
    for (int i = 0; i < 16; ++i) {
        uint32_t t = (x[i] ^ (x[i + 16] >> 16)) & 0x0000FFFFu;
        x[i] ^= t;
        x[i + 16] ^= (t << 16);
    }

    for (int i = 0; i < 8; ++i) {
        uint32_t t0 = (x[i] ^ (x[i + 8] >> 8)) & 0x00FF00FFu;
        x[i] ^= t0;
        x[i + 8] ^= (t0 << 8);

        uint32_t t1 = (x[i + 16] ^ (x[i + 24] >> 8)) & 0x00FF00FFu;
        x[i + 16] ^= t1;
        x[i + 24] ^= (t1 << 8);
    }

    for (int i = 0; i < 4; ++i) {
        uint32_t t0 = (x[i] ^ (x[i + 4] >> 4)) & 0x0F0F0F0Fu;
        x[i] ^= t0;
        x[i + 4] ^= (t0 << 4);

        uint32_t t1 = (x[i + 8] ^ (x[i + 12] >> 4)) & 0x0F0F0F0Fu;
        x[i + 8] ^= t1;
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
        x[i] ^= t0;
        x[i + 2] ^= (t0 << 2);

        uint32_t t1 = (x[i + 4] ^ (x[i + 6] >> 2)) & 0x33333333u;
        x[i + 4] ^= t1;
        x[i + 6] ^= (t1 << 2);

        uint32_t t2 = (x[i + 8] ^ (x[i + 10] >> 2)) & 0x33333333u;
        x[i + 8] ^= t2;
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
        x[i] ^= t;
        x[i + 1] ^= (t << 1);
    }
}

void TDES_Bitslice_AVX2::blocks_to_bitslice(const uint8_t* in,
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
            (v6 << 8) |
            (v7 << 0);

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

        int idx = bit; // zamiast 31 - bit

        bs[idx] = _mm256_set1_epi32(int32_t(mask_hi));
        bs[idx + 32] = _mm256_set1_epi32(int32_t(mask_lo));
    }


}


void TDES_Bitslice_AVX2::bitslice_to_blocks(const BitSliceState& bs,
    uint8_t* out,
    std::size_t blocks) {
    if (!out) return;
    if (blocks == 0) return;
    if (blocks != BS_BLOCKS)
        throw std::invalid_argument("bitslice_to_blocks: blocks must equal BS_BLOCKS (32)");

    uint32_t hi[32];
    uint32_t lo[32];

    for (int bit = 0; bit < 32; ++bit) {
        int idx = bit; // zamiast 31 - bit

        int32_t v_hi = _mm256_cvtsi256_si32(bs[idx]);
        int32_t v_lo = _mm256_cvtsi256_si32(bs[idx + 32]);

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
        out[i * 8 + 6] = uint8_t(v >> 8);
        out[i * 8 + 7] = uint8_t(v >> 0);
    }
}



// --- Warstwa klucza: szkielet ---

TDES_Bitslice_AVX2::SubkeyScheduleScalar
TDES_Bitslice_AVX2::GenerateSubkeysScalar(uint64_t key64) {
    SubkeyScheduleScalar sk{};

    // PC-1: 64-bit key -> 56-bit permutacja (C||D)
    uint64_t perm = 0;
    for (int i = 0; i < 56; ++i) {
        uint64_t bit = (key64 >> (64 - DES_PC1[i])) & 1ULL;
        perm |= (bit << (55 - i));
    }

    uint32_t C = uint32_t((perm >> 28) & 0x0FFFFFFFu);
    uint32_t D = uint32_t(perm & 0x0FFFFFFFu);

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


void TDES_Bitslice_AVX2::expand_subkeys_to_bitslice()
{
    auto expand_one = [this](const SubkeyScheduleScalar& sk_scalar, int key_index) {
        __m256i all1 = _mm256_set1_epi32(-1);
        __m256i zero = _mm256_setzero_si256();

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

void TDES_Bitslice_AVX2::IP_bitslice(BitSliceState& bs) {
    BitSliceState tmp;

    for (int i = 0; i < 64; ++i) {
        int src = int(DES_IP[i]) - 1;
        tmp[i] = bs[src];
    }

    for (int i = 0; i < 64; ++i) {
        bs[i] = tmp[i];
    }
}

void TDES_Bitslice_AVX2::FP_bitslice(BitSliceState& bs) {
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

// E-expansion: 32 -> 48 bitow
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

// P-permutation: 32 -> 32 bitow
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

inline __m256i xor256(__m256i a, __m256i b)
{
    __m256i t1 = _mm256_or_si256(a, b);
    __m256i t2 = _mm256_and_si256(a, b);
    __m256i t3 = _mm256_andnot_si256(t2, t1);
    return t3;
}


void TDES_Bitslice_AVX2::feistel_bitslice(const BitSliceState& bs,
    BitSliceState& F,
    int round,
    int key_index) const
{
    __m256i Ebits[48];

    // E: 32 -> 48 (z prawej połowy bs)
    for (int i = 0; i < 48; ++i) {
        int src = DES_E[i] - 1;
        Ebits[i] = bs[32 + src];
    }

    // XOR z podkluczem bitslice
    for (int i = 0; i < 48; ++i) {
        Ebits[i] = _mm256_xor_si256(Ebits[i], subkeys_bitslice[key_index][round][i]);
    }

    // S‑boxy → 32 bit‑plane’ów w S_out
    __m256i S_out[32];

    // ===== S1 =====
    {
        __m256i a0 = Ebits[5];
        __m256i a1 = Ebits[4];
        __m256i a2 = Ebits[3];
        __m256i a3 = Ebits[2];
        __m256i a4 = Ebits[1];
        __m256i a5 = Ebits[0];
        __m256i all1 = _mm256_set1_epi32(-1);

        __m256i t_0_1 = _mm256_and_si256(a1, a0);
        __m256i t_0_2 = _mm256_and_si256(a2, a0);
        __m256i t_1_2 = _mm256_and_si256(a2, a1);
        __m256i t_0_3 = _mm256_and_si256(a3, a0);
        __m256i t_1_3 = _mm256_and_si256(a3, a1);
        __m256i t_2_3 = _mm256_and_si256(a3, a2);
        __m256i t_0_4 = _mm256_and_si256(a4, a0);
        __m256i t_1_4 = _mm256_and_si256(a4, a1);
        __m256i t_2_4 = _mm256_and_si256(a4, a2);
        __m256i t_3_4 = _mm256_and_si256(a4, a3);
        __m256i t_0_5 = _mm256_and_si256(a5, a0);
        __m256i t_1_5 = _mm256_and_si256(a5, a1);
        __m256i t_2_5 = _mm256_and_si256(a5, a2);
        __m256i t_3_5 = _mm256_and_si256(a5, a3);
        __m256i t_4_5 = _mm256_and_si256(a5, a4);
        __m256i t_0_1_2 = _mm256_and_si256(t_1_2, a0);
        __m256i t_0_1_3 = _mm256_and_si256(t_1_3, a0);
        __m256i t_0_2_3 = _mm256_and_si256(t_2_3, a0);
        __m256i t_1_2_3 = _mm256_and_si256(t_2_3, a1);
        __m256i t_0_1_4 = _mm256_and_si256(t_1_4, a0);
        __m256i t_0_2_4 = _mm256_and_si256(t_2_4, a0);
        __m256i t_1_2_4 = _mm256_and_si256(t_2_4, a1);
        __m256i t_0_3_4 = _mm256_and_si256(t_3_4, a0);
        __m256i t_1_3_4 = _mm256_and_si256(t_3_4, a1);
        __m256i t_2_3_4 = _mm256_and_si256(t_3_4, a2);
        __m256i t_0_1_5 = _mm256_and_si256(t_1_5, a0);
        __m256i t_0_2_5 = _mm256_and_si256(t_2_5, a0);
        __m256i t_1_2_5 = _mm256_and_si256(t_2_5, a1);
        __m256i t_0_3_5 = _mm256_and_si256(t_3_5, a0);
        __m256i t_1_3_5 = _mm256_and_si256(t_3_5, a1);
        __m256i t_2_3_5 = _mm256_and_si256(t_3_5, a2);
        __m256i t_0_4_5 = _mm256_and_si256(t_4_5, a0);
        __m256i t_1_4_5 = _mm256_and_si256(t_4_5, a1);
        __m256i t_2_4_5 = _mm256_and_si256(t_4_5, a2);
        __m256i t_3_4_5 = _mm256_and_si256(t_4_5, a3);
        __m256i t_0_1_2_3 = _mm256_and_si256(t_1_2_3, a0);
        __m256i t_0_1_2_4 = _mm256_and_si256(t_1_2_4, a0);
        __m256i t_0_1_3_4 = _mm256_and_si256(t_1_3_4, a0);
        __m256i t_0_2_3_4 = _mm256_and_si256(t_2_3_4, a0);
        __m256i t_0_1_2_5 = _mm256_and_si256(t_1_2_5, a0);
        __m256i t_0_1_3_5 = _mm256_and_si256(t_1_3_5, a0);
        __m256i t_0_2_3_5 = _mm256_and_si256(t_2_3_5, a0);
        __m256i t_1_2_3_5 = _mm256_and_si256(t_2_3_5, a1);
        __m256i t_0_1_4_5 = _mm256_and_si256(t_1_4_5, a0);
        __m256i t_0_2_4_5 = _mm256_and_si256(t_2_4_5, a0);
        __m256i t_1_2_4_5 = _mm256_and_si256(t_2_4_5, a1);
        __m256i t_0_3_4_5 = _mm256_and_si256(t_3_4_5, a0);
        __m256i t_1_3_4_5 = _mm256_and_si256(t_3_4_5, a1);
        __m256i t_2_3_4_5 = _mm256_and_si256(t_3_4_5, a2);
        __m256i t_0_1_2_3_5 = _mm256_and_si256(t_1_2_3_5, a0);
        __m256i t_0_1_2_4_5 = _mm256_and_si256(t_1_2_4_5, a0);
        __m256i t_0_1_3_4_5 = _mm256_and_si256(t_1_3_4_5, a0);
        __m256i t_0_2_3_4_5 = _mm256_and_si256(t_2_3_4_5, a0);

        __m256i y0 = _mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(t_0_1, a2), t_1_3), a4), t_0_4), t_1_4), t_0_2_4), t_1_2_4), t_0_3_4), t_0_1_3_4), t_0_5), t_1_5), t_0_1_5), t_2_5), t_0_2_5), t_1_2_5), t_3_5), t_1_3_5), t_2_3_5), t_0_2_3_5), t_1_2_3_5), t_0_1_2_3_5), t_1_4_5), t_0_1_4_5), t_1_2_4_5), t_3_4_5), t_0_1_3_4_5), t_2_3_4_5), t_0_2_3_4_5);
        __m256i y1 = _mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(all1, a0), a1), a2), t_1_2), t_0_1_2), t_0_3), t_1_3), t_2_3), t_0_2_3), t_0_4), t_1_4), t_2_4), t_0_2_4), t_0_1_2_4), t_3_4), t_0_3_4), t_1_3_4), t_2_3_4), t_0_2_3_4), a5), t_1_5), t_0_1_5), t_2_3_5), t_0_1_2_3_5), t_4_5), t_0_4_5), t_0_1_4_5), t_2_4_5), t_0_2_4_5), t_1_2_4_5), t_0_1_2_4_5), t_3_4_5), t_0_3_4_5), t_1_3_4_5), t_0_1_3_4_5), t_2_3_4_5), t_0_2_3_4_5);
        __m256i y2 = _mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(all1, a0), t_0_1), t_0_2), t_1_2), a3), t_1_3), t_0_1_3), t_0_2_3), t_0_1_2_3), a4), t_0_4), t_2_4), t_0_2_4), t_1_2_4), t_0_3_4), t_0_5), t_1_5), t_1_2_5), t_3_5), t_0_1_3_5), t_2_3_5), t_0_1_2_3_5), t_4_5), t_0_4_5), t_1_4_5), t_0_1_2_4_5), t_3_4_5), t_0_3_4_5), t_1_3_4_5), t_0_1_3_4_5), t_2_3_4_5), t_0_2_3_4_5);
        __m256i y3 = _mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(all1, a0), a1), t_0_1_2), a3), t_2_3), t_0_2_3), t_1_2_3), a4), t_3_4), t_2_3_4), a5), t_1_5), t_2_5), t_0_2_5), t_1_3_5), t_2_3_5), t_0_2_3_5), t_1_2_3_5), t_0_1_4_5), t_2_4_5), t_0_2_4_5), t_1_2_4_5), t_3_4_5), t_0_1_3_4_5), t_2_3_4_5), t_0_2_3_4_5);

        S_out[0] = y3;
        S_out[1] = y2;
        S_out[2] = y1;
        S_out[3] = y0;
    }

    // ===== S2 =====
    {
        __m256i a0 = Ebits[11];
        __m256i a1 = Ebits[10];
        __m256i a2 = Ebits[9];
        __m256i a3 = Ebits[8];
        __m256i a4 = Ebits[7];
        __m256i a5 = Ebits[6];
        __m256i all1 = _mm256_set1_epi32(-1);

        __m256i t_0_1 = _mm256_and_si256(a1, a0);
        __m256i t_0_2 = _mm256_and_si256(a2, a0);
        __m256i t_1_2 = _mm256_and_si256(a2, a1);
        __m256i t_0_3 = _mm256_and_si256(a3, a0);
        __m256i t_1_3 = _mm256_and_si256(a3, a1);
        __m256i t_2_3 = _mm256_and_si256(a3, a2);
        __m256i t_0_4 = _mm256_and_si256(a4, a0);
        __m256i t_1_4 = _mm256_and_si256(a4, a1);
        __m256i t_2_4 = _mm256_and_si256(a4, a2);
        __m256i t_3_4 = _mm256_and_si256(a4, a3);
        __m256i t_0_5 = _mm256_and_si256(a5, a0);
        __m256i t_1_5 = _mm256_and_si256(a5, a1);
        __m256i t_2_5 = _mm256_and_si256(a5, a2);
        __m256i t_3_5 = _mm256_and_si256(a5, a3);
        __m256i t_4_5 = _mm256_and_si256(a5, a4);
        __m256i t_0_1_2 = _mm256_and_si256(t_1_2, a0);
        __m256i t_0_1_3 = _mm256_and_si256(t_1_3, a0);
        __m256i t_0_2_3 = _mm256_and_si256(t_2_3, a0);
        __m256i t_1_2_3 = _mm256_and_si256(t_2_3, a1);
        __m256i t_0_1_4 = _mm256_and_si256(t_1_4, a0);
        __m256i t_0_2_4 = _mm256_and_si256(t_2_4, a0);
        __m256i t_1_2_4 = _mm256_and_si256(t_2_4, a1);
        __m256i t_0_3_4 = _mm256_and_si256(t_3_4, a0);
        __m256i t_1_3_4 = _mm256_and_si256(t_3_4, a1);
        __m256i t_2_3_4 = _mm256_and_si256(t_3_4, a2);
        __m256i t_0_1_5 = _mm256_and_si256(t_1_5, a0);
        __m256i t_0_2_5 = _mm256_and_si256(t_2_5, a0);
        __m256i t_1_2_5 = _mm256_and_si256(t_2_5, a1);
        __m256i t_0_3_5 = _mm256_and_si256(t_3_5, a0);
        __m256i t_1_3_5 = _mm256_and_si256(t_3_5, a1);
        __m256i t_2_3_5 = _mm256_and_si256(t_3_5, a2);
        __m256i t_0_4_5 = _mm256_and_si256(t_4_5, a0);
        __m256i t_1_4_5 = _mm256_and_si256(t_4_5, a1);
        __m256i t_2_4_5 = _mm256_and_si256(t_4_5, a2);
        __m256i t_3_4_5 = _mm256_and_si256(t_4_5, a3);
        __m256i t_0_1_2_3 = _mm256_and_si256(t_1_2_3, a0);
        __m256i t_0_1_2_4 = _mm256_and_si256(t_1_2_4, a0);
        __m256i t_0_1_3_4 = _mm256_and_si256(t_1_3_4, a0);
        __m256i t_0_1_2_5 = _mm256_and_si256(t_1_2_5, a0);
        __m256i t_0_1_3_5 = _mm256_and_si256(t_1_3_5, a0);
        __m256i t_0_2_3_5 = _mm256_and_si256(t_2_3_5, a0);
        __m256i t_1_2_3_5 = _mm256_and_si256(t_2_3_5, a1);
        __m256i t_0_1_4_5 = _mm256_and_si256(t_1_4_5, a0);
        __m256i t_0_2_4_5 = _mm256_and_si256(t_2_4_5, a0);
        __m256i t_1_2_4_5 = _mm256_and_si256(t_2_4_5, a1);
        __m256i t_0_3_4_5 = _mm256_and_si256(t_3_4_5, a0);
        __m256i t_1_3_4_5 = _mm256_and_si256(t_3_4_5, a1);
        __m256i t_2_3_4_5 = _mm256_and_si256(t_3_4_5, a2);
        __m256i t_0_1_2_4_5 = _mm256_and_si256(t_1_2_4_5, a0);
        __m256i t_0_1_3_4_5 = _mm256_and_si256(t_1_3_4_5, a0);

        __m256i y0 = _mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(all1, a2), t_0_1_2), a3), t_0_3), t_1_3), t_0_4), t_1_2_4), t_0_1_2_4), t_1_3_4), t_0_1_3_4), a5), t_0_5), t_0_1_5), t_0_1_2_5), t_3_5), t_0_3_5), t_1_3_5), t_0_1_3_5), t_4_5), t_1_4_5), t_0_1_4_5), t_0_2_4_5), t_0_3_4_5), t_0_1_3_4_5);
        __m256i y1 = _mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(all1, a1), a2), t_1_3), t_2_3), t_0_2_3), t_1_2_3), a4), t_0_1_4), t_0_2_4), t_0_1_2_4), t_0_3_4), a5), t_0_1_5), t_1_2_5), t_3_5), t_1_3_5), t_2_3_5), t_0_2_3_5), t_1_2_3_5), t_4_5), t_0_4_5), t_1_4_5), t_2_4_5), t_0_2_4_5), t_0_1_2_4_5), t_3_4_5), t_1_3_4_5), t_0_1_3_4_5), t_2_3_4_5);
        __m256i y2 = _mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(all1, a0), a1), a2), t_0_1_2), t_0_3), t_0_1_2_3), a4), t_2_4), t_0_2_4), t_3_4), a5), t_1_2_4_5), t_0_1_2_4_5), t_1_3_4_5), t_0_1_3_4_5);
        __m256i y3 = _mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(all1, a0), a1), t_1_2), a3), t_0_4), t_2_4), t_1_2_4), t_3_4), t_0_3_4), a5), t_0_1_5), t_1_2_5), t_0_1_2_5), t_0_1_3_5), t_0_4_5), t_0_1_4_5), t_1_2_4_5), t_0_1_2_4_5), t_3_4_5), t_0_3_4_5);

        S_out[4] = y3;
        S_out[5] = y2;
        S_out[6] = y1;
        S_out[7] = y0;
    }

    // ===== S3 =====
    {
        __m256i a0 = Ebits[17];
        __m256i a1 = Ebits[16];
        __m256i a2 = Ebits[15];
        __m256i a3 = Ebits[14];
        __m256i a4 = Ebits[13];
        __m256i a5 = Ebits[12];
        __m256i all1 = _mm256_set1_epi32(-1);

        __m256i t_0_1 = _mm256_and_si256(a1, a0);
        __m256i t_0_2 = _mm256_and_si256(a2, a0);
        __m256i t_1_2 = _mm256_and_si256(a2, a1);
        __m256i t_0_3 = _mm256_and_si256(a3, a0);
        __m256i t_1_3 = _mm256_and_si256(a3, a1);
        __m256i t_2_3 = _mm256_and_si256(a3, a2);
        __m256i t_0_4 = _mm256_and_si256(a4, a0);
        __m256i t_1_4 = _mm256_and_si256(a4, a1);
        __m256i t_2_4 = _mm256_and_si256(a4, a2);
        __m256i t_3_4 = _mm256_and_si256(a4, a3);
        __m256i t_0_5 = _mm256_and_si256(a5, a0);
        __m256i t_1_5 = _mm256_and_si256(a5, a1);
        __m256i t_2_5 = _mm256_and_si256(a5, a2);
        __m256i t_3_5 = _mm256_and_si256(a5, a3);
        __m256i t_4_5 = _mm256_and_si256(a5, a4);
        __m256i t_0_1_2 = _mm256_and_si256(t_1_2, a0);
        __m256i t_0_1_3 = _mm256_and_si256(t_1_3, a0);
        __m256i t_0_2_3 = _mm256_and_si256(t_2_3, a0);
        __m256i t_1_2_3 = _mm256_and_si256(t_2_3, a1);
        __m256i t_0_1_4 = _mm256_and_si256(t_1_4, a0);
        __m256i t_0_2_4 = _mm256_and_si256(t_2_4, a0);
        __m256i t_1_2_4 = _mm256_and_si256(t_2_4, a1);
        __m256i t_0_3_4 = _mm256_and_si256(t_3_4, a0);
        __m256i t_1_3_4 = _mm256_and_si256(t_3_4, a1);
        __m256i t_2_3_4 = _mm256_and_si256(t_3_4, a2);
        __m256i t_0_1_5 = _mm256_and_si256(t_1_5, a0);
        __m256i t_0_2_5 = _mm256_and_si256(t_2_5, a0);
        __m256i t_1_2_5 = _mm256_and_si256(t_2_5, a1);
        __m256i t_0_3_5 = _mm256_and_si256(t_3_5, a0);
        __m256i t_1_3_5 = _mm256_and_si256(t_3_5, a1);
        __m256i t_2_3_5 = _mm256_and_si256(t_3_5, a2);
        __m256i t_0_4_5 = _mm256_and_si256(t_4_5, a0);
        __m256i t_1_4_5 = _mm256_and_si256(t_4_5, a1);
        __m256i t_2_4_5 = _mm256_and_si256(t_4_5, a2);
        __m256i t_3_4_5 = _mm256_and_si256(t_4_5, a3);
        __m256i t_0_1_2_3 = _mm256_and_si256(t_1_2_3, a0);
        __m256i t_0_1_2_4 = _mm256_and_si256(t_1_2_4, a0);
        __m256i t_0_1_3_4 = _mm256_and_si256(t_1_3_4, a0);
        __m256i t_0_2_3_4 = _mm256_and_si256(t_2_3_4, a0);
        __m256i t_0_1_2_5 = _mm256_and_si256(t_1_2_5, a0);
        __m256i t_0_1_3_5 = _mm256_and_si256(t_1_3_5, a0);
        __m256i t_0_2_3_5 = _mm256_and_si256(t_2_3_5, a0);
        __m256i t_1_2_3_5 = _mm256_and_si256(t_2_3_5, a1);
        __m256i t_0_1_4_5 = _mm256_and_si256(t_1_4_5, a0);
        __m256i t_0_2_4_5 = _mm256_and_si256(t_2_4_5, a0);
        __m256i t_1_2_4_5 = _mm256_and_si256(t_2_4_5, a1);
        __m256i t_0_3_4_5 = _mm256_and_si256(t_3_4_5, a0);
        __m256i t_1_3_4_5 = _mm256_and_si256(t_3_4_5, a1);
        __m256i t_2_3_4_5 = _mm256_and_si256(t_3_4_5, a2);
        __m256i t_0_1_2_3_5 = _mm256_and_si256(t_1_2_3_5, a0);
        __m256i t_0_1_2_4_5 = _mm256_and_si256(t_1_2_4_5, a0);
        __m256i t_0_1_3_4_5 = _mm256_and_si256(t_1_3_4_5, a0);
        __m256i t_0_2_3_4_5 = _mm256_and_si256(t_2_3_4_5, a0);

        __m256i y0 = _mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(a0, a2), t_1_2), t_1_3), a4), a5), t_0_5), t_1_5), t_0_2_5), t_1_2_5), t_3_5), t_1_3_5), t_4_5), t_0_4_5), t_1_4_5), t_0_1_4_5), t_3_4_5), t_0_3_4_5), t_1_3_4_5), t_0_2_3_4_5);
        __m256i y1 = _mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(all1, a0), a1), a2), t_0_2), t_0_1_2), t_0_3), t_1_3), t_0_1_3), t_2_3), t_0_2_3), t_1_2_3), t_0_1_2_3), a4), t_1_4), t_0_1_4), t_2_4), t_1_2_4), t_3_4), t_0_3_4), t_2_3_4), t_0_2_3_4), a5), t_0_5), t_2_5), t_0_2_5), t_1_2_5), t_0_1_2_5), t_1_3_5), t_0_1_3_5), t_0_2_3_5), t_0_1_2_3_5), t_0_4_5), t_1_4_5), t_0_1_4_5), t_2_4_5), t_0_2_4_5), t_0_1_2_4_5), t_2_3_4_5), t_0_2_3_4_5);
        __m256i y2 = _mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(a0, t_0_2), t_1_2), t_0_1_2), a3), t_1_3), t_0_4), t_1_4), t_0_1_4), t_2_4), t_0_2_4), t_3_4), t_0_3_4), t_1_3_4), t_0_1_3_4), t_2_3_4), a5), t_0_1_2_5), t_0_1_2_3_5), t_4_5), t_0_4_5), t_1_4_5), t_0_1_4_5), t_2_4_5), t_3_4_5), t_0_3_4_5), t_1_3_4_5), t_0_1_3_4_5), t_2_3_4_5);
        __m256i y3 = _mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(all1, a1), t_0_2), t_1_2), t_0_1_2), a3), t_1_3), t_2_3), t_0_1_2_3), a4), t_2_4), t_1_2_4), t_0_1_2_4), t_1_3_4), t_0_1_3_4), t_2_3_4), t_0_5), t_2_5), t_0_2_5), t_1_2_5), t_0_1_2_5), t_3_5), t_0_1_3_5), t_2_3_5), t_0_1_2_3_5), t_4_5), t_2_4_5), t_1_2_4_5), t_0_1_2_4_5), t_3_4_5), t_2_3_4_5);

        S_out[8] = y3;
        S_out[9] = y2;
        S_out[10] = y1;
        S_out[11] = y0;
    }

    // ===== S4 =====
    {
        __m256i a0 = Ebits[23];
        __m256i a1 = Ebits[22];
        __m256i a2 = Ebits[21];
        __m256i a3 = Ebits[20];
        __m256i a4 = Ebits[19];
        __m256i a5 = Ebits[18];
        __m256i all1 = _mm256_set1_epi32(-1);

        __m256i t_0_1 = _mm256_and_si256(a1, a0);
        __m256i t_0_2 = _mm256_and_si256(a2, a0);
        __m256i t_1_2 = _mm256_and_si256(a2, a1);
        __m256i t_0_3 = _mm256_and_si256(a3, a0);
        __m256i t_1_3 = _mm256_and_si256(a3, a1);
        __m256i t_2_3 = _mm256_and_si256(a3, a2);
        __m256i t_0_4 = _mm256_and_si256(a4, a0);
        __m256i t_1_4 = _mm256_and_si256(a4, a1);
        __m256i t_2_4 = _mm256_and_si256(a4, a2);
        __m256i t_3_4 = _mm256_and_si256(a4, a3);
        __m256i t_0_5 = _mm256_and_si256(a5, a0);
        __m256i t_1_5 = _mm256_and_si256(a5, a1);
        __m256i t_2_5 = _mm256_and_si256(a5, a2);
        __m256i t_3_5 = _mm256_and_si256(a5, a3);
        __m256i t_4_5 = _mm256_and_si256(a5, a4);
        __m256i t_0_1_2 = _mm256_and_si256(t_1_2, a0);
        __m256i t_0_1_3 = _mm256_and_si256(t_1_3, a0);
        __m256i t_0_2_3 = _mm256_and_si256(t_2_3, a0);
        __m256i t_1_2_3 = _mm256_and_si256(t_2_3, a1);
        __m256i t_0_1_4 = _mm256_and_si256(t_1_4, a0);
        __m256i t_0_2_4 = _mm256_and_si256(t_2_4, a0);
        __m256i t_1_2_4 = _mm256_and_si256(t_2_4, a1);
        __m256i t_0_3_4 = _mm256_and_si256(t_3_4, a0);
        __m256i t_1_3_4 = _mm256_and_si256(t_3_4, a1);
        __m256i t_2_3_4 = _mm256_and_si256(t_3_4, a2);
        __m256i t_0_1_5 = _mm256_and_si256(t_1_5, a0);
        __m256i t_0_2_5 = _mm256_and_si256(t_2_5, a0);
        __m256i t_1_2_5 = _mm256_and_si256(t_2_5, a1);
        __m256i t_0_3_5 = _mm256_and_si256(t_3_5, a0);
        __m256i t_1_3_5 = _mm256_and_si256(t_3_5, a1);
        __m256i t_2_3_5 = _mm256_and_si256(t_3_5, a2);
        __m256i t_0_4_5 = _mm256_and_si256(t_4_5, a0);
        __m256i t_1_4_5 = _mm256_and_si256(t_4_5, a1);
        __m256i t_2_4_5 = _mm256_and_si256(t_4_5, a2);
        __m256i t_3_4_5 = _mm256_and_si256(t_4_5, a3);
        __m256i t_0_1_2_3 = _mm256_and_si256(t_1_2_3, a0);
        __m256i t_0_1_2_4 = _mm256_and_si256(t_1_2_4, a0);
        __m256i t_0_1_3_4 = _mm256_and_si256(t_1_3_4, a0);
        __m256i t_0_2_3_4 = _mm256_and_si256(t_2_3_4, a0);
        __m256i t_0_1_2_5 = _mm256_and_si256(t_1_2_5, a0);
        __m256i t_0_1_3_5 = _mm256_and_si256(t_1_3_5, a0);
        __m256i t_0_2_3_5 = _mm256_and_si256(t_2_3_5, a0);
        __m256i t_1_2_3_5 = _mm256_and_si256(t_2_3_5, a1);
        __m256i t_0_1_4_5 = _mm256_and_si256(t_1_4_5, a0);
        __m256i t_1_2_4_5 = _mm256_and_si256(t_2_4_5, a1);
        __m256i t_0_3_4_5 = _mm256_and_si256(t_3_4_5, a0);
        __m256i t_1_3_4_5 = _mm256_and_si256(t_3_4_5, a1);
        __m256i t_2_3_4_5 = _mm256_and_si256(t_3_4_5, a2);
        __m256i t_0_1_2_3_5 = _mm256_and_si256(t_1_2_3_5, a0);
        __m256i t_0_1_3_4_5 = _mm256_and_si256(t_1_3_4_5, a0);

        __m256i y0 = _mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(all1, t_0_1), a2), t_0_2), t_1_2), a3), t_0_1_2_3), t_0_4), t_1_4), t_0_1_4), t_1_2_4), t_0_1_2_4), t_3_4), t_0_3_4), t_0_2_3_4), a5), t_0_5), t_0_1_5), t_0_2_5), t_0_1_2_5), t_3_5), t_0_3_5), t_1_3_5), t_0_1_2_3_5), t_4_5), t_1_4_5), t_2_4_5), t_1_2_4_5), t_3_4_5), t_0_3_4_5), t_0_1_3_4_5), t_2_3_4_5);
        __m256i y1 = _mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(all1, a0), a1), t_0_1), t_0_2), t_1_2), a3), t_1_2_3), t_0_1_2_3), a4), t_0_4), t_0_1_4), t_0_1_2_4), t_0_3_4), t_2_3_4), t_0_2_3_4), t_0_5), t_1_5), t_0_1_5), t_2_5), t_0_2_5), t_1_2_5), t_0_1_2_5), t_0_3_5), t_1_3_5), t_1_2_3_5), t_0_1_2_3_5), t_4_5), t_1_4_5), t_2_4_5), t_1_2_4_5), t_0_3_4_5), t_1_3_4_5), t_0_1_3_4_5), t_2_3_4_5);
        __m256i y2 = _mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(all1, t_0_1), t_0_2), t_1_2), t_0_1_2), a3), t_0_3), t_1_3), a4), t_0_4), t_0_1_4), t_0_1_2_4), t_3_4), t_0_1_3_4), t_2_3_4), t_0_2_3_4), a5), t_1_5), t_0_1_5), t_0_2_5), t_1_3_5), t_0_1_3_5), t_0_2_3_5), t_0_1_2_3_5), t_0_1_4_5), t_2_4_5), t_1_2_4_5), t_0_1_3_4_5), t_2_3_4_5);
        __m256i y3 = _mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(a0, a1), t_0_1), a2), t_0_2), t_0_1_2), t_0_3), t_1_3), t_0_4), t_1_4), t_0_1_4), t_1_2_4), t_0_1_2_4), t_3_4), t_1_3_4), t_0_1_3_4), t_0_2_3_4), a5), t_0_1_5), t_2_5), t_0_2_5), t_0_1_3_5), t_2_3_5), t_0_2_3_5), t_1_2_3_5), t_0_1_2_3_5), t_1_4_5), t_0_1_4_5), t_2_4_5), t_1_2_4_5), t_1_3_4_5), t_0_1_3_4_5), t_2_3_4_5);

        S_out[12] = y3;
        S_out[13] = y2;
        S_out[14] = y1;
        S_out[15] = y0;
    }

    // ===== S5 =====
    {
        __m256i a0 = Ebits[29];
        __m256i a1 = Ebits[28];
        __m256i a2 = Ebits[27];
        __m256i a3 = Ebits[26];
        __m256i a4 = Ebits[25];
        __m256i a5 = Ebits[24];
        __m256i all1 = _mm256_set1_epi32(-1);

        __m256i t_0_1 = _mm256_and_si256(a1, a0);
        __m256i t_0_2 = _mm256_and_si256(a2, a0);
        __m256i t_1_2 = _mm256_and_si256(a2, a1);
        __m256i t_0_3 = _mm256_and_si256(a3, a0);
        __m256i t_1_3 = _mm256_and_si256(a3, a1);
        __m256i t_2_3 = _mm256_and_si256(a3, a2);
        __m256i t_0_4 = _mm256_and_si256(a4, a0);
        __m256i t_1_4 = _mm256_and_si256(a4, a1);
        __m256i t_2_4 = _mm256_and_si256(a4, a2);
        __m256i t_3_4 = _mm256_and_si256(a4, a3);
        __m256i t_0_5 = _mm256_and_si256(a5, a0);
        __m256i t_1_5 = _mm256_and_si256(a5, a1);
        __m256i t_2_5 = _mm256_and_si256(a5, a2);
        __m256i t_3_5 = _mm256_and_si256(a5, a3);
        __m256i t_4_5 = _mm256_and_si256(a5, a4);
        __m256i t_0_1_2 = _mm256_and_si256(t_1_2, a0);
        __m256i t_0_1_3 = _mm256_and_si256(t_1_3, a0);
        __m256i t_0_2_3 = _mm256_and_si256(t_2_3, a0);
        __m256i t_1_2_3 = _mm256_and_si256(t_2_3, a1);
        __m256i t_0_1_4 = _mm256_and_si256(t_1_4, a0);
        __m256i t_0_2_4 = _mm256_and_si256(t_2_4, a0);
        __m256i t_1_2_4 = _mm256_and_si256(t_2_4, a1);
        __m256i t_0_3_4 = _mm256_and_si256(t_3_4, a0);
        __m256i t_1_3_4 = _mm256_and_si256(t_3_4, a1);
        __m256i t_2_3_4 = _mm256_and_si256(t_3_4, a2);
        __m256i t_0_1_5 = _mm256_and_si256(t_1_5, a0);
        __m256i t_0_2_5 = _mm256_and_si256(t_2_5, a0);
        __m256i t_1_2_5 = _mm256_and_si256(t_2_5, a1);
        __m256i t_0_3_5 = _mm256_and_si256(t_3_5, a0);
        __m256i t_1_3_5 = _mm256_and_si256(t_3_5, a1);
        __m256i t_2_3_5 = _mm256_and_si256(t_3_5, a2);
        __m256i t_0_4_5 = _mm256_and_si256(t_4_5, a0);
        __m256i t_1_4_5 = _mm256_and_si256(t_4_5, a1);
        __m256i t_2_4_5 = _mm256_and_si256(t_4_5, a2);
        __m256i t_3_4_5 = _mm256_and_si256(t_4_5, a3);
        __m256i t_0_1_2_3 = _mm256_and_si256(t_1_2_3, a0);
        __m256i t_0_1_2_4 = _mm256_and_si256(t_1_2_4, a0);
        __m256i t_0_1_3_4 = _mm256_and_si256(t_1_3_4, a0);
        __m256i t_0_2_3_4 = _mm256_and_si256(t_2_3_4, a0);
        __m256i t_0_1_2_5 = _mm256_and_si256(t_1_2_5, a0);
        __m256i t_0_1_3_5 = _mm256_and_si256(t_1_3_5, a0);
        __m256i t_0_2_3_5 = _mm256_and_si256(t_2_3_5, a0);
        __m256i t_1_2_3_5 = _mm256_and_si256(t_2_3_5, a1);
        __m256i t_0_1_4_5 = _mm256_and_si256(t_1_4_5, a0);
        __m256i t_0_2_4_5 = _mm256_and_si256(t_2_4_5, a0);
        __m256i t_1_2_4_5 = _mm256_and_si256(t_2_4_5, a1);
        __m256i t_0_3_4_5 = _mm256_and_si256(t_3_4_5, a0);
        __m256i t_1_3_4_5 = _mm256_and_si256(t_3_4_5, a1);
        __m256i t_2_3_4_5 = _mm256_and_si256(t_3_4_5, a2);
        __m256i t_0_1_2_3_5 = _mm256_and_si256(t_1_2_3_5, a0);
        __m256i t_0_1_2_4_5 = _mm256_and_si256(t_1_2_4_5, a0);
        __m256i t_0_1_3_4_5 = _mm256_and_si256(t_1_3_4_5, a0);
        __m256i t_0_2_3_4_5 = _mm256_and_si256(t_2_3_4_5, a0);

        __m256i y0 = _mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(t_0_1, t_1_2), a3), t_0_3), t_1_3), t_0_1_3), t_0_2_3), t_1_2_3), t_0_1_2_3), t_0_4), t_1_4), t_0_1_4), t_2_4), t_0_2_4), t_0_1_2_4), t_1_3_4), t_0_5), t_2_5), t_1_2_5), t_3_5), t_0_3_5), t_0_2_3_5), t_1_2_3_5), t_0_1_2_3_5), t_4_5), t_0_4_5), t_1_4_5), t_0_1_4_5), t_2_4_5), t_1_2_4_5), t_3_4_5), t_0_3_4_5), t_1_3_4_5), t_0_1_3_4_5), t_2_3_4_5);
        __m256i y1 = _mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(all1, a1), t_0_1), a2), t_0_2), t_1_2), t_0_3), t_1_3), t_2_3), t_0_2_3), t_1_2_3), t_0_1_2_3), a4), t_1_4), t_0_1_4), t_0_2_4), t_1_2_4), t_1_3_4), t_0_1_3_4), t_2_3_4), t_0_2_3_4), a5), t_0_5), t_0_1_5), t_2_5), t_1_2_5), t_3_5), t_0_3_5), t_1_3_5), t_2_3_5), t_0_2_3_5), t_1_2_3_5), t_0_1_2_3_5), t_0_4_5), t_1_4_5), t_2_4_5), t_0_1_2_4_5), t_3_4_5), t_0_1_3_4_5), t_2_3_4_5), t_0_2_3_4_5);
        __m256i y2 = _mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(a0, a1), a2), a3), t_0_3), t_0_1_3), t_0_2_3), t_0_1_2_3), t_2_4), t_0_3_4), t_0_2_3_4), a5), t_0_1_5), t_1_2_5), t_0_1_2_5), t_1_2_3_5), t_0_4_5), t_0_2_4_5), t_3_4_5), t_0_3_4_5), t_2_3_4_5), t_0_2_3_4_5);
        __m256i y3 = _mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(a0, a1), t_0_1), t_0_2), t_1_2), t_0_3), t_2_3), t_0_2_3), t_1_2_3), t_0_1_2_3), a4), t_2_4), t_0_2_4), t_1_2_4), t_0_3_4), t_0_1_3_4), t_1_5), t_0_1_5), t_0_2_5), t_3_5), t_0_3_5), t_0_1_3_5), t_1_2_3_5), t_0_1_4_5), t_2_4_5), t_0_2_4_5), t_1_2_4_5), t_0_1_2_4_5), t_0_3_4_5), t_2_3_4_5);

        S_out[16] = y3;
        S_out[17] = y2;
        S_out[18] = y1;
        S_out[19] = y0;
    }

    // ===== S6 =====
    {
        __m256i a0 = Ebits[35];
        __m256i a1 = Ebits[34];
        __m256i a2 = Ebits[33];
        __m256i a3 = Ebits[32];
        __m256i a4 = Ebits[31];
        __m256i a5 = Ebits[30];
        __m256i all1 = _mm256_set1_epi32(-1);

        __m256i t_0_1 = _mm256_and_si256(a1, a0);
        __m256i t_0_2 = _mm256_and_si256(a2, a0);
        __m256i t_1_2 = _mm256_and_si256(a2, a1);
        __m256i t_0_3 = _mm256_and_si256(a3, a0);
        __m256i t_1_3 = _mm256_and_si256(a3, a1);
        __m256i t_2_3 = _mm256_and_si256(a3, a2);
        __m256i t_0_4 = _mm256_and_si256(a4, a0);
        __m256i t_1_4 = _mm256_and_si256(a4, a1);
        __m256i t_2_4 = _mm256_and_si256(a4, a2);
        __m256i t_3_4 = _mm256_and_si256(a4, a3);
        __m256i t_0_5 = _mm256_and_si256(a5, a0);
        __m256i t_1_5 = _mm256_and_si256(a5, a1);
        __m256i t_2_5 = _mm256_and_si256(a5, a2);
        __m256i t_3_5 = _mm256_and_si256(a5, a3);
        __m256i t_4_5 = _mm256_and_si256(a5, a4);
        __m256i t_0_1_2 = _mm256_and_si256(t_1_2, a0);
        __m256i t_0_1_3 = _mm256_and_si256(t_1_3, a0);
        __m256i t_0_2_3 = _mm256_and_si256(t_2_3, a0);
        __m256i t_1_2_3 = _mm256_and_si256(t_2_3, a1);
        __m256i t_0_1_4 = _mm256_and_si256(t_1_4, a0);
        __m256i t_0_2_4 = _mm256_and_si256(t_2_4, a0);
        __m256i t_1_2_4 = _mm256_and_si256(t_2_4, a1);
        __m256i t_0_3_4 = _mm256_and_si256(t_3_4, a0);
        __m256i t_1_3_4 = _mm256_and_si256(t_3_4, a1);
        __m256i t_2_3_4 = _mm256_and_si256(t_3_4, a2);
        __m256i t_0_1_5 = _mm256_and_si256(t_1_5, a0);
        __m256i t_0_2_5 = _mm256_and_si256(t_2_5, a0);
        __m256i t_1_2_5 = _mm256_and_si256(t_2_5, a1);
        __m256i t_0_3_5 = _mm256_and_si256(t_3_5, a0);
        __m256i t_1_3_5 = _mm256_and_si256(t_3_5, a1);
        __m256i t_2_3_5 = _mm256_and_si256(t_3_5, a2);
        __m256i t_0_4_5 = _mm256_and_si256(t_4_5, a0);
        __m256i t_1_4_5 = _mm256_and_si256(t_4_5, a1);
        __m256i t_2_4_5 = _mm256_and_si256(t_4_5, a2);
        __m256i t_3_4_5 = _mm256_and_si256(t_4_5, a3);
        __m256i t_0_1_2_3 = _mm256_and_si256(t_1_2_3, a0);
        __m256i t_0_1_2_4 = _mm256_and_si256(t_1_2_4, a0);
        __m256i t_0_1_3_4 = _mm256_and_si256(t_1_3_4, a0);
        __m256i t_0_2_3_4 = _mm256_and_si256(t_2_3_4, a0);
        __m256i t_0_1_2_5 = _mm256_and_si256(t_1_2_5, a0);
        __m256i t_0_1_3_5 = _mm256_and_si256(t_1_3_5, a0);
        __m256i t_0_2_3_5 = _mm256_and_si256(t_2_3_5, a0);
        __m256i t_1_2_3_5 = _mm256_and_si256(t_2_3_5, a1);
        __m256i t_0_1_4_5 = _mm256_and_si256(t_1_4_5, a0);
        __m256i t_0_2_4_5 = _mm256_and_si256(t_2_4_5, a0);
        __m256i t_1_2_4_5 = _mm256_and_si256(t_2_4_5, a1);
        __m256i t_0_3_4_5 = _mm256_and_si256(t_3_4_5, a0);
        __m256i t_1_3_4_5 = _mm256_and_si256(t_3_4_5, a1);
        __m256i t_2_3_4_5 = _mm256_and_si256(t_3_4_5, a2);
        __m256i t_0_1_2_3_5 = _mm256_and_si256(t_1_2_3_5, a0);
        __m256i t_0_1_2_4_5 = _mm256_and_si256(t_1_2_4_5, a0);
        __m256i t_0_1_3_4_5 = _mm256_and_si256(t_1_3_4_5, a0);
        __m256i t_0_2_3_4_5 = _mm256_and_si256(t_2_3_4_5, a0);

        __m256i y0 = _mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(a1, t_0_1_2), a3), t_2_3), t_0_2_3), t_1_2_3), t_0_1_2_3), t_2_4), t_0_1_2_4), t_3_4), t_2_3_4), t_0_2_3_4), a5), t_0_5), t_1_2_5), t_0_1_2_5), t_1_3_5), t_2_3_5), t_0_2_3_5), t_1_2_3_5), t_0_1_2_3_5), t_0_4_5), t_0_2_4_5), t_0_1_2_4_5), t_0_3_4_5);
        __m256i y1 = _mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(a0, a2), t_0_1_2), t_1_3), t_0_1_4), t_1_2_4), t_3_4), t_1_3_4), t_0_5), t_1_5), t_0_1_2_5), t_3_5), t_0_3_5), t_1_3_5), t_0_1_3_5), t_4_5), t_1_2_4_5), t_0_1_2_4_5), t_3_4_5), t_0_1_3_4_5);
        __m256i y2 = _mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(all1, a0), a1), a2), a3), t_1_3), t_1_2_3), a4), t_2_4), t_0_1_2_4), a5), t_1_2_5), t_0_1_2_5), t_3_5), t_0_3_5), t_0_1_3_5), t_1_2_3_5), t_1_2_4_5), t_3_4_5), t_0_3_4_5), t_1_3_4_5), t_0_1_3_4_5), t_0_2_3_4_5);
        __m256i y3 = _mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(all1, a1), t_0_1), t_0_2), t_1_2), t_0_1_2), t_0_3), t_0_1_3), t_2_3), t_0_2_3), t_1_2_3), t_0_1_2_3), a4), t_3_4), t_0_2_3_4), t_0_5), t_1_5), t_0_1_5), t_0_2_5), t_0_1_2_5), t_3_5), t_0_3_5), t_1_3_5), t_0_1_3_5), t_0_2_4_5), t_0_1_2_4_5), t_0_3_4_5), t_0_1_3_4_5), t_0_2_3_4_5);

        S_out[20] = y3;
        S_out[21] = y2;
        S_out[22] = y1;
        S_out[23] = y0;
    }

    // ===== S7 =====
    {
        __m256i a0 = Ebits[41];
        __m256i a1 = Ebits[40];
        __m256i a2 = Ebits[39];
        __m256i a3 = Ebits[38];
        __m256i a4 = Ebits[37];
        __m256i a5 = Ebits[36];
        __m256i all1 = _mm256_set1_epi32(-1);

        __m256i t_0_1 = _mm256_and_si256(a1, a0);
        __m256i t_0_2 = _mm256_and_si256(a2, a0);
        __m256i t_1_2 = _mm256_and_si256(a2, a1);
        __m256i t_0_3 = _mm256_and_si256(a3, a0);
        __m256i t_1_3 = _mm256_and_si256(a3, a1);
        __m256i t_2_3 = _mm256_and_si256(a3, a2);
        __m256i t_0_4 = _mm256_and_si256(a4, a0);
        __m256i t_1_4 = _mm256_and_si256(a4, a1);
        __m256i t_2_4 = _mm256_and_si256(a4, a2);
        __m256i t_3_4 = _mm256_and_si256(a4, a3);
        __m256i t_0_5 = _mm256_and_si256(a5, a0);
        __m256i t_1_5 = _mm256_and_si256(a5, a1);
        __m256i t_2_5 = _mm256_and_si256(a5, a2);
        __m256i t_3_5 = _mm256_and_si256(a5, a3);
        __m256i t_4_5 = _mm256_and_si256(a5, a4);
        __m256i t_0_1_2 = _mm256_and_si256(t_1_2, a0);
        __m256i t_0_1_3 = _mm256_and_si256(t_1_3, a0);
        __m256i t_0_2_3 = _mm256_and_si256(t_2_3, a0);
        __m256i t_1_2_3 = _mm256_and_si256(t_2_3, a1);
        __m256i t_0_1_4 = _mm256_and_si256(t_1_4, a0);
        __m256i t_0_2_4 = _mm256_and_si256(t_2_4, a0);
        __m256i t_1_2_4 = _mm256_and_si256(t_2_4, a1);
        __m256i t_0_3_4 = _mm256_and_si256(t_3_4, a0);
        __m256i t_1_3_4 = _mm256_and_si256(t_3_4, a1);
        __m256i t_2_3_4 = _mm256_and_si256(t_3_4, a2);
        __m256i t_0_1_5 = _mm256_and_si256(t_1_5, a0);
        __m256i t_0_2_5 = _mm256_and_si256(t_2_5, a0);
        __m256i t_1_2_5 = _mm256_and_si256(t_2_5, a1);
        __m256i t_0_3_5 = _mm256_and_si256(t_3_5, a0);
        __m256i t_1_3_5 = _mm256_and_si256(t_3_5, a1);
        __m256i t_2_3_5 = _mm256_and_si256(t_3_5, a2);
        __m256i t_0_4_5 = _mm256_and_si256(t_4_5, a0);
        __m256i t_1_4_5 = _mm256_and_si256(t_4_5, a1);
        __m256i t_2_4_5 = _mm256_and_si256(t_4_5, a2);
        __m256i t_3_4_5 = _mm256_and_si256(t_4_5, a3);
        __m256i t_0_1_2_3 = _mm256_and_si256(t_1_2_3, a0);
        __m256i t_0_1_2_4 = _mm256_and_si256(t_1_2_4, a0);
        __m256i t_0_1_3_4 = _mm256_and_si256(t_1_3_4, a0);
        __m256i t_0_2_3_4 = _mm256_and_si256(t_2_3_4, a0);
        __m256i t_0_1_2_5 = _mm256_and_si256(t_1_2_5, a0);
        __m256i t_0_1_3_5 = _mm256_and_si256(t_1_3_5, a0);
        __m256i t_0_2_3_5 = _mm256_and_si256(t_2_3_5, a0);
        __m256i t_1_2_3_5 = _mm256_and_si256(t_2_3_5, a1);
        __m256i t_0_1_4_5 = _mm256_and_si256(t_1_4_5, a0);
        __m256i t_0_2_4_5 = _mm256_and_si256(t_2_4_5, a0);
        __m256i t_1_2_4_5 = _mm256_and_si256(t_2_4_5, a1);
        __m256i t_0_3_4_5 = _mm256_and_si256(t_3_4_5, a0);
        __m256i t_1_3_4_5 = _mm256_and_si256(t_3_4_5, a1);
        __m256i t_2_3_4_5 = _mm256_and_si256(t_3_4_5, a2);
        __m256i t_0_1_2_3_5 = _mm256_and_si256(t_1_2_3_5, a0);
        __m256i t_0_1_2_4_5 = _mm256_and_si256(t_1_2_4_5, a0);
        __m256i t_0_1_3_4_5 = _mm256_and_si256(t_1_3_4_5, a0);
        __m256i t_0_2_3_4_5 = _mm256_and_si256(t_2_3_4_5, a0);

        __m256i y0 = _mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(a0, a1), t_1_2), a3), t_2_3), t_1_2_3), a4), t_0_2_4), t_0_1_2_4), t_3_4), a5), t_0_2_5), t_0_1_2_5), t_0_2_3_5), t_0_1_2_3_5), t_0_1_4_5), t_0_2_4_5), t_0_3_4_5);
        __m256i y1 = _mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(a1, t_0_1), a2), t_1_2), t_0_1_2), a3), t_0_3), t_0_2_3), t_0_1_2_3), a4), t_1_2_4), t_0_1_2_4), t_0_2_3_4), t_0_5), t_1_5), t_0_1_5), t_3_5), t_1_3_5), t_0_1_3_5), t_0_2_3_5), t_0_1_2_3_5), t_2_4_5), t_1_2_4_5), t_3_4_5), t_0_3_4_5), t_1_3_4_5), t_0_1_3_4_5), t_0_2_3_4_5);
        __m256i y2 = _mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(all1, a1), a2), t_0_1_2_3), a4), t_0_4), t_2_4), t_0_1_2_4), t_3_4), a5), t_0_5), t_2_5), t_3_5), t_1_2_3_5), t_4_5), t_0_2_4_5), t_0_1_2_4_5), t_0_3_4_5), t_2_3_4_5);
        __m256i y3 = _mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(a0, a1), a3), t_1_2_3), t_0_1_2_3), t_2_4), t_3_4), t_0_3_4), t_2_3_4), t_0_2_3_4), t_0_5), t_1_5), t_0_1_5), t_2_5), t_0_1_2_5), t_0_3_5), t_1_3_5), t_1_2_3_5), t_0_1_2_3_5), t_4_5), t_2_4_5), t_1_2_4_5), t_3_4_5), t_0_3_4_5), t_1_3_4_5), t_2_3_4_5), t_0_2_3_4_5);

        S_out[24] = y3;
        S_out[25] = y2;
        S_out[26] = y1;
        S_out[27] = y0;
    }

    // ===== S8 =====
    {
        __m256i a0 = Ebits[47];
        __m256i a1 = Ebits[46];
        __m256i a2 = Ebits[45];
        __m256i a3 = Ebits[44];
        __m256i a4 = Ebits[43];
        __m256i a5 = Ebits[42];
        __m256i all1 = _mm256_set1_epi32(-1);

        __m256i t_0_1 = _mm256_and_si256(a1, a0);
        __m256i t_0_2 = _mm256_and_si256(a2, a0);
        __m256i t_1_2 = _mm256_and_si256(a2, a1);
        __m256i t_0_3 = _mm256_and_si256(a3, a0);
        __m256i t_1_3 = _mm256_and_si256(a3, a1);
        __m256i t_2_3 = _mm256_and_si256(a3, a2);
        __m256i t_0_4 = _mm256_and_si256(a4, a0);
        __m256i t_1_4 = _mm256_and_si256(a4, a1);
        __m256i t_2_4 = _mm256_and_si256(a4, a2);
        __m256i t_3_4 = _mm256_and_si256(a4, a3);
        __m256i t_0_5 = _mm256_and_si256(a5, a0);
        __m256i t_1_5 = _mm256_and_si256(a5, a1);
        __m256i t_2_5 = _mm256_and_si256(a5, a2);
        __m256i t_3_5 = _mm256_and_si256(a5, a3);
        __m256i t_4_5 = _mm256_and_si256(a5, a4);
        __m256i t_0_1_2 = _mm256_and_si256(t_1_2, a0);
        __m256i t_0_1_3 = _mm256_and_si256(t_1_3, a0);
        __m256i t_0_2_3 = _mm256_and_si256(t_2_3, a0);
        __m256i t_1_2_3 = _mm256_and_si256(t_2_3, a1);
        __m256i t_0_1_4 = _mm256_and_si256(t_1_4, a0);
        __m256i t_0_2_4 = _mm256_and_si256(t_2_4, a0);
        __m256i t_1_2_4 = _mm256_and_si256(t_2_4, a1);
        __m256i t_0_3_4 = _mm256_and_si256(t_3_4, a0);
        __m256i t_1_3_4 = _mm256_and_si256(t_3_4, a1);
        __m256i t_2_3_4 = _mm256_and_si256(t_3_4, a2);
        __m256i t_0_1_5 = _mm256_and_si256(t_1_5, a0);
        __m256i t_0_2_5 = _mm256_and_si256(t_2_5, a0);
        __m256i t_1_2_5 = _mm256_and_si256(t_2_5, a1);
        __m256i t_0_3_5 = _mm256_and_si256(t_3_5, a0);
        __m256i t_1_3_5 = _mm256_and_si256(t_3_5, a1);
        __m256i t_2_3_5 = _mm256_and_si256(t_3_5, a2);
        __m256i t_0_4_5 = _mm256_and_si256(t_4_5, a0);
        __m256i t_1_4_5 = _mm256_and_si256(t_4_5, a1);
        __m256i t_2_4_5 = _mm256_and_si256(t_4_5, a2);
        __m256i t_3_4_5 = _mm256_and_si256(t_4_5, a3);
        __m256i t_0_1_2_3 = _mm256_and_si256(t_1_2_3, a0);
        __m256i t_0_1_2_4 = _mm256_and_si256(t_1_2_4, a0);
        __m256i t_0_1_3_4 = _mm256_and_si256(t_1_3_4, a0);
        __m256i t_0_2_3_4 = _mm256_and_si256(t_2_3_4, a0);
        __m256i t_0_1_2_5 = _mm256_and_si256(t_1_2_5, a0);
        __m256i t_0_1_3_5 = _mm256_and_si256(t_1_3_5, a0);
        __m256i t_0_2_3_5 = _mm256_and_si256(t_2_3_5, a0);
        __m256i t_0_1_4_5 = _mm256_and_si256(t_1_4_5, a0);
        __m256i t_0_2_4_5 = _mm256_and_si256(t_2_4_5, a0);
        __m256i t_1_2_4_5 = _mm256_and_si256(t_2_4_5, a1);
        __m256i t_0_3_4_5 = _mm256_and_si256(t_3_4_5, a0);
        __m256i t_1_3_4_5 = _mm256_and_si256(t_3_4_5, a1);
        __m256i t_2_3_4_5 = _mm256_and_si256(t_3_4_5, a2);
        __m256i t_0_1_2_4_5 = _mm256_and_si256(t_1_2_4_5, a0);
        __m256i t_0_1_3_4_5 = _mm256_and_si256(t_1_3_4_5, a0);
        __m256i t_0_2_3_4_5 = _mm256_and_si256(t_2_3_4_5, a0);

        __m256i y0 = _mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(all1, a1), t_0_1), a2), t_0_2), t_1_2), a3), t_0_1_3), t_0_2_3), t_0_1_2_3), a4), t_0_1_4), t_1_2_4), t_0_3_4), t_0_5), t_1_5), t_0_1_2_5), t_3_5), t_1_3_5), t_0_1_3_5), t_0_2_3_5), t_0_1_4_5), t_2_4_5), t_0_2_4_5), t_1_2_4_5), t_3_4_5), t_1_3_4_5), t_0_1_3_4_5), t_0_2_3_4_5);
        __m256i y1 = _mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(a1, t_1_2), a3), t_1_3), a4), t_0_4), t_0_1_4), t_0_2_4), t_0_1_2_4), t_0_3_4), t_0_2_3_4), a5), t_1_5), t_0_1_5), t_2_5), t_0_2_5), t_1_2_5), t_0_1_2_5), t_1_3_5), t_1_4_5), t_0_1_2_4_5), t_1_3_4_5), t_0_1_3_4_5);
        __m256i y2 = _mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(all1, a0), a1), a2), t_1_3), a4), t_1_4), t_2_4), t_1_2_4), t_3_4), t_0_1_5), t_2_5), t_0_2_5), t_3_5), t_1_3_5), t_0_1_3_5), t_2_3_5), t_0_2_3_5), t_1_4_5), t_2_4_5), t_1_2_4_5), t_3_4_5), t_2_3_4_5), t_0_2_3_4_5);
        __m256i y3 = _mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(all1, a0), a1), t_0_2), t_0_1_2), a3), t_2_3), t_0_2_3), t_0_4), t_1_4), t_0_1_4), t_2_4), t_0_2_4), t_1_2_4), t_2_3_4), t_0_2_3_4), a5), t_0_5), t_0_1_5), t_1_2_5), t_0_1_2_5), t_0_3_5), t_1_3_5), t_2_3_5), t_0_2_3_5), t_0_2_4_5), t_0_1_2_4_5), t_0_3_4_5), t_0_1_3_4_5), t_2_3_4_5), t_0_2_3_4_5);

        S_out[28] = y3;
        S_out[29] = y2;
        S_out[30] = y1;
        S_out[31] = y0;
    }

    // P‑permutacja: 32 bit‑plane’ów S_out → F[0..31]
    for (int i = 0; i < 32; ++i) {
        int src = DES_P[i] - 1;
        F[i] = S_out[src];
    }
}


void TDES_Bitslice_AVX2::DES_encrypt_bitslice_block(BitSliceState& bs, int key_index) const {
    IP_bitslice(bs);
    DES_encrypt_bitslice(bs, key_index);

    // swap L/R
    for (int i = 0; i < 32; ++i) {
        __m256i tmp = bs[i];
        bs[i] = bs[32 + i];
        bs[32 + i] = tmp;
    }

    FP_bitslice(bs);
}

void TDES_Bitslice_AVX2::DES_decrypt_bitslice_block(BitSliceState& bs, int key_index) const {
    IP_bitslice(bs);
    DES_decrypt_bitslice(bs, key_index);

    // swap L/R
    for (int i = 0; i < 32; ++i) {
        __m256i tmp = bs[i];
        bs[i] = bs[32 + i];
        bs[32 + i] = tmp;
    }

    FP_bitslice(bs);
}


void TDES_Bitslice_AVX2::DES_encrypt_bitslice(BitSliceState& bs, int key_index) const {
    for (int round = 0; round < 16; ++round) {
        BitSliceState F{};
        feistel_bitslice(bs, F, round, key_index);

        for (int i = 0; i < 32; ++i) {
            __m256i L = bs[i];
            __m256i R = bs[32 + i];
            __m256i Fbit = F[i];
            __m256i newR = xor256(L, Fbit);
            bs[i] = R;
            bs[32 + i] = newR;
        }
    }
}

void TDES_Bitslice_AVX2::DES_decrypt_bitslice(BitSliceState& bs, int key_index) const {
    for (int round = 15; round >= 0; --round) {
        BitSliceState F{};
        feistel_bitslice(bs, F, round, key_index);

        for (int i = 0; i < 32; ++i) {
            __m256i L = bs[i];
            __m256i R = bs[32 + i];
            __m256i Fbit = F[i];
            __m256i newR = xor256(L, Fbit);
            bs[i] = R;
            bs[32 + i] = newR;
        }
    }
}




void TDES_Bitslice_AVX2::TripleDES_encrypt_bitslice(BitSliceState& bs) const {
    uint32_t R = extract_block_from_bitslice(bs); 
    DES_encrypt_bitslice_block(bs, 0);
    DES_decrypt_bitslice_block(bs, 1);
    DES_encrypt_bitslice_block(bs, 2);

}

void TDES_Bitslice_AVX2::TripleDES_decrypt_bitslice(BitSliceState& bs) const {
    DES_decrypt_bitslice_block(bs, 2);
    DES_encrypt_bitslice_block(bs, 1);
    DES_decrypt_bitslice_block(bs, 0);
}

void TDES_Bitslice_AVX2::encryptBlock(const uint8_t* in, uint8_t* out) const {
    encryptBlock_bitslice_single(in, out);
}

void TDES_Bitslice_AVX2::decryptBlock(const uint8_t* in, uint8_t* out) const {
    decryptBlock_bitslice_single(in, out);
}

void TDES_Bitslice_AVX2::encryptBlock_bitslice_single(const uint8_t* in, uint8_t* out) const {
    if (!in || !out) return;

    // 1 blok → 32 kopie
    alignas(32) uint8_t in32[BS_BLOCKS * BLOCK_SIZE];
    for (int i = 0; i < BS_BLOCKS; ++i)
        memcpy(in32 + i * BLOCK_SIZE, in, BLOCK_SIZE);

    BitSliceState bs{};
    blocks_to_bitslice(in32, BS_BLOCKS, bs);

    TripleDES_encrypt_bitslice(bs);

    alignas(32) uint8_t out32[BS_BLOCKS * BLOCK_SIZE];
    bitslice_to_blocks(bs, out32, BS_BLOCKS);

    memcpy(out, out32, BLOCK_SIZE); // pierwszy blok
}

void TDES_Bitslice_AVX2::decryptBlock_bitslice_single(const uint8_t* in, uint8_t* out) const {
    if (!in || !out) return;

    alignas(32) uint8_t in32[BS_BLOCKS * BLOCK_SIZE];
    for (int i = 0; i < BS_BLOCKS; ++i)
        memcpy(in32 + i * BLOCK_SIZE, in, BLOCK_SIZE);

    BitSliceState bs{};
    blocks_to_bitslice(in32, BS_BLOCKS, bs);

    TripleDES_decrypt_bitslice(bs);

    alignas(32) uint8_t out32[BS_BLOCKS * BLOCK_SIZE];
    bitslice_to_blocks(bs, out32, BS_BLOCKS);

    memcpy(out, out32, BLOCK_SIZE);
}



static void dump_bitslice_state(const char* label, const TDES_Bitslice_AVX2::BitSliceState& bs)
{
    uint32_t hi[32];
    uint32_t lo[32];

    for (int bit = 0; bit < 32; ++bit) {
        hi[bit] = uint32_t(_mm256_cvtsi256_si32(bs[bit]));
        lo[bit] = uint32_t(_mm256_cvtsi256_si32(bs[bit + 32]));
    }

    uint32_t hi_copy[32];
    uint32_t lo_copy[32];
    memcpy(hi_copy, hi, sizeof(hi));
    memcpy(lo_copy, lo, sizeof(lo));

    transpose_32x32(hi_copy);
    transpose_32x32(lo_copy);

    std::cout << "=== " << label << " ===\n";
    for (int i = 0; i < 32; ++i) {
        uint64_t v = (uint64_t(hi_copy[i]) << 32) | uint64_t(lo_copy[i]);
        std::cout << "block[" << i << "] = 0x"
            << std::hex << std::setw(16) << std::setfill('0') << v
            << std::dec << "\n";
    }
}

void TDES_Bitslice_AVX2::debug_des_rounds(const uint8_t* in) const
{
    BitSliceState bs{};
    blocks_to_bitslice(in, BS_BLOCKS, bs);

    dump_bitslice_state("After load (before IP)", bs);

    IP_bitslice(bs);
    dump_bitslice_state("After IP", bs);

    for (int r = 0; r < 16; ++r) {
        BitSliceState L = bs;
        BitSliceState R = bs;

        BitSliceState F{};
        feistel_bitslice(bs, F, r, 0);

        for (int i = 0; i < 32; ++i) {
            R[32 + i] = xor256(L[i], F[i]);
        }

        for (int i = 0; i < 32; ++i) {
            R[i] = L[32 + i];
        }

        bs = R;

        char label[64];
        sprintf(label, "After round %d", r + 1);
        dump_bitslice_state(label, bs);
    }

    FP_bitslice(bs);
    dump_bitslice_state("After FP", bs);
}

uint8_t TDES_Bitslice_AVX2::scalar_S(int box, uint8_t x) const{
    int row = ((x & 0b100000) >> 4) | (x & 1);
    int col = (x >> 1) & 0b1111;
    return SBOXES[box][row * 16 + col];
}

void TDES_Bitslice_AVX2::bitslice_S(int box, const uint64_t in[6], uint64_t out[4]) const{
    out[0] = out[1] = out[2] = out[3] = 0;

    for (int b = 0; b < 64; b++) {
        uint8_t six =
            ((in[0] >> b) & 1) |
            (((in[1] >> b) & 1) << 1) |
            (((in[2] >> b) & 1) << 2) |
            (((in[3] >> b) & 1) << 3) |
            (((in[4] >> b) & 1) << 4) |
            (((in[5] >> b) & 1) << 5);

        uint8_t s = scalar_S(box, six);

        if (s & 1) out[0] |= (1ULL << b);
        if (s & 2) out[1] |= (1ULL << b);
        if (s & 4) out[2] |= (1ULL << b);
        if (s & 8) out[3] |= (1ULL << b);
    }
}

const uint8_t TDES_Bitslice_AVX2::SBOXES[8][64] = {
    {
        14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
        0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
        4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
        15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13
    },
    {
        15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
        3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
        0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
        13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9
    },
    {
        10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
        13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
        13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
        1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12
    },
    {
        7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
        13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
        10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
        3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14
    },
    {
        2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
        14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
        4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
        11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3
    },
    {
        12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
        10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
        9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
        4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13
    },
    {
        4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
        13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
        1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
        6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12
    },
    {
        13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
        1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
        7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
        2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11
    }
};

uint64_t TDES_Bitslice_AVX2::DES_encrypt_scalar_block(uint64_t block, int key_index) const {
    // IP
    uint64_t ip = 0;
    for (int i = 0; i < 64; ++i) {
        uint64_t bit = (block >> (64 - DES_IP[i])) & 1ULL;
        ip |= bit << (63 - i);
    }

    uint32_t L = uint32_t(ip >> 32);
    uint32_t R = uint32_t(ip & 0xFFFFFFFFu);

    for (int round = 0; round < 16; ++round) {
        uint32_t F = feistel_scalar(R, round, key_index);
        uint32_t newL = R;
        uint32_t newR = L ^ F;
        L = newL;
        R = newR;
    }

    // swap L/R
    uint64_t pre_fp = (uint64_t(R) << 32) | uint64_t(L);

    // FP
    uint64_t out = 0;
    for (int i = 0; i < 64; ++i) {
        uint64_t bit = (pre_fp >> (64 - DES_FP[i])) & 1ULL;
        out |= bit << (63 - i);
    }

    return out;
}
void TDES_Bitslice_AVX2::test_des_single(const TDES_Bitslice_AVX2& tdes, uint64_t block) {
    // scalar lokalny
    uint64_t C_scalar = DES_encrypt_scalar_block(block, 0);

    // bitslice
    TDES_Bitslice_AVX2::BitSliceState bs{};
    load_block_to_bitslice(bs, block);
    DES_encrypt_bitslice_block(bs, 0);
    uint64_t C_bitslice = extract_block_from_bitslice(bs);

    printf("scalar : %016llx\n", (unsigned long long)C_scalar);
    printf("bitslice: %016llx\n", (unsigned long long)C_bitslice);
}


void TDES_Bitslice_AVX2::load_block_to_bitslice(BitSliceState& bs, uint64_t block)
{
    for (int i = 0; i < 64; ++i) {
        uint64_t bit = (block >> (63 - i)) & 1;
        uint64_t lane0 = bit ? ~0ULL : 0ULL;
        bs[i] = _mm256_set_epi64x(0, 0, 0, lane0);
    }
}

uint64_t TDES_Bitslice_AVX2::extract_block_from_bitslice(const BitSliceState& bs)
{
    uint64_t block = 0;
    for (int i = 0; i < 64; ++i) {
        __m256i v = bs[i];
        alignas(32) uint64_t tmp[4];
        _mm256_storeu_si256((__m256i*)tmp, v);
        uint64_t lane0 = tmp[0];
        uint64_t bit = lane0 & 1;
        block |= bit << (63 - i);
    }
    return block;
}

uint32_t TDES_Bitslice_AVX2::feistel_scalar(uint32_t R, int round, int key_index) const
{
    uint64_t E = 0;
    for (int i = 0; i < 48; ++i) {
        int src = DES_E[i] - 1;
        uint64_t bit = (R >> (31 - src)) & 1;
        E |= bit << (47 - i);
    }
    uint64_t key{};
	if (key_index == 0)
        key = subkeys1_scalar[round];
    else if(key_index == 1)
        key = subkeys2_scalar[round];
    else if(key_index == 2)
        key = subkeys3_scalar[round];
    else
        throw std::invalid_argument("feistel_scalar: invalid key_index");
    uint64_t K = key & 0xFFFFFFFFFFFFULL;
    uint64_t X = E ^ K;

    uint32_t S_out = 0;
    for (int s = 0; s < 8; ++s) {
        uint8_t six = (X >> (42 - 6 * s)) & 0x3F;
        uint8_t v = scalar_S(s, six);
        S_out |= uint32_t(v) << (28 - 4 * s);
    }

    uint32_t F = 0;
    for (int i = 0; i < 32; ++i) {
        int src = DES_P[i] - 1;
        uint32_t bit = (S_out >> (31 - src)) & 1;
        F |= bit << (31 - i);
    }

    return F;
}
uint32_t TDES_Bitslice_AVX2::extract_L32_lane0(const BitSliceState& bs)
{
    uint32_t L = 0;
    for (int i = 0; i < 32; ++i) {
        __m256i v = bs[i];   // lewa polowa
        alignas(32) uint64_t tmp[4];
        _mm256_storeu_si256((__m256i*)tmp, v);
        uint64_t lane0 = tmp[0];
        uint32_t bit = lane0 & 1;
        L |= bit << (31 - i);
    }
    return L;
}


uint32_t TDES_Bitslice_AVX2::extract_R32_lane0(const BitSliceState& bs)
{
    uint32_t R = 0;
    for (int i = 0; i < 32; ++i) {
        __m256i v = bs[32 + i]; 
        alignas(32) uint64_t tmp[4];
        _mm256_storeu_si256((__m256i*)tmp, v);
        uint64_t lane0 = tmp[0];
        uint32_t bit = lane0 & 1;
        R |= bit << (31 - i);
    }
    return R;
}

uint32_t TDES_Bitslice_AVX2::extract_F32_lane0(const BitSliceState& F)
{
    uint32_t out = 0;
    for (int i = 0; i < 32; ++i) {
        __m256i v = F[i];
        alignas(32) uint64_t tmp[4];
        _mm256_storeu_si256((__m256i*)tmp, v);
        uint64_t lane0 = tmp[0];
        uint32_t bit = lane0 & 1;
        out |= bit << (31 - i);
    }
    return out;
}

uint64_t TDES_Bitslice_AVX2::subkey_scalar_from_bitslice(int key_index, int round) const
{
    uint64_t K = 0;
    for (int i = 0; i < 48; ++i) {
        __m256i v = subkeys_bitslice[key_index][round][i];
        alignas(32) uint64_t tmp[4];
        _mm256_storeu_si256((__m256i*)tmp, v);
        uint64_t lane0 = tmp[0];
        uint64_t bit = lane0 & 1;
        K |= bit << (47 - i);
    }
    return K;
}

FeistelTrace TDES_Bitslice_AVX2::feistel_scalar_trace(uint32_t R, int round, int key_index) const
{
    FeistelTrace t{};

    // E: 32 -> 48
    uint64_t E = 0;
    for (int i = 0; i < 48; ++i) {
        int src = DES_E[i] - 1;
        uint64_t bit = (R >> (31 - src)) & 1;
        E |= bit << (47 - i);
    }
    t.E = E;

    // XOR z podkluczem
    uint64_t K = subkey_scalar_from_bitslice(key_index, round);
    uint64_t X = E ^ K;
    t.X = X;

    // S-boksy
    uint32_t S_out = 0;
    for (int s = 0; s < 8; ++s) {
        uint8_t six = (X >> (42 - 6 * s)) & 0x3F;
        uint8_t v = scalar_S(s, six);
        S_out |= uint32_t(v) << (28 - 4 * s);
    }
    t.S = S_out;

    // P
    uint32_t F = 0;
    for (int i = 0; i < 32; ++i) {
        int src = DES_P[i] - 1;
        uint32_t bit = (S_out >> (31 - src)) & 1;
        F |= bit << (31 - i);
    }
    t.P = F;

    return t;
}

FeistelTrace TDES_Bitslice_AVX2::feistel_bitslice_trace_lane0(const BitSliceState& bs_R,
    int round,
    int key_index) const
{
    FeistelTrace t{};
    __m256i Ebits[48];

    // E w bitslice
    for (int i = 0; i < 48; ++i) {
        int src = DES_E[i] - 1;
        Ebits[i] = bs_R[32 + src];
    }

    // E -> scalar lane0
    uint64_t E = 0;
    for (int i = 0; i < 48; ++i) {
        alignas(32) uint64_t tmp[4];
        _mm256_storeu_si256((__m256i*)tmp, Ebits[i]);
        uint64_t lane0 = tmp[0];
        uint64_t bit = lane0 & 1;
        E |= bit << (47 - i);
    }
    t.E = E;

    // XOR z podkluczem bitslice
    for (int i = 0; i < 48; ++i) {
        Ebits[i] = xor256(Ebits[i], subkeys_bitslice[key_index][round][i]);
    }

    // X -> scalar lane0
    uint64_t X = 0;
    for (int i = 0; i < 48; ++i) {
        alignas(32) uint64_t tmp[4];
        _mm256_storeu_si256((__m256i*)tmp, Ebits[i]);
        uint64_t lane0 = tmp[0];
        uint64_t bit = lane0 & 1;
        X |= bit << (47 - i);
    }
    t.X = X;

    // DEBUG: porownanie six_scalar vs six_bitslice dla lane0
    for (int s = 0; s < 8; ++s) {
        // scalar six z X (dokladnie tak, jak w feistel_scalar)
        uint8_t six_scalar = (uint8_t)((X >> (42 - 6 * s)) & 0x3F);

        // bitslice: wyciagamy 6 bit‑plane’ow dla tego S‑boksa
        __m256i a0 = Ebits[6 * s + 0];
        __m256i a1 = Ebits[6 * s + 1];
        __m256i a2 = Ebits[6 * s + 2];
        __m256i a3 = Ebits[6 * s + 3];
        __m256i a4 = Ebits[6 * s + 4];
        __m256i a5 = Ebits[6 * s + 5];

        alignas(32) uint64_t tmp0[4], tmp1[4], tmp2[4], tmp3[4], tmp4[4], tmp5[4];
        _mm256_storeu_si256((__m256i*)tmp0, a0);
        _mm256_storeu_si256((__m256i*)tmp1, a1);
        _mm256_storeu_si256((__m256i*)tmp2, a2);
        _mm256_storeu_si256((__m256i*)tmp3, a3);
        _mm256_storeu_si256((__m256i*)tmp4, a4);
        _mm256_storeu_si256((__m256i*)tmp5, a5);

        // b = 0 -> pierwszy blok (bit 0 w lane0)
        int b = 0;
        uint8_t six_bitslice =
            (((tmp0[0] >> b) & 1) << 5) |
            (((tmp1[0] >> b) & 1) << 4) |
            (((tmp2[0] >> b) & 1) << 3) |
            (((tmp3[0] >> b) & 1) << 2) |
            (((tmp4[0] >> b) & 1) << 1) |
            (((tmp5[0] >> b) & 1) << 0);


        if (six_scalar != six_bitslice) {
            printf("SBOX %d: six mismatch: scalar=%02x bitslice=%02x\n",
                s, six_scalar, six_bitslice);
            // mozesz tu zrobic break/return, zeby nie spamowac
        }
    }


    // S-boksy bitslice (jak masz teraz), ale tylko lane0 wynikow
    __m256i S_out_bits[32];

    for (int s = 0; s < 8; ++s) {
        __m256i a0 = Ebits[6 * s + 0];
        __m256i a1 = Ebits[6 * s + 1];
        __m256i a2 = Ebits[6 * s + 2];
        __m256i a3 = Ebits[6 * s + 3];
        __m256i a4 = Ebits[6 * s + 4];
        __m256i a5 = Ebits[6 * s + 5];

        __m256i y0 = _mm256_setzero_si256();
        __m256i y1 = _mm256_setzero_si256();
        __m256i y2 = _mm256_setzero_si256();
        __m256i y3 = _mm256_setzero_si256();

        alignas(32) uint64_t tmp0[4], tmp1[4], tmp2[4], tmp3[4], tmp4[4], tmp5[4];
        _mm256_storeu_si256((__m256i*)tmp0, a0);
        _mm256_storeu_si256((__m256i*)tmp1, a1);
        _mm256_storeu_si256((__m256i*)tmp2, a2);
        _mm256_storeu_si256((__m256i*)tmp3, a3);
        _mm256_storeu_si256((__m256i*)tmp4, a4);
        _mm256_storeu_si256((__m256i*)tmp5, a5);

        auto or_bit = [](__m256i v, int lane, int bit) {
            uint64_t mask = 1ULL << bit;
            __m256i lane_mask = _mm256_set_epi64x(
                lane == 3 ? mask : 0,
                lane == 2 ? mask : 0,
                lane == 1 ? mask : 0,
                lane == 0 ? mask : 0
            );
            return _mm256_or_si256(v, lane_mask);
            };

        for (int lane = 0; lane < 4; ++lane) {
            uint64_t w0 = tmp0[lane];
            uint64_t w1 = tmp1[lane];
            uint64_t w2 = tmp2[lane];
            uint64_t w3 = tmp3[lane];
            uint64_t w4 = tmp4[lane];
            uint64_t w5 = tmp5[lane];

            for (int b = 0; b < 64; ++b) {
                uint8_t six =
                    (((w0 >> b) & 1) << 5) |
                    (((w1 >> b) & 1) << 4) |
                    (((w2 >> b) & 1) << 3) |
                    (((w3 >> b) & 1) << 2) |
                    (((w4 >> b) & 1) << 1) |
                    (((w5 >> b) & 1) << 0);

                uint8_t v = scalar_S(s, six);

                if (v & 0x8) y0 = or_bit(y0, lane, b);
                if (v & 0x4) y1 = or_bit(y1, lane, b);
                if (v & 0x2) y2 = or_bit(y2, lane, b);
                if (v & 0x1) y3 = or_bit(y3, lane, b);
            }

        }

        S_out_bits[4 * s + 0] = y0;
        S_out_bits[4 * s + 1] = y1;
        S_out_bits[4 * s + 2] = y2;
        S_out_bits[4 * s + 3] = y3;
    }

    // S -> scalar lane0
    uint32_t S = 0;
    for (int i = 0; i < 32; ++i) {
        alignas(32) uint64_t tmp[4];
        _mm256_storeu_si256((__m256i*)tmp, S_out_bits[i]);
        uint64_t lane0 = tmp[0];
        uint32_t bit = lane0 & 1;
        S |= bit << (31 - i);
    }
    t.S = S;

    // P w bitslice
    __m256i Fbits[32];
    for (int i = 0; i < 32; ++i) {
        int src = DES_P[i] - 1;
        Fbits[i] = S_out_bits[src];
    }

    // P -> scalar lane0
    uint32_t F = 0;
    for (int i = 0; i < 32; ++i) {
        alignas(32) uint64_t tmp[4];
        _mm256_storeu_si256((__m256i*)tmp, Fbits[i]);
        uint64_t lane0 = tmp[0];
        uint32_t bit = lane0 & 1;
        F |= bit << (31 - i);
    }
    t.P = F;

    return t;
}

void TDES_Bitslice_AVX2::test_feistel_round(uint32_t R, int round, int key_index) const
{
    // scalar
    FeistelTrace ts = feistel_scalar_trace(R, round, key_index);

    // bitslice: zbuduj bs z R tylko w prawej polowie lane0
    BitSliceState bs{};
    // lewa polowa = 0
    for (int i = 0; i < 32; ++i) {
        bs[i] = _mm256_setzero_si256();
    }
    // prawa polowa = R
    for (int i = 0; i < 32; ++i) {
        uint32_t bit = (R >> (31 - i)) & 1;
        uint64_t lane0 = bit ? ~0ULL : 0ULL;
        bs[32 + i] = _mm256_set_epi64x(0, 0, 0, lane0);
    }

    FeistelTrace tb = feistel_bitslice_trace_lane0(bs, round, key_index);



    printf("ROUND %d, R=%08x\n", round, R);
    printf("  E: scalar=%012llx bitslice=%012llx\n",
        (unsigned long long)ts.E, (unsigned long long)tb.E);
    printf("  X: scalar=%012llx bitslice=%012llx\n",
        (unsigned long long)ts.X, (unsigned long long)tb.X);
    printf("  S: scalar=%08x bitslice=%08x\n",
        ts.S, tb.S);
    printf("  P: scalar=%08x bitslice=%08x\n",
        ts.P, tb.P);
}
