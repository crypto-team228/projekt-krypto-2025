#include "cipher/TDES/tdes.hpp"
#include <cstdint>

// ================= Klasyczne tablice DES =================

const int initialPermutation[64] = {
    58, 50, 42, 34, 26, 18, 10,  2,
    60, 52, 44, 36, 28, 20, 12,  4,
    62, 54, 46, 38, 30, 22, 14,  6,
    64, 56, 48, 40, 32, 24, 16,  8,
    57, 49, 41, 33, 25, 17,  9,  1,
    59, 51, 43, 35, 27, 19, 11,  3,
    61, 53, 45, 37, 29, 21, 13,  5,
    63, 55, 47, 39, 31, 23, 15,  7
};

const int finalPermutation[64] = {
    40,  8, 48, 16, 56, 24, 64, 32,
    39,  7, 47, 15, 55, 23, 63, 31,
    38,  6, 46, 14, 54, 22, 62, 30,
    37,  5, 45, 13, 53, 21, 61, 29,
    36,  4, 44, 12, 52, 20, 60, 28,
    35,  3, 43, 11, 51, 19, 59, 27,
    34,  2, 42, 10, 50, 18, 58, 26,
    33,  1, 41,  9, 49, 17, 57, 25
};

const int expansionD[48] = {
    32,  1,  2,  3,  4,  5,
     4,  5,  6,  7,  8,  9,
     8,  9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32,  1
};

const int straightPermutation[32] = {
    16,  7, 20, 21,
    29, 12, 28, 17,
     1, 15, 23, 26,
     5, 18, 31, 10,
     2,  8, 24, 14,
    32, 27,  3,  9,
    19, 13, 30,  6,
    22, 11,  4, 25
};

const int parityBitDropTable[56] = {
    57, 49, 41, 33, 25, 17,  9,
     1, 58, 50, 42, 34, 26, 18,
    10,  2, 59, 51, 43, 35, 27,
    19, 11,  3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
     7, 62, 54, 46, 38, 30, 22,
    14,  6, 61, 53, 45, 37, 29,
    21, 13,  5, 28, 20, 12,  4
};

const int keyCompressionTable[48] = {
    14, 17, 11, 24,  1,  5,
     3, 28, 15,  6, 21, 10,
    23, 19, 12,  4, 26,  8,
    16,  7, 27, 20, 13,  2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32
};

const int keyShiftTable[16] = {
    1, 1, 2, 2,
    2, 2, 2, 2,
    1, 2, 2, 2,
    2, 2, 2, 1
};

const uint8_t sbox[8][4][16] = {
    {
        {14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7},
        { 0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8},
        { 4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0},
        {15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13}
    },
    {
        {15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10},
        { 3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5},
        { 0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15},
        {13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9}
    },
    {
        {10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8},
        {13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1},
        {13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7},
        { 1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12}
    },
    {
        { 7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15},
        {13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9},
        {10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4},
        { 3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14}
    },
    {
        { 2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9},
        {14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6},
        { 4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14},
        {11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3}
    },
    {
        {12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11},
        {10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8},
        { 9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6},
        { 4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13}
    },
    {
        { 4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1},
        {13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6},
        { 1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2},
        { 6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12}
    },
    {
        {13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7},
        { 1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2},
        { 7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8},
        { 2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11}
    }
};

// ================= LUT-y =================

// IP/FP: 8 bajtów wejścia → 8× lookup → OR
uint64_t ip_lut[8][256];
uint64_t fp_lut[8][256];

// E: 4 bajty (32 bity) → 48 bitów
uint64_t e_lut[4][256];

// P: 4 bajty (32 bity) → 32 bity
uint32_t p_lut[4][256];

// PC-1: 8 bajtów (64 bity) → 56 bitów
uint64_t pc1_lut[8][256];

// PC-2: 7 bajtów (56 bity) → 48 bitów
uint64_t pc2_lut[7][256];

// S-box LUT: 6-bit → 4-bit
uint8_t sbox_lut[8][64];

// ================= Helper do permutacji pojedynczego bajtu =================

static uint64_t permute_byte_to_u64(const int* table, int tableLen, int byteIndex, uint8_t value)
{
    uint64_t out = 0;
    int bitBase = byteIndex * 8; // bity 0..7, 8..15, ...
    for (int i = 0; i < tableLen; ++i) {
        int src = table[i] - 1;
        int srcByte = src / 8;
        int srcBit = src % 8;
        if (srcByte != byteIndex)
            continue;
        uint8_t bit = (value >> (7 - srcBit)) & 0x1;
        if (bit) {
            int dstBit = i;
            out |= (uint64_t(1) << (63 - dstBit));
        }
    }
    return out;
}

static uint64_t permute_byte_to_u56(const int* table, int tableLen, int byteIndex, uint8_t value)
{
    uint64_t out = 0;
    for (int i = 0; i < tableLen; ++i) {
        int src = table[i] - 1;
        int srcByte = src / 8;
        int srcBit = src % 8;
        if (srcByte != byteIndex)
            continue;
        uint8_t bit = (value >> (7 - srcBit)) & 0x1;
        if (bit) {
            int dstBit = i;
            out |= (uint64_t(1) << (55 - dstBit));
        }
    }
    return out;
}

static uint64_t permute_byte_to_u48(const int* table, int tableLen, int byteIndex, uint8_t value)
{
    uint64_t out = 0;
    for (int i = 0; i < tableLen; ++i) {
        int src = table[i] - 1;
        int srcByte = src / 8;
        int srcBit = src % 8;
        if (srcByte != byteIndex)
            continue;
        uint8_t bit = (value >> (7 - srcBit)) & 0x1;
        if (bit) {
            int dstBit = i;
            out |= (uint64_t(1) << (47 - dstBit));
        }
    }
    return out;
}

static uint32_t permute_byte_to_u32(const int* table, int tableLen, int byteIndex, uint8_t value)
{
    uint32_t out = 0;
    for (int i = 0; i < tableLen; ++i) {
        int src = table[i] - 1;
        int srcByte = src / 8;
        int srcBit = src % 8;
        if (srcByte != byteIndex)
            continue;
        uint8_t bit = (value >> (7 - srcBit)) & 0x1;
        if (bit) {
            int dstBit = i;
            out |= (uint32_t(1) << (31 - dstBit));
        }
    }
    return out;
}

// ================= Inicjalizacja LUT-ów =================

struct DESLutInitializer {
    DESLutInitializer() {
        // IP LUT
        for (int b = 0; b < 8; ++b) {
            for (int v = 0; v < 256; ++v) {
                ip_lut[b][v] = permute_byte_to_u64(initialPermutation, 64, b, static_cast<uint8_t>(v));
                fp_lut[b][v] = permute_byte_to_u64(finalPermutation, 64, b, static_cast<uint8_t>(v));
            }
        }

        // PC-1 LUT (64 -> 56)
        for (int b = 0; b < 8; ++b) {
            for (int v = 0; v < 256; ++v) {
                pc1_lut[b][v] = permute_byte_to_u56(parityBitDropTable, 56, b, static_cast<uint8_t>(v));
            }
        }

        // PC-2 LUT (56 -> 48) – 7 bajtów
        for (int b = 0; b < 7; ++b) {
            for (int v = 0; v < 256; ++v) {
                pc2_lut[b][v] = permute_byte_to_u48(keyCompressionTable, 48, b, static_cast<uint8_t>(v));
            }
        }

        // E LUT (32 -> 48) – 4 bajty
        for (int b = 0; b < 4; ++b) {
            for (int v = 0; v < 256; ++v) {
                e_lut[b][v] = permute_byte_to_u48(expansionD, 48, b, static_cast<uint8_t>(v));
            }
        }

        // P LUT (32 -> 32) – 4 bajty
        for (int b = 0; b < 4; ++b) {
            for (int v = 0; v < 256; ++v) {
                p_lut[b][v] = permute_byte_to_u32(straightPermutation, 32, b, static_cast<uint8_t>(v));
            }
        }

        // S-box LUT
        for (int box = 0; box < 8; ++box) {
            for (int v = 0; v < 64; ++v) {
                int row = ((v & 0x20) >> 4) | (v & 0x01); // b0,b5
                int col = (v >> 1) & 0x0F;                // b1..b4
                sbox_lut[box][v] = sbox[box][row][col];
            }
        }
    }
} desLutInitializerInstance;
