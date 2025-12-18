#include "AES/aes.hpp"
#include <vector>



// ######################################################## BASE AES ########################################################


AES::AES(const Key128 &key)
{
    keyExpansion(key);
}

// GF(2^8) multiply by 2
inline uint8_t AES::xtime(uint8_t x)
{
    return (uint8_t)((x << 1) ^ ((x & 0x80) ? 0x1b : 0x00));
}

void AES::addRoundKey(State &st, const State &key) const
{
    for (int i = 0; i < 16; i++)
        st[i] ^= key[i];
}

// --- Key expansion helper functions ---
uint8_t AES::Rcon(int i)
{
    static uint8_t rcon[11] = {
        0x00,
        0x01, 0x02, 0x04, 0x08, 0x10,
        0x20, 0x40, 0x80, 0x1B, 0x36};
    return rcon[i];
}

void AES::rotWord(uint8_t *w)
{
    uint8_t tmp = w[0];
    w[0] = w[1];
    w[1] = w[2];
    w[2] = w[3];
    w[3] = tmp;
}

void AES::subWord(uint8_t *w)
{
    for (int i = 0; i < 4; i++)
        w[i] = sbox[w[i]];
}

// --- Key Expansion (AES-128) ---
void AES::keyExpansion(const Key128& key)
{
    uint8_t w[44][4];

    // Copy original key (first 4 words)
    for (int i = 0; i < 4; i++)
    {
        w[i][0] = key[4 * i];
        w[i][1] = key[4 * i + 1];
        w[i][2] = key[4 * i + 2];
        w[i][3] = key[4 * i + 3];
    }

    // Generate 44 words (11 round keys * 4 words)
    for (int i = 4; i < 44; i++)
    {
        uint8_t tmp[4];
        for (int j = 0; j < 4; j++)
            tmp[j] = w[i - 1][j];

        if (i % 4 == 0)
        {
            rotWord(tmp);
            subWord(tmp);
            tmp[0] ^= Rcon(i / 4);
        }

        for (int j = 0; j < 4; j++)
            w[i][j] = w[i - 4][j] ^ tmp[j];
    }

    // Copy words into roundKeys
    for (int r = 0; r < 11; r++)
    {
        for (int c = 0; c < 4; c++)
        {
            roundKeys[r][4 * c + 0] = w[4 * r + c][0];
            roundKeys[r][4 * c + 1] = w[4 * r + c][1];
            roundKeys[r][4 * c + 2] = w[4 * r + c][2];
            roundKeys[r][4 * c + 3] = w[4 * r + c][3];
        }
    }
};


// ##################################################### ENCODE AES ########################################################


EncodeAES::EncodeAES(const Key128 &key) : AES(key) {}

// Encrypt 16-byte block (ECB mode)
void EncodeAES::encryptBlock(State &state) const
{
    addRoundKey(state, roundKeys[0]);

    for (int round = 1; round <= 9; round++)
    {
        subBytes(state);
        shiftRows(state);
        mixColumns(state);
        addRoundKey(state, roundKeys[round]);
    }

    // Final round (no MixColumns)
    subBytes(state);
    shiftRows(state);
    addRoundKey(state, roundKeys[10]);
}

void EncodeAES::encryptBlocks(std::vector<AES::State> &blocks) const
{
    for (auto& block : blocks)
    {
        encryptBlock(block);
    }
};


// --- EncodeAES forward operations ---
void EncodeAES::subBytes(State &st) const
{
    for (auto &b : st)
        b = sbox[b];
}

void EncodeAES::shiftRows(State &st) const
{
    State tmp = st;

    // Row 0 unchanged
    tmp[0] = st[0];
    tmp[4] = st[4];
    tmp[8] = st[8];
    tmp[12] = st[12];

    // Row 1 shift left 1
    tmp[1] = st[5];
    tmp[5] = st[9];
    tmp[9] = st[13];
    tmp[13] = st[1];

    // Row 2 shift left 2
    tmp[2] = st[10];
    tmp[6] = st[14];
    tmp[10] = st[2];
    tmp[14] = st[6];

    // Row 3 shift left 3
    tmp[3] = st[15];
    tmp[7] = st[3];
    tmp[11] = st[7];
    tmp[15] = st[11];

    st = tmp;
}

void EncodeAES::mixColumns(State &st) const
{
    for (int c = 0; c < 4; c++)
    {
        int i = 4 * c;
        uint8_t a0 = st[i], a1 = st[i + 1], a2 = st[i + 2], a3 = st[i + 3];

        st[i] = (uint8_t)(xtime(a0) ^ (xtime(a1) ^ a1) ^ a2 ^ a3);
        st[i + 1] = (uint8_t)(a0 ^ xtime(a1) ^ (xtime(a2) ^ a2) ^ a3);
        st[i + 2] = (uint8_t)(a0 ^ a1 ^ xtime(a2) ^ (xtime(a3) ^ a3));
        st[i + 3] = (uint8_t)((xtime(a0) ^ a0) ^ a1 ^ a2 ^ xtime(a3));
    }
}




// ######################################################## DECODE AES ########################################################


DecodeAES::DecodeAES(const Key128 &key) : AES(key) {}


// Decrypt 16-byte block (ECB mode)
void DecodeAES::decryptBlock(State &state) const
{
    // Start with last round key
    addRoundKey(state, roundKeys[10]);

    // Inverse rounds 9 down to 1
    for (int round = 9; round >= 1; round--)
    {
        invShiftRows(state);
        invSubBytes(state);
        addRoundKey(state, roundKeys[round]);
        invMixColumns(state);
    }

    // Final inverse round (no InvMixColumns)
    invShiftRows(state);
    invSubBytes(state);
    addRoundKey(state, roundKeys[0]);
}

void DecodeAES::decryptBlocks(std::vector<AES::State> &blocks) const
{
    for (auto& block : blocks)
    {
        decryptBlock(block);
    }
}

// GF(2^8) multiply by arbitrary constant (for invMixColumns)
uint8_t DecodeAES::gmul(uint8_t a, uint8_t b)
{
    uint8_t result = 0;
    while (b)
    {
        if (b & 1)
            result ^= a;
        a = xtime(a);
        b >>= 1;
    }
    return result;
}

// --- AES inverse operations (for decryption) ---
void DecodeAES::invSubBytes(State &st) const
{
    for (auto &b : st)
        b = inv_sbox[b];
}

void DecodeAES::invShiftRows(State &st) const
{
    State tmp = st;

    // Row 0 unchanged
    tmp[0] = st[0];
    tmp[4] = st[4];
    tmp[8] = st[8];
    tmp[12] = st[12];

    // Row 1 shift right 1 (inverse of left 1)
    tmp[1] = st[13];
    tmp[5] = st[1];
    tmp[9] = st[5];
    tmp[13] = st[9];

    // Row 2 shift right 2 (inverse of left 2)
    tmp[2] = st[10];
    tmp[6] = st[14];
    tmp[10] = st[2];
    tmp[14] = st[6];

    // Row 3 shift right 3 (inverse of left 3)
    tmp[3] = st[7];
    tmp[7] = st[11];
    tmp[11] = st[15];
    tmp[15] = st[3];

    st = tmp;
}

void DecodeAES::invMixColumns(State &st) const
{
    for (int c = 0; c < 4; c++)
    {
        int i = 4 * c;
        uint8_t a0 = st[i], a1 = st[i + 1], a2 = st[i + 2], a3 = st[i + 3];

        st[i] = gmul(a0, 14) ^ gmul(a1, 11) ^ gmul(a2, 13) ^ gmul(a3, 9);
        st[i + 1] = gmul(a0, 9) ^ gmul(a1, 14) ^ gmul(a2, 11) ^ gmul(a3, 13);
        st[i + 2] = gmul(a0, 13) ^ gmul(a1, 9) ^ gmul(a2, 14) ^ gmul(a3, 11);
        st[i + 3] = gmul(a0, 11) ^ gmul(a1, 13) ^ gmul(a2, 9) ^ gmul(a3, 14);
    }
}

