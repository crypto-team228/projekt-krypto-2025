#include "AES/aes.hpp"
#include <vector>
#include <stdexcept>

AES::AES(const Key128 &key)
{
    keyExpansion(key);
}

void AES::setKey(const std::vector<uint8_t> &key)
{
    if (key.size() != 16)
    {
        throw std::invalid_argument("AES key must be 16 bytes");
    }
    Key128 key128;
    std::copy(key.begin(), key.end(), key128.begin());
    keyExpansion(key128);
}

void AES::setMode(Mode mode)
{
    currentMode = mode;
    if (mode == Mode::GCM)
    {
        initGhashKey();
    }
}

void AES::setIV(const std::vector<uint8_t> &initVector)
{
    if (initVector.size() != 16)
    {
        throw std::invalid_argument("IV must be 16 bytes");
    }
    std::copy(initVector.begin(), initVector.end(), iv.begin());
}

void AES::encrypt(std::vector<uint8_t> &block)
{
    if (block.size() % 16 != 0)
    {
        throw std::invalid_argument("Block size must be multiple of 16 bytes");
    }

    switch (currentMode)
    {
    case Mode::ECB:
        for (size_t i = 0; i < block.size(); i += 16)
        {
            State state;
            std::copy(block.begin() + i, block.begin() + i + 16, state.begin());
            encryptBlock(state);
            std::copy(state.begin(), state.end(), block.begin() + i);
        }
        break;

    case Mode::CBC:
    {
        State currentIV = iv;
        for (size_t i = 0; i < block.size(); i += 16)
        {
            State state;
            std::copy(block.begin() + i, block.begin() + i + 16, state.begin());

            // XOR with IV (or previous ciphertext)
            for (int j = 0; j < 16; j++)
                state[j] ^= currentIV[j];

            encryptBlock(state);
            std::copy(state.begin(), state.end(), block.begin() + i);
            currentIV = state; // Use current ciphertext as next IV
        }
        break;
    }

    case Mode::CTR:
    {
        State counter = iv;
        for (size_t i = 0; i < block.size(); i += 16)
        {
            State keystream = counter;
            encryptBlock(keystream);

            // XOR plaintext with keystream
            for (int j = 0; j < 16; j++)
                block[i + j] ^= keystream[j];

            // Increment counter
            for (int j = 15; j >= 0; j--)
            {
                if (++counter[j] != 0)
                    break;
            }
        }
        break;
    }

    case Mode::GCM:
    {
        // GCM uses 96-bit IV, we'll assume first 12 bytes of iv are the nonce
        if (iv.size() < 12)
        {
            throw std::invalid_argument("GCM requires at least 12-byte IV");
        }

        // Construct J0 = IV || 0^31 || 1
        std::array<uint8_t, 16> j0 = {0};
        std::copy(iv.begin(), iv.begin() + 12, j0.begin());
        j0[15] = 1;

        // Save plaintext for GHASH
        std::vector<uint8_t> plaintext = block;

        // Encrypt using GCTR
        gctrEncrypt(plaintext, block, j0);

        // Prepare data for GHASH: AAD || padding || ciphertext || padding || len(AAD) || len(C)
        std::vector<uint8_t> ghashInput;

        // Add AAD with padding
        ghashInput.insert(ghashInput.end(), aad.begin(), aad.end());
        size_t aadPadding = (16 - (aad.size() % 16)) % 16;
        ghashInput.insert(ghashInput.end(), aadPadding, 0);

        // Add ciphertext with padding
        ghashInput.insert(ghashInput.end(), block.begin(), block.end());
        size_t cPadding = (16 - (block.size() % 16)) % 16;
        ghashInput.insert(ghashInput.end(), cPadding, 0);

        // Add lengths (in bits, big-endian 64-bit)
        uint64_t aadBits = aad.size() * 8;
        uint64_t cBits = block.size() * 8;
        for (int i = 7; i >= 0; i--)
        {
            ghashInput.push_back((aadBits >> (i * 8)) & 0xFF);
        }
        for (int i = 7; i >= 0; i--)
        {
            ghashInput.push_back((cBits >> (i * 8)) & 0xFF);
        }

        // Compute GHASH
        std::array<uint8_t, 16> s;
        ghash(ghashInput, s);

        // Compute authentication tag: T = GCTR(J0, S)
        std::vector<uint8_t> sVec(s.begin(), s.end());
        std::vector<uint8_t> tagVec;
        gctrEncrypt(sVec, tagVec, j0);
        std::copy(tagVec.begin(), tagVec.end(), authTag.begin());

        break;
    }
    }
}

void AES::decrypt(std::vector<uint8_t> &block)
{
    if (block.size() % 16 != 0)
    {
        throw std::invalid_argument("Block size must be multiple of 16 bytes");
    }

    switch (currentMode)
    {
    case Mode::ECB:
        for (size_t i = 0; i < block.size(); i += 16)
        {
            State state;
            std::copy(block.begin() + i, block.begin() + i + 16, state.begin());
            decryptBlock(state);
            std::copy(state.begin(), state.end(), block.begin() + i);
        }
        break;

    case Mode::CBC:
    {
        State currentIV = iv;
        for (size_t i = 0; i < block.size(); i += 16)
        {
            State ciphertext;
            std::copy(block.begin() + i, block.begin() + i + 16, ciphertext.begin());

            State state = ciphertext;
            decryptBlock(state);

            // XOR with IV (or previous ciphertext)
            for (int j = 0; j < 16; j++)
                state[j] ^= currentIV[j];

            std::copy(state.begin(), state.end(), block.begin() + i);
            currentIV = ciphertext; // Use current ciphertext as next IV
        }
        break;
    }

    case Mode::CTR:
    {
        // CTR mode is symmetric - encryption and decryption are the same
        State counter = iv;
        for (size_t i = 0; i < block.size(); i += 16)
        {
            State keystream = counter;
            encryptBlock(keystream);

            // XOR ciphertext with keystream
            for (int j = 0; j < 16; j++)
                block[i + j] ^= keystream[j];

            // Increment counter
            for (int j = 15; j >= 0; j--)
            {
                if (++counter[j] != 0)
                    break;
            }
        }
        break;
    }

    case Mode::GCM:
    {
        // GCM uses 96-bit IV
        if (iv.size() < 12)
        {
            throw std::invalid_argument("GCM requires at least 12-byte IV");
        }

        // Construct J0 = IV || 0^31 || 1
        std::array<uint8_t, 16> j0 = {0};
        std::copy(iv.begin(), iv.begin() + 12, j0.begin());
        j0[15] = 1;

        // Save ciphertext for GHASH verification
        std::vector<uint8_t> ciphertext = block;

        // Prepare data for GHASH: AAD || padding || ciphertext || padding || len(AAD) || len(C)
        std::vector<uint8_t> ghashInput;

        // Add AAD with padding
        ghashInput.insert(ghashInput.end(), aad.begin(), aad.end());
        size_t aadPadding = (16 - (aad.size() % 16)) % 16;
        ghashInput.insert(ghashInput.end(), aadPadding, 0);

        // Add ciphertext with padding
        ghashInput.insert(ghashInput.end(), ciphertext.begin(), ciphertext.end());
        size_t cPadding = (16 - (ciphertext.size() % 16)) % 16;
        ghashInput.insert(ghashInput.end(), cPadding, 0);

        // Add lengths (in bits, big-endian 64-bit)
        uint64_t aadBits = aad.size() * 8;
        uint64_t cBits = ciphertext.size() * 8;
        for (int i = 7; i >= 0; i--)
        {
            ghashInput.push_back((aadBits >> (i * 8)) & 0xFF);
        }
        for (int i = 7; i >= 0; i--)
        {
            ghashInput.push_back((cBits >> (i * 8)) & 0xFF);
        }

        // Compute GHASH
        std::array<uint8_t, 16> s;
        ghash(ghashInput, s);

        // Compute authentication tag: T = GCTR(J0, S)
        std::vector<uint8_t> sVec(s.begin(), s.end());
        std::vector<uint8_t> tagVec;
        gctrEncrypt(sVec, tagVec, j0);
        std::copy(tagVec.begin(), tagVec.end(), authTag.begin());

        // Decrypt using GCTR (same as encryption in CTR mode)
        gctrEncrypt(ciphertext, block, j0);

        break;
    }
    }
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
void AES::keyExpansion(const Key128 &key)
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

// Encrypt 16-byte block (ECB mode)
void AES::encryptBlock(State &state) const
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

// --- AES forward operations ---
void AES::subBytes(State &st) const
{
    for (auto &b : st)
        b = sbox[b];
}

void AES::shiftRows(State &st) const
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

void AES::mixColumns(State &st) const
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

// Decrypt 16-byte block (ECB mode)
void AES::decryptBlock(State &state) const
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

// GF(2^8) multiply by arbitrary constant (for invMixColumns)
uint8_t AES::gmul(uint8_t a, uint8_t b)
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
void AES::invSubBytes(State &st) const
{
    for (auto &b : st)
        b = inv_sbox[b];
}

void AES::invShiftRows(State &st) const
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

void AES::invMixColumns(State &st) const
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

// --- GCM-specific methods ---

void AES::setAAD(const std::vector<uint8_t> &additionalData)
{
    aad = additionalData;
}

std::vector<uint8_t> AES::getTag()
{
    return std::vector<uint8_t>(authTag.begin(), authTag.end());
}

bool AES::verifyTag(const std::vector<uint8_t> &tag)
{
    if (tag.size() != 16)
        return false;

    for (size_t i = 0; i < 16; i++)
    {
        if (tag[i] != authTag[i])
            return false;
    }
    return true;
}

// Initialize GHASH key H = E(K, 0^128)
void AES::initGhashKey()
{
    ghashKey.fill(0);
    State state = {0};
    encryptBlock(state);
    std::copy(state.begin(), state.end(), ghashKey.begin());
}

// GF(2^128) multiplication for GHASH
void AES::gfMul128(std::array<uint8_t, 16> &x, const std::array<uint8_t, 16> &y) const
{
    std::array<uint8_t, 16> z = {0};
    std::array<uint8_t, 16> v = y;

    for (int i = 0; i < 128; i++)
    {
        // If bit i of x is 1, XOR z with v
        int byteIdx = i / 8;
        int bitIdx = 7 - (i % 8);
        if ((x[byteIdx] >> bitIdx) & 1)
        {
            for (int j = 0; j < 16; j++)
                z[j] ^= v[j];
        }

        // Check if LSB of v is 1
        bool lsb = v[15] & 1;

        // Right shift v by 1 bit
        for (int j = 15; j > 0; j--)
        {
            v[j] = (v[j] >> 1) | ((v[j-1] & 1) << 7);
        }
        v[0] >>= 1;

        // If LSB was 1, XOR v with R (0xE1 in the MSB)
        if (lsb)
            v[0] ^= 0xE1;
    }

    x = z;
}

// GHASH function
void AES::ghash(const std::vector<uint8_t> &data, std::array<uint8_t, 16> &result) const
{
    result.fill(0);

    // Process complete 16-byte blocks
    size_t numBlocks = (data.size() + 15) / 16;

    for (size_t i = 0; i < numBlocks; i++)
    {
        std::array<uint8_t, 16> block = {0};
        size_t blockSize = std::min<size_t>(16, data.size() - i * 16);
        std::copy(data.begin() + i * 16, data.begin() + i * 16 + blockSize, block.begin());

        // XOR with current result
        for (int j = 0; j < 16; j++)
            result[j] ^= block[j];

        // Multiply by H in GF(2^128)
        gfMul128(result, ghashKey);
    }
}

// GCTR function (CTR mode encryption for GCM)
void AES::gctrEncrypt(const std::vector<uint8_t> &input, std::vector<uint8_t> &output,
                      const std::array<uint8_t, 16> &icb)
{
    output.resize(input.size());
    std::array<uint8_t, 16> counter = icb;

    for (size_t i = 0; i < input.size(); i += 16)
    {
        State keystream = counter;
        encryptBlock(keystream);

        size_t blockSize = std::min<size_t>(16, input.size() - i);
        for (size_t j = 0; j < blockSize; j++)
            output[i + j] = input[i + j] ^ keystream[j];

        // Increment counter (big-endian)
        for (int j = 15; j >= 0; j--)
        {
            if (++counter[j] != 0)
                break;
        }
    }
}
