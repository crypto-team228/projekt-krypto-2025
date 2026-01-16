#include "mode/GCM.hpp"
#include <algorithm>
#include <stdexcept>

void GCM::setIV(const std::vector<uint8_t> ivInput)
{
    if (ivInput.size() == 12) {
        // NIST fast path: J0 = IV || 0x00000001
        iv.fill(0);
        std::copy(ivInput.begin(), ivInput.end(), iv.begin());
        iv[12] = 0x00;
        iv[13] = 0x00;
        iv[14] = 0x00;
        iv[15] = 0x01;
    }
    else {
        // General case: J0 = GHASH(IV || pad || len(IV))
        std::vector<uint8_t> s = ivInput;
        if (s.size() % 16 != 0)
            s.resize((s.size() + 15) / 16 * 16, 0);

        std::array<uint8_t, 16> S{};
        ghash(s, S);

        uint64_t ivBits = static_cast<uint64_t>(ivInput.size()) * 8;
        ghashLengths(0, ivBits, S); // AAD=0, cipherBits=ivBits

        iv = S; // J0
    }

    ivSet = true;
}


void GCM::setAAD(const std::vector<uint8_t>& additionalData)
{
    aad = additionalData;
}

GCM::Block GCM::getTag() const
{
    return authTag;
}

bool GCM::verifyTag(const Block& tag) const 
{
    uint8_t diff = 0;
    for (size_t i = 0; i < 16; i++)
        diff |= (tag[i] ^ authTag[i]);
    return diff == 0;
}

std::vector<uint8_t> GCM::encrypt(const std::vector<uint8_t>& plaintext,
    Cipher& cipher)
{
    if (!ivSet)
        throw std::runtime_error("IV not set");

    // 1) H = E_K(0^128)
    initGhashKey(cipher);

    // 2) CTR counter = IV
    Block counter = iv;

    std::vector<uint8_t> ciphertext;
    ctrCrypt(plaintext, ciphertext, counter, cipher);

    // 3) GHASH(AAD || C || lengths)
    std::vector<uint8_t> ghashInput;

    // AAD
    ghashInput.insert(ghashInput.end(), aad.begin(), aad.end());
    if (ghashInput.size() % 16 != 0)
        ghashInput.resize((ghashInput.size() + 15) / 16 * 16, 0);

    // Ciphertext
    ghashInput.insert(ghashInput.end(), ciphertext.begin(), ciphertext.end());
    if (ghashInput.size() % 16 != 0)
        ghashInput.resize((ghashInput.size() + 15) / 16 * 16, 0);

    Block S{};
    ghash(ghashInput, S);

    uint64_t aadBits = aad.size() * 8;
    uint64_t cipherBits = ciphertext.size() * 8;
    ghashLengths(aadBits, cipherBits, S);

    // 4) authTag = S XOR E_K(IV)
    Block EkIV = iv;
    encryptBlock(EkIV, cipher);

    for (int i = 0; i < 16; i++)
        authTag[i] = S[i] ^ EkIV[i];

    return ciphertext;
}

std::vector<uint8_t> GCM::decrypt(const std::vector<uint8_t>& ciphertext,
    Cipher& cipher)
{
    if (!ivSet)
        throw std::runtime_error("IV not set");

    // 1) H = E_K(0^128)
    initGhashKey(cipher);

    // 2) GHASH(AAD || C || lengths)
    std::vector<uint8_t> ghashInput;

    ghashInput.insert(ghashInput.end(), aad.begin(), aad.end());
    if (ghashInput.size() % 16 != 0)
        ghashInput.resize((ghashInput.size() + 15) / 16 * 16, 0);

    ghashInput.insert(ghashInput.end(), ciphertext.begin(), ciphertext.end());
    if (ghashInput.size() % 16 != 0)
        ghashInput.resize((ghashInput.size() + 15) / 16 * 16, 0);

    Block S{};
    ghash(ghashInput, S);

    uint64_t aadBits = aad.size() * 8;
    uint64_t cipherBits = ciphertext.size() * 8;
    ghashLengths(aadBits, cipherBits, S);

    Block EkIV = iv;
    encryptBlock(EkIV, cipher);

    Block computedTag{};
    for (int i = 0; i < 16; i++)
        computedTag[i] = S[i] ^ EkIV[i];

    authTag = computedTag;

    // 3) CTR decrypt
    Block counter = iv;
    std::vector<uint8_t> plaintext;
    ctrCrypt(ciphertext, plaintext, counter, cipher);

    return plaintext;
}

void GCM::initGhashKey(Cipher& cipher)
{
    Block zero{};
    encryptBlock(zero, cipher);
    ghashKey = zero;
}

void GCM::encryptBlock(Block& block, Cipher& cipher) const
{
    uint8_t out[16];
    cipher.encryptBlock(block.data(), out);
    std::copy(out, out + 16, block.begin());
}

void GCM::ctrCrypt(const std::vector<uint8_t>& in,
    std::vector<uint8_t>& out,
    const Block& initialCounter,
    Cipher& cipher) const
{
    out.resize(in.size());

    Block counter = initialCounter;
    Block keystream{};

    size_t numBlocks = (in.size() + 15) / 16;

    for (size_t i = 0; i < numBlocks; i++) {
        Block tmp = counter;
        encryptBlock(tmp, cipher);
        keystream = tmp;

        size_t offset = i * 16;
        size_t blockSize = std::min<size_t>(16, in.size() - offset);

        for (size_t j = 0; j < blockSize; j++)
            out[offset + j] = in[offset + j] ^ keystream[j];

        incCounter(counter);
    }
}

void GCM::incCounter(Block& counter) const
{
    for (int i = 15; i >= 0; i--) {
        uint16_t v = counter[i] + 1;
        counter[i] = v & 0xFF;
        if (!(v & 0x100))
            break;
    }
}

void GCM::gfMul128(Block& x, const Block& y) const
{
    Block z{};
    Block v = y;

    for (int i = 0; i < 128; i++) {
        int byteIdx = i / 8;
        int bitIdx = 7 - (i % 8);

        if ((x[byteIdx] >> bitIdx) & 1)
            for (int j = 0; j < 16; j++)
                z[j] ^= v[j];

        bool lsb = v[15] & 1;

        for (int j = 15; j > 0; j--)
            v[j] = (v[j] >> 1) | ((v[j - 1] & 1) << 7);

        v[0] >>= 1;

        if (lsb)
            v[0] ^= 0xE1;
    }

    x = z;
}

void GCM::ghash(const std::vector<uint8_t>& data, Block& result) const
{
    result.fill(0);

    size_t numBlocks = (data.size() + 15) / 16;

    for (size_t i = 0; i < numBlocks; i++) {
        Block block{};
        size_t blockSize = std::min<size_t>(16, data.size() - i * 16);
        std::copy(data.begin() + i * 16,
            data.begin() + i * 16 + blockSize,
            block.begin());

        for (int j = 0; j < 16; j++)
            result[j] ^= block[j];

        gfMul128(result, ghashKey);
    }
}

void GCM::ghashLengths(uint64_t aadBits,
    uint64_t cipherBits,
    Block& S) const
{
    Block lenBlock{};

    for (int i = 0; i < 8; i++)
        lenBlock[7 - i] = (aadBits >> (8 * i)) & 0xFF;

    for (int i = 0; i < 8; i++)
        lenBlock[15 - i] = (cipherBits >> (8 * i)) & 0xFF;

    for (int j = 0; j < 16; j++)
        S[j] ^= lenBlock[j];

    gfMul128(S, ghashKey);
}
