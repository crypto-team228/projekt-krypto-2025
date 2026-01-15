#include <mode/GCM.hpp>

GCM::GCM(std::vector<uint8_t> initVector, std::vector<uint8_t> additionalData)
	: aad(std::move(additionalData))
{
    iv = initVector;
	initGhashKey();

    ghashKey.fill(0);
    authTag.fill(0);
    currentCipher = nullptr;
    ivSet = true;
}

std::vector<uint8_t> GCM::encrypt(const std::vector<uint8_t>& data, Cipher& cipher)
{
    currentCipher = &cipher;

    if (!ivSet)
        throw std::runtime_error("IV not set");

    // 1) H = E_K(0^128)
    initGhashKey();

    // 2) CTR: licznik startuje od IV
    std::array<uint8_t, 16> initialCounter;
	copy(iv.begin(), iv.begin()+16, initialCounter.begin());

    std::vector<uint8_t> ciphertext;
    ctrCrypt(data, ciphertext, initialCounter);

    // 3) GHASH(AAD || padding || C || padding || len(AAD)||len(C))
    std::vector<uint8_t> ghashInput;

    // AAD
    ghashInput.insert(ghashInput.end(), aad.begin(), aad.end());
    if ((ghashInput.size() % 16) != 0)
        ghashInput.resize(((ghashInput.size() + 15) / 16) * 16, 0);

    // Ciphertext
    ghashInput.insert(ghashInput.end(), ciphertext.begin(), ciphertext.end());
    if ((ghashInput.size() % 16) != 0)
        ghashInput.resize(((ghashInput.size() + 15) / 16) * 16, 0);

    std::array<uint8_t, 16> S{};
    ghash(ghashInput, S);

    uint64_t aadBits = static_cast<uint64_t>(aad.size()) * 8;
    uint64_t cipherBits = static_cast<uint64_t>(ciphertext.size()) * 8;
    ghashLengths(aadBits, cipherBits, S);

    // 4) authTag = S XOR E_K(IV)
    std::array<uint8_t, 16> EkIV{};
    {
        std::array<uint8_t, 16> ivCopy;
		copy(iv.begin(), iv.begin() + 16, ivCopy.begin());
        encryptBlock(ivCopy);
        EkIV = ivCopy;
    }

    for (int i = 0; i < 16; ++i)
        authTag[i] = static_cast<uint8_t>(S[i] ^ EkIV[i]);

    return ciphertext;
}

std::vector<uint8_t> GCM::decrypt(const std::vector<uint8_t>& data, Cipher& cipher)
{
    currentCipher = &cipher;

    if (!ivSet)
        throw std::runtime_error("IV not set");

    // 1) H = E_K(0^128)
    initGhashKey();

    // 2) GHASH nad AAD i ciphertextem (jak przy szyfrowaniu)
    std::vector<uint8_t> ghashInput;

    ghashInput.insert(ghashInput.end(), aad.begin(), aad.end());
    if ((ghashInput.size() % 16) != 0)
        ghashInput.resize(((ghashInput.size() + 15) / 16) * 16, 0);

    ghashInput.insert(ghashInput.end(), data.begin(), data.end());
    if ((ghashInput.size() % 16) != 0)
        ghashInput.resize(((ghashInput.size() + 15) / 16) * 16, 0);

    std::array<uint8_t, 16> S{};
    ghash(ghashInput, S);

    uint64_t aadBits = static_cast<uint64_t>(aad.size()) * 8;
    uint64_t cipherBits = static_cast<uint64_t>(data.size()) * 8;
    ghashLengths(aadBits, cipherBits, S);

    std::array<uint8_t, 16> EkIV{};
    {
        std::array<uint8_t, 16> ivCopy;
		copy(iv.begin(), iv.begin() + 16, ivCopy.begin());
        encryptBlock(ivCopy);
        EkIV = ivCopy;
    }

    std::array<uint8_t, 16> computedTag{};
    for (int i = 0; i < 16; ++i)
        computedTag[i] = static_cast<uint8_t>(S[i] ^ EkIV[i]);

    // Tag wyliczony przy decrypt – mo¿esz go zweryfikowaæ przez verifyTag().
    authTag = computedTag;

    // 3) CTR: odszyfrowanie
    std::array<uint8_t, 16> initialCounter;
	copy(iv.begin(), iv.begin() + 16, initialCounter.begin());
    std::vector<uint8_t> plaintext;
    ctrCrypt(data, plaintext, initialCounter);

    return plaintext;
}

void GCM::setIV(const std::vector<uint8_t>& initVector)
{
    if (initVector.size() != 16)
    {
        throw std::invalid_argument("IV must be 16 bytes");
    }
    std::copy(initVector.begin(), initVector.end(), iv.begin());
    ivSet = true;
}

void GCM::setAAD(const std::vector<uint8_t>& additionalData)
{
    aad = additionalData;
}

std::vector<uint8_t> GCM::getTag()
{
    return std::vector<uint8_t>(authTag.begin(), authTag.end());
}

bool GCM::verifyTag(const std::vector<uint8_t>& tag)
{
    if (tag.size() != 16)
        return false;

    uint8_t diff = 0;
    for (size_t i = 0; i < 16; i++)
    {
        diff |= static_cast<uint8_t>(tag[i] ^ authTag[i]);
    }
    return diff == 0;
}

// Initialize GHASH key H = E_K(0^128)
void GCM::initGhashKey()
{
    if (!currentCipher)
        throw std::runtime_error("Cipher not set in GCM (currentCipher is null)");

    std::array<uint8_t, 16> state{};
    encryptBlock(state);   // state = E_K(0^128)
    ghashKey = state;
}

// GF(2^128) multiplication for GHASH
void GCM::gfMul128(std::array<uint8_t, 16>& x, const std::array<uint8_t, 16>& y) const
{
    std::array<uint8_t, 16> z = { 0 };
    std::array<uint8_t, 16> v = y;

    for (int i = 0; i < 128; i++)
    {
        int byteIdx = i / 8;
        int bitIdx = 7 - (i % 8);
        if ((x[byteIdx] >> bitIdx) & 1)
        {
            for (int j = 0; j < 16; j++)
                z[j] ^= v[j];
        }

        bool lsb = (v[15] & 1) != 0;

        for (int j = 15; j > 0; j--)
        {
            v[j] = static_cast<uint8_t>((v[j] >> 1) | ((v[j - 1] & 1) << 7));
        }
        v[0] >>= 1;

        if (lsb)
            v[0] ^= 0xE1;
    }

    x = z;
}

// GHASH function
void GCM::ghash(const std::vector<uint8_t>& data, std::array<uint8_t, 16>& result) const
{
    result.fill(0);

    size_t numBlocks = (data.size() + 15) / 16;

    for (size_t i = 0; i < numBlocks; i++)
    {
        std::array<uint8_t, 16> block = { 0 };
        size_t blockSize = std::min<size_t>(16, data.size() - i * 16);
        std::copy(data.begin() + i * 16, data.begin() + i * 16 + blockSize, block.begin());

        for (int j = 0; j < 16; j++)
            result[j] ^= block[j];

        gfMul128(result, ghashKey);
    }
}

void GCM::ghashLengths(uint64_t aadBits,
    uint64_t cipherBits,
    std::array<uint8_t, 16>& S) const
{
    std::array<uint8_t, 16> lenBlock = { 0 };

    for (int i = 0; i < 8; ++i)
        lenBlock[7 - i] = static_cast<uint8_t>((aadBits >> (8 * i)) & 0xFF);

    for (int i = 0; i < 8; ++i)
        lenBlock[15 - i] = static_cast<uint8_t>((cipherBits >> (8 * i)) & 0xFF);

    for (int j = 0; j < 16; j++)
        S[j] ^= lenBlock[j];

    gfMul128(S, ghashKey);
}

void GCM::incCounter(std::array<uint8_t, 16>& counter) const
{
    for (int i = 15; i >= 0; --i)
    {
        uint16_t val = static_cast<uint16_t>(counter[i]) + 1;
        counter[i] = static_cast<uint8_t>(val & 0xFF);
        if ((val & 0x100) == 0)
            break;
    }
}

void GCM::ctrCrypt(const std::vector<uint8_t>& in,
    std::vector<uint8_t>& out,
    const std::array<uint8_t, 16>& initialCounter)
{
    if (!currentCipher)
        throw std::runtime_error("Cipher not set in GCM (currentCipher is null)");

    out.resize(in.size());
    std::array<uint8_t, 16> counter = initialCounter;
    std::array<uint8_t, 16> keystream{};

    size_t numBlocks = (in.size() + 15) / 16;

    for (size_t i = 0; i < numBlocks; ++i)
    {
        encryptBlock(counter);       // counter = E_K(counter)
        keystream = counter;         // u¿ywamy go jako keystream

        size_t offset = i * 16;
        size_t blockSize = std::min<size_t>(16, in.size() - offset);

        for (size_t j = 0; j < blockSize; ++j)
        {
            out[offset + j] = static_cast<uint8_t>(
                in[offset + j] ^ keystream[j]
                );
        }

        incCounter(counter);
    }
}

// Jednoblokowe szyfrowanie "in place" u¿ywaj¹ce bie¿¹cego szyfru blokowego.
void GCM::encryptBlock(std::array<uint8_t, 16>& block)
{
    if (!currentCipher)
        throw std::runtime_error("Cipher not set in GCM (currentCipher is null)");

    uint8_t out[16];
    currentCipher->encryptBlock(block.data(), out);
    std::copy(out, out + 16, block.begin());
}
