#pragma once
#include <array>
#include <vector>
#include "cipher/cipher.hpp"

class GCM {
public:
    using Block = std::array<uint8_t, 16>;

    GCM() = default;

    void setIV(const std::vector<uint8_t> iv);
    void setAAD(const std::vector<uint8_t>& aad);

    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& plaintext,
        Cipher& cipher);

    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& ciphertext,
        Cipher& cipher);

    Block getTag() const;
    bool verifyTag(const Block& tag) const;

private:
    void initGhashKey(Cipher& cipher);
    void ghash(const std::vector<uint8_t>& data, Block& S) const;
    void ghashLengths(uint64_t aadBits, uint64_t cipherBits, Block& S) const;
    void gfMul128(Block& x, const Block& y) const;

    void incCounter(Block& counter) const;

    void ctrCrypt(const std::vector<uint8_t>& in,
        std::vector<uint8_t>& out,
        const Block& initialCounter,
        Cipher& cipher) const;

    void encryptBlock(Block& block, Cipher& cipher) const;

private:
    Block iv{};
    bool ivSet = false;

    std::vector<uint8_t> aad;
    Block ghashKey{};
    Block authTag{};
};
