#include "cipher/TDES/tdes.hpp"

TDES::TDES(const std::vector<uint8_t>& key) {
    setKey(key);
}
size_t TDES::blockSize() const {
    return BLOCK_SIZE;
}

void TDES::setKey(const std::vector<uint8_t>& key) {
    // zak³adam: key to 64/128/192 bitów *w bitach* (0/1), jak wczeœniej
    if (key.size() == 64) {
        // 1-key 3DES: K1 = K2 = K3
        subkeys1 = GenerateSubkeys(key);
        subkeys2 = subkeys1;
        subkeys3 = subkeys1;
    }
    else if (key.size() == 128) {
        // 2-key 3DES: K1, K2, K3 = K1
        std::vector<uint8_t> k1(key.begin(), key.begin() + 64);
        std::vector<uint8_t> k2(key.begin() + 64, key.begin() + 128);

        subkeys1 = GenerateSubkeys(k1);
        subkeys2 = GenerateSubkeys(k2);
        subkeys3 = subkeys1;
    }
    else if (key.size() == 192) {
        // 3-key 3DES: K1, K2, K3
        std::vector<uint8_t> k1(key.begin(), key.begin() + 64);
        std::vector<uint8_t> k2(key.begin() + 64, key.begin() + 128);
        std::vector<uint8_t> k3(key.begin() + 128, key.begin() + 192);

        subkeys1 = GenerateSubkeys(k1);
        subkeys2 = GenerateSubkeys(k2);
        subkeys3 = GenerateSubkeys(k3);
    }
    else {
		
        throw std::invalid_argument("TDES::setKey: expected 64, 128 or 192 bits:"+ key.size());
    }
}

void TDES::encryptBlock(const uint8_t* in, uint8_t* out) const {
    if (!in || !out) return;
    auto blockBytes = DataConverter::BytesToArray<8>(in);
    auto blockBits = DataConverter::BytesArrayToBits(blockBytes);

    auto encBits = TripleDESEncrypt(blockBits);
    auto encBytes = DataConverter::BitsArrayToBytes(encBits);

    DataConverter::ArrayToBytes(encBytes, out);
}

void TDES::decryptBlock(const uint8_t* in, uint8_t* out) const {
    if (!in || !out) return;
    auto blockBytes = DataConverter::BytesToArray<8>(in);
    auto blockBits = DataConverter::BytesArrayToBits(blockBytes);

    Bit64 decBits = TripleDESDecrypt(blockBits);
	auto decBytes = DataConverter::BitsArrayToBytes(decBits);

    DataConverter::ArrayToBytes(decBits, out);
}

// ================= 3DES (EDE) na bitach =================

TDES::Bit64 TDES::TripleDESEncrypt(const Bit64& bits) const {
    Bit64 r = DESEncryptBlock(bits, subkeys1);  // E(K1)
    r = DESDecryptBlock(r, subkeys2);           // D(K2)
    r = DESEncryptBlock(r, subkeys3);           // E(K3)
    return r;
}

TDES::Bit64 TDES::TripleDESDecrypt(const Bit64& bits) const {
    Bit64 r = DESDecryptBlock(bits, subkeys3);  // D(K3)
    r = DESEncryptBlock(r, subkeys2);           // E(K2)
    r = DESDecryptBlock(r, subkeys1);           // D(K1)
    return r;
}

// ================= pojedynczy DES =================

TDES::Bit64 TDES::DESEncryptBlock(const Bit64& block,
    const SubkeySchedule& subkeys) const
{
    Bit64 permutedBlock = Permute(initialPermutation, block);

    Bit32 left{};
    Bit32 right{};
    for (std::size_t i = 0; i < 32; i++) {
        left[i] = permutedBlock[i];
        right[i] = permutedBlock[i + 32];
    }

    for (std::size_t round = 0; round < 16; round++) {
        Bit32 f = FeistelFunction(right, subkeys[round]);

        std::transform(left.begin(), left.end(), f.begin(), left.begin(),
            [](uint8_t l, uint8_t v) { return static_cast<uint8_t>(l ^ v); });

        if (round < 15) {
            std::swap(left, right);
        }
    }

    Bit64 combined{};
    for (std::size_t i = 0; i < 32; i++) {
        combined[i] = left[i];
        combined[i + 32] = right[i];
    }

    return Permute(finalPermutation, combined);
}

TDES::Bit64 TDES::DESDecryptBlock(const Bit64& block,
    const SubkeySchedule& subkeys) const
{
    Bit64 permutedBlock = Permute(initialPermutation, block);

    Bit32 left{};
    Bit32 right{};
    for (std::size_t i = 0; i < 32; i++) {
        left[i] = permutedBlock[i];
        right[i] = permutedBlock[i + 32];
    }

    for (int round = 15; round >= 0; --round) {
        Bit32 f = FeistelFunction(right, subkeys[round]);

        std::transform(left.begin(), left.end(), f.begin(), left.begin(),
            [](uint8_t l, uint8_t v) { return static_cast<uint8_t>(l ^ v); });

        if (round > 0) {
            std::swap(left, right);
        }
    }

    Bit64 combined{};
    for (std::size_t i = 0; i < 32; i++) {
        combined[i] = left[i];
        combined[i + 32] = right[i];
    }

    return Permute(finalPermutation, combined);
}

// ================= Feistel =================

TDES::Bit32 TDES::FeistelFunction(const Bit32& right, const Bit48& subkey) const {
    Bit48 expanded = Permute(expansionD, right);

    Bit48 xored{};
    std::transform(expanded.begin(), expanded.end(), subkey.begin(), xored.begin(),
        [](uint8_t r, uint8_t k) { return static_cast<uint8_t>(r ^ k); });

    Bit32 sboxOutput{};
    for (std::size_t i = 0; i < 8; i++) {
        uint8_t b0 = xored[i * 6 + 0];
        uint8_t b1 = xored[i * 6 + 1];
        uint8_t b2 = xored[i * 6 + 2];
        uint8_t b3 = xored[i * 6 + 3];
        uint8_t b4 = xored[i * 6 + 4];
        uint8_t b5 = xored[i * 6 + 5];

        uint8_t row = static_cast<uint8_t>((b0 << 1) | b5);
        uint8_t col = static_cast<uint8_t>((b1 << 3) | (b2 << 2) | (b3 << 1) | b4);

        uint8_t s = sbox[i][row][col];
        for (int j = 0; j < 4; j++) {
            sboxOutput[i * 4 + (3 - j)] = static_cast<uint8_t>((s >> j) & 1U);
        }
    }

    Bit32 permuted = Permute(straightPermutation, sboxOutput);
    return permuted;
}

// ================= generate subkeys =================

TDES::SubkeySchedule TDES::GenerateSubkeys(const std::vector<uint8_t>& keyBits) {
    if (keyBits.size() != 64)
        throw std::invalid_argument("GenerateSubkeys: expected 64 bits");

    SubkeySchedule subkeys{};

    Bit56 permutedKey = Permute(parityBitDropTable, keyBits);

    Bit28 left{};
    Bit28 right{};
    for (std::size_t i = 0; i < 28; i++) {
        left[i] = permutedKey[i];
        right[i] = permutedKey[i + 28];
    }

    for (std::size_t round = 0; round < 16; round++) {
        left = ShiftLeft(left, keyShiftTable[round]);
        right = ShiftLeft(right, keyShiftTable[round]);

        Bit56 combined{};
        for (std::size_t i = 0; i < 28; i++) {
            combined[i] = left[i];
            combined[i + 28] = right[i];
        }

        subkeys[round] = Permute(keyCompressionTable, combined);
    }

    return subkeys;
}

TDES::Bit28 TDES::ShiftLeft(const Bit28& halfKey, int shifts) const {
    Bit28 shifted{};
    for (std::size_t i = 0; i < 28; i++) {
        shifted[i] = halfKey[(i + shifts) % 28];
    }
    return shifted;
}
