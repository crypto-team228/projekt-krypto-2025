#include "cipher/TDES/tdes_b.hpp"

TDES_B::TDES_B(const std::vector<uint8_t>& key) {
    setKey(key);
}

TDES_B::~TDES_B()
{
    secure_memzero(subkeys1.data(), sizeof(subkeys1));
    secure_memzero(subkeys2.data(), sizeof(subkeys2));
	secure_memzero(subkeys3.data(), sizeof(subkeys3));
}

size_t TDES_B::blockSize() const {
    return BLOCK_SIZE;
}

void TDES_B::setKey(const std::vector<uint8_t>& key)
{
    if (key.size() == 8) {
        // 1-key 3DES
        subkeys1 = GenerateSubkeys( DataConverter::BytesToBits(key));
        subkeys2 = subkeys1;
        subkeys3 = subkeys1;
    }
    else if (key.size() == 16) {
        // 2-key 3DES
        std::vector<uint8_t> k1(key.begin(), key.begin() + 8);
        std::vector<uint8_t> k2(key.begin() + 8, key.begin() + 16);

        subkeys1 = GenerateSubkeys(DataConverter::BytesToBits(k1));
        subkeys2 = GenerateSubkeys(DataConverter::BytesToBits(k2));
        subkeys3 = subkeys1;
    }
    else if (key.size() == 24) {
        // 3-key 3DES
        std::vector<uint8_t> k1(key.begin(), key.begin() + 8);
        std::vector<uint8_t> k2(key.begin() + 8, key.begin() + 16);
        std::vector<uint8_t> k3(key.begin() + 16, key.begin() + 24);

        subkeys1 = GenerateSubkeys(DataConverter::BytesToBits(k1));
        subkeys2 = GenerateSubkeys(DataConverter::BytesToBits(k2));
        subkeys3 = GenerateSubkeys(DataConverter::BytesToBits(k3));
    }
    else {
        throw std::invalid_argument("TDES_B::setKey: expected 8, 16 or 24 bytes");
    }
}


void TDES_B::encryptBlock(const uint8_t* in, uint8_t* out) const {
    if (!in || !out) return;
    auto blockBytes = DataConverter::BytesToArray<8>(in);
    auto blockBits = DataConverter::BytesArrayToBits(blockBytes);

    auto encBits = TripleDESEncrypt(blockBits);
    auto encBytes = DataConverter::BitsArrayToBytes(encBits);

    DataConverter::ArrayToBytes(encBytes, out);
}

void TDES_B::decryptBlock(const uint8_t* in, uint8_t* out) const {
    if (!in || !out) return;
    auto blockBytes = DataConverter::BytesToArray<8>(in);
    auto blockBits = DataConverter::BytesArrayToBits(blockBytes);

    Bit64 decBits = TripleDESDecrypt(blockBits);
	auto decBytes = DataConverter::BitsArrayToBytes(decBits);

    DataConverter::ArrayToBytes(decBytes, out);
}

// ================= 3DES (EDE) na bitach =================

TDES_B::Bit64 TDES_B::TripleDESEncrypt(const Bit64& bits) const {
    Bit64 r = DESEncryptBlock(bits, subkeys1);  // E(K1)
    r = DESDecryptBlock(r, subkeys2);           // D(K2)
    r = DESEncryptBlock(r, subkeys3);           // E(K3)
    return r;
}

TDES_B::Bit64 TDES_B::TripleDESDecrypt(const Bit64& bits) const {
    Bit64 r = DESDecryptBlock(bits, subkeys3);  // D(K3)
    r = DESEncryptBlock(r, subkeys2);           // E(K2)
    r = DESDecryptBlock(r, subkeys1);           // D(K1)
    return r;
}

// ================= pojedynczy DES =================

TDES_B::Bit64 TDES_B::DESEncryptBlock(const Bit64& block,
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

TDES_B::Bit64 TDES_B::DESDecryptBlock(const Bit64& block,
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

TDES_B::Bit32 TDES_B::FeistelFunction(const Bit32& right, const Bit48& subkey) const {
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

TDES_B::SubkeySchedule TDES_B::GenerateSubkeys(const std::vector<uint8_t>& keyBits) {
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

TDES_B::Bit28 TDES_B::ShiftLeft(const Bit28& halfKey, int shifts) const {
    Bit28 shifted{};
    for (std::size_t i = 0; i < 28; i++) {
        shifted[i] = halfKey[(i + shifts) % 28];
    }
    return shifted;
}
