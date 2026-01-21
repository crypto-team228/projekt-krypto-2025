#include "cipher/TDES/tdes.hpp"
#include <cstdint>
#include <stdexcept>
#include <vector>

extern uint64_t ip_lut[8][256];
extern uint64_t fp_lut[8][256];
extern uint64_t e_lut[4][256];
extern uint32_t p_lut[4][256];
extern uint64_t pc1_lut[8][256];
extern uint64_t pc2_lut[7][256];
extern uint8_t  sbox_lut[8][64];
extern const int keyShiftTable[16];


    inline uint64_t load_be64(const uint8_t* in) noexcept
    {
        return (uint64_t(in[0]) << 56) |
            (uint64_t(in[1]) << 48) |
            (uint64_t(in[2]) << 40) |
            (uint64_t(in[3]) << 32) |
            (uint64_t(in[4]) << 24) |
            (uint64_t(in[5]) << 16) |
            (uint64_t(in[6]) << 8) |
            (uint64_t(in[7]) << 0);
    }

    inline void store_be64(uint64_t v, uint8_t* out) noexcept
    {
        out[0] = uint8_t(v >> 56);
        out[1] = uint8_t(v >> 48);
        out[2] = uint8_t(v >> 40);
        out[3] = uint8_t(v >> 32);
        out[4] = uint8_t(v >> 24);
        out[5] = uint8_t(v >> 16);
        out[6] = uint8_t(v >> 8);
        out[7] = uint8_t(v >> 0);
    }

    inline uint32_t rotl28(uint32_t v, int s) noexcept
    {
        v &= 0x0FFFFFFFu;
        return ((v << s) | (v >> (28 - s))) & 0x0FFFFFFFu;
    }

    inline void secure_memzero(void* p, std::size_t n) noexcept
    {
        volatile uint8_t* v = static_cast<volatile uint8_t*>(p);
        while (n--) *v++ = 0;
    }

    inline uint64_t ip_permute(uint64_t block) noexcept
    {
        return ip_lut[0][(block >> 56) & 0xFF] |
            ip_lut[1][(block >> 48) & 0xFF] |
            ip_lut[2][(block >> 40) & 0xFF] |
            ip_lut[3][(block >> 32) & 0xFF] |
            ip_lut[4][(block >> 24) & 0xFF] |
            ip_lut[5][(block >> 16) & 0xFF] |
            ip_lut[6][(block >> 8) & 0xFF] |
            ip_lut[7][(block >> 0) & 0xFF];
    }

    inline uint64_t fp_permute(uint64_t block) noexcept
    {
        return fp_lut[0][(block >> 56) & 0xFF] |
            fp_lut[1][(block >> 48) & 0xFF] |
            fp_lut[2][(block >> 40) & 0xFF] |
            fp_lut[3][(block >> 32) & 0xFF] |
            fp_lut[4][(block >> 24) & 0xFF] |
            fp_lut[5][(block >> 16) & 0xFF] |
            fp_lut[6][(block >> 8) & 0xFF] |
            fp_lut[7][(block >> 0) & 0xFF];
    }

    inline uint64_t pc1_permute(uint64_t key) noexcept
    {
        return pc1_lut[0][(key >> 56) & 0xFF] |
            pc1_lut[1][(key >> 48) & 0xFF] |
            pc1_lut[2][(key >> 40) & 0xFF] |
            pc1_lut[3][(key >> 32) & 0xFF] |
            pc1_lut[4][(key >> 24) & 0xFF] |
            pc1_lut[5][(key >> 16) & 0xFF] |
            pc1_lut[6][(key >> 8) & 0xFF] |
            pc1_lut[7][(key >> 0) & 0xFF];
    }

    inline uint64_t pc2_permute(uint64_t cd56) noexcept
    {
        return pc2_lut[0][(cd56 >> 48) & 0xFF] |
            pc2_lut[1][(cd56 >> 40) & 0xFF] |
            pc2_lut[2][(cd56 >> 32) & 0xFF] |
            pc2_lut[3][(cd56 >> 24) & 0xFF] |
            pc2_lut[4][(cd56 >> 16) & 0xFF] |
            pc2_lut[5][(cd56 >> 8) & 0xFF] |
            pc2_lut[6][(cd56 >> 0) & 0xFF];
    }

    inline uint64_t e_expand(uint32_t r) noexcept
    {
        return e_lut[0][(r >> 24) & 0xFF] |
            e_lut[1][(r >> 16) & 0xFF] |
            e_lut[2][(r >> 8) & 0xFF] |
            e_lut[3][(r >> 0) & 0xFF];
    }

    inline uint32_t p_permute(uint32_t x) noexcept
    {
        return p_lut[0][(x >> 24) & 0xFF] |
            p_lut[1][(x >> 16) & 0xFF] |
            p_lut[2][(x >> 8) & 0xFF] |
            p_lut[3][(x >> 0) & 0xFF];
    }


TDES::TDES(const std::vector<uint8_t>& key)
{
    setKey(key);
}

TDES::~TDES()
{
    secure_memzero(subkeys1.data(), subkeys1.size() * sizeof(SubkeySchedule::value_type));
    secure_memzero(subkeys2.data(), subkeys2.size() * sizeof(SubkeySchedule::value_type));
    secure_memzero(subkeys3.data(), subkeys3.size() * sizeof(SubkeySchedule::value_type));
}

size_t TDES::blockSize() const
{
    return BLOCK_SIZE;
}

void TDES::setKey(const std::vector<uint8_t>& key)
{
    if (key.size() != 8 && key.size() != 16 && key.size() != 24) {
        throw std::invalid_argument("TDES::setKey: expected 8, 16 or 24 bytes");
    }

    auto load_key64 = [](const uint8_t* k) noexcept -> uint64_t {
        return load_be64(k);
        };

    if (key.size() == 8) {
        uint64_t k1 = load_key64(key.data());
        subkeys1 = GenerateSubkeys(k1);
        subkeys2 = subkeys1;
        subkeys3 = subkeys1;
    }
    else if (key.size() == 16) {
        uint64_t k1 = load_key64(key.data());
        uint64_t k2 = load_key64(key.data() + 8);

        subkeys1 = GenerateSubkeys(k1);
        subkeys2 = GenerateSubkeys(k2);
        subkeys3 = subkeys1;
    }
    else {
        uint64_t k1 = load_key64(key.data());
        uint64_t k2 = load_key64(key.data() + 8);
        uint64_t k3 = load_key64(key.data() + 16);

        subkeys1 = GenerateSubkeys(k1);
        subkeys2 = GenerateSubkeys(k2);
        subkeys3 = GenerateSubkeys(k3);
    }
}

void TDES::encryptBlock(const uint8_t* in, uint8_t* out) const
{
    if (!in || !out) return;

    uint64_t block = load_be64(in);
    uint64_t enc = TripleDESEncrypt(block);
    store_be64(enc, out);
}

void TDES::decryptBlock(const uint8_t* in, uint8_t* out) const
{
    if (!in || !out) return;

    uint64_t block = load_be64(in);
    uint64_t dec = TripleDESDecrypt(block);
    store_be64(dec, out);
}

// ================= 3DES (EDE) =================

TDES::Bit64 TDES::TripleDESEncrypt(const Bit64 bits) const
{
    Bit64 r = DESEncryptBlock(bits, subkeys1);
    r = DESDecryptBlock(r, subkeys2);
    r = DESEncryptBlock(r, subkeys3);
    return r;
}

TDES::Bit64 TDES::TripleDESDecrypt(const Bit64 bits) const
{
    Bit64 r = DESDecryptBlock(bits, subkeys3);
    r = DESEncryptBlock(r, subkeys2);
    r = DESDecryptBlock(r, subkeys1);
    return r;
}

// ================= DES =================

TDES::Bit64 TDES::DESEncryptBlock(const Bit64 block,
    const SubkeySchedule& subkeys) const
{
    uint64_t ip = ip_permute(block);

    uint32_t left = static_cast<uint32_t>(ip >> 32);
    uint32_t right = static_cast<uint32_t>(ip & 0xFFFFFFFFu);

    for (int round = 0; round < 16; ++round) {
        uint32_t f = FeistelFunction(right, subkeys[round]);
        uint32_t newLeft = right;
        right = left ^ f;
        left = newLeft;
    }

    uint64_t preOutput = (static_cast<uint64_t>(right) << 32) | left;
    return fp_permute(preOutput);
}

TDES::Bit64 TDES::DESDecryptBlock(const Bit64 block,
    const SubkeySchedule& subkeys) const
{
    uint64_t ip = ip_permute(block);

    uint32_t left = static_cast<uint32_t>(ip >> 32);
    uint32_t right = static_cast<uint32_t>(ip & 0xFFFFFFFFu);

    for (int round = 15; round >= 0; --round) {
        uint32_t f = FeistelFunction(right, subkeys[round]);
        uint32_t newLeft = right;
        right = left ^ f;
        left = newLeft;
    }

    uint64_t preOutput = (static_cast<uint64_t>(right) << 32) | left;
    return fp_permute(preOutput);
}

// ================= Feistel =================

TDES::Bit32 TDES::FeistelFunction(const Bit32 right, const Bit48 subkey) const
{
    uint64_t expanded = e_expand(right);
    uint64_t x = expanded ^ subkey;

    uint32_t sboxOut = 0;
    // 8 S-boxów, ka¿dy 6 bitów
    sboxOut = (sboxOut << 4) | sbox_lut[0][(x >> 42) & 0x3F];
    sboxOut = (sboxOut << 4) | sbox_lut[1][(x >> 36) & 0x3F];
    sboxOut = (sboxOut << 4) | sbox_lut[2][(x >> 30) & 0x3F];
    sboxOut = (sboxOut << 4) | sbox_lut[3][(x >> 24) & 0x3F];
    sboxOut = (sboxOut << 4) | sbox_lut[4][(x >> 18) & 0x3F];
    sboxOut = (sboxOut << 4) | sbox_lut[5][(x >> 12) & 0x3F];
    sboxOut = (sboxOut << 4) | sbox_lut[6][(x >> 6) & 0x3F];
    sboxOut = (sboxOut << 4) | sbox_lut[7][(x >> 0) & 0x3F];

    return p_permute(sboxOut);
}

// ================= Subkeys =================

TDES::SubkeySchedule TDES::GenerateSubkeys(const Bit64 key64)
{
    SubkeySchedule subkeys{};

    uint64_t permuted = pc1_permute(key64); // 56 bitów

    uint32_t c = static_cast<uint32_t>((permuted >> 28) & 0x0FFFFFFFu);
    uint32_t d = static_cast<uint32_t>(permuted & 0x0FFFFFFFu);

    for (int round = 0; round < 16; ++round) {
        int shift = keyShiftTable[round];
        c = rotl28(c, shift);
        d = rotl28(d, shift);

        uint64_t cd = (static_cast<uint64_t>(c) << 28) | d; // 56 bitów
        subkeys[round] = pc2_permute(cd);                   // 48 bitów
    }

    return subkeys;
}
