#include "cipher/AES/aes.hpp"
#include <vector>
#include <stdexcept>
#include <algorithm>

AES::AES(const std::vector<uint8_t>& key)
{
    setKey(key);
}

AES::~AES()
{
    secure_memzero(roundKeys.data(), roundKeys.size() * sizeof(roundKeys[0]));
}

size_t AES::blockSize() const {
    return BLOCK_SIZE;
}

void AES::setKey(const std::vector<uint8_t>& key)
{
    if (key.size() != 16 && key.size() != 24 && key.size() != 32)
    {
        throw std::invalid_argument("AES key must be 16, 24, or 32 bytes");
    }

    Nk = static_cast<int>(key.size()) / 4; // 4, 6, 8
    Nr = Nk + 6;                           // 10, 12, 14

    keyExpansion(key);
}

void AES::encryptBlock(const uint8_t* in, uint8_t* out) const
{
    State state;
    std::copy(in, in + 16, state.begin());

    addRoundKey(state, roundKeys[0]);

    for (int round = 1; round < Nr; round++)
    {
        subBytes(state);
        shiftRows(state);
        mixColumns(state);
        addRoundKey(state, roundKeys[round]);
    }

    subBytes(state);
    shiftRows(state);
    addRoundKey(state, roundKeys[Nr]);

    std::copy(state.begin(), state.end(), out);
}

void AES::decryptBlock(const uint8_t* in, uint8_t* out) const
{
    State state;
    std::copy(in, in + 16, state.begin());

    addRoundKey(state, roundKeys[Nr]);

    for (int round = Nr - 1; round >= 1; round--)
    {
        invShiftRows(state);
        invSubBytes(state);
        addRoundKey(state, roundKeys[round]);
        invMixColumns(state);
    }

    invShiftRows(state);
    invSubBytes(state);
    addRoundKey(state, roundKeys[0]);

    std::copy(state.begin(), state.end(), out);
}

inline uint8_t AES::xtime(uint8_t x)
{
    return static_cast<uint8_t>((x << 1) ^ ((x & 0x80) ? 0x1b : 0x00));
}

void AES::addRoundKey(State& st, const State& key) const
{
    for (int i = 0; i < 16; i++)
        st[i] ^= key[i];
}

uint8_t AES::Rcon(int i)
{
    static uint8_t rcon[11] = {
        0x00,
        0x01, 0x02, 0x04, 0x08, 0x10,
        0x20, 0x40, 0x80, 0x1B, 0x36 };
    return rcon[i];
}

void AES::rotWord(uint8_t* w)
{
    uint8_t tmp = w[0];
    w[0] = w[1];
    w[1] = w[2];
    w[2] = w[3];
    w[3] = tmp;
}

void AES::subWord(uint8_t* w)
{
    for (int i = 0; i < 4; i++)
        w[i] = sbox[w[i]];
}

// --- Key Expansion (AES-128/192/256) ---
void AES::keyExpansion(const std::vector<uint8_t>& key)
{
    // Maksymalnie 60 s³ów (AES-256: 4*(14+1))
    uint8_t w[60][4];

    const int Nb = 4;
    const int totalWords = Nb * (Nr + 1); // 44, 52, 60

    // Kopiujemy klucz wejœciowy do pierwszych Nk s³ów
    for (int i = 0; i < Nk; ++i)
    {
        w[i][0] = key[4 * i + 0];
        w[i][1] = key[4 * i + 1];
        w[i][2] = key[4 * i + 2];
        w[i][3] = key[4 * i + 3];
    }

    // Generujemy kolejne s³owa
    for (int i = Nk; i < totalWords; ++i)
    {
        uint8_t temp[4];
        temp[0] = w[i - 1][0];
        temp[1] = w[i - 1][1];
        temp[2] = w[i - 1][2];
        temp[3] = w[i - 1][3];

        if (i % Nk == 0)
        {
            rotWord(temp);
            subWord(temp);
            temp[0] ^= Rcon(i / Nk);
        }
        else if (Nk > 6 && (i % Nk) == 4)
        {
            subWord(temp);
        }

        w[i][0] = w[i - Nk][0] ^ temp[0];
        w[i][1] = w[i - Nk][1] ^ temp[1];
        w[i][2] = w[i - Nk][2] ^ temp[2];
        w[i][3] = w[i - Nk][3] ^ temp[3];
    }

    // Przepisujemy s³owa do roundKeys
    for (int r = 0; r <= Nr; ++r)
    {
        for (int c = 0; c < Nb; ++c)
        {
            roundKeys[r][4 * c + 0] = w[4 * r + c][0];
            roundKeys[r][4 * c + 1] = w[4 * r + c][1];
            roundKeys[r][4 * c + 2] = w[4 * r + c][2];
            roundKeys[r][4 * c + 3] = w[4 * r + c][3];
        }
    }
}

void AES::subBytes(State& st) const
{
    for (auto& b : st)
        b = sbox[b];
}

void AES::shiftRows(State& st) const
{
    State tmp = st;

    tmp[0] = st[0];
    tmp[4] = st[4];
    tmp[8] = st[8];
    tmp[12] = st[12];

    tmp[1] = st[5];
    tmp[5] = st[9];
    tmp[9] = st[13];
    tmp[13] = st[1];

    tmp[2] = st[10];
    tmp[6] = st[14];
    tmp[10] = st[2];
    tmp[14] = st[6];

    tmp[3] = st[15];
    tmp[7] = st[3];
    tmp[11] = st[7];
    tmp[15] = st[11];

    st = tmp;
}

void AES::mixColumns(State& st) const
{
    for (int c = 0; c < 4; c++)
    {
        int i = 4 * c;
        uint8_t a0 = st[i], a1 = st[i + 1], a2 = st[i + 2], a3 = st[i + 3];

        st[i] = static_cast<uint8_t>(xtime(a0) ^ (xtime(a1) ^ a1) ^ a2 ^ a3);
        st[i + 1] = static_cast<uint8_t>(a0 ^ xtime(a1) ^ (xtime(a2) ^ a2) ^ a3);
        st[i + 2] = static_cast<uint8_t>(a0 ^ a1 ^ xtime(a2) ^ (xtime(a3) ^ a3));
        st[i + 3] = static_cast<uint8_t>((xtime(a0) ^ a0) ^ a1 ^ a2 ^ xtime(a3));
    }
}

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

void AES::invSubBytes(State& st) const
{
    for (auto& b : st)
        b = inv_sbox[b];
}

void AES::invShiftRows(State& st) const
{
    State tmp = st;

    tmp[0] = st[0];
    tmp[4] = st[4];
    tmp[8] = st[8];
    tmp[12] = st[12];

    tmp[1] = st[13];
    tmp[5] = st[1];
    tmp[9] = st[5];
    tmp[13] = st[9];

    tmp[2] = st[10];
    tmp[6] = st[14];
    tmp[10] = st[2];
    tmp[14] = st[6];

    tmp[3] = st[7];
    tmp[7] = st[11];
    tmp[11] = st[15];
    tmp[15] = st[3];

    st = tmp;
}

void AES::invMixColumns(State& st) const
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
