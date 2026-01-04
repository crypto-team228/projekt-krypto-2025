#pragma once
#include <array>
#include <cstdint>
#include <iostream>
#include <iomanip>
#include <vector>

#include <cipher/cipher.hpp>


class AES : public Cipher
{
public:
    using State = std::array<uint8_t, 16>;
    using Key128 = std::array<uint8_t, 16>;
    using RoundKeys = std::array<State, 11>; // 11 round keys for AES-128

    // --- S-box ---
    static const std::array<uint8_t, 256> sbox;    
    // --- Inverse S-box ---
    static const std::array<uint8_t, 256> inv_sbox;

    RoundKeys roundKeys;

    AES(const Key128 &key);
    AES();

    // GF(2^8) multiply by 2
    static inline uint8_t xtime(uint8_t x);
    
    void addRoundKey(State &st, const State &key) const;

    // --- Key expansion helper functions ---
    static uint8_t Rcon(int i);

    static void rotWord(uint8_t *w);

    static void subWord(uint8_t *w);

    // --- Key Expansion (AES-128) ---
    void keyExpansion(const Key128 &key);


    // Encrypt 16-byte block (ECB mode)
    std::string encryptBlock(const std::string& data, std::string key) override;

    std::string decryptBlock(const std::string& data, std::string key) override;

    // --- AES forward operations ---
    void subBytes(State& st) const;

    void shiftRows(State& st) const;

    void mixColumns(State& st) const;


    static uint8_t gmul(uint8_t a, uint8_t b);

    // --- AES inverse operations (for decryption) ---
    void invSubBytes(State& st) const;

    void invShiftRows(State& st) const;

    void invMixColumns(State& st) const;
};
