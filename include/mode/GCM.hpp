#pragma once

#include <array>
#include <cstdint>
#include <vector>
#include <algorithm>
#include <stdexcept>

#include "cipher/cipher.hpp"

class GCM {
public:
    GCM(std::vector<uint8_t> iv, std::vector<uint8_t> aad = {});

    // Szyfruje dane w trybie GCM przy użyciu bieżącego szyfru blokowego.
    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& data, Cipher& cipher);

    // Odszyfrowuje dane w trybie GCM przy użyciu bieżącego szyfru blokowego.
    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& data, Cipher& cipher);

    // Ustawienie IV (16 bajtów, traktowany jako 128‑bitowy licznik startowy CTR).
    void setIV(const std::vector<uint8_t>& initVector);

    // Ustawienie dodatkowych danych uwierzytelnianych.
    void setAAD(const std::vector<uint8_t>& additionalData);

    // Zwraca aktualny tag uwierzytelniający (16 bajtów).
    std::vector<uint8_t> getTag();

    // Sprawdza, czy podany tag jest równy aktualnemu authTag.
    bool verifyTag(const std::vector<uint8_t>& tag);

private:
    // Inicjalizacja klucza GHASH: H = E_K(0^128)
    // E_K to używany szyfr blokowy 128‑bitowy.
    void initGhashKey();

    // Mnożenie w GF(2^128) dla GHASH.
    void gfMul128(std::array<uint8_t, 16>& x, const std::array<uint8_t, 16>& y) const;

    // GHASH nad zadanymi danymi z użyciem klucza ghashKey.
    void ghash(const std::vector<uint8_t>& data, std::array<uint8_t, 16>& result) const;

    // GHASH ostatniego bloku z długościami AAD i ciphertextu.
    void ghashLengths(uint64_t aadBits,
        uint64_t cipherBits,
        std::array<uint8_t, 16>& S) const;

    // Inkrementacja 128‑bitowego licznika (big‑endian).
    void incCounter(std::array<uint8_t, 16>& counter) const;

    // CTR: in -> out przy użyciu E_K(counter), counter++.
    void ctrCrypt(const std::vector<uint8_t>& in,
        std::vector<uint8_t>& out,
        const std::array<uint8_t, 16>& initialCounter);

    // Jednoblokowe szyfrowanie "in place" przez aktualnie ustawiony szyfr blokowy.
    void encryptBlock(std::array<uint8_t, 16>& block);

private:
    std::vector<uint8_t> iv{};
    std::array<uint8_t, 16> ghashKey{};   // H
    std::array<uint8_t, 16> authTag{};    // T
    std::vector<uint8_t> aad;

    Cipher* currentCipher = nullptr;
    bool ivSet = false;
};
