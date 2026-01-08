#pragma once
#include <string>
#include <vector>
#include <array>
#include <cstdint>
#include <stdexcept>
#include <algorithm>

class DataConverter {
public:
    // STRING <-> HEX

    // string (bajty) -> hex ASCII (2 znaki na bajt)
    static std::string StringToHex(const std::string& input) {
        static const char* hex = "0123456789ABCDEF";
        std::string out;
        out.reserve(input.size() * 2);

        for (unsigned char c : input) {
            out.push_back(hex[c >> 4]);
            out.push_back(hex[c & 0x0F]);
        }
        return out;
    }

    // hex ASCII -> string (bajty)
    static std::string HexToString(const std::string& hex) {
        if (hex.size() % 2 != 0)
            throw std::invalid_argument("HexToString: hex length must be even");

        std::string out;
        out.reserve(hex.size() / 2);

        for (std::size_t i = 0; i < hex.size(); i += 2) {
            uint8_t high = HexCharToValue(hex[i]);
            uint8_t low = HexCharToValue(hex[i + 1]);
            out.push_back(static_cast<char>((high << 4) | low));
        }
        return out;
    }

    // BYTES <-> HEX

    static std::vector<uint8_t> HexToBytes(const std::string& hex) {
        if (hex.size() % 2 != 0)
            throw std::invalid_argument("HexToBytes: hex length must be even");

        std::vector<uint8_t> bytes;
        bytes.reserve(hex.size() / 2);

        for (std::size_t i = 0; i < hex.size(); i += 2) {
            uint8_t high = HexCharToValue(hex[i]);
            uint8_t low = HexCharToValue(hex[i + 1]);
            bytes.push_back(static_cast<uint8_t>((high << 4) | low));
        }
        return bytes;
    }

    static std::string BytesToHex(const std::vector<uint8_t>& bytes) {
        static const char* hex = "0123456789ABCDEF";
        std::string out;
        out.reserve(bytes.size() * 2);

        for (uint8_t b : bytes) {
            out.push_back(hex[b >> 4]);
            out.push_back(hex[b & 0x0F]);
        }
        return out;
    }

    template<std::size_t N>
    static std::string BytesToHex(const std::array<uint8_t, N>& bytes) {
        static const char* hex = "0123456789ABCDEF";
        std::string out;
        out.reserve(N * 2);

        for (uint8_t b : bytes) {
            out.push_back(hex[b >> 4]);
            out.push_back(hex[b & 0x0F]);
        }
        return out;
    }

	// HexToBytes dla std::array ma sens tylko, jeœli d³ugoœæ jest znana w czasie kompilacji
    template<std::size_t N>
    static std::array<uint8_t, N> HexToBytesFixed(const std::string& hex) {
        if (hex.size() != N * 2)
            throw std::invalid_argument("HexToBytesFixed: hex length must be exactly 2*N");

        std::array<uint8_t, N> bytes{};
        for (std::size_t i = 0; i < N; ++i) {
            uint8_t high = HexCharToValue(hex[2 * i]);
            uint8_t low = HexCharToValue(hex[2 * i + 1]);
            bytes[i] = static_cast<uint8_t>((high << 4) | low);
        }
        return bytes;
    }

    // STRING <-> BITS (wektor bitów, MSB-first)

    static std::vector<uint8_t> StringToBits(const std::string& input) {
        std::vector<uint8_t> bits;
        bits.reserve(input.size() * 8);

        for (unsigned char c : input) {
            for (int i = 7; i >= 0; i--) {
                bits.push_back(static_cast<uint8_t>((c >> i) & 1U));
            }
        }
        return bits;
    }

    static std::string BitsToString(const std::vector<uint8_t>& bits) {
        if (bits.size() % 8 != 0)
            throw std::invalid_argument("BitsToString: bit count must be multiple of 8");

        std::string out;
        out.reserve(bits.size() / 8);

        for (std::size_t i = 0; i < bits.size(); i += 8) {
            uint8_t byte = 0;
            for (int j = 0; j < 8; j++) {
                byte = static_cast<uint8_t>((byte << 1) | (bits[i + j] & 1U));
            }
            out.push_back(static_cast<char>(byte));
        }
        return out;
    }

    template<std::size_t N>
    static std::array<uint8_t, N> StringToBitArray(const std::string& input) {
        std::array<uint8_t, N> bits{};
        std::size_t bitCount = std::min<std::size_t>(N, input.size() * 8);

        for (std::size_t i = 0; i < bitCount; i++) {
            uint8_t byte = static_cast<uint8_t>(input[i / 8]);
            bits[i] = static_cast<uint8_t>((byte >> (7 - (i % 8))) & 1U);
        }
        return bits;
    }

    template<std::size_t N>
    static std::string BitArrayToString(const std::array<uint8_t, N>& bits) {
        static_assert(N % 8 == 0, "BitArrayToString: N must be multiple of 8");
        std::string out;
        out.reserve(N / 8);

        for (std::size_t i = 0; i < N; i += 8) {
            uint8_t byte = 0;
            for (int j = 0; j < 8; j++) {
                byte = static_cast<uint8_t>((byte << 1) | (bits[i + j] & 1U));
            }
            out.push_back(static_cast<char>(byte));
        }
        return out;
    }

    // BYTES <-> BITS

    static std::vector<uint8_t> BytesToBits(const std::vector<uint8_t>& bytes) {
        std::vector<uint8_t> bits;
        bits.reserve(bytes.size() * 8);

        for (uint8_t b : bytes) {
            for (int i = 7; i >= 0; i--) {
                bits.push_back(static_cast<uint8_t>((b >> i) & 1U));
            }
        }
        return bits;
    }

    static std::vector<uint8_t> BitsToBytes(const std::vector<uint8_t>& bits) {
        if (bits.size() % 8 != 0)
            throw std::invalid_argument("BitsToBytes: bit count must be multiple of 8");

        std::vector<uint8_t> bytes;
        bytes.reserve(bits.size() / 8);

        for (std::size_t i = 0; i < bits.size(); i += 8) {
            uint8_t byte = 0;
            for (int j = 0; j < 8; j++) {
                byte = static_cast<uint8_t>((byte << 1) | (bits[i + j] & 1U));
            }
            bytes.push_back(byte);
        }
        return bytes;
    }

    template<std::size_t N>
    static std::array<uint8_t, N * 8> BytesArrayToBits(const std::array<uint8_t, N>& bytes) {
        std::array<uint8_t, N * 8> bits{};
        for (std::size_t i = 0; i < N; ++i) {
            uint8_t b = bytes[i];
            for (int j = 7; j >= 0; --j) {
                bits[i * 8 + (7 - j)] = static_cast<uint8_t>((b >> j) & 1U);
            }
        }
        return bits;
    }

    template<std::size_t N>
    static std::array<uint8_t, N / 8> BitsArrayToBytes(const std::array<uint8_t, N>& bits) {
        static_assert(N % 8 == 0, "BitsArrayToBytes: N must be multiple of 8");
        std::array<uint8_t, N / 8> bytes{};

        for (std::size_t i = 0; i < N; i += 8) {
            uint8_t byte = 0;
            for (int j = 0; j < 8; j++) {
                byte = static_cast<uint8_t>((byte << 1) | (bits[i + j] & 1U));
            }
            bytes[i / 8] = byte;
        }
        return bytes;
    }
    

    // HEX <-> BITS

    static std::vector<uint8_t> HexToBits(const std::string& hex) {
        std::vector<uint8_t> bits;
        bits.reserve(hex.size() * 4);

        for (char c : hex) {
            uint8_t value = HexCharToValue(c);
            bits.push_back(static_cast<uint8_t>((value >> 3) & 1U));
            bits.push_back(static_cast<uint8_t>((value >> 2) & 1U));
            bits.push_back(static_cast<uint8_t>((value >> 1) & 1U));
            bits.push_back(static_cast<uint8_t>((value >> 0) & 1U));
        }
        return bits;
    }

    static std::string BitsToHex(const std::vector<uint8_t>& bits) {
        if (bits.size() % 4 != 0)
            throw std::invalid_argument("BitsToHex: bit count must be multiple of 4");

        std::string hex;
        hex.reserve(bits.size() / 4);

        for (std::size_t i = 0; i < bits.size(); i += 4) {
            uint8_t value =
                static_cast<uint8_t>((bits[i] << 3) |
                    (bits[i + 1] << 2) |
                    (bits[i + 2] << 1) |
                    (bits[i + 3]));
            hex.push_back(ValueToHexChar(value));
        }
        return hex;
    }

    template<std::size_t N>
    static std::array<uint8_t, N * 4> HexToBitArray(const std::array<char, N>& hex) {
        std::array<uint8_t, N * 4> bits{};
        for (std::size_t i = 0; i < N; ++i) {
            uint8_t value = HexCharToValue(hex[i]);
            bits[i * 4 + 0] = static_cast<uint8_t>((value >> 3) & 1U);
            bits[i * 4 + 1] = static_cast<uint8_t>((value >> 2) & 1U);
            bits[i * 4 + 2] = static_cast<uint8_t>((value >> 1) & 1U);
            bits[i * 4 + 3] = static_cast<uint8_t>((value >> 0) & 1U);
        }
        return bits;
    }

    template<std::size_t N>
    static std::array<char, N / 4> BitArrayToHex(const std::array<uint8_t, N>& bits) {
        static_assert(N % 4 == 0, "BitArrayToHex: N must be multiple of 4");
        std::array<char, N / 4> hex{};

        for (std::size_t i = 0; i < N; i += 4) {
            uint8_t value =
                static_cast<uint8_t>((bits[i] << 3) |
                    (bits[i + 1] << 2) |
                    (bits[i + 2] << 1) |
                    (bits[i + 3]));
            hex[i / 4] = ValueToHexChar(value);
        }
        return hex;
    }

	// BYTES <-> ARRAY
    template<std::size_t N>
    static std::array<uint8_t, N> BytesToArray(const uint8_t* in) {
        std::array<uint8_t, N> arr{};
        for (std::size_t i = 0; i < N; i++) {
            arr[i] = in[i];
        }
        return arr;
    }

    template<std::size_t N>
    static void ArrayToBytes(const std::array<uint8_t, N>& arr, uint8_t* out) {
        for (std::size_t i = 0; i < N; i++) {
            out[i] = arr[i];
        }
    }


private:
    static uint8_t HexCharToValue(char c) {
        if (c >= '0' && c <= '9') return static_cast<uint8_t>(c - '0');
        if (c >= 'A' && c <= 'F') return static_cast<uint8_t>(c - 'A' + 10);
        if (c >= 'a' && c <= 'f') return static_cast<uint8_t>(c - 'a' + 10);
        throw std::invalid_argument("Invalid hex character");
    }

    static char ValueToHexChar(uint8_t v) {
        static const char* hex = "0123456789ABCDEF";
        return hex[v & 0x0F];
    }
};
