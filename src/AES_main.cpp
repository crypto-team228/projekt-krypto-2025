#include <iostream>
#include <iomanip>
#include <string>
#include <vector>
#include <array>

#include "AES/aes.hpp"


std::vector<std::array<uint8_t, 16>> split_to_128bit_blocks(const std::string& text) {
    std::vector<std::array<uint8_t, 16>> blocks;

    std::array<uint8_t, 16> block{};
    size_t index = 0;

    for (unsigned char c : text) {
        block[index++] = c;

        if (index == 16) {
            blocks.push_back(block);
            block.fill(0);
            index = 0;
        }
    }

    // if leftover bytes exist, add padded block
    if (index > 0) {
        for (size_t i = index; i < 16; i++) {
            block[i] = 0;  
        }
        blocks.push_back(block);
    }

    return blocks;
};


std::string fromBlocksToString(const std::vector<std::array<uint8_t, 16>>& blocks) {
    std::string result;

    for (const auto& block : blocks) {
        for (uint8_t byte : block) {
            if (byte == 0) break;  
            result += static_cast<char>(byte);
        }
    }

    return result;
};


void printBlock(const AES::State &st)
{
    for (int i = 0; i < 16; i++)
    {
        std::cout << std::hex << std::setfill('0')
                  << std::setw(2) << (int)st[i] << " ";
    }
    std::cout << "\n";
};

int main()
{
    std::cout << "========================================\n";
    std::cout << "         AES Encryption/Decryption     \n";
    std::cout << "========================================\n\n";

    AES::Key128 key = {
        0x2b, 0x28, 0xab, 0x09, 0x7e, 0xae, 0xf7, 0xcf,
        0x15, 0xd2, 0x15, 0x4f, 0x16, 0xa6, 0x88, 0x3c
    };

    AES aes(key);

    auto blocks = split_to_128bit_blocks("This is a test message for AES encryption!");
    for (const auto& b : blocks) {
        printBlock(b);
    }
    std::cout << "Original Text: This is a test message for AES encryption!\n";
    std::cout << "\n";

    EncodeAES encodeAes(key);
    encodeAes.encryptBlocks(blocks);

    std::cout << "Encrypted Blocks:\n";
    for (const auto& b : blocks) {
        printBlock(b);
    }
    std::string encryptedText = fromBlocksToString(blocks);
    std::cout << "Encrypted Text: " << "\n" << encryptedText << "\n\n";

    DecodeAES decodeAes(key);
    decodeAes.decryptBlocks(blocks);
    std::cout << "Decrypted Blocks:\n";
    for (const auto& b : blocks) {
        printBlock(b);
    }
    std::string decryptedText = fromBlocksToString(blocks);
    std::cout << "Decrypted Text: " << "\n" << decryptedText << "\n";

    return 0;
}
