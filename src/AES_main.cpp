#include <iostream>
#include <iomanip>
#include <string>
#include <vector>
#include <array>

#include "cipher/AES/aes.hpp"

std::vector<std::array<uint8_t, 16>> split_to_128bit_blocks(const std::string &text)
{
    std::vector<std::array<uint8_t, 16>> blocks;

    std::array<uint8_t, 16> block{};
    size_t index = 0;

    for (unsigned char c : text)
    {
        block[index++] = c;

        if (index == 16)
        {
            blocks.push_back(block);
            block.fill(0);
            index = 0;
        }
    }

    // PKCS7 padding
    uint8_t padding_value = static_cast<uint8_t>(16 - index);
    for (size_t i = index; i < 16; i++)
    {
        block[i] = padding_value;
    }
    blocks.push_back(block);

    return blocks;
};

std::string fromBlocksToString(const std::vector<std::array<uint8_t, 16>> &blocks)
{
    std::string result;

    for (const auto &block : blocks)
    {
        for (uint8_t byte : block)
        {
            result += static_cast<char>(byte);
        }
    }

    // Remove PKCS7 padding
    if (!result.empty())
    {
        uint8_t padding_value = static_cast<uint8_t>(result.back());
        if (padding_value > 0 && padding_value <= 16)
        {
            result.erase(result.end() - padding_value, result.end());
        }
    }

    return result;
};

std::vector<uint8_t> blocksToBytes(const std::vector<std::array<uint8_t, 16>> &blocks)
{
    std::vector<uint8_t> result;
    for (const auto &block : blocks)
    {
        result.insert(result.end(), block.begin(), block.end());
    }
    return result;
}

std::vector<std::array<uint8_t, 16>> bytesToBlocks(const std::vector<uint8_t> &bytes)
{
    std::vector<std::array<uint8_t, 16>> blocks;
    for (size_t i = 0; i < bytes.size(); i += 16)
    {
        std::array<uint8_t, 16> block;
        std::copy(bytes.begin() + i, bytes.begin() + i + 16, block.begin());
        blocks.push_back(block);
    }
    return blocks;
}

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

    std::cout << "Wprowadź tekst do zaszyfrowania (max 256 znaków): ";
    std::string plaintext;
    std::getline(std::cin, plaintext);

    std::string secret_key = "Awawqwer123!!90L"; // 16 bytes = 128 bits

    AES::Key128 key = split_to_128bit_blocks(secret_key)[0];
    std::cout << "Secret key in blocks\n";
    for (int i = 0; i < 16; i++)
    {
        std::cout << std::hex << std::setfill('0')
                  << std::setw(2) << (int)key[i] << " ";
    }
    std::cout << "\n";

    AES aes(key);

    auto blocks = split_to_128bit_blocks(plaintext);
    for (const auto &b : blocks)
    {
        printBlock(b);
    }
    std::cout << "Original Text:\n"
              << plaintext << "\n";
    std::cout << "\n";

    std::vector<uint8_t> data = blocksToBytes(blocks);
    aes.encryptBlock(data);
    blocks = bytesToBlocks(data);

    std::cout << "Encrypted Blocks:\n";
    for (const auto &b : blocks)
    {
        printBlock(b);
    }
    std::string encryptedText = fromBlocksToString(blocks);
    std::cout << "Encrypted Text: " << "\n"
              << encryptedText << "\n\n";

    aes.decryptBlock(data);
    blocks = bytesToBlocks(data);
    std::cout << "Decrypted Blocks:\n";
    for (const auto &b : blocks)
    {
        printBlock(b);
    }
    std::string decryptedText = fromBlocksToString(blocks);
    std::cout << "Decrypted Text: " << "\n"
              << decryptedText << "\n";

    return 0;
}
