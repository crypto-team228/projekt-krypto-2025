#include <iostream>
#include <iomanip>
#include <string>
#include <vector>
#include <array>

#include "cipher/AES/aes.hpp"
#include "mode/mode.hpp"
#include "mode/ecb.hpp"
#include "mode/ctr.hpp"
#include "mode/cbc.hpp"

std::vector<std::vector<uint8_t>> split_to_128bit_blocks(const std::string& text)
{
    std::vector<std::vector<uint8_t>> blocks;

    std::vector<uint8_t> block(16, 0);
    size_t index = 0;

    for (unsigned char c : text)
    {
        block[index++] = c;

        if (index == 16)
        {
            blocks.push_back(block);
            block.assign(16, 0);
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
}


std::string fromBlocksToString(const std::vector<std::vector<uint8_t>> &blocks)
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

std::vector<uint8_t> blocksToBytes(const std::vector<std::vector<uint8_t>> &blocks)
{
    std::vector<uint8_t> result;
    for (const auto &block : blocks)
    {
        result.insert(result.end(), block.begin(), block.end());
    }
    return result;
}

std::vector<std::vector<uint8_t>> bytesToBlocks(const std::vector<uint8_t>& bytes)
{
    std::vector<std::vector<uint8_t>> blocks;

    for (size_t i = 0; i < bytes.size(); i += 16)
    {
        std::vector<uint8_t> block(16, 0);

        size_t remaining = bytes.size() - i;
        size_t toCopy = remaining < 16 ? remaining : 16;

        std::copy_n(bytes.begin() + i, toCopy, block.begin());

        blocks.push_back(block);
    }

    return blocks;
}


void printBlock(const std::vector<uint8_t> &st)
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
    ECB ecb;



    std::cout << "========================================\n";
    std::cout << "         AES Encryption/Decryption     \n";
    std::cout << "========================================\n\n";

    std::cout << "Wprowadź tekst do zaszyfrowania (max 256 znaków): ";
    std::string plaintext;
    std::getline(std::cin, plaintext);

    std::string secret_key = "Awawqwer123!!90L"; // 16 bytes = 128 bits

    std::vector<uint8_t> key = split_to_128bit_blocks(secret_key)[0];
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
    auto enc = ecb.encrypt(data, aes);
    blocks = bytesToBlocks(enc);

    std::cout << "Encrypted Blocks:\n";
    for (const auto &b : blocks)
    {
        printBlock(b);
    }
    std::string encryptedText = fromBlocksToString(blocks);
    std::cout << "Encrypted Text: " << "\n"
              << encryptedText << "\n\n";

    auto dec = ecb.decrypt(enc, aes);
    blocks = bytesToBlocks(dec);
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
