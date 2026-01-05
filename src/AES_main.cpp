#include <iostream>
#include <iomanip>
#include <string>
#include <vector>
#include <array>

#include "AES/aes.hpp"

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
                  << std::setw(2) << (int)st[i];
    }
    std::cout << "\n";
};

int main()
{
    std::cout << "========================================\n";
    std::cout << "         AES Encryption/Decryption     \n";
    std::cout << "========================================\n\n";

    // Wybór trybu szyfrowania
    std::cout << "Wybierz tryb szyfrowania:\n";
    std::cout << "1. ECB (Electronic Codebook)\n";
    std::cout << "2. CBC (Cipher Block Chaining)\n";
    std::cout << "3. CTR (Counter)\n";
    std::cout << "Wybór: ";

    int modeChoice;
    std::cin >> modeChoice;
    std::cin.ignore(); // Clear newline from buffer

    Mode selectedMode;
    switch (modeChoice)
    {
    case 1:
        selectedMode = Mode::ECB;
        std::cout << "Wybrany tryb: ECB\n\n";
        break;
    case 2:
        selectedMode = Mode::CBC;
        std::cout << "Wybrany tryb: CBC\n\n";
        break;
    case 3:
        selectedMode = Mode::CTR;
        std::cout << "Wybrany tryb: CTR\n\n";
        break;
    default:
        std::cout << "Nieprawidłowy wybór. Ustawiam ECB.\n\n";
        selectedMode = Mode::ECB;
        break;
    }

    std::cout << "Wprowadź klucz szyfrowania (dokładnie 16 znaków): ";
    std::string secret_key;
    std::getline(std::cin, secret_key);

    // Upewnij się, że klucz ma dokładnie 16 bajtów
    if (secret_key.length() < 16)
    {
        secret_key.resize(16, '0'); // Wypełnij zerami
        std::cout << "Uwaga: Klucz był za krótki, został uzupełniony do 16 znaków.\n";
    }
    else if (secret_key.length() > 16)
    {
        secret_key = secret_key.substr(0, 16); // Obetnij do 16 znaków
        std::cout << "Uwaga: Klucz był za długi, został obcięty do 16 znaków.\n";
    }

    AES::Key128 key = split_to_128bit_blocks(secret_key)[0];

    AES aes(key);
    aes.setMode(selectedMode);

    // Dla trybów CBC i CTR ustaw IV
    if (selectedMode == Mode::CBC || selectedMode == Mode::CTR)
    {
        std::cout << "Wprowadź wektor inicjalizujący IV (dokładnie 16 znaków): ";
        std::string iv_string;
        std::getline(std::cin, iv_string);

        // Upewnij się, że IV ma dokładnie 16 bajtów
        if (iv_string.length() < 16)
        {
            iv_string.resize(16, '0'); // Wypełnij zerami
            std::cout << "Uwaga: IV był za krótki, został uzupełniony do 16 znaków.\n";
        }
        else if (iv_string.length() > 16)
        {
            iv_string = iv_string.substr(0, 16); // Obetnij do 16 znaków
            std::cout << "Uwaga: IV był za długi, został obcięty do 16 znaków.\n";
        }

        std::vector<uint8_t> iv(iv_string.begin(), iv_string.end());
        aes.setIV(iv);
    }

    std::cout << "\nWprowadź tekst do zaszyfrowania (max 256 znaków): ";
    std::string plaintext;
    std::getline(std::cin, plaintext);

    auto blocks = split_to_128bit_blocks(plaintext);
    std::cout << "\nOriginal Blocks:\n";
    for (const auto &b : blocks)
    {
        printBlock(b);
    }
    std::cout << "Original Text:\n"
              << plaintext << "\n";
    std::cout << "\n";

    std::vector<uint8_t> data = blocksToBytes(blocks);
    aes.encrypt(data);
    blocks = bytesToBlocks(data);

    std::cout << "Encrypted Blocks:\n";
    for (const auto &b : blocks)
    {
        printBlock(b);
    }
    std::string encryptedText = fromBlocksToString(blocks);
    std::cout << "Encrypted Text: " << "\n"
              << encryptedText << "\n\n";

    aes.decrypt(data);
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
