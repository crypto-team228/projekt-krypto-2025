#include <iostream>
#include <iomanip>
#include "aes.cpp"

void printBlock(const AES::State &st, const std::string &label = "")
{
    if (!label.empty())
        std::cout << label << ":\n";

    for (int i = 0; i < 16; i++)
    {
        std::cout << std::hex << std::setfill('0')
                  << std::setw(2) << (int)st[i] << " ";
    }
    std::cout << "\n\n";
}

int main()
{
    AES::Key128 key = {
        0x2b, 0x28, 0xab, 0x09, 0x7e, 0xae, 0xf7, 0xcf,
        0x15, 0xd2, 0x15, 0x4f, 0x16, 0xa6, 0x88, 0x3c};

    AES aes(key);
    AES::State block = {
        0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
        0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34};

    AES::State original = block; 

    printBlock(block, "Plaintext block");

    aes.encryptBlock(block);

    printBlock(block, "Ciphertext block");

    aes.decryptBlock(block);

    printBlock(block, "Decrypted block");

    // Verify roundtrip
    bool success = true;
    for (int i = 0; i < 16; i++)
    {
        if (block[i] != original[i])
        {
            success = false;
            break;
        }
    }

    std::cout << "Encryption roundtrip: "
              << (success ? "SUCCESS" : "FAILED") << "\n";

    return 0;
}
