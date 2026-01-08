#include <mode/ECB.hpp>

std::vector<uint8_t> ECB::encrypt(const std::vector<uint8_t>& data, Cipher& cipher) {
    const size_t blockSize = cipher.blockSize();
    const size_t dataSize = data.size();

    std::vector<uint8_t> out(dataSize);

    for (size_t i = 0; i < dataSize; i += blockSize) {
        cipher.encryptBlock(&data[i], &out[i]);
    }

    return out;
}


std::vector<uint8_t> ECB::decrypt(const std::vector<uint8_t>& data, Cipher& cipher) {
    const size_t blockSize = cipher.blockSize();
    const size_t dataSize = data.size();

    std::vector<uint8_t> out(dataSize);

    for (size_t i = 0; i < dataSize; i += blockSize) {
        cipher.decryptBlock(&data[i], &out[i]);
    }

    return out;
}
