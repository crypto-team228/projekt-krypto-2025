#include <CLI/CLI.hpp>
#include <string>
#include <vector>
#include <iostream>
#include <stdexcept>

#include <core/cipherFactory.hpp>
#include <core/modeFactory.hpp>
#include <mode/CBC.hpp>
#include <mode/CTR.hpp>
#include <mode/ECB.hpp>
#include <mode/blockMode.hpp>
#include <utils/DataConverter.hpp>

std::vector<uint8_t> decode(const std::string& input, const std::string& encoding) {
    if (encoding == "utf8") {
        return std::vector<uint8_t>(input.begin(), input.end());
    }
    if (encoding == "hex") {
        return DataConverter::HexToBytes(input);
    }
    if (encoding == "base64") {
        throw std::runtime_error("base64 not implemented");
    }
    throw std::runtime_error("Unknown encoding: " + encoding);
}

void validateKey(const std::vector<uint8_t>& key, const std::string& algorithm) {
    if (algorithm == "AES") {
        if (key.size() != 16 && key.size() != 24 && key.size() != 32) {
            throw std::runtime_error("AES key must be 16, 24, or 32 bytes (128/192/256 bits). Got: " + std::to_string(key.size()) + " bytes");
        }
    } else if (algorithm == "TDES") {
        if (key.size() != 24) {
            throw std::runtime_error("TDES key must be 24 bytes (192 bits). Got: " + std::to_string(key.size()) + " bytes");
        }
    } else {
        throw std::runtime_error("Unknown algorithm: " + algorithm);
    }
}

void validateIV(const std::vector<uint8_t>& iv, const std::string& algorithm, const std::string& mode) {
    if (mode == "ECB") {
        return; // ECB doesn't need IV
    }

    size_t requiredSize = (algorithm == "AES") ? 16 : 8;
    if (iv.empty()) {
        throw std::runtime_error("IV is required for " + mode + " mode");
    }
    if (iv.size() != requiredSize) {
        throw std::runtime_error("IV must be " + std::to_string(requiredSize) + " bytes for " + algorithm + ". Got: " + std::to_string(iv.size()) + " bytes");
    }
}

int main(int argc, char** argv) {
    CLI::App app{"Crypto CLI - AES/TDES Encryption/Decryption Tool"};

    std::string text;
    std::string text_encoding = "utf8";

    std::string key;
    std::string key_encoding = "hex";

    std::string mode = "CBC";
    std::string iv;

    std::string algorithm = "AES";
    std::string operation = "encrypt";
    std::string padding = "PKCS7";
    std::string output_encoding = "hex";

    // Text options
    app.add_option("--text,-t", text, "Text to encrypt/decrypt")->required();
    app.add_option("--text-encoding", text_encoding, "Text encoding (utf8, hex)");

    // Key options
    app.add_option("--key,-k", key, "Encryption key")->required();
    app.add_option("--key-encoding", key_encoding, "Key encoding (hex, utf8)");

    // Algorithm and mode options
    app.add_option("--algorithm,-a", algorithm, "Algorithm (AES, TDES)");
    app.add_option("--mode,-m", mode, "Cipher mode (ECB, CBC, CTR)");
    app.add_option("--iv", iv, "Initialization vector (hex)");

    // Operation options
    app.add_option("--operation,-o", operation, "Operation (encrypt, decrypt)");
    app.add_option("--padding,-p", padding, "Padding mode (PKCS7, Zero, None)");
    app.add_option("--output-encoding", output_encoding, "Output encoding (hex, utf8)");

    CLI11_PARSE(app, argc, argv);

    try {
        // Normalize input
        auto data_bytes = decode(text, text_encoding);
        auto key_bytes = decode(key, key_encoding);
        auto iv_bytes = iv.empty() ? std::vector<uint8_t>() : decode(iv, "hex");

        // Validate inputs
        validateKey(key_bytes, algorithm);
        if (mode != "ECB") {
            validateIV(iv_bytes, algorithm, mode);
        }

        // Create cipher
        auto cipher = CipherFactory::create(algorithm);
        cipher->setKey(key_bytes);

        // Create mode
        auto modePtr = ModeFactory::create(mode);

        // Set IV for CBC/CTR
        if (mode == "CBC") {
            auto* cbc = dynamic_cast<CBC*>(modePtr.get());
            if (cbc) {
                cbc->setIV(iv_bytes);
            }
        } else if (mode == "CTR") {
            auto* ctr = dynamic_cast<CTR*>(modePtr.get());
            if (ctr) {
                ctr->setIV(iv_bytes);
            }
        }

        // Set padding mode
        auto* blockMode = dynamic_cast<BlockMode*>(modePtr.get());
        if (blockMode) {
            if (padding == "PKCS7") {
                blockMode->setPadding(PaddingMode::PKCS7);
            } else if (padding == "Zero") {
                blockMode->setPadding(PaddingMode::ZeroPadding);
            } else if (padding == "None") {
                blockMode->setPadding(PaddingMode::None);
            } else {
                throw std::runtime_error("Unknown padding mode: " + padding);
            }
        }

        // Execute operation
        std::vector<uint8_t> result;
        if (operation == "encrypt") {
            result = modePtr->encrypt(data_bytes, *cipher);
        } else if (operation == "decrypt") {
            result = modePtr->decrypt(data_bytes, *cipher);
        } else {
            throw std::runtime_error("Unknown operation: " + operation + ". Use 'encrypt' or 'decrypt'");
        }

        // Output result
        if (output_encoding == "hex") {
            std::cout << DataConverter::BytesToHex(result) << std::endl;
        } else if (output_encoding == "utf8") {
            std::cout << std::string(result.begin(), result.end()) << std::endl;
        } else {
            throw std::runtime_error("Unknown output encoding: " + output_encoding);
        }

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
