#include <iostream>
#include "utils/DataConverter.hpp"
#include "cipher/TDES/tdes.hpp"
#include "mode/mode.hpp"
#include "mode/ECB.hpp"
#include "mode/CBC.hpp"
#include "mode/CTR.hpp"


int main() {

	std::string text = "0123456789ABCDEF0123456789ABCDEF";
	std::vector<uint8_t> plaintext = DataConverter::HexToBytes(text);
	std::vector<uint8_t> keyBytes = DataConverter::HexToBytes("033457799BBCDFF1133457799BBCDFF1233457799BBCDFF1");
	std::string expectedEncrypted = "37d174403fc04f1a";

	TDES tdes(keyBytes);

	ECB ecb;
	auto test = ecb.encrypt(plaintext, tdes);
	std::cout << "Encrypted: ";
	for (auto b : test) {
		std::cout << std::hex << (int)b;
	}

	std::cout << std::endl;
	std::cout << "Expected : " << expectedEncrypted << std::endl;



	return 0;
}
