#include <iostream>
#include "utils/DataConverter.hpp"
#include "cipher/TDES/tdes.hpp"
#include "cipher/TDES/tdes_Bitslice_AVX2.hpp"
#include "cipher/AES/aes.hpp"
#include "mode/mode.hpp"
#include "mode/ECB.hpp"
#include "mode/CBC.hpp"
#include "mode/CTR.hpp"


int main() {

	std::cout << "TDES Bitslice AVX2 Test\n";


	std::string text = "0123456789ABCDEF0123456789ABCDEF";
	std::vector<uint8_t> plaintext = DataConverter::HexToBytes(text);
	std::vector<uint8_t> keyBytes = DataConverter::HexToBytes("033457799BBCDFF1133457799BBCDFF1233457799BBCDFF1");
	std::vector<uint8_t> IV ;
	std::string expectedEncrypted = "37d174403fc04f1a";

	TDES tdes(keyBytes);

	ECB ecb;
	ecb.setPadding(PaddingMode::None);
	auto test = ecb.encrypt(plaintext, tdes);
	std::cout << "Encrypted: ";
	for (auto b : test) {
		std::cout << std::hex << (int)b;
	}

	std::cout << std::endl;
	std::cout << "Expected : " << expectedEncrypted << std::endl;


	text = "0123456789ABCDEF";
	plaintext = DataConverter::HexToBytes(text);
	keyBytes = DataConverter::HexToBytes("033457799BBCDFF1133457799BBCDFF1233457799BBCDFF1");
	expectedEncrypted = "37d174403fc04f1a";

	
	TDES_Bitslice_AVX2 tdes_bi_avx2(keyBytes);
	ECB ecb_bi;
	ecb_bi.setPadding(PaddingMode::None);
	auto test_bi = ecb_bi.encrypt(plaintext, tdes_bi_avx2);
	std::cout << "Encrypted: ";
	for (auto b : test_bi) {
		std::cout << std::hex << (int)b;
	}
	std::cout << std::endl;
	std::cout << "Expected : " << expectedEncrypted << std::endl;





	return 0;
}
