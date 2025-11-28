#include <iostream>
#include "mylib.hpp"
#include "TDES/tdes.hpp"

int main() {
	TDES tdes = TDES();
	std::string plaintext1 = "123456ABCD132536";
	std::string key1 = "AABB09182736CCDD";

	std::string plaintext2 = "0123456789ABCDEF";
	std::string key2 = "133457799BBCDFF1";
	std::string ciphertext = tdes.Encrypt(plaintext2, key2);
	std::string decryptedtext = tdes.Decrypt(ciphertext, key2);

	std::cout << "Plaintext: " << plaintext2 << std::endl;

	//std::string cipher, recovered, hex;
	//
	//CBC_Mode<DES>::Encryption encryptor;
	//

	//
	//auto bits = tdes.HexStringToBitArray<64>(key); 
	//const byte* p = bits.data(); 

	//std::array<byte, 8> keyBytes{};
	//for (size_t i = 0; i < 8; ++i) {
	//	byte b = 0;
	//	for (int bit = 0; bit < 8; ++bit) {
	//		b = (b << 1) | (bits[i * 8 + bit] & 0x1);
	//	}
	//	keyBytes[i] = b;
	//}
	//
	//encryptor.SetKey(keyBytes.data(), keyBytes.size());


	//StringSource ss1(plaintext, true,
	//	new StreamTransformationFilter(encryptor,
	//		new StringSink(cipher)
	//	)
	//);
	//
	//std::cout << "Crypto++ Ciphertext: " << hex << std::endl;
	
	std::cout << "TEST "<< std::endl;
	std::cout << "Ciphertext: " << tdes.BitArrayToHexString(tdes.StringToBitArray<64>(ciphertext)) << std::endl;
	std::cout << "Decrypted Text: " << decryptedtext << std::endl;
	
	return 0;
}
