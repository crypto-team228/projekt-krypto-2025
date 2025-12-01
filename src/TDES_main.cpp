#include <iostream>
#include "mylib.hpp"
#include "TDES/tdes.hpp"

int main() {
	TDES tdes = TDES();
	
	std::string plaintext = "0123456789ABCDEF";
	std::string key1 = "033457799BBCDFF1";
	std::string key2 = "133457799BBCDFF1";
	std::string key3 = "233457799BBCDFF1";
	std::string ciphertext = tdes.EncryptBlock(plaintext,key1, key2, key3);
	std::string decryptedtext = tdes.DecryptBlock(ciphertext,key1, key2, key3);

	std::cout << "Plaintext: " << plaintext << std::endl;

	std::cout << "Ciphertext: " << tdes.BitArrayToHexString(tdes.StringToBitArray<64>(ciphertext)) << std::endl;
	std::cout << "Decrypted Text: " << decryptedtext << std::endl;
	
	return 0;
}
