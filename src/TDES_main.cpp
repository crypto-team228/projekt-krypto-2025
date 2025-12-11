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
	std::string expectedEncrypted = "37d174403fc04f1a";

	std::cout << "Plaintext: " << plaintext << std::endl;
	std::cout << "Key: " << key1 + key2 + key3 << std::endl;
	std::cout << "\n";
	std::cout << "Encrypted Ciphertext: " << tdes.BitArrayToHexString(tdes.StringToBitArray<64>(ciphertext)) << std::endl;
	std::cout << "Expected Ciphertext:  " << expectedEncrypted << std::endl;
	std::cout << "\n";
	std::cout << "Decrypted Text: " << decryptedtext << std::endl;
	std::cout << "Expected Text:  " << plaintext << std::endl;
	std::cout << "\n\n";

	return 0;
}
