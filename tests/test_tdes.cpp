#include <iostream>
#include <iomanip>
#include <string>
#include <vector>
#include "TDES\tdes.hpp"

int main() {
	TDES tdes;

	std::string plaintext = "0123456789ABCDEF";
	std::string key1 = "033457799BBCDFF1";
	std::string key2 = "133457799BBCDFF1";
	std::string key3 = "233457799BBCDFF1";
	std::string ciphertext = tdes.EncryptBlock(plaintext, key1, key2, key3);
	std::string decryptedtext = tdes.DecryptBlock(ciphertext, key1, key2, key3);
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


	plaintext = "FEDCBA9876543210";
	key1 = "233457799BBCDFF1";
	key2 = "133457799BBCDFF1";
	key3 = "033457799BBCDFF1";
	ciphertext = tdes.EncryptBlock(plaintext, key1, key2, key3);
	decryptedtext = tdes.DecryptBlock(ciphertext, key1, key2, key3);
	expectedEncrypted = "473eeb07b08f7d13";

	std::cout << "Plaintext: " << plaintext << std::endl;
	std::cout << "Key: " << key1 + key2 + key3 << std::endl;
	std::cout << "\n";
	std::cout << "Encrypted Ciphertext: " << tdes.BitArrayToHexString(tdes.StringToBitArray<64>(ciphertext)) << std::endl;
	std::cout << "Expected Ciphertext:  " << expectedEncrypted << std::endl;
	std::cout << "\n";
	std::cout << "Decrypted Text: " << decryptedtext << std::endl;
	std::cout << "Expected Text:  " << plaintext << std::endl;
	std::cout << "\n\n";


	plaintext = "0123456789ABCDEF0123456789ABCDEF";
	key1 = "033457799BBCDFF1";
	key2 = "133457799BBCDFF1";
	key3 = "233457799BBCDFF1";
	ciphertext = tdes.EncryptBlock(plaintext, key1, key2, key3);
	decryptedtext = tdes.DecryptBlock(ciphertext, key1, key2, key3);
	expectedEncrypted = "37d174403fc04f1a37d174403fc04f1a";

	std::cout << "Plaintext: " << plaintext << std::endl;
	std::cout << "Key: " << key1 + key2 + key3 << std::endl;
	std::cout << "\n";
	std::cout << "Encrypted Ciphertext: " << tdes.BitArrayToHexString(tdes.StringToBitArray<64>(ciphertext)) << std::endl;
	std::cout << "Expected Ciphertext:  " << expectedEncrypted << std::endl;
	std::cout << "\n";
	std::cout << "Decrypted Text: " << decryptedtext << std::endl;
	std::cout << "Expected Text:  " << plaintext << std::endl;
	std::cout << "\n\n";


	plaintext = "0123456789ABCDEF";
	key1 = "033457799BBCDFF1";
	key2 = "133457799BBCDFF1";
	key3 = "23345779";
	ciphertext = tdes.EncryptBlock(plaintext, key1, key2, key3);
	decryptedtext = tdes.DecryptBlock(ciphertext, key1, key2, key3);
	expectedEncrypted = "none";

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