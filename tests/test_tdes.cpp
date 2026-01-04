#include <iostream>
#include <iomanip>
#include <string>
#include <vector>
#include "cipher/TDES\tdes.hpp"

int main() {
	TDES tdes;

	std::string plaintext = "0123456789ABCDEF";
	std::string key1 = "033457799BBCDFF1";
	std::string key2 = "133457799BBCDFF1";
	std::string key3 = "233457799BBCDFF1";
	std::string ciphertext = tdes.EncryptBlock(plaintext, key1, key2, key3);
	std::string decryptedtext = tdes.DecryptBlock(ciphertext, key1, key2, key3);
	std::string expectedEncrypted = "37d174403fc04f1a";



	plaintext = "FEDCBA9876543210";
	key1 = "233457799BBCDFF1";
	key2 = "133457799BBCDFF1";
	key3 = "033457799BBCDFF1";
	ciphertext = tdes.EncryptBlock(plaintext, key1, key2, key3);
	decryptedtext = tdes.DecryptBlock(ciphertext, key1, key2, key3);
	expectedEncrypted = "473eeb07b08f7d13";


	plaintext = "0123456789ABCDEF0123456789ABCDEF";
	key1 = "033457799BBCDFF1";
	key2 = "133457799BBCDFF1";
	key3 = "233457799BBCDFF1";
	ciphertext = tdes.EncryptBlock(plaintext, key1, key2, key3);
	decryptedtext = tdes.DecryptBlock(ciphertext, key1, key2, key3);
	expectedEncrypted = "37d174403fc04f1a37d174403fc04f1a";


	plaintext = "0123456789ABCDEF";
	key1 = "033457799BBCDFF1";
	key2 = "133457799BBCDFF1";
	key3 = "23345779";
	ciphertext = tdes.EncryptBlock(plaintext, key1, key2, key3);
	decryptedtext = tdes.DecryptBlock(ciphertext, key1, key2, key3);
	expectedEncrypted = "none";


	return 0;
}