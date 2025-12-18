

class Cipher {
public:
	virtual ~BaseCipher() = default;

	// Encrypt the input data
	virtual std::string encryptBlock(const std::string& data) = 0;
	
	// Decrypt the input data
	virtual std::string decryptBlock(const std::string& data) = 0;
}