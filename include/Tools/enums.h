enum Algorithms {
	AES,
	TDES
};

enum StringFormat{
	BYTE,
	HEX,
	UTF8,
	UTF16
};

// Note: Mode enum is now defined in algorithm.hpp
// This is kept for reference only - use algorithm.hpp version
enum ModeReference {
	ECB,   // Electronic Codebook
	CBC,   // Cipher Block Chaining
	CFB,   // Cipher Feedback (not yet implemented)
	CTR,   // Counter
	GCM    // Galois/Counter Mode (uses GHASH internally)
};