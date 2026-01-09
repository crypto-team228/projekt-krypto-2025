#pragma once
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
enum Mode {
	ECB,   // Electronic Codebook
	CBC,   // Cipher Block Chaining
	CTR,   // Counter
	GCM    // Galois/Counter Mode (uses GHASH internally)
};