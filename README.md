# AES-128 Implementation

A complete C++ implementation of the AES-128 (Advanced Encryption Standard) block cipher algorithm following the NIST FIPS 197 specification.

## Features

- ✅ Full AES-128 encryption and decryption
- ✅ NIST FIPS 197 compliant
- ✅ Comprehensive test suite with official test vectors
- ✅ Clean, readable C++17 code
- ✅ ECB (Electronic Codebook) mode

## Requirements

- C++ compiler with C++17 support (g++, clang++)
- Make (for building)
- Linux/Unix environment (or WSL on Windows)

## Project Structure

```
.
├── aes.cpp           # AES class implementation
├── main.cpp          # Demo program
├── test_aes.cpp      # Comprehensive test suite
├── Makefile          # Build configuration
└── README.md         # This file
```

## Building the Project

### Build the demo program:

```bash
make
```

This creates the `program` executable.

### Build and run tests:

```bash
make test
```

This compiles and runs the test suite with NIST test vectors.

### Clean build artifacts:

```bash
make clean
```

## Usage

### Running the Demo

```bash
make run
```

Or directly:

```bash
./program
```

This will demonstrate encrypting and decrypting a sample block.

### Using in Your Code

Include the AES implementation:

```cpp
#include "aes.cpp"

int main() {
    // Define a 128-bit key (16 bytes)
    AES::Key128 key = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };

    // Create AES cipher with the key
    AES aes(key);

    // Define a 128-bit plaintext block (16 bytes)
    AES::State plaintext = {
        0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
        0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34
    };

    // Encrypt the block (modifies in place)
    aes.encryptBlock(plaintext);

    // Decrypt the block (modifies in place)
    aes.decryptBlock(plaintext);

    return 0;
}
```

## API Reference

### Class: `AES`

#### Types

- `AES::State` - A 16-byte array representing a block (std::array<uint8_t, 16>)
- `AES::Key128` - A 16-byte array representing the key (std::array<uint8_t, 16>)

#### Constructor

```cpp
AES(const Key128& key)
```

Creates an AES cipher instance and expands the key for all rounds.

#### Methods

**`void encryptBlock(State& state) const`**

- Encrypts a 16-byte block in place
- Parameters:
  - `state`: The plaintext block to encrypt (modified in place)

**`void decryptBlock(State& state) const`**

- Decrypts a 16-byte block in place
- Parameters:
  - `state`: The ciphertext block to decrypt (modified in place)

## Examples

### Example 1: Basic Encryption/Decryption

```cpp
#include "aes.cpp"
#include <iostream>

int main() {
    // Create a key
    AES::Key128 key = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };

    // Create cipher
    AES aes(key);

    // Create plaintext
    AES::State data = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
    };

    // Encrypt
    aes.encryptBlock(data);
    std::cout << "Encrypted!\n";

    // Decrypt
    aes.decryptBlock(data);
    std::cout << "Decrypted!\n";

    return 0;
}
```

### Example 2: Multiple Blocks

```cpp
#include "aes.cpp"
#include <vector>

int main() {
    AES::Key128 key = {/* your key */};
    AES aes(key);

    // Prepare multiple blocks
    std::vector<AES::State> blocks = {
        {/* block 1 */},
        {/* block 2 */},
        {/* block 3 */}
    };

    // Encrypt all blocks
    for (auto& block : blocks) {
        aes.encryptBlock(block);
    }

    // Decrypt all blocks
    for (auto& block : blocks) {
        aes.decryptBlock(block);
    }

    return 0;
}
```

## Testing

The test suite includes:

- ✅ NIST FIPS 197 official test vectors
- ✅ NIST SP 800-38A test vectors
- ✅ Edge cases (all zeros, all ones)
- ✅ Multiple block tests
- ✅ Key differentiation tests
- ✅ Avalanche effect verification
- ✅ 100 roundtrip tests

Run tests with:

```bash
make test
```

Expected output:

```
========================================
     AES-128 Implementation Tests
========================================
...
🎉 All tests PASSED! 🎉
```

## Implementation Details

### Algorithm Components

1. **Key Expansion** - Expands the 128-bit key into 11 round keys (44 words)
2. **SubBytes** - Non-linear byte substitution using S-box
3. **ShiftRows** - Circular shift of state rows
4. **MixColumns** - Matrix multiplication in GF(2^8)
5. **AddRoundKey** - XOR with round key

### Encryption Process

1. Initial round: AddRoundKey
2. Rounds 1-9: SubBytes → ShiftRows → MixColumns → AddRoundKey
3. Final round 10: SubBytes → ShiftRows → AddRoundKey

### Decryption Process

1. Initial: AddRoundKey (round 10)
2. Rounds 9-1: InvShiftRows → InvSubBytes → AddRoundKey → InvMixColumns
3. Final: InvShiftRows → InvSubBytes → AddRoundKey (round 0)

## Important Notes

⚠️ **Security Considerations:**

- This implementation is for **educational purposes**
- Uses ECB mode (not recommended for production - use CBC, CTR, or GCM instead)
- No padding implementation (blocks must be exactly 16 bytes)
- Not hardened against side-channel attacks
- For production use, consider established libraries like OpenSSL or libsodium

⚠️ **Block Size:**

- AES operates on 16-byte blocks
- Input must be exactly 16 bytes
- For larger data, implement a mode of operation (CBC, CTR, etc.)

## Performance

The implementation uses:

- Lookup tables for S-box operations (O(1))
- Inline functions for GF(2^8) multiplication
- Optimized for readability over maximum performance

## References

- [NIST FIPS 197](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf) - AES Specification
- [NIST SP 800-38A](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf) - Block Cipher Modes

## License

This is an educational implementation. Use at your own risk.

## Author

Created for Software Engineering course 2025.

## Troubleshooting

### Compilation errors

Make sure you have C++17 support:

```bash
g++ --version  # Should be >= 7.0
```

### Tests failing

If tests fail, verify:

- Compiler optimization is enabled (-O2)
- No modifications were made to the AES algorithm
- Test vectors match NIST specifications

### Linker errors

The implementation is header-only (in .cpp files). Include `aes.cpp` directly in your source files.

## Contributing

This is an educational project. Suggestions for improvements are welcome!

## Changelog

- **v1.0** - Initial implementation
  - AES-128 encryption
  - AES-128 decryption
  - Full test suite
  - Documentation
