#include <vector>
#include <cstdint>

enum class Mode {
    ECB,   // Electronic Codebook
    CBC,   // Cipher Block Chaining
    CTR,   // Counter
    GCM    // Galois/Counter Mode (authenticated encryption)
};

class Algorithm {
public:
    virtual void setKey(const std::vector<uint8_t>& key) = 0;
    virtual void setMode(Mode mode) = 0;
    virtual void encrypt(std::vector<uint8_t>& block) = 0;
    virtual void decrypt(std::vector<uint8_t>& block) = 0;

    // GCM-specific methods
    virtual void setAAD(const std::vector<uint8_t>& aad) { (void)aad; }
    virtual std::vector<uint8_t> getTag() { return {}; }
    virtual bool verifyTag(const std::vector<uint8_t>& tag) { (void)tag; return false; }

    virtual ~Algorithm() = default;
};
