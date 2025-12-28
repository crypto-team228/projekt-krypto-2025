#include <vector>
#include <cstdint>


class Algorithm {
public:
    virtual void setKey(const std::vector<uint8_t>& key) = 0;
    virtual void encrypt(std::vector<uint8_t>& block) = 0;
    virtual void decrypt(std::vector<uint8_t>& block) = 0;
    virtual ~Algorithm() = default;
};
