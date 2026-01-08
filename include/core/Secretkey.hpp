#pragma once
#include <cstddef>
#include <span>
#include <vector>

class SecretKey {
public:
    explicit SecretKey(std::vector<uint8_t> data);
    SecretKey(SecretKey&& other) noexcept;
    SecretKey& operator=(SecretKey&& other) noexcept;

    SecretKey(const SecretKey&) = delete;
    SecretKey& operator=(const SecretKey&) = delete;

    ~SecretKey();

    std::vector<uint8_t> bytes() const noexcept;

private:
    void secure_zero() noexcept;

    uint8_t* ptr;
    size_t size;
};
