#pragma once
#include "RNG.hpp"
#include <vector>
#include <cstdint>

namespace utils {
	class NonceGenerator {
	public:
		NonceGenerator(CSPRNG* rng) : rng(rng) {}
		virtual ~NonceGenerator() = default;
		virtual std::vector<uint8_t> generate(size_t size);
	protected:
		CSPRNG* rng;
	};
} // namespace utils