#include "utils/Nonce.hpp"
#include <stdexcept>

namespace utils {
	std::vector<uint8_t> NonceGenerator::generate(size_t size) {
		if (!rng) throw std::runtime_error("RNG not set");
		return rng->randomBytes(size);
	}
} // namespace utils