#include "utils/RNG.hpp"
#include <random>

namespace utils {

	uint64_t CSPRNG::randomUint64() {
		auto bytes = randomBytes(8);
		uint64_t val = 0;
		for (int i = 0; i < 8; i++) {
			val = (val << 8) | bytes[i];
		}
		return val;
	}

	std::vector<uint8_t> OSCSPRNG::randomBytes(size_t size) {
		std::vector<uint8_t> data(size);
		// Uses std::random_device which is OS-backed on most platforms
		// NOTE: std::random_device may not be cryptographically secure on all platforms
		std::random_device rd;
		size_t i = 0;
		while (i < size) {
			uint32_t val = rd();
			for (int b = 0; b < 4 && i < size; b++, i++) {
				data[i] = (val >> (b * 8)) & 0xFF;
			}
		}
		return data;
	}

	std::vector<uint8_t> TestCSPRNG::randomBytes(size_t size) {
		std::vector<uint8_t> data(size);
		for (size_t i = 0;i < size;i++) {
			state = state * 6364136223846793005ULL + 1;
			data[i] = (state >> 32) & 0xFF;
		}
		return data;
	}

	
} // namespace utils