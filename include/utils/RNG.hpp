#pragma once
#include <vector>
#include <cstdint>


namespace utils {


	class CSPRNG {
	public:
		virtual ~CSPRNG() = default;
		virtual std::vector<uint8_t> randomBytes(size_t size) = 0;
		virtual uint64_t randomUint64();
	};


	class OSCSPRNG : public CSPRNG {
	public:
		std::vector<uint8_t> randomBytes(size_t size) override;
	};


	class TestCSPRNG : public CSPRNG {
	public:
		std::vector<uint8_t> randomBytes(size_t size) override;
	private:
		uint64_t state = 0xDEADBEEFCAFEBABEULL;
	};


} // namespace utils