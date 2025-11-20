#include <iostream>
#include "mylib.hpp"
#include "TDES/tdes.hpp"

int main() {
	TDES tdes = TDES();
	std::array<uint8_t, 64> test;
	for (int i = 0; i < 64; i++) {
		test[i]=i;
	}
	test = tdes.test(test);
	for (int i = 0; i < 64; i++) {
		std::cout << (int)test[i] << std::endl;
	}
	return 0;
}
