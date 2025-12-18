struct Key {
	std::vector<uint8_t> data;
	std::string encoding;
	bool zeroOnDestroy = true;
	bool isHandle = false;
};