CXX=g++
CXXFLAGS=-std=c++17 -O2
OUT=program
TEST_OUT=test_aes

all: main.cpp aes.cpp
	$(CXX) $(CXXFLAGS) main.cpp -o $(OUT)

test: test_aes.cpp aes.cpp
	$(CXX) $(CXXFLAGS) test_aes.cpp -o $(TEST_OUT)
	./$(TEST_OUT)

run: all
	./$(OUT)

clean:
	rm -f $(OUT) $(TEST_OUT)
