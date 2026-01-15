#include "utils/RNG.hpp"
#include "utils/Nonce.hpp"
#include "utils/CounterNonce.hpp"
#include <gtest/gtest.h>
#include <set>
#include <chrono>


//Sprawdza, czy OSCSPRNG zwraca prawid³ow¹ iloœæ bajtów i ¿e nie s¹ one wszystkie zerami.
TEST(RNGTest, OSCSPRNG_Works) {
    utils::OSCSPRNG rng;
    auto bytes = rng.randomBytes(16);

    EXPECT_EQ(bytes.size(), 16);

    bool hasNonZero = false;
    for (auto b : bytes) {
        if (b != 0) {
            hasNonZero = true;
            break;
        }
    }
    EXPECT_TRUE(hasNonZero);
}

//Testuje czy przy tym samym seed zwraca te same wyniki
TEST(RNGTest, TestCSPRNG_Deterministic) {
    utils::TestCSPRNG rng1;
    utils::TestCSPRNG rng2;

    auto b1 = rng1.randomBytes(16);
    auto b2 = rng2.randomBytes(16);

    EXPECT_EQ(b1, b2);
}

// Sprawdza równomierny rozk³ad wartoœci parzyste/nieparzyste
TEST(RNGTest, CSPRNG_Distribution) {
    utils::TestCSPRNG rng;
    int evenCount = 0;
    int oddCount = 0;

    for (int i = 0; i < 10000; i++) {
        uint64_t n = rng.randomUint64();
        if (n % 2 == 0) evenCount++;
        else oddCount++;
    }

    EXPECT_NEAR(evenCount, 5000, 300);
    EXPECT_NEAR(oddCount, 5000, 300);
}


// Sprawdza, czy NonceGenerator nie powtarza liczb
TEST(NonceTest, RandomNonceUnique) {
    utils::OSCSPRNG rng;
    utils::NonceGenerator gen(&rng);
    std::set<std::vector<uint8_t>> seen;
    int collisions = 0;

    for (int i = 0; i < 1000; i++) {
        auto n = gen.generate(16);
        if (!seen.insert(n).second) {
            collisions++;
        }
    }

    EXPECT_EQ(collisions, 0) << "Nonces should be unique";
}

// Sprawdza czy NonceTest zwraca poprawn¹ d³ugoœæ
TEST(NonceTest, RandomNonceLength) {
    utils::TestCSPRNG rng;
    utils::NonceGenerator gen(&rng);

    EXPECT_EQ(gen.generate(8).size(), 8);
    EXPECT_EQ(gen.generate(16).size(), 16);
    EXPECT_EQ(gen.generate(32).size(), 32);
}

class CounterNonceTest : public ::testing::Test {
protected:
    std::string testFile;

    void SetUp() override {
        testFile = "test_counter_" +
            std::to_string(std::chrono::system_clock::now()
                .time_since_epoch().count()) + ".dat";
        std::remove(testFile.c_str());
    }

    void TearDown() override {
        std::remove(testFile.c_str());
    }

    uint64_t nonceToUint64(const std::vector<uint8_t>& nonce) {
        EXPECT_GE(nonce.size(), 8);
        uint64_t val = 0;
        for (size_t i = 0; i < 8; i++) {
            val |= static_cast<uint64_t>(nonce[i]) << ((7 - i) * 8);
        }
        return val;
    }
};

// Sprawdza, czy licznik faktycznie inkrementuje przy kolejnych wywo³aniach
TEST_F(CounterNonceTest, CounterIncrement) {
    utils::CounterNonceGenerator gen(0, testFile);

    auto n1 = gen.generate(8);
    auto n2 = gen.generate(8);
    auto n3 = gen.generate(8);

    EXPECT_EQ(nonceToUint64(n1), 0);
    EXPECT_EQ(nonceToUint64(n2), 1);
    EXPECT_EQ(nonceToUint64(n3), 2);
}

// Sprawdza zapis licznika do pliku i poprawne wczytanie przy nowym obiekcie.
TEST_F(CounterNonceTest, CounterPersistence) {
    {
        utils::CounterNonceGenerator gen1(0, testFile);
        auto n1 = gen1.generate(8);
        auto n2 = gen1.generate(8);

        EXPECT_EQ(nonceToUint64(n1), 0);
        EXPECT_EQ(nonceToUint64(n2), 1);
    } // Destruktor zapisuje counter=2

    {
        utils::CounterNonceGenerator gen2(0, testFile);
        gen2.load();
        auto n3 = gen2.generate(8);

        EXPECT_EQ(nonceToUint64(n3), 2);
    }
}

// Sprawdza czy domyœlny start countera = 0
TEST_F(CounterNonceTest, CounterStartsAtZero) {
    utils::CounterNonceGenerator gen(0, testFile);
    auto n = gen.generate(8);

    EXPECT_EQ(nonceToUint64(n), 0);
}

// Testuje start countera od wartoœci ró¿nej ni¿ zero.
TEST_F(CounterNonceTest, CounterCustomStart) {
    utils::CounterNonceGenerator gen(100, testFile);
    auto n1 = gen.generate(8);
    auto n2 = gen.generate(8);
    EXPECT_EQ(nonceToUint64(n1), 100);
    EXPECT_EQ(nonceToUint64(n2), 101);
}

// Sprawdza, czy CounterNonceGenerator generuje poprawne d³ugoœci
TEST_F(CounterNonceTest, DifferentLengths) {
    utils::CounterNonceGenerator gen(0, testFile);

    EXPECT_EQ(gen.generate(8).size(), 8);
    EXPECT_EQ(gen.generate(16).size(), 16);
    EXPECT_EQ(gen.generate(32).size(), 32);
}

// Sprawdza czy jeœli plik z licznikiem zostanie usuniêty, generator startuje od zera.
TEST_F(CounterNonceTest, FileDeletionResetsCounter) {
    utils::CounterNonceGenerator gen(0, testFile);
    auto n1 = gen.generate(8);
    auto n2 = gen.generate(8);

    EXPECT_EQ(nonceToUint64(n1), 0);
    EXPECT_EQ(nonceToUint64(n2), 1);

    std::remove(testFile.c_str());

    utils::CounterNonceGenerator gen2(0, testFile);
    auto n3 = gen2.generate(8);
    EXPECT_EQ(nonceToUint64(n3), 0);
}

// Testuje edge case: Sprawdza zachowanie licznika przy overflow uint64_t
TEST_F(CounterNonceTest, CounterMaxValue) {
    utils::CounterNonceGenerator gen(UINT64_MAX - 1, testFile);

    auto n1 = gen.generate(8);
    EXPECT_EQ(nonceToUint64(n1), UINT64_MAX - 1);

    auto n2 = gen.generate(8);
    EXPECT_EQ(nonceToUint64(n2), UINT64_MAX);

    // overflow zachowa siê jak 0 (dla uint64_t)
    auto n3 = gen.generate(8);
    EXPECT_EQ(nonceToUint64(n3), 0);
}
