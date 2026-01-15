#include <gtest/gtest.h>
#include "TestReporter.hpp"

int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);

    auto& listeners = ::testing::UnitTest::GetInstance()->listeners();
    // pozostaw domyœlny printer GTest, ale dodaj swój
    listeners.Append(new SummaryReporter());

    return RUN_ALL_TESTS();
}
