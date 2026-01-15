#pragma once
#include <gtest/gtest.h>
#include <iostream>

class SummaryReporter : public ::testing::EmptyTestEventListener {
public:
    SummaryReporter()
        : passed_(0), failed_(0) {
    }

    void OnTestEnd(const ::testing::TestInfo& test_info) override {
        const bool ok = test_info.result()->Passed();
        if (ok) {
            ++passed_;
            std::cout << "[PASS] "
                << test_info.test_suite_name() << "."
                << test_info.name() << "\n";
        }
        else {
            ++failed_;
            std::cout << "[FAIL] "
                << test_info.test_suite_name() << "."
                << test_info.name() << "\n";
        }
    }

    void OnTestProgramEnd(const ::testing::UnitTest& /*unit_test*/) override {
        std::cout << "\n=== TEST SUMMARY ===\n";
        std::cout << "TOTAL : " << (passed_ + failed_) << "\n";
        std::cout << "PASSED: " << passed_ << "\n";
        std::cout << "FAILED: " << failed_ << "\n";
        std::cout << "====================\n";
    }

private:
    int passed_;
    int failed_;
};
