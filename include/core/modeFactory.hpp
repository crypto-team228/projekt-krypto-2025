#pragma once
#include <memory>
#include <string>
#include <mode/mode.hpp>

class ModeFactory {
public:
    static std::unique_ptr<Mode> create(const std::string& name);
};
