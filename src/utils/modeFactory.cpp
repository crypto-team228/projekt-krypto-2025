#include <memory>
#include <string>
#include <stdexcept>


#include <core/modeFactory.hpp>

#include <mode/mode.hpp>
#include <mode/CBC.hpp>
#include <mode/CTR.hpp>
#include <mode/ECB.hpp>

std::unique_ptr<Mode> ModeFactory::create(const std::string& name) {
    if (name == "CBC") {
        return std::make_unique<CBC>();
    }
    if (name == "CTR") {
        return std::make_unique<CTR>();
    }
    if (name == "ECB") {
        return std::make_unique<ECB>();
    }

    throw std::runtime_error("Unknown mode: " + name);
}
