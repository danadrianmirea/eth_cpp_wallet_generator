#pragma once

#include <string>
#include <vector>
#include <iomanip>
#include <sstream>

namespace utils {
    inline std::string bytesToHex(const std::vector<uint8_t>& bytes) {
        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        for (uint8_t byte : bytes) {
            ss << std::setw(2) << static_cast<int>(byte);
        }
        return ss.str();
    }
} 