#pragma once

#include <vector>
#include <cstdint>
#include <string>

class Keccak {
public:
    // Keccak-256 hash function
    static std::vector<uint8_t> hash256(const std::vector<uint8_t>& input);
    
    // Keccak-256 hash function with hex string output
    static std::string hash256Hex(const std::vector<uint8_t>& input);
    
    // Keccak-256 hash function with hex string input and output
    static std::string hash256Hex(const std::string& input);

private:
    // Helper function to convert hex string to bytes
    static std::vector<uint8_t> hexToBytes(const std::string& hex);
}; 