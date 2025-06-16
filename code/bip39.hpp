#pragma once

#include <string>
#include <vector>
#include <array>
#include <unordered_map>
#include <cstdint>

class BIP39 {
public:
    static constexpr size_t ENTROPY_LEN_128 = 16;  // 128 bits
    static constexpr size_t ENTROPY_LEN_160 = 20;  // 160 bits
    static constexpr size_t ENTROPY_LEN_192 = 24;  // 192 bits
    static constexpr size_t ENTROPY_LEN_224 = 28;  // 224 bits
    static constexpr size_t ENTROPY_LEN_256 = 32;  // 256 bits

    // Convert mnemonic to seed
    static std::vector<uint8_t> mnemonicToSeed(const std::string& mnemonic, const std::string& passphrase = "");

    // Validate mnemonic
    static bool validateMnemonic(const std::string& mnemonic);

    // Convert mnemonic to entropy
    static std::vector<uint8_t> mnemonicToEntropy(const std::string& mnemonic);

    // Convert entropy to mnemonic
    static std::string entropyToMnemonic(const std::vector<uint8_t>& entropy);

private:
    static const std::array<std::string, 2048> wordlist;
    static std::unordered_map<std::string, uint16_t> wordMap;

    // Helper functions
    static std::vector<uint8_t> pbkdf2(const std::vector<uint8_t>& password, 
                                     const std::vector<uint8_t>& salt,
                                     int iterations,
                                     size_t keyLength);
    
    static std::vector<uint8_t> hmacSha512(const std::vector<uint8_t>& key, 
                                         const std::vector<uint8_t>& data);
}; 