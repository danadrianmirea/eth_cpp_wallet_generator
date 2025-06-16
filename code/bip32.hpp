#pragma once

#include <string>
#include <vector>
#include <array>
#include <memory>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <cstdint>

struct BIP32 {
    struct Key {
        std::vector<uint8_t> key;
        std::vector<uint8_t> chainCode;
        uint32_t depth;
        uint32_t childNumber;
        std::array<uint8_t, 4> fingerprint;
        bool isPrivate;
    };

    static constexpr size_t CHAIN_CODE_SIZE = 32;
    static constexpr size_t KEY_SIZE = 32;
    static constexpr size_t FINGERPRINT_SIZE = 4;
    static constexpr size_t SERIALIZED_SIZE = 78;

    // Derive a child key from a parent key
    static Key deriveChildKey(const Key& parent, uint32_t childNumber);

    // Derive a key from a path
    static Key derivePath(const std::vector<uint8_t>& seed, const std::string& path);

    // Convert a key to a string representation
    static std::string keyToString(const Key& key);

    // Convert a string representation to a key
    static Key stringToKey(const std::string& str);

private:
    // Helper functions
    static std::vector<uint8_t> hmacSha512(const std::vector<uint8_t>& key, 
                                         const std::vector<uint8_t>& data);
    
    static std::array<uint8_t, FINGERPRINT_SIZE> getFingerprint(const std::vector<uint8_t>& key);
    
    static bool isHardened(uint32_t childNumber);
    
    static uint32_t getChildNumber(const std::string& pathComponent);
}; 