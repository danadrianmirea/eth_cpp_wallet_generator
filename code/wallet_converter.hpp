#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include "bip32.hpp"
#include "utils.hpp"

class WalletConverter {
public:
    WalletConverter();
    ~WalletConverter();

    // Convert a mnemonic phrase to an Ethereum address
    std::string mnemonicToAddress(const std::string& mnemonic);

    // Helper functions
    std::vector<uint8_t> generatePublicKey(const std::vector<uint8_t>& privateKey);
    std::string publicKeyToAddress(const std::vector<uint8_t>& publicKey);
    std::vector<uint8_t> keccak256(const std::vector<uint8_t>& input);
    std::vector<uint8_t> hmacSha512(const std::vector<uint8_t>& key, const std::vector<uint8_t>& data);
}; 