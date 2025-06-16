#include "keccak.hpp"
#include "utils.hpp"
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <sstream>
#include <iomanip>

std::vector<uint8_t> Keccak::hash256(const std::vector<uint8_t>& input) {
    std::vector<uint8_t> output(32); // Keccak-256 produces 32 bytes
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    
    // Use SHA3-256 (which is actually Keccak-256 in OpenSSL)
    const EVP_MD* md = EVP_sha3_256();
    if (!md) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("Failed to get SHA3-256 digest");
    }
    
    EVP_DigestInit_ex(ctx, md, nullptr);
    EVP_DigestUpdate(ctx, input.data(), input.size());
    unsigned int len;
    EVP_DigestFinal_ex(ctx, output.data(), &len);
    EVP_MD_CTX_free(ctx);
    return output;
}

std::string Keccak::hash256Hex(const std::vector<uint8_t>& input) {
    std::vector<uint8_t> hash = hash256(input);
    return utils::bytesToHex(hash);
}

std::string Keccak::hash256Hex(const std::string& input) {
    std::vector<uint8_t> bytes = hexToBytes(input);
    return hash256Hex(bytes);
}

std::vector<uint8_t> Keccak::hexToBytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(std::stoi(byteString, nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
} 