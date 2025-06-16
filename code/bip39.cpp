#include "bip39.hpp"
#include "wordlist.hpp"
#include <sodium.h>
#include <sstream>
#include <algorithm>
#include <stdexcept>
#include <cstring>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <iostream>

// Initialize the wordlist from wordlist.hpp
const std::array<std::string, 2048> BIP39::wordlist = []() {
    std::cout << "Initializing BIP39 wordlist..." << std::endl;
    std::array<std::string, 2048> result;
    for (size_t i = 0; i < BIP39_WORDS::WORDLIST_SIZE && i < 2048; ++i) {
        result[i] = std::string(BIP39_WORDS::WORDLIST[i]);
        if (i < 5) {  // Print first few words for debugging
            std::cout << "Word " << i << ": " << result[i] << std::endl;
        }
    }
    std::cout << "BIP39 wordlist initialized with " << BIP39_WORDS::WORDLIST_SIZE << " words" << std::endl;
    return result;
}();

// Initialize the word map
std::unordered_map<std::string, uint16_t> BIP39::wordMap = []() {
    std::cout << "Initializing BIP39 word map..." << std::endl;
    std::unordered_map<std::string, uint16_t> map;
    for (size_t i = 0; i < wordlist.size(); ++i) {
        map[wordlist[i]] = static_cast<uint16_t>(i);
    }
    std::cout << "BIP39 word map initialized with " << map.size() << " entries" << std::endl;
    return map;
}();

std::vector<uint8_t> BIP39::mnemonicToSeed(const std::string& mnemonic, const std::string& passphrase) {
    if (!validateMnemonic(mnemonic)) {
        throw std::runtime_error("Invalid mnemonic");
    }

    // Convert mnemonic to bytes
    std::vector<uint8_t> mnemonicBytes(mnemonic.begin(), mnemonic.end());
    
    // Convert passphrase to bytes
    std::vector<uint8_t> saltBytes;
    saltBytes.reserve(8 + passphrase.size());
    saltBytes.insert(saltBytes.end(), {'m', 'n', 'e', 'm', 'o', 'n', 'i', 'c'});
    saltBytes.insert(saltBytes.end(), passphrase.begin(), passphrase.end());
    
    // Use PBKDF2 with HMAC-SHA512
    return pbkdf2(mnemonicBytes, saltBytes, 2048, 64);
}

bool BIP39::validateMnemonic(const std::string& mnemonic) {
    std::cout << "Validating mnemonic: " << mnemonic << std::endl;
    std::istringstream iss(mnemonic);
    std::string word;
    int wordCount = 0;
    
    while (iss >> word) {
        std::cout << "Checking word: " << word << std::endl;
        if (wordMap.find(word) == wordMap.end()) {
            std::cout << "Word not found in wordlist: " << word << std::endl;
            return false;
        }
        wordCount++;
    }
    
    std::cout << "Word count: " << wordCount << std::endl;
    if (wordCount != 12 && wordCount != 24) {
        std::cout << "Invalid word count: " << wordCount << std::endl;
        return false;
    }
    
    try {
        std::vector<uint8_t> entropy = mnemonicToEntropy(mnemonic);
        std::cout << "Mnemonic validation successful" << std::endl;
        return true;
    } catch (const std::exception& e) {
        std::cout << "Mnemonic validation failed: " << e.what() << std::endl;
        return false;
    }
}

std::vector<uint8_t> BIP39::mnemonicToEntropy(const std::string& mnemonic) {
    std::istringstream iss(mnemonic);
    std::string word;
    std::vector<uint8_t> entropy;
    
    while (iss >> word) {
        auto it = wordMap.find(word);
        if (it == wordMap.end()) {
            throw std::runtime_error("Invalid word in mnemonic");
        }
        uint16_t index = it->second;
        entropy.push_back(index >> 8);
        entropy.push_back(index & 0xFF);
    }
    
    return entropy;
}

std::string BIP39::entropyToMnemonic(const std::vector<uint8_t>& entropy) {
    if (entropy.size() != 16 && entropy.size() != 32) {
        throw std::runtime_error("Invalid entropy length");
    }
    
    std::stringstream ss;
    for (size_t i = 0; i < entropy.size(); i += 2) {
        uint16_t index = (entropy[i] << 8) | entropy[i + 1];
        // TODO: Convert index to word using wordMap
    }
    
    return ss.str();
}

std::vector<uint8_t> BIP39::pbkdf2(const std::vector<uint8_t>& password,
                                 const std::vector<uint8_t>& salt,
                                 int iterations,
                                 size_t keyLength) {
    std::vector<uint8_t> key(keyLength);
    PKCS5_PBKDF2_HMAC(
        reinterpret_cast<const char*>(password.data()),
        password.size(),
        salt.data(),
        salt.size(),
        iterations,
        EVP_sha512(),
        keyLength,
        key.data()
    );
    return key;
}

std::vector<uint8_t> BIP39::hmacSha512(const std::vector<uint8_t>& key,
                                     const std::vector<uint8_t>& data) {
    std::vector<uint8_t> hmac(64);
    unsigned int len;
    HMAC_CTX* ctx = HMAC_CTX_new();
    HMAC_Init_ex(ctx, key.data(), key.size(), EVP_sha512(), nullptr);
    HMAC_Update(ctx, data.data(), data.size());
    HMAC_Final(ctx, hmac.data(), &len);
    HMAC_CTX_free(ctx);
    return hmac;
} 