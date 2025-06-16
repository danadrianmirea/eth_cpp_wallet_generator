#include "wallet_converter.hpp"
#include "bip39.hpp"
#include "bip32.hpp"
#include "keccak.hpp"
#include "utils.hpp"
#include <sodium.h>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <iostream>

WalletConverter::WalletConverter() {
    std::cout << "Initializing WalletConverter..." << std::endl << std::flush;
    
    // Initialize libsodium
    std::cout << "Initializing libsodium..." << std::endl << std::flush;
    int result = sodium_init();
    if (result < 0) {
        std::cerr << "Failed to initialize libsodium. Error code: " << result << std::endl << std::flush;
        throw std::runtime_error("Failed to initialize libsodium");
    }
    std::cout << "libsodium initialized successfully" << std::endl << std::flush;
    
    // Test libsodium
    std::cout << "Testing libsodium..." << std::endl << std::flush;
    if (sodium_library_version_major() == 0) {
        std::cerr << "libsodium version check failed" << std::endl << std::flush;
        throw std::runtime_error("libsodium version check failed");
    }
    std::cout << "libsodium version: " << sodium_version_string() << std::endl << std::flush;
}

WalletConverter::~WalletConverter() {
    // No cleanup needed
}

std::string WalletConverter::mnemonicToAddress(const std::string& mnemonic) {
    std::cout << "\nStarting mnemonic to address conversion..." << std::endl;
    
    // Convert mnemonic to seed using BIP39
    std::cout << "Converting mnemonic to seed..." << std::endl;
    auto seed = BIP39::mnemonicToSeed(mnemonic);
    std::cout << "Seed (hex): " << utils::bytesToHex(seed) << std::endl;
    
    // Derive the Ethereum path (m/44'/60'/0'/0/0) using BIP32
    std::cout << "\nDeriving key from path m/44'/60'/0'/0/0..." << std::endl;
    auto derivedKey = BIP32::derivePath(seed, "m/44'/60'/0'/0/0");
    std::cout << "Derived private key (hex): " << utils::bytesToHex(derivedKey.key) << std::endl;
    
    // Generate public key from private key
    std::cout << "\nGenerating public key from private key..." << std::endl;
    auto publicKey = privateKeyToPublicKey(derivedKey.key);
    std::cout << "Public key (hex): " << utils::bytesToHex(publicKey) << std::endl;
    
    // Convert public key to Ethereum address
    std::cout << "\nConverting public key to address..." << std::endl;
    return publicKeyToAddress(publicKey);
}

std::vector<uint8_t> WalletConverter::privateKeyToPublicKey(const std::vector<uint8_t>& privateKey) {
    std::cout << "Creating EC key..." << std::endl;
    // Create EC key
    EC_KEY* key = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (!key) {
        throw std::runtime_error("Failed to create EC key");
    }

    // Set private key
    std::cout << "Setting private key..." << std::endl;
    BIGNUM* priv = BN_bin2bn(privateKey.data(), privateKey.size(), nullptr);
    if (!priv) {
        EC_KEY_free(key);
        throw std::runtime_error("Failed to create BIGNUM");
    }

    if (!EC_KEY_set_private_key(key, priv)) {
        BN_free(priv);
        EC_KEY_free(key);
        throw std::runtime_error("Failed to set private key");
    }

    // Get public key
    std::cout << "Computing public key..." << std::endl;
    const EC_GROUP* group = EC_KEY_get0_group(key);
    EC_POINT* pub = EC_POINT_new(group);
    if (!pub) {
        BN_free(priv);
        EC_KEY_free(key);
        throw std::runtime_error("Failed to create EC point");
    }

    if (!EC_POINT_mul(group, pub, priv, nullptr, nullptr, nullptr)) {
        EC_POINT_free(pub);
        BN_free(priv);
        EC_KEY_free(key);
        throw std::runtime_error("Failed to compute public key");
    }

    // Serialize public key (uncompressed)
    std::cout << "Serializing public key..." << std::endl;
    size_t pub_len = EC_POINT_point2oct(group, pub, POINT_CONVERSION_UNCOMPRESSED, nullptr, 0, nullptr);
    if (pub_len == 0) {
        EC_POINT_free(pub);
        BN_free(priv);
        EC_KEY_free(key);
        throw std::runtime_error("Failed to get public key length");
    }

    std::vector<uint8_t> publicKey(pub_len);
    if (!EC_POINT_point2oct(group, pub, POINT_CONVERSION_UNCOMPRESSED, publicKey.data(), pub_len, nullptr)) {
        EC_POINT_free(pub);
        BN_free(priv);
        EC_KEY_free(key);
        throw std::runtime_error("Failed to serialize public key");
    }

    // Cleanup
    EC_POINT_free(pub);
    BN_free(priv);
    EC_KEY_free(key);

    return publicKey;
}

std::string WalletConverter::publicKeyToAddress(const std::vector<uint8_t>& publicKey) {
    std::cout << "Processing public key format..." << std::endl;
    std::cout << "Public key first byte: 0x" << std::hex << static_cast<int>(publicKey[0]) << std::dec << std::endl;
    
    // For Ethereum, we need to:
    // 1. Remove the first byte (0x04 for uncompressed, 0x02/0x03 for compressed)
    // 2. Take only the X coordinate (first 32 bytes after the prefix)
    // 3. Hash with Keccak-256
    // 4. Take the last 20 bytes
    
    std::vector<uint8_t> hashInput;
    if (publicKey[0] == 0x04) {
        std::cout << "Processing uncompressed public key..." << std::endl;
        // Uncompressed public key - take only X coordinate
        hashInput = std::vector<uint8_t>(publicKey.begin() + 1, publicKey.begin() + 33);
    } else if (publicKey[0] == 0x02 || publicKey[0] == 0x03) {
        std::cout << "Processing compressed public key..." << std::endl;
        // Compressed public key - we need to decompress it
        EC_KEY* key = EC_KEY_new_by_curve_name(NID_secp256k1);
        if (!key) {
            throw std::runtime_error("Failed to create EC key");
        }

        const EC_GROUP* group = EC_KEY_get0_group(key);
        EC_POINT* point = EC_POINT_new(group);
        if (!point) {
            EC_KEY_free(key);
            throw std::runtime_error("Failed to create EC point");
        }

        if (!EC_POINT_oct2point(group, point, publicKey.data(), publicKey.size(), nullptr)) {
            EC_POINT_free(point);
            EC_KEY_free(key);
            throw std::runtime_error("Failed to convert public key to point");
        }

        // Get uncompressed point
        size_t len = EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED, nullptr, 0, nullptr);
        if (len == 0) {
            EC_POINT_free(point);
            EC_KEY_free(key);
            throw std::runtime_error("Failed to get public key length");
        }

        std::vector<uint8_t> uncompressed(len);
        if (!EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED, uncompressed.data(), len, nullptr)) {
            EC_POINT_free(point);
            EC_KEY_free(key);
            throw std::runtime_error("Failed to serialize public key");
        }

        std::cout << "Decompressed public key (hex): " << utils::bytesToHex(uncompressed) << std::endl;
        
        // Remove the first byte (0x04) and take only X coordinate
        hashInput = std::vector<uint8_t>(uncompressed.begin() + 1, uncompressed.begin() + 33);

        EC_POINT_free(point);
        EC_KEY_free(key);
    } else {
        throw std::runtime_error("Invalid public key format");
    }

    std::cout << "Hash input (hex): " << utils::bytesToHex(hashInput) << std::endl;
    
    // Hash with Keccak-256
    std::cout << "Computing Keccak-256 hash..." << std::endl;
    auto hash = keccak256(hashInput);
    std::cout << "Keccak-256 hash (hex): " << utils::bytesToHex(hash) << std::endl;
    
    // Take the last 20 bytes
    std::vector<uint8_t> address(hash.end() - 20, hash.end());
    std::cout << "Final address bytes (hex): " << utils::bytesToHex(address) << std::endl;
    
    // Convert to hex string with 0x prefix
    return "0x" + utils::bytesToHex(address);
}

std::vector<uint8_t> WalletConverter::keccak256(const std::vector<uint8_t>& input) {
    return Keccak::hash256(input);
}

std::vector<uint8_t> WalletConverter::hmacSha512(const std::vector<uint8_t>& key, const std::vector<uint8_t>& data) {
    std::vector<uint8_t> hmac(crypto_auth_hmacsha512_BYTES);
    crypto_auth_hmacsha512_state state;
    
    crypto_auth_hmacsha512_init(&state, key.data(), key.size());
    crypto_auth_hmacsha512_update(&state, data.data(), data.size());
    crypto_auth_hmacsha512_final(&state, hmac.data());
    
    return hmac;
} 