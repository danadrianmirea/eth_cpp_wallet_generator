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
    auto publicKey = generatePublicKey(derivedKey.key);
    std::cout << "Public key (hex): " << utils::bytesToHex(publicKey) << std::endl;
    
    // Convert public key to Ethereum address
    std::cout << "\nConverting public key to address..." << std::endl;
    return publicKeyToAddress(publicKey);
}

std::vector<uint8_t> WalletConverter::generatePublicKey(const std::vector<uint8_t>& privateKey) {
    std::cout << "\nGenerating public key from private key..." << std::endl;
    
    std::cout << "Creating EC key..." << std::endl;
    EC_KEY* key = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (!key) {
        throw std::runtime_error("Failed to create EC key");
    }

    std::cout << "Setting private key..." << std::endl;
    BIGNUM* priv = BN_new();
    if (!priv) {
        EC_KEY_free(key);
        throw std::runtime_error("Failed to create BIGNUM");
    }

    BN_bin2bn(privateKey.data(), privateKey.size(), priv);
    if (!EC_KEY_set_private_key(key, priv)) {
        BN_free(priv);
        EC_KEY_free(key);
        throw std::runtime_error("Failed to set private key");
    }

    std::cout << "Computing public key..." << std::endl;
    const EC_GROUP* group = EC_KEY_get0_group(key);
    if (!group) {
        BN_free(priv);
        EC_KEY_free(key);
        throw std::runtime_error("Failed to get EC group");
    }

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

    // Get the point coordinates
    BIGNUM* x = BN_new();
    BIGNUM* y = BN_new();
    if (!x || !y) {
        if (x) BN_free(x);
        if (y) BN_free(y);
        EC_POINT_free(pub);
        BN_free(priv);
        EC_KEY_free(key);
        throw std::runtime_error("Failed to create coordinate BIGNUMs");
    }

    if (!EC_POINT_get_affine_coordinates(group, pub, x, y, nullptr)) {
        BN_free(x);
        BN_free(y);
        EC_POINT_free(pub);
        BN_free(priv);
        EC_KEY_free(key);
        throw std::runtime_error("Failed to get point coordinates");
    }

    // Convert coordinates to bytes
    std::vector<uint8_t> x_bytes(32);
    std::vector<uint8_t> y_bytes(32);
    BN_bn2bin(x, x_bytes.data());
    BN_bn2bin(y, y_bytes.data());

    // Create compressed public key
    std::vector<uint8_t> publicKey;
    publicKey.push_back(y_bytes[31] & 1 ? 0x03 : 0x02);  // Compressed format
    publicKey.insert(publicKey.end(), x_bytes.begin(), x_bytes.end());

    std::cout << "Public key (hex): " << utils::bytesToHex(publicKey) << std::endl;

    // Cleanup
    BN_free(x);
    BN_free(y);
    EC_POINT_free(pub);
    BN_free(priv);
    EC_KEY_free(key);

    return publicKey;
}

std::string WalletConverter::publicKeyToAddress(const std::vector<uint8_t>& publicKey) {
    std::cout << "\nConverting public key to address..." << std::endl;
    
    // Process the public key format
    std::cout << "Processing public key format..." << std::endl;
    if (publicKey.empty()) {
        throw std::runtime_error("Empty public key");
    }

    std::vector<uint8_t> hashInput;
    uint8_t firstByte = publicKey[0];
    std::cout << "Public key first byte: 0x" << std::hex << static_cast<int>(firstByte) << std::dec << std::endl;

    if (firstByte == 0x04) {
        std::cout << "Processing uncompressed public key..." << std::endl;
        // For uncompressed keys, use X and Y coordinates (skip prefix)
        hashInput.assign(publicKey.begin() + 1, publicKey.end());
    } else if (firstByte == 0x02 || firstByte == 0x03) {
        std::cout << "Processing compressed public key..." << std::endl;
        // For compressed keys, use X coordinate (skip prefix)
        hashInput.assign(publicKey.begin() + 1, publicKey.end());
    } else {
        throw std::runtime_error("Invalid public key format");
    }

    std::cout << "Hash input (hex): " << utils::bytesToHex(hashInput) << std::endl;

    // Compute Keccak-256 hash
    std::cout << "Computing Keccak-256 hash..." << std::endl;
    auto hash = keccak256(hashInput);
    std::cout << "Keccak-256 hash (hex): " << utils::bytesToHex(hash) << std::endl;

    // Take the last 20 bytes of the hash
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