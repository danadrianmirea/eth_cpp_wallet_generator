#include "bip32.hpp"
#include "utils.hpp"
#include <sodium.h>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <cstring>
#include <iostream>

BIP32::Key BIP32::deriveChildKey(const Key& parent, uint32_t childNumber) {
    try {
        std::cout << "\nDeriving child key for number: " << childNumber << std::endl;
        std::cout << "Parent key (hex): " << utils::bytesToHex(parent.key) << std::endl;
        std::cout << "Parent chain code (hex): " << utils::bytesToHex(parent.chainCode) << std::endl;

        if (parent.key.size() != KEY_SIZE || parent.chainCode.size() != CHAIN_CODE_SIZE) {
            throw std::runtime_error("Invalid parent key");
        }

        // Check if this is a hardened key
        bool isHardened = (childNumber & 0x80000000) != 0;
        std::cout << (isHardened ? "Deriving hardened key..." : "Deriving normal key...") << std::endl;

        // Prepare data for HMAC
        std::vector<uint8_t> data;
        if (isHardened) {
            // For hardened keys, use 0x00 || parent private key || index
            data.push_back(0x00);
            data.insert(data.end(), parent.key.begin(), parent.key.end());
        } else {
            // For normal keys, use parent public key || index
            std::vector<uint8_t> parentPubKey = getPublicKey(parent.key);
            data.insert(data.end(), parentPubKey.begin(), parentPubKey.end());
        }

        // Append the child number as a 4-byte big-endian integer
        data.push_back((childNumber >> 24) & 0xFF);
        data.push_back((childNumber >> 16) & 0xFF);
        data.push_back((childNumber >> 8) & 0xFF);
        data.push_back(childNumber & 0xFF);

        std::cout << "HMAC input (hex): " << utils::bytesToHex(data) << std::endl;

        // Calculate HMAC-SHA512
        std::vector<uint8_t> hmacOutput(64);
        crypto_auth_hmacsha512_state state;
        crypto_auth_hmacsha512_init(&state, parent.chainCode.data(), parent.chainCode.size());
        crypto_auth_hmacsha512_update(&state, data.data(), data.size());
        crypto_auth_hmacsha512_final(&state, hmacOutput.data());

        std::cout << "HMAC output (hex): " << utils::bytesToHex(hmacOutput) << std::endl;

        // Split HMAC output into child key and chain code
        std::vector<uint8_t> childKey(hmacOutput.begin(), hmacOutput.begin() + KEY_SIZE);
        std::vector<uint8_t> childChainCode(hmacOutput.begin() + KEY_SIZE, hmacOutput.end());

        std::cout << "HMAC key part (hex): " << utils::bytesToHex(childKey) << std::endl;
        std::cout << "HMAC chain code part (hex): " << utils::bytesToHex(childChainCode) << std::endl;

        // For private key derivation, we need to add the HMAC output to the parent private key
        if (parent.isPrivate) {
            std::cout << "Deriving private key..." << std::endl;
            
            // Create BIGNUMs for the private keys
            BIGNUM* parentPriv = BN_bin2bn(parent.key.data(), parent.key.size(), nullptr);
            BIGNUM* childPriv = BN_bin2bn(childKey.data(), childKey.size(), nullptr);
            BIGNUM* n = BN_new();
            BIGNUM* sum = BN_new();
            BIGNUM* result = BN_new();
            BIGNUM* temp = BN_new();
            BN_CTX* ctx = BN_CTX_new();
            
            if (!parentPriv || !childPriv || !n || !sum || !result || !temp || !ctx) {
                if (parentPriv) BN_free(parentPriv);
                if (childPriv) BN_free(childPriv);
                if (n) BN_free(n);
                if (sum) BN_free(sum);
                if (result) BN_free(result);
                if (temp) BN_free(temp);
                if (ctx) BN_CTX_free(ctx);
                throw std::runtime_error("Failed to create BIGNUMs for private key derivation");
            }
            std::cout << "Created BIGNUMs for private key derivation" << std::endl;

            // Print parent private key
            char* parent_hex = BN_bn2hex(parentPriv);
            if (parent_hex) {
                std::cout << "Parent private key (hex): " << parent_hex << std::endl;
                OPENSSL_free(parent_hex);
            }

            // Print child private key
            char* child_hex = BN_bn2hex(childPriv);
            if (child_hex) {
                std::cout << "Child private key (hex): " << child_hex << std::endl;
                OPENSSL_free(child_hex);
            }

            // Set the curve order (n) directly
            // n = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
            const char* n_hex = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";
            if (!BN_hex2bn(&n, n_hex)) {
                BN_free(parentPriv);
                BN_free(childPriv);
                BN_free(n);
                BN_free(sum);
                BN_free(result);
                BN_free(temp);
                BN_CTX_free(ctx);
                throw std::runtime_error("Failed to set curve order");
            }
            std::cout << "Set curve order" << std::endl;

            // Print curve order
            char* n_hex_str = BN_bn2hex(n);
            if (n_hex_str) {
                std::cout << "Curve order (hex): " << n_hex_str << std::endl;
                OPENSSL_free(n_hex_str);
            }

            // Add the parent private key and child private key
            if (!BN_add(sum, parentPriv, childPriv)) {
                BN_free(parentPriv);
                BN_free(childPriv);
                BN_free(n);
                BN_free(sum);
                BN_free(result);
                BN_free(temp);
                BN_CTX_free(ctx);
                throw std::runtime_error("Failed to add private keys");
            }
            std::cout << "Added private keys" << std::endl;

            // Print sum before modulo
            char* sum_hex = BN_bn2hex(sum);
            if (sum_hex) {
                std::cout << "Sum before modulo (hex): " << sum_hex << std::endl;
                OPENSSL_free(sum_hex);
            }

            // Take modulo n using BN_CTX for better error handling
            if (!BN_mod(result, sum, n, ctx)) {
                BN_free(parentPriv);
                BN_free(childPriv);
                BN_free(n);
                BN_free(sum);
                BN_free(result);
                BN_free(temp);
                BN_CTX_free(ctx);
                throw std::runtime_error("Failed to compute modulo");
            }
            std::cout << "Computed modulo" << std::endl;

            // Check if result is zero
            if (BN_is_zero(result)) {
                std::cout << "Result is zero, incrementing index and retrying..." << std::endl;
                // Clean up current BIGNUMs
                BN_free(parentPriv);
                BN_free(childPriv);
                BN_free(n);
                BN_free(sum);
                BN_free(result);
                BN_free(temp);
                BN_CTX_free(ctx);
                
                // Increment the index and retry
                return deriveChildKey(parent, childNumber + 1);
            }

            // Print result
            char* result_hex = BN_bn2hex(result);
            if (result_hex) {
                std::cout << "Result (hex): " << result_hex << std::endl;
                OPENSSL_free(result_hex);
            }

            // Convert back to bytes
            std::vector<uint8_t> newChildKey(KEY_SIZE, 0);
            int len = BN_bn2bin(result, newChildKey.data());
            if (len <= 0) {
                BN_free(parentPriv);
                BN_free(childPriv);
                BN_free(n);
                BN_free(sum);
                BN_free(result);
                BN_free(temp);
                BN_CTX_free(ctx);
                throw std::runtime_error("Failed to convert BIGNUM to bytes");
            }
            std::cout << "Converted BIGNUM to bytes, length: " << len << std::endl;

            // If the result is shorter than KEY_SIZE, we need to pad with zeros
            if (len < KEY_SIZE) {
                std::rotate(newChildKey.begin(), newChildKey.begin() + len, newChildKey.end());
                std::fill(newChildKey.begin(), newChildKey.begin() + (KEY_SIZE - len), 0);
                std::cout << "Padded key to " << KEY_SIZE << " bytes" << std::endl;
            }

            std::cout << "Final child key (hex): " << utils::bytesToHex(newChildKey) << std::endl;
            childKey = newChildKey;

            // Cleanup
            BN_free(parentPriv);
            BN_free(childPriv);
            BN_free(n);
            BN_free(sum);
            BN_free(result);
            BN_free(temp);
            BN_CTX_free(ctx);
            std::cout << "Cleaned up OpenSSL resources for private key derivation" << std::endl;
        }

        std::cout << "Child key (hex): " << utils::bytesToHex(childKey) << std::endl;
        std::cout << "Child chain code (hex): " << utils::bytesToHex(childChainCode) << std::endl;

        // Create child key
        Key child;
        child.key = childKey;
        child.chainCode = childChainCode;
        child.depth = parent.depth + 1;
        child.childNumber = childNumber;
        child.fingerprint = getFingerprint(parent.key);
        child.isPrivate = parent.isPrivate;

        std::cout << "Successfully created child key" << std::endl;
        return child;
    } catch (const std::exception& e) {
        std::cerr << "Error in deriveChildKey: " << e.what() << std::endl;
        throw;
    }
}

BIP32::Key BIP32::derivePath(const std::vector<uint8_t>& seed, const std::string& path) {
    std::cout << "\nDeriving path: " << path << std::endl;
    std::cout << "Seed (hex): " << utils::bytesToHex(seed) << std::endl;

    if (seed.size() < 16) {
        throw std::runtime_error("Seed too short");
    }

    // Create master key using HMAC-SHA512 with "Bitcoin seed" as key
    std::vector<uint8_t> key(32, 0);
    std::string bitcoinSeed = "Bitcoin seed";
    std::copy(bitcoinSeed.begin(), bitcoinSeed.end(), key.begin());

    std::cout << "Master key input (hex): " << utils::bytesToHex(key) << std::endl;

    // Calculate HMAC-SHA512
    std::vector<uint8_t> hmac(crypto_auth_hmacsha512_BYTES);
    crypto_auth_hmacsha512_state state;
    crypto_auth_hmacsha512_init(&state, key.data(), key.size());
    crypto_auth_hmacsha512_update(&state, seed.data(), seed.size());
    crypto_auth_hmacsha512_final(&state, hmac.data());

    std::cout << "Master HMAC output (hex): " << utils::bytesToHex(hmac) << std::endl;

    // Split into key and chain code
    Key master;
    master.key = std::vector<uint8_t>(hmac.begin(), hmac.begin() + KEY_SIZE);
    master.chainCode = std::vector<uint8_t>(hmac.begin() + KEY_SIZE, hmac.end());
    master.depth = 0;
    master.childNumber = 0;
    master.fingerprint = {0, 0, 0, 0};
    master.isPrivate = true;

    std::cout << "Master key (hex): " << utils::bytesToHex(master.key) << std::endl;
    std::cout << "Master chain code (hex): " << utils::bytesToHex(master.chainCode) << std::endl;

    // Parse path
    std::istringstream iss(path);
    std::string component;
    Key current = master;

    while (std::getline(iss, component, '/')) {
        if (component == "m") continue;
        uint32_t childNumber = getChildNumber(component);
        current = deriveChildKey(current, childNumber);
    }

    return current;
}

std::string BIP32::keyToString(const Key& key) {
    std::vector<uint8_t> data;
    
    // Version
    if (key.isPrivate) {
        data.push_back(0x04);
        data.push_back(0x88);
        data.push_back(0xAD);
        data.push_back(0xE4);
    } else {
        data.push_back(0x04);
        data.push_back(0x88);
        data.push_back(0xB2);
        data.push_back(0x1E);
    }

    // Depth
    data.push_back(static_cast<uint8_t>(key.depth));

    // Fingerprint
    data.insert(data.end(), key.fingerprint.begin(), key.fingerprint.end());

    // Child number
    data.push_back((key.childNumber >> 24) & 0xFF);
    data.push_back((key.childNumber >> 16) & 0xFF);
    data.push_back((key.childNumber >> 8) & 0xFF);
    data.push_back(key.childNumber & 0xFF);

    // Chain code
    data.insert(data.end(), key.chainCode.begin(), key.chainCode.end());

    // Key
    if (key.isPrivate) {
        data.push_back(0);
    }
    data.insert(data.end(), key.key.begin(), key.key.end());

    // Calculate checksum using libsodium
    std::vector<uint8_t> hash(crypto_generichash_BYTES);
    crypto_generichash(hash.data(), hash.size(), data.data(), data.size(), nullptr, 0);

    // Append checksum
    data.insert(data.end(), hash.begin(), hash.begin() + 4);

    // Convert to base58
    // TODO: Implement base58 encoding
    return "xprv..."; // Placeholder
}

BIP32::Key BIP32::stringToKey(const std::string& str) {
    // TODO: Implement base58 decoding and key parsing
    throw std::runtime_error("Not implemented");
}

std::array<uint8_t, BIP32::FINGERPRINT_SIZE> BIP32::getFingerprint(const std::vector<uint8_t>& key) {
    std::array<uint8_t, FINGERPRINT_SIZE> fingerprint;
    std::vector<uint8_t> hash(crypto_generichash_BYTES);
    
    crypto_generichash(hash.data(), hash.size(), key.data(), key.size(), nullptr, 0);
    std::copy(hash.begin(), hash.begin() + FINGERPRINT_SIZE, fingerprint.begin());
    
    return fingerprint;
}

bool BIP32::isHardened(uint32_t childNumber) {
    return (childNumber & 0x80000000) != 0;
}

uint32_t BIP32::getChildNumber(const std::string& pathComponent) {
    bool hardened = pathComponent.back() == '\'' || pathComponent.back() == 'h';
    std::string number = hardened ? pathComponent.substr(0, pathComponent.length() - 1) : pathComponent;
    
    uint32_t childNumber = std::stoul(number);
    if (hardened) {
        childNumber |= 0x80000000;
    }
    
    return childNumber;
}

std::vector<uint8_t> BIP32::getPublicKey(const std::vector<uint8_t>& privateKey) {
    std::cout << "\nGetting public key from private key..." << std::endl;
    
    EC_KEY* key = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (!key) {
        throw std::runtime_error("Failed to create EC key");
    }
    std::cout << "EC key created successfully" << std::endl;

    BIGNUM* priv = BN_new();
    if (!priv) {
        EC_KEY_free(key);
        throw std::runtime_error("Failed to create BIGNUM");
    }
    std::cout << "BIGNUM created from private key" << std::endl;

    BN_bin2bn(privateKey.data(), privateKey.size(), priv);
    if (!EC_KEY_set_private_key(key, priv)) {
        BN_free(priv);
        EC_KEY_free(key);
        throw std::runtime_error("Failed to set private key");
    }
    std::cout << "Private key set in EC key" << std::endl;

    const EC_GROUP* group = EC_KEY_get0_group(key);
    if (!group) {
        BN_free(priv);
        EC_KEY_free(key);
        throw std::runtime_error("Failed to get EC group");
    }
    std::cout << "Got EC group" << std::endl;

    EC_POINT* pub = EC_POINT_new(group);
    if (!pub) {
        BN_free(priv);
        EC_KEY_free(key);
        throw std::runtime_error("Failed to create EC point");
    }
    std::cout << "Created EC point" << std::endl;

    if (!EC_POINT_mul(group, pub, priv, nullptr, nullptr, nullptr)) {
        EC_POINT_free(pub);
        BN_free(priv);
        EC_KEY_free(key);
        throw std::runtime_error("Failed to compute public key");
    }
    std::cout << "Computed public key" << std::endl;

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
    std::cout << "Cleaned up OpenSSL resources" << std::endl;

    return publicKey;
} 