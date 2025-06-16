#include <iostream>
#include <string>
#include <openssl/bn.h>
#include "wallet_converter.hpp"

int main() {
    std::cout << "Program starting..." << std::endl << std::flush;
    
    try {
        // Initialize OpenSSL
        std::cout << "Initializing OpenSSL..." << std::endl << std::flush;
        // No need for OpenSSL initialization since we're only using BIGNUM functions
        
        std::cout << "Starting wallet conversion..." << std::endl << std::flush;
        
        WalletConverter converter;
        std::cout << "WalletConverter initialized successfully" << std::endl << std::flush;
        
        // Example mnemonic (replace with actual input)
        std::string mnemonic = "comfort toy reform zero february acid lab dream misery vital loan noodle";
        std::cout << "Using mnemonic: " << mnemonic << std::endl << std::flush;
        
        std::cout << "Converting mnemonic to address..." << std::endl << std::flush;
        std::string address = converter.mnemonicToAddress(mnemonic);
        std::cout << "Ethereum Address: " << address << std::endl << std::flush;
        
        // Expected address for this mnemonic
        std::string expected = "0xc3ae875ffcdc3e76f69b5ecf5862fb60391ceb78";
        std::cout << "Expected address: " << expected << std::endl << std::flush;
        
        if (address == expected) {
            std::cout << "Success! Address matches expected value." << std::endl << std::flush;
        } else {
            std::cout << "Warning: Address does not match expected value." << std::endl << std::flush;
        }
        
        std::cout << "Program finished." << std::endl << std::flush;
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl << std::flush;
        return 1;
    }
}