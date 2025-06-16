#include <iostream>
#include <string>
#include "wallet_converter.hpp"

int main() {
    std::cout << "Program starting..." << std::endl << std::flush;
    
    try {
        std::cout << "Starting wallet conversion..." << std::endl << std::flush;
        
        WalletConverter converter;
        std::cout << "WalletConverter initialized successfully" << std::endl << std::flush;
        
        // Example mnemonic (replace with actual input)
        std::string mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        std::cout << "Using mnemonic: " << mnemonic << std::endl << std::flush;
        
        std::cout << "Converting mnemonic to address..." << std::endl << std::flush;
        std::string address = converter.mnemonicToAddress(mnemonic);
        std::cout << "Ethereum Address: " << address << std::endl << std::flush;
        
        // Expected address for this mnemonic
        std::string expected = "0x9858EfFD232B4033E47d90003D41EC34EcaEda94";
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