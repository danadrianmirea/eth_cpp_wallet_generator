cmake_minimum_required(VERSION 3.15)

# Set vcpkg toolchain file
set(CMAKE_TOOLCHAIN_FILE "D:/vcpkg/scripts/buildsystems/vcpkg.cmake" CACHE STRING "Vcpkg toolchain file")

project(eth_wallet_converter)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Set library paths
set(LIBRARY_DIR ${CMAKE_CURRENT_SOURCE_DIR}/lib)
set(LIBRARY_INCLUDE_DIR ${LIBRARY_DIR}/include)
set(LIBRARY_BIN_DIR ${LIBRARY_DIR}/bin)
set(LIBRARY_LIB_DIR ${LIBRARY_DIR}/lib)

# Find OpenSSL package
find_package(OpenSSL REQUIRED)

# Add executable
add_executable(wallet_converter 
    code/main.cpp
    code/wallet_converter.cpp
    code/bip39.cpp
    code/bip32.cpp
    code/keccak.cpp
)

# Include directories
target_include_directories(wallet_converter PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/code
    ${LIBRARY_INCLUDE_DIR}
    ${OPENSSL_INCLUDE_DIR}
)

# Link directories
link_directories(${LIBRARY_LIB_DIR})

# Copy DLLs to output directory
add_custom_command(TARGET wallet_converter POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_directory
    ${LIBRARY_BIN_DIR} $<TARGET_FILE_DIR:wallet_converter>
)

# Link libraries
target_link_libraries(wallet_converter PRIVATE
    ${LIBRARY_LIB_DIR}/libsodium.lib
    OpenSSL::SSL
    OpenSSL::Crypto
)