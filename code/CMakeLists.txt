add_executable(eth_wallet_converter
    main.cpp
    wallet_converter.cpp
    wallet_converter.hpp
    bip39.cpp
    bip39.hpp
    bip32.cpp
    bip32.hpp
    keccak.cpp
    keccak.hpp
)

target_link_libraries(eth_wallet_converter
    PRIVATE
    secp256k1
    ${SODIUM_LIBRARIES}
    ${OPENSSL_LIBRARIES}
    xkcp
)

# Add include directories
target_include_directories(eth_wallet_converter
    PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${SODIUM_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIR}
)

add_custom_target(run 
    COMMAND ${PROJECT_NAME}
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}/build"
)

set(SOURCES
   main.cpp
)
#message(STATUS "The value of SOURCES is: ${SOURCES}")

target_sources(${PROJECT_NAME}  PRIVATE ${SOURCES})

set_target_properties(${PROJECT_NAME} PROPERTIES RUNTIME_OUTPUT_DIRECTORY_DEBUG   "${CMAKE_SOURCE_DIR}/build"
                                                 RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_SOURCE_DIR}/build")  