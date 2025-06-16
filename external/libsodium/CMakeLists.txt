cmake_minimum_required(VERSION 3.15)
project(sodium)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Add library
add_library(sodium STATIC
    src/libsodium/crypto_aead/aegis128l/aegis128l.c
    src/libsodium/crypto_aead/aegis256/aegis256.c
    src/libsodium/crypto_aead/chacha20poly1305/sodium/aead_chacha20poly1305.c
    src/libsodium/crypto_aead/xchacha20poly1305/sodium/aead_xchacha20poly1305.c
    src/libsodium/crypto_auth/crypto_auth.c
    src/libsodium/crypto_auth/hmacsha256/auth_hmacsha256.c
    src/libsodium/crypto_auth/hmacsha512/auth_hmacsha512.c
    src/libsodium/crypto_auth/hmacsha512256/auth_hmacsha512256.c
    src/libsodium/crypto_box/crypto_box.c
    src/libsodium/crypto_box/crypto_box_easy.c
    src/libsodium/crypto_box/crypto_box_seal.c
    src/libsodium/crypto_box/curve25519xchacha20poly1305/box_curve25519xchacha20poly1305.c
    src/libsodium/crypto_box/curve25519xchacha20poly1305/box_seal_curve25519xchacha20poly1305.c
    src/libsodium/crypto_core/ed25519/ref10/ed25519_ref10.c
    src/libsodium/crypto_core/hchacha20/core_hchacha20.c
    src/libsodium/crypto_core/hsalsa20/core_hsalsa20.c
    src/libsodium/crypto_core/salsa/ref/core_salsa_ref.c
    src/libsodium/crypto_generichash/blake2b/generichash_blake2.c
    src/libsodium/crypto_generichash/crypto_generichash.c
    src/libsodium/crypto_hash/crypto_hash.c
    src/libsodium/crypto_hash/sha256/hash_sha256.c
    src/libsodium/crypto_hash/sha512/hash_sha512.c
    src/libsodium/crypto_kdf/blake2b/kdf_blake2b.c
    src/libsodium/crypto_kdf/crypto_kdf.c
    src/libsodium/crypto_kx/crypto_kx.c
    src/libsodium/crypto_onetimeauth/crypto_onetimeauth.c
    src/libsodium/crypto_onetimeauth/poly1305/onetimeauth_poly1305.c
    src/libsodium/crypto_pwhash/argon2/argon2-core.c
    src/libsodium/crypto_pwhash/argon2/argon2-encoding.c
    src/libsodium/crypto_pwhash/argon2/argon2-fill-block-ref.c
    src/libsodium/crypto_pwhash/argon2/argon2.c
    src/libsodium/crypto_pwhash/argon2/blake2b-long.c
    src/libsodium/crypto_pwhash/argon2/pwhash_argon2i.c
    src/libsodium/crypto_pwhash/crypto_pwhash.c
    src/libsodium/crypto_scalarmult/crypto_scalarmult.c
    src/libsodium/crypto_scalarmult/curve25519/scalarmult_curve25519.c
    src/libsodium/crypto_scalarmult/ed25519/ref10/scalarmult_ed25519_ref10.c
    src/libsodium/crypto_scalarmult/ristretto255/ref10/scalarmult_ristretto255_ref10.c
    src/libsodium/crypto_secretbox/crypto_secretbox.c
    src/libsodium/crypto_secretbox/crypto_secretbox_easy.c
    src/libsodium/crypto_secretbox/xchacha20poly1305/secretbox_xchacha20poly1305.c
    src/libsodium/crypto_secretstream/xchacha20poly1305/secretstream_xchacha20poly1305.c
    src/libsodium/crypto_shorthash/crypto_shorthash.c
    src/libsodium/crypto_shorthash/siphash24/shorthash_siphash24.c
    src/libsodium/crypto_sign/crypto_sign.c
    src/libsodium/crypto_sign/ed25519/ref10/keypair.c
    src/libsodium/crypto_sign/ed25519/ref10/open.c
    src/libsodium/crypto_sign/ed25519/ref10/sign.c
    src/libsodium/crypto_stream/chacha20/stream_chacha20.c
    src/libsodium/crypto_stream/salsa20/stream_salsa20.c
    src/libsodium/crypto_stream/salsa2012/stream_salsa2012.c
    src/libsodium/crypto_stream/salsa208/stream_salsa208.c
    src/libsodium/crypto_stream/xchacha20/stream_xchacha20.c
    src/libsodium/crypto_stream/xsalsa20/stream_xsalsa20.c
    src/libsodium/crypto_verify/sodium/verify.c
    src/libsodium/randombytes/randombytes.c
    src/libsodium/sodium/core.c
    src/libsodium/sodium/runtime.c
    src/libsodium/sodium/utils.c
    src/libsodium/sodium/version.c
)

# Include directories
target_include_directories(sodium PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src/libsodium/include
) 