cmake_minimum_required(VERSION 3.10)

# Project Name
project(Learn_OPENSSL)

# Specify C++ standard
set(CMAKE_CXX_STANDARD 14)

# Find OpenSSL package
find_package(OpenSSL REQUIRED PATHS /opt/homebrew/opt/openssl@3)

# Add the executable
add_executable(aes_example src/aes_example.cpp)
add_executable(ecdh_example src/ecdh_example.cpp)
add_executable(ecdh_w_aes_example src/ecdh_w_aes_example.cpp)
add_executable(ecdh_w_rsa_example src/ecdh_w_rsa_example.cpp)
add_executable(kem_example src/kem_example.cpp)
add_executable(signature_example src/signature_example.cpp)


# Link OpenSSL libraries to your project
target_link_libraries(aes_example OpenSSL::Crypto)
target_link_libraries(ecdh_example OpenSSL::Crypto)
target_link_libraries(ecdh_w_aes_example OpenSSL::Crypto)
target_link_libraries(ecdh_w_rsa_example OpenSSL::Crypto)
target_link_libraries(kem_example OpenSSL::Crypto)
target_link_libraries(signature_example OpenSSL::Crypto)