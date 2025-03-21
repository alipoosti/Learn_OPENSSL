#include <iostream>
#include <string>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>  
#include <openssl/core_names.h>

std::string to_hex(const unsigned char* data, size_t length) {
    std::string hex_str;
    hex_str.reserve(length * 2);
    for (size_t i = 0; i < length; ++i) {
        char buf[3];
        snprintf(buf, sizeof(buf), "%02x", data[i]);
        hex_str.append(buf);
    }
    return hex_str;
}

void handleErrors() {
    std::cerr << "An error occurred." << std::endl;
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}

EVP_PKEY* generate_ec_key() {
    EVP_PKEY* pkey = nullptr;
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
    if (!ctx)
        handleErrors();

    if (EVP_PKEY_keygen_init(ctx) <= 0)
        handleErrors();

    if (EVP_PKEY_CTX_set_group_name(ctx, "prime256v1") <= 0)
        handleErrors();

    if (EVP_PKEY_generate(ctx, &pkey) <= 0)
        handleErrors();

    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

unsigned char* derive_shared_secret(EVP_PKEY* local_key, EVP_PKEY* peer_key, size_t& secret_len) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(local_key, nullptr);
    if (!ctx)
        handleErrors();

    if (EVP_PKEY_derive_init(ctx) <= 0)
        handleErrors();

    if (EVP_PKEY_derive_set_peer(ctx, peer_key) <= 0)
        handleErrors();

    if (EVP_PKEY_derive(ctx, nullptr, &secret_len) <= 0)
        handleErrors();

    unsigned char* secret = static_cast<unsigned char*>(OPENSSL_malloc(secret_len));
    if (!secret)
        handleErrors();

    if (EVP_PKEY_derive(ctx, secret, &secret_len) <= 0)
        handleErrors();

    EVP_PKEY_CTX_free(ctx);
    return secret;
}

int main() {
    // Generate key pairs for two parties
    EVP_PKEY* pkey1 = generate_ec_key();
    EVP_PKEY* pkey2 = generate_ec_key();

    // Derive shared secrets
    size_t secret1_len, secret2_len;
    unsigned char* secret1 = derive_shared_secret(pkey1, pkey2, secret1_len);
    unsigned char* secret2 = derive_shared_secret(pkey2, pkey1, secret2_len);

    // Compare shared secrets
    if (secret1_len == secret2_len && CRYPTO_memcmp(secret1, secret2, secret1_len) == 0) {
        std::cout << "SUCCESS! The shared secrets are equal." << std::endl;
    } else {
        std::cout << "FAILURE! The shared secrets are different." << std::endl;
    }

    // Clean up
    EVP_PKEY_free(pkey1);
    EVP_PKEY_free(pkey2);
    OPENSSL_free(secret1);
    OPENSSL_free(secret2);

    return 0;
}
