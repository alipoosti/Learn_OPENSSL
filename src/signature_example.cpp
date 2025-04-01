#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <iostream>
#include <vector>
#include <memory>

// Helper function for OpenSSL error handling
void handle_openssl_error() {
    ERR_print_errors_fp(stderr);
    exit(1);
}

// Function to generate an RSA key pair
EVP_PKEY* generate_rsa_key() {
    EVP_PKEY* pkey = nullptr;
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);

    if (!ctx) handle_openssl_error();
    if (EVP_PKEY_keygen_init(ctx) <= 0) handle_openssl_error();
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) handle_openssl_error();
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) handle_openssl_error();

    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

// Function to extract and return the public key from a private key
EVP_PKEY* extract_public_key(EVP_PKEY* private_key) {
    BIO* bio = BIO_new(BIO_s_mem());
    if (!PEM_write_bio_PUBKEY(bio, private_key)) handle_openssl_error();

    EVP_PKEY* public_key = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    return public_key;
}

// Function to sign a message
std::vector<unsigned char> sign_message(EVP_PKEY* private_key, const std::string& message) {
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) handle_openssl_error();

    size_t sig_len = EVP_PKEY_size(private_key);  // Correctly determine signature size
    std::vector<unsigned char> signature(sig_len);

    if (EVP_DigestSignInit(md_ctx, nullptr, EVP_sha256(), nullptr, private_key) <= 0) handle_openssl_error();
    if (EVP_DigestSignUpdate(md_ctx, message.c_str(), message.length()) <= 0) handle_openssl_error();
    if (EVP_DigestSignFinal(md_ctx, signature.data(), &sig_len) <= 0) handle_openssl_error();

    signature.resize(sig_len);  // Trim to actual size
    EVP_MD_CTX_free(md_ctx);
    return signature;
}

// Function to verify the signature
bool verify_signature(EVP_PKEY* public_key, const std::string& message, const std::vector<unsigned char>& signature) {
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    bool is_valid = false;

    if (EVP_DigestVerifyInit(md_ctx, nullptr, EVP_sha256(), nullptr, public_key) <= 0) handle_openssl_error();
    if (EVP_DigestVerifyUpdate(md_ctx, message.c_str(), message.length()) <= 0) handle_openssl_error();
    
    if (EVP_DigestVerifyFinal(md_ctx, signature.data(), signature.size()) == 1) {
        is_valid = true;
    } else {
        std::cerr << "Signature verification failed ❌\n";
    }

    EVP_MD_CTX_free(md_ctx);
    return is_valid;
}

int main() {
    // Bob generates an RSA key pair (private + public)
    EVP_PKEY* bob_private_key = generate_rsa_key();
    if (!bob_private_key) return 1;

    // Bob extracts his public key to share with Alice
    EVP_PKEY* bob_public_key = extract_public_key(bob_private_key);
    if (!bob_public_key) {
        std::cerr << "Error extracting public key\n";
        return 1;
    }

    // Bob's message
    std::string message = "I love RSA";

    // Bob signs the message with his private key
    std::vector<unsigned char> signature = sign_message(bob_private_key, message);

    // Alice receives Bob's public key and verifies the signature
    if (verify_signature(bob_public_key, message, signature)) {
        std::cout << "Signature is valid! ✅\n";
    } else {
        std::cout << "Signature verification failed ❌\n";
    }

    // Cleanup
    EVP_PKEY_free(bob_private_key);
    EVP_PKEY_free(bob_public_key);
    return 0;
}
