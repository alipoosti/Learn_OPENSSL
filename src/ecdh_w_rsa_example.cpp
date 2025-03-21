#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <iostream>
#include <vector>
#include <cstring>

#define RSA_KEY_SIZE 2048  // RSA Key size (2048-bit for security)

// Error handling
void handleErrors() {
    ERR_print_errors_fp(stderr);
    abort();
}

// Generate an RSA key pair for Bob
EVP_PKEY* generate_rsa_key() {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(nullptr, "RSA", nullptr);
    if (!ctx) handleErrors();

    if (EVP_PKEY_keygen_init(ctx) <= 0) handleErrors();
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, RSA_KEY_SIZE) <= 0) handleErrors();

    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_generate(ctx, &pkey) <= 0) handleErrors();

    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

// Serialize public key to PEM format (string)
std::string serialize_public_key(EVP_PKEY* pkey) {
    BIO* bio = BIO_new(BIO_s_mem());
    if (!PEM_write_bio_PUBKEY(bio, pkey)) handleErrors();

    char* data;
    long len = BIO_get_mem_data(bio, &data);
    std::string pem(data, len);

    BIO_free(bio);
    return pem;
}

// Deserialize public key from PEM format
EVP_PKEY* deserialize_public_key(const std::string& pem) {
    BIO* bio = BIO_new_mem_buf(pem.data(), pem.size());
    EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);

    if (!pkey) handleErrors();
    return pkey;
}

// RSA Encryption using Bob's public key
std::vector<unsigned char> rsa_encrypt(EVP_PKEY* public_key, const std::string& plaintext) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(public_key, nullptr);
    if (!ctx) handleErrors();

    if (EVP_PKEY_encrypt_init(ctx) <= 0) handleErrors();
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) handleErrors();

    size_t outlen;
    if (EVP_PKEY_encrypt(ctx, nullptr, &outlen, (unsigned char*)plaintext.c_str(), plaintext.size()) <= 0) handleErrors();

    std::vector<unsigned char> ciphertext(outlen);
    if (EVP_PKEY_encrypt(ctx, ciphertext.data(), &outlen, (unsigned char*)plaintext.c_str(), plaintext.size()) <= 0) handleErrors();

    EVP_PKEY_CTX_free(ctx);
    return ciphertext;
}

// RSA Decryption using Bob's private key
std::string rsa_decrypt(EVP_PKEY* private_key, const std::vector<unsigned char>& ciphertext) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(private_key, nullptr);
    if (!ctx) handleErrors();

    if (EVP_PKEY_decrypt_init(ctx) <= 0) handleErrors();
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) handleErrors();

    size_t outlen;
    if (EVP_PKEY_decrypt(ctx, nullptr, &outlen, ciphertext.data(), ciphertext.size()) <= 0) handleErrors();

    std::vector<unsigned char> plaintext(outlen);
    if (EVP_PKEY_decrypt(ctx, plaintext.data(), &outlen, ciphertext.data(), ciphertext.size()) <= 0) handleErrors();

    EVP_PKEY_CTX_free(ctx);
    return std::string(plaintext.begin(), plaintext.end());
}

// Main function to demonstrate secure communication
int main() {
    // Bob generates his RSA key pair
    EVP_PKEY* bob_key = generate_rsa_key();

    // Bob shares his public key with Alice (serialization)
    std::string bob_public_pem = serialize_public_key(bob_key);

    // Alice receives Bob’s public key and encrypts the message
    EVP_PKEY* bob_public_key = deserialize_public_key(bob_public_pem);
    std::string message = "I Love You!";
    std::vector<unsigned char> ciphertext = rsa_encrypt(bob_public_key, message);

    // Bob decrypts the message using his private key
    std::string decrypted_message = rsa_decrypt(bob_key, ciphertext);

    // Output result
    std::cout << "Decrypted Message: " << decrypted_message << std::endl;

    // Cleanup
    EVP_PKEY_free(bob_key);
    EVP_PKEY_free(bob_public_key);

    return 0;
}
