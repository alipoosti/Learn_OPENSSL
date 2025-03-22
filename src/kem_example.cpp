#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <iostream>
#include <vector>
#include <string>

#define RSA_KEY_SIZE 2048
#define AES_KEY_SIZE 32  // AES-256
#define AES_IV_SIZE 12   // GCM Standard IV size
#define AES_TAG_SIZE 16  // GCM authentication tag size

// Structure to hold the encrypted key and message
struct CipherPackage {
    std::vector<unsigned char> cipher_key;
    std::vector<unsigned char> cipher_message;
    std::vector<unsigned char> iv;
    std::vector<unsigned char> tag;
};

// Error handling
void handleErrors() {
    ERR_print_errors_fp(stderr);
    abort();
}

// Generate RSA key pair for Bob
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

// Extract Bob’s Public Key (PEM format)
EVP_PKEY* extract_public_key(EVP_PKEY* keypair) {
    BIO* bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(bio, keypair);  // Serialize public key

    EVP_PKEY* public_key = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);

    return public_key;  // Return a new EVP_PKEY containing only the public key
}

// Encrypt symmetric AES key with RSA public key
std::vector<unsigned char> rsa_encrypt(EVP_PKEY* public_key, const std::vector<unsigned char>& plaintext) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(public_key, nullptr);
    if (!ctx) handleErrors();

    if (EVP_PKEY_encrypt_init(ctx) <= 0) handleErrors();
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) handleErrors();

    size_t outlen;
    if (EVP_PKEY_encrypt(ctx, nullptr, &outlen, plaintext.data(), plaintext.size()) <= 0) handleErrors();

    std::vector<unsigned char> ciphertext(outlen);
    if (EVP_PKEY_encrypt(ctx, ciphertext.data(), &outlen, plaintext.data(), plaintext.size()) <= 0) handleErrors();

    EVP_PKEY_CTX_free(ctx);
    return ciphertext;
}

// Decrypt RSA encrypted AES key
std::vector<unsigned char> rsa_decrypt(EVP_PKEY* private_key, const std::vector<unsigned char>& ciphertext) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(private_key, nullptr);
    if (!ctx) handleErrors();

    if (EVP_PKEY_decrypt_init(ctx) <= 0) handleErrors();
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) handleErrors();

    size_t outlen;
    if (EVP_PKEY_decrypt(ctx, nullptr, &outlen, ciphertext.data(), ciphertext.size()) <= 0) handleErrors();

    std::vector<unsigned char> plaintext(outlen);
    if (EVP_PKEY_decrypt(ctx, plaintext.data(), &outlen, ciphertext.data(), ciphertext.size()) <= 0) handleErrors();

    EVP_PKEY_CTX_free(ctx);
    return plaintext;
}

// AES-GCM encryption
CipherPackage aes_encrypt(const std::vector<unsigned char>& key, const std::string& plaintext) {
    CipherPackage package;
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handleErrors();

    package.iv.resize(AES_IV_SIZE);
    RAND_bytes(package.iv.data(), AES_IV_SIZE);

    std::vector<unsigned char> ciphertext(plaintext.size());

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) <= 0) handleErrors();
    if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), package.iv.data()) <= 0) handleErrors();

    int len;
    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, (unsigned char*)plaintext.c_str(), plaintext.size()) <= 0)
        handleErrors();

    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) <= 0) handleErrors();

    package.cipher_message = ciphertext;
    package.tag.resize(AES_TAG_SIZE);
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AES_TAG_SIZE, package.tag.data()) <= 0) handleErrors();

    EVP_CIPHER_CTX_free(ctx);
    return package;
}

// AES-GCM decryption
std::string aes_decrypt(const std::vector<unsigned char>& key, const CipherPackage& package) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handleErrors();

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) <= 0) handleErrors();
    if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), package.iv.data()) <= 0) handleErrors();

    std::vector<unsigned char> plaintext(package.cipher_message.size());
    int len;
    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, package.cipher_message.data(), package.cipher_message.size()) <= 0)
        handleErrors();

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AES_TAG_SIZE, (void*)package.tag.data()) <= 0) handleErrors();
    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) <= 0) {
        std::cerr << "Decryption failed. Authentication tag mismatch.\n";
        exit(1);
    }

    EVP_CIPHER_CTX_free(ctx);
    return std::string(plaintext.begin(), plaintext.end());
}

// KEM encapsulation (Alice encrypts a message for Bob)
CipherPackage kem_encrypt(EVP_PKEY* public_key, const std::string& message) {
    std::vector<unsigned char> aes_key(AES_KEY_SIZE);
    RAND_bytes(aes_key.data(), AES_KEY_SIZE);

    std::vector<unsigned char> encrypted_key = rsa_encrypt(public_key, aes_key);
    CipherPackage package = aes_encrypt(aes_key, message);
    package.cipher_key = encrypted_key;
    
    return package;
}

// KEM decapsulation (Bob decrypts the CipherPackage)
std::string kem_decrypt(EVP_PKEY* private_key, const CipherPackage& package) {
    std::vector<unsigned char> decrypted_key = rsa_decrypt(private_key, package.cipher_key);
    return aes_decrypt(decrypted_key, package);
}

// Main function to demonstrate KEM framework
int main() {
    // Bob generates RSA key pair
    EVP_PKEY* bob_key = generate_rsa_key();

    // Bob extracts and shares his public key
    EVP_PKEY* bob_public_key = extract_public_key(bob_key);

    // Alice encrypts message using only Bob’s PUBLIC key
    std::string message = "I Love RSA!";
    CipherPackage package = kem_encrypt(bob_public_key, message);

    // Bob decrypts the message using his PRIVATE key
    std::string decrypted_message = kem_decrypt(bob_key, package);

    // Output result
    std::cout << "Decrypted Message: " << decrypted_message << std::endl;

    // Cleanup
    EVP_PKEY_free(bob_key);
    EVP_PKEY_free(bob_public_key);
    return 0;
}
