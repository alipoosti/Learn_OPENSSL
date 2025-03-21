#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <iostream>
#include <vector>
#include <cstring>

#define AES_KEY_SIZE 32  // 256-bit AES key
#define AES_IV_SIZE 12   // GCM standard IV size
#define TAG_SIZE 16      // AES-GCM Tag size

void handleErrors() {
    ERR_print_errors_fp(stderr);
    abort();
}

// Generate an EC key pair for Bob
EVP_PKEY* generate_ec_key() {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
    if (!ctx) handleErrors();

    if (EVP_PKEY_keygen_init(ctx) <= 0) handleErrors();
    if (EVP_PKEY_CTX_set_group_name(ctx, "P-256") <= 0) handleErrors(); // NIST P-256 curve
    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_generate(ctx, &pkey) <= 0) handleErrors();

    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

// Derive a shared secret using ECDH
std::vector<unsigned char> derive_shared_secret(EVP_PKEY* private_key, EVP_PKEY* peer_public_key) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(private_key, nullptr);
    if (!ctx) handleErrors();
    
    if (EVP_PKEY_derive_init(ctx) <= 0) handleErrors();
    if (EVP_PKEY_derive_set_peer(ctx, peer_public_key) <= 0) handleErrors();

    size_t secret_len;
    if (EVP_PKEY_derive(ctx, nullptr, &secret_len) <= 0) handleErrors();
    
    std::vector<unsigned char> shared_secret(secret_len);
    if (EVP_PKEY_derive(ctx, shared_secret.data(), &secret_len) <= 0) handleErrors();

    EVP_PKEY_CTX_free(ctx);
    return shared_secret;
}

// Encrypt message using AES-GCM
std::vector<unsigned char> aes_gcm_encrypt(const std::vector<unsigned char>& key, const std::string& plaintext, std::vector<unsigned char>& iv, std::vector<unsigned char>& tag) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handleErrors();

    iv.resize(AES_IV_SIZE);
    if (!RAND_bytes(iv.data(), AES_IV_SIZE)) handleErrors();

    std::vector<unsigned char> ciphertext(plaintext.size());

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key.data(), iv.data()) != 1) handleErrors();

    int len;
    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, reinterpret_cast<const unsigned char*>(plaintext.c_str()), plaintext.size()) != 1) handleErrors();

    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) handleErrors();

    tag.resize(TAG_SIZE);
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, TAG_SIZE, tag.data()) != 1) handleErrors();

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext;
}

// Decrypt message using AES-GCM
std::string aes_gcm_decrypt(const std::vector<unsigned char>& key, const std::vector<unsigned char>& ciphertext, const std::vector<unsigned char>& iv, const std::vector<unsigned char>& tag) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handleErrors();

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key.data(), iv.data()) != 1) handleErrors();

    std::vector<unsigned char> plaintext(ciphertext.size());
    int len;
    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size()) != 1) handleErrors();

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, TAG_SIZE, const_cast<unsigned char*>(tag.data())) != 1) handleErrors();

    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1) {
        std::cerr << "Decryption failed! (Tag mismatch)" << std::endl;
        handleErrors();
    }

    EVP_CIPHER_CTX_free(ctx);
    return std::string(plaintext.begin(), plaintext.end());
}

// Serialize public key to a byte array
std::vector<unsigned char> serialize_public_key(EVP_PKEY* pkey) {
    int len = i2d_PUBKEY(pkey, nullptr);
    std::vector<unsigned char> buffer(len);
    unsigned char* p = buffer.data();
    i2d_PUBKEY(pkey, &p);
    return buffer;
}

// Deserialize byte array to EVP_PKEY
EVP_PKEY* deserialize_public_key(const std::vector<unsigned char>& buffer) {
    const unsigned char* p = buffer.data();
    return d2i_PUBKEY(nullptr, &p, buffer.size());
}

// Main function to demonstrate secure communication
int main() {
    // Bob generates his key pair
    EVP_PKEY* bob_key = generate_ec_key();

    // Bob shares his public key with Alice
    std::vector<unsigned char> bob_public_bytes = serialize_public_key(bob_key);

    // Alice receives Bob’s public key and derives shared secret
    EVP_PKEY* bob_public_key = deserialize_public_key(bob_public_bytes);
    EVP_PKEY* alice_key = generate_ec_key();
    std::vector<unsigned char> shared_secret_alice = derive_shared_secret(alice_key, bob_public_key);

    // Alice encrypts the message
    std::string message = "I Love You!";
    std::vector<unsigned char> iv, tag;
    std::vector<unsigned char> ciphertext = aes_gcm_encrypt(shared_secret_alice, message, iv, tag);

    // Bob receives the encrypted message and decrypts it
    std::vector<unsigned char> shared_secret_bob = derive_shared_secret(bob_key, alice_key);
    std::string decrypted_message = aes_gcm_decrypt(shared_secret_bob, ciphertext, iv, tag);

    // Output result
    std::cout << "Decrypted Message: " << decrypted_message << std::endl;

    // Cleanup
    EVP_PKEY_free(bob_key);
    EVP_PKEY_free(alice_key);
    EVP_PKEY_free(bob_public_key);
    
    return 0;
}
