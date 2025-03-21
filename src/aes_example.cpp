#include <iostream>
#include <string>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <cstring>

void handleErrors() {
    std::cerr << "Error occurred.\n";
    abort();
}

void generateRandomKey(unsigned char* key, int key_size) {
    if (RAND_bytes(key, key_size) != 1) {
        handleErrors();
    }
}

void aesEncrypt(const char* message, int message_len, unsigned char* key, unsigned char* iv, char* cipher) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        handleErrors();
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), nullptr, key, iv) != 1) {
        handleErrors();
    }

    int out_len;
    if (EVP_EncryptUpdate(ctx, reinterpret_cast<unsigned char*>(cipher), &out_len, reinterpret_cast<const unsigned char*>(message), message_len) != 1) {
        handleErrors();
    }

    int final_len;
    if (EVP_EncryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(cipher + out_len), &final_len) != 1) {
        handleErrors();
    }

    EVP_CIPHER_CTX_free(ctx);
}

void aesDecrypt(const char* cipher, int cipher_len, unsigned char* key, unsigned char* iv, char* received_message) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        handleErrors();
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_ctr(), nullptr, key, iv) != 1) {
        handleErrors();
    }

    int out_len;
    if (EVP_DecryptUpdate(ctx, reinterpret_cast<unsigned char*>(received_message), &out_len, reinterpret_cast<const unsigned char*>(cipher), cipher_len) != 1) {
        handleErrors();
    }

    int final_len;
    if (EVP_DecryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(received_message + out_len), &final_len) != 1) {
        handleErrors();
    }

    out_len += final_len; // Total length of the decrypted data

    // Add null-terminator
    received_message[out_len] = '\0';

    EVP_CIPHER_CTX_free(ctx);
}

int main() {
    // Initialize OpenSSL library
    OpenSSL_add_all_algorithms();

    const char message[] = "Hello World!";
    
    printf("Original message: \n %s \n", message);

    // Generate a random 256-bit key
    const int key_size = 32; // 256 bits
    unsigned char key[key_size];
    generateRandomKey(key, key_size);

    // Initialize the IV (nonce) for CTR mode
    unsigned char iv[EVP_MAX_IV_LENGTH] = {0};

    // Encrypt the message
    char cipher[sizeof(message)];
    int message_len = sizeof(message);

    aesEncrypt(message, message_len, key, iv, cipher);

    printf("The ciphertext:\n %s\n", cipher);

    // Decrypt the ciphertext
    char received_message[sizeof(cipher)];
    int cipher_len = sizeof(cipher); // Use the correct ciphertext length for decryption
    aesDecrypt(cipher, cipher_len, key, iv, received_message);

    

    printf("The decrypted message: \n %s \n", received_message);


    printf("\n\nSize of message: \t%ld\nSize of cipher: \t%ld\nSize of rec_m: \t\t%ld\n\n", sizeof(message) , sizeof(cipher) , sizeof(received_message));


    // Compare original message and received message
    if (strcmp (message,received_message) == 0) {
        std::cout << "SUCCESS: Original message and received message match.\n";
    } else {
        std::cout << "ERROR: Original message and received message do not match.\n";
    }

    // Clean up OpenSSL
    EVP_cleanup();

    return 0;
}
