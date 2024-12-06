#include "encryption.h"
#include <iostream>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <stdexcept>
#include "secret_key.h"
#include <cstring>

const std::string CA_CERTIFICATE = "ca.crt"; // Path to your CA certificate

// Function to create a mixed key using CA cert and secret key
std::string createMixedKey() {
    // Combine CA certificate and SECRET_KEY
    std::string mixedKey = CA_CERTIFICATE + SECRET_KEY;

    // Hash the combined key for additional security
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<unsigned char*>(mixedKey.data()), mixedKey.size(), hash);
    return std::string(reinterpret_cast<char*>(hash), SHA256_DIGEST_LENGTH);
}

// AES encryption function using EVP
std::string aesEncrypt(const std::string& plaintext, const std::string& mixedKey) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    std::string ciphertext(plaintext.size() + EVP_MAX_BLOCK_LENGTH, '\0'); // For safety
    unsigned char iv[EVP_MAX_IV_LENGTH]; // IV buffer
    int len = 0;

    // Generate a random IV
    if (RAND_bytes(iv, sizeof(iv)) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to generate IV");
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), nullptr, reinterpret_cast<const unsigned char*>(mixedKey.data()), iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to initialize encryption");
    }

    if (EVP_EncryptUpdate(ctx, reinterpret_cast<unsigned char*>(&ciphertext[0]), &len,
                          reinterpret_cast<const unsigned char*>(plaintext.data()), plaintext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to encrypt data");
    }

    int ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(&ciphertext[0]) + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to finalize encryption");
    }

    ciphertext_len += len;
    ciphertext.resize(ciphertext_len); // Resize to the actual length of the ciphertext

    // Prepend the IV to the ciphertext
    ciphertext.insert(0, reinterpret_cast<char*>(iv), sizeof(iv));

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext;
}

// AES decryption function using EVP
std::string aesDecrypt(const std::string& ciphertext, const std::string& mixedKey) {
    if (ciphertext.size() <= EVP_MAX_IV_LENGTH) {
        throw std::runtime_error("Ciphertext too short, possibly missing IV or corrupted.");
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("Failed to create cipher context");

    std::string plaintext(ciphertext.size(), '\0');
    unsigned char iv[EVP_MAX_IV_LENGTH];
    memcpy(iv, ciphertext.data(), EVP_MAX_IV_LENGTH); // Extract IV from the start

    int len = 0;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), nullptr, 
                           reinterpret_cast<const unsigned char*>(mixedKey.data()), iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to initialize decryption");
    }

    if (EVP_DecryptUpdate(ctx, reinterpret_cast<unsigned char*>(&plaintext[0]), &len, 
                          reinterpret_cast<const unsigned char*>(&ciphertext[EVP_MAX_IV_LENGTH]), 
                          ciphertext.size() - EVP_MAX_IV_LENGTH) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to decrypt data");
    }

    int plaintext_len = len;
    if (EVP_DecryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(&plaintext[0]) + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to finalize decryption - possible padding error or corrupt ciphertext.");
    }

    plaintext_len += len;
    plaintext.resize(plaintext_len); // Resize to the actual length of plaintext
    EVP_CIPHER_CTX_free(ctx);
    return plaintext;
}

// Function to encrypt a file
void encryptFile(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Failed to open file for reading");
    }

    std::ostringstream oss;
    oss << file.rdbuf(); // Read the entire file
    std::string content = oss.str();
    
    std::string mixedKey = createMixedKey(); // Create mixed key without noise
    std::string encryptedContent = aesEncrypt(content, mixedKey); // Encrypt the content

    std::ofstream outFile(filename, std::ios::binary);
    if (!outFile) {
        throw std::runtime_error("Failed to open file for writing");
    }
    outFile << encryptedContent; // Write the encrypted content back to the file
}

// Function to decrypt a file
void decryptFile(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Failed to open file for reading");
    }

    std::ostringstream oss;
    oss << file.rdbuf(); // Read the entire file
    std::string encryptedContent = oss.str();

    std::string mixedKey = createMixedKey(); // Create mixed key without noise
    std::string decryptedContent = aesDecrypt(encryptedContent, mixedKey); // Decrypt the content

    std::ofstream outFile(filename, std::ios::binary);
    if (!outFile) {
        throw std::runtime_error("Failed to open file for writing");
    }
    outFile << decryptedContent; // Write the decrypted content back to the file
}
