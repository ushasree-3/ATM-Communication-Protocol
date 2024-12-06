#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include <string>

// Function declarations
std::string generateNoise();
std::string createMixedKey(const std::string& noise);
std::string aesEncrypt(const std::string& plaintext, const std::string& mixedKey);
std::string aesDecrypt(const std::string& ciphertext, const std::string& mixedKey);
void encryptFile(const std::string& filename);
void decryptFile(const std::string& filename);

#endif // ENCRYPTION_H
