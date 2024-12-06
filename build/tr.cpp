#include <iostream>
#include <regex>
#include <string>
#include <fstream>
#include "encryption.h"

void createAndEncryptBankData(const std::string& fileName) {
    // Create a blank file (if it doesn't exist)
    std::ofstream file(fileName, std::ios::out | std::ios::trunc);
    
    if (!file) {  // Check if the file was created successfully
        std::cerr << "Error creating file: " << fileName << std::endl;
        return;
    }
    
    // Optionally, you can add a default content or leave it empty
    file.close();  // Close the file after creation

    // Now encrypt the file using your encryption function
    encryptFile(fileName);  // Call your existing encryption function
}

int main() {
    std::string fileName = "bank.data";  // The file to create and encrypt
    createAndEncryptBankData(fileName);
    
    return 0;
}
