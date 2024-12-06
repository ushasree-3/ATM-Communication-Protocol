#include <iostream>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <json/json.h>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <map>
#include <mutex>
#include <csignal>
#include <regex>
#include <filesystem> // For checking file existence
#include "secret_key.h" // Include the header file with the secret key
#include "encryption.h"
#include <set>

const char* CERT_FILE = "server.crt";
const char* KEY_FILE = "server.key";
const char* CA_FILE = "ca.crt";
const std::regex ACCOUNT_PATTERN("^([a-z0-9_.-]{1,122})$");
std::mutex authFileMutex;
std::map<std::string, double> accountBalances;
std::map<std::string, std::string> accountPins;

bool isValidAccountName(const std::string& account) {
    return std::regex_match(account, ACCOUNT_PATTERN);
    //  && account != "." && account != "..";
}

int PORT = 3000; // Default port
std::string authFileName = "bank.auth"; // Default auth file name

const std::regex FILENAME_PATTERN("^(?!\\.{1,2}$)[_\\-.0-9a-z]{1,127}$");

// Function declarations
void saveAccountBalancesToFile(const std::string& fileName);
void loadAccountBalancesFromFile(const std::string& fileName);
void loadAccountPinsFromFile(const std::string& fileName);
std::string generateHMAC(const std::string& message);
bool verifyHMAC(const std::string& message, const std::string& receivedHmac);
bool createAccount(const std::string& accountNumber, double initialBalance, const std::string& pin);
bool verifyPin(const std::string& accountNumber, const std::string& inputPin, std::string accountName);
SSL_CTX* InitServerCTX();
void handleClient(SSL* ssl);
void signalHandler(int signum);
int parseCommandLineArguments(int argc, char* argv[]);
std::pair<std::string, std::string> readCardFile(const std::string& cardFile);
void sendErrorResponse(SSL* ssl, const std::string& message);
void sendResponse(SSL* ssl, const Json::Value& responseJson);

bool isValidPort(int port) {
    return port >= 1024 && port <= 65535;
}

bool isValidFileName(const std::string& fileName) {
    return std::regex_match(fileName, FILENAME_PATTERN);
}

// Main function
int main(int argc, char* argv[]) {
    // Parse command line arguments
    if (parseCommandLineArguments(argc, argv) != 0) {
        return 255; // Exit on argument parse failure
    }

    if (!isValidPort(PORT)) {
        std::cerr << "Error: Invalid PORT number." << std::endl;
        return 255;
    }

    if (!isValidFileName(authFileName)) {
        std::cerr << "Error: Invalid Auth FileName." << std::endl;
        return 255;
    }

    // Check if auth file exists
    if (std::filesystem::exists(authFileName)) {
        std::cerr << "Error: Auth file already exists." << std::endl;
        return 255; // Exit if the auth file already exists
    }

    // Create the auth file
    std::ofstream authFile(authFileName);
    if (!authFile) {
        std::cerr << "Error: Unable to create auth file." << std::endl;
        return 255; // Exit on failure to create file
    }


    // List of files to exclude
    std::set<std::string> excludeFiles = {
        "atm", "atm.cpp", "bank", "bank.cpp", "bank.data", "ca.crt", "client.crt", "client.key",
        "encryption.cpp", "encryption.h", "Makefile", "secret_key.h",
        "server.crt", "server.key", "tr", "tr.cpp", authFileName
    };


    // Iterate over all files in the current directory
    for (const auto& entry : std::filesystem::directory_iterator(".")) {
        if (entry.is_regular_file()) {
            // Get the filename without the extension
            std::string fileName = entry.path().string().substr(2);
            // std::cout << fileName << std::endl;

            // Skip files if their base name is in the exclude list
            if (excludeFiles.find(fileName) != excludeFiles.end()) {
                continue;
            }

            // Get the full path of the file to process
            std::string filePath = entry.path().string();
            // std::cout << filePath << std::endl;

            // Decrypt the file
            decryptFile(filePath);

            // Read account details from the file (assuming it follows the .card file format)
            std::pair<std::string, std::string> accountData = readCardFile(filePath);
            std::string accountName = accountData.first;
            std::string pin = accountData.second;

            // Re-encrypt the file after reading
            encryptFile(filePath);

            // Validate the account data before adding to auth file
            if (!accountName.empty() && !pin.empty() && isValidAccountName(accountName)) {
                // Write to auth file in "account,pin" format
                authFile << accountName << "," << pin << std::endl;
            }
        }
    }
    decryptFile("bank.data");
    loadAccountBalancesFromFile("bank.data");
    encryptFile("bank.data");
    loadAccountPinsFromFile(authFileName);
    encryptFile(authFileName);
    authFile.close();
    std::cout << "created" << std::endl; // Print confirmation

    // SSL setup
    SSL_CTX* ctx = InitServerCTX();
    
    // Signal handling for graceful exit
    signal(SIGTERM, signalHandler);

    // Socket setup and listening...
    int server_fd, new_socket;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);

    // Creating socket file descriptor
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    // Attaching socket to the port
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    // Binding the socket to the specified port
    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    // Start listening for incoming connections
    if (listen(server_fd, 3) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    // Accept clients in a loop
    while (true) {
        std::cout << "Waiting for connections..." << std::endl;
        if ((new_socket = accept(server_fd, (struct sockaddr*)&address, (socklen_t*)&addrlen)) < 0) {
            perror("accept");
            exit(EXIT_FAILURE);
        }

        // SSL connection handling
        SSL* ssl = SSL_new(ctx);
        SSL_set_fd(ssl, new_socket);
        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
        } else {
            handleClient(ssl);
        }

        // Clean up
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(new_socket);
    }

    // Clean up
    close(server_fd);
    SSL_CTX_free(ctx);
    return 0;
}

// Function implementations

std::string generateHMAC(const std::string& message) {
    unsigned char* hmacResult;
    unsigned int len = EVP_MAX_MD_SIZE;

    hmacResult = HMAC(EVP_sha256(), SECRET_KEY.c_str(), SECRET_KEY.size(),
                      (unsigned char*)message.c_str(), message.size(), nullptr, &len);

    std::stringstream hmacHex;
    for (unsigned int i = 0; i < len; i++) {
        hmacHex << std::hex << std::setw(2) << std::setfill('0') << (int)hmacResult[i];
    }

    return hmacHex.str();
}

bool verifyHMAC(const std::string& message, const std::string& receivedHmac) {
    std::string computedHmac = generateHMAC(message);
    return computedHmac == receivedHmac;
}

bool createAccount(const std::string& accountNumber, double initialBalance, const std::string& pin) {
    std::lock_guard<std::mutex> lock(authFileMutex);

    if (accountBalances.find(accountNumber) != accountBalances.end()) {
        std::cerr << "Account already exists." << std::endl;
        return 0; // Do not exit, just return
    }

    decryptFile(authFileName);

    accountBalances[accountNumber] = initialBalance;
    accountPins[accountNumber] = pin;

    std::ofstream authFile(authFileName, std::ios::app);
    if (authFile.is_open()) {
        authFile << accountNumber << "," << pin << std::endl; // Save account and PIN
        authFile.close();
    } else {
        std::cerr << "Failed to open auth file for writing." << std::endl;
    }

    encryptFile(authFileName);

    decryptFile("bank.data");
    saveAccountBalancesToFile("bank.data");
    encryptFile("bank.data");

    std::cout << "Account " << accountNumber << " created successfully with initial balance: " << initialBalance << std::endl;
    return 1;
}

bool verifyPin(const std::string& accountNumber, const std::string& inputPin, std::string accountName) {
    auto it = accountPins.find(accountNumber);
    if (it != accountPins.end()) {
        return (it->second == inputPin) && (accountNumber == accountName);
    }
    return false;
}

SSL_CTX* InitServerCTX() {
    const SSL_METHOD* method;
    SSL_CTX* ctx;

    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    method = TLS_server_method();
    ctx = SSL_CTX_new(method);

    if (ctx == nullptr) {
        ERR_print_errors_fp(stderr);
        abort();
    }

    if (SSL_CTX_use_certificate_file(ctx, CERT_FILE, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        abort();
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, KEY_FILE, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        abort();
    }

    if (!SSL_CTX_load_verify_locations(ctx, CA_FILE, nullptr)) {
        ERR_print_errors_fp(stderr);
        abort();
    }

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
    SSL_CTX_set_verify_depth(ctx, 1);

    return ctx;
}

void handleClient(SSL* ssl) {
    char buffer[1024] = {0};
    int bytes = SSL_read(ssl, buffer, sizeof(buffer));

    if (bytes <= 0) {
        std::cerr << "Failed to read from client." << std::endl;
        return; // Exit function if reading fails
    }

    std::string requestMessage(buffer, bytes);
    Json::Value requestJson;
    Json::Reader reader;

    if (!reader.parse(requestMessage, requestJson)) {
        std::cerr << "Failed to parse JSON request." << std::endl;
        sendErrorResponse(ssl, "Invalid JSON format");
        return;
    }

    std::string receivedHmac = requestJson["hmac"].asString();
    requestJson.removeMember("hmac");

    if (!verifyHMAC(Json::writeString(Json::StreamWriterBuilder(), requestJson), receivedHmac)) {
        std::cerr << "HMAC verification failed." << std::endl;
        sendErrorResponse(ssl, "HMAC verification failed");
        return;
    }

    // Validate required fields
    if (!requestJson.isMember("operation") || !requestJson.isMember("account")) {
        sendErrorResponse(ssl, "Missing required fields: operation or account");
        return;
    }

    std::string operation = requestJson["operation"].asString();
    std::string account = requestJson["account"].asString();
    std::string authFile = requestJson["authFile"].asString();
    if (authFile != authFileName) {
        sendErrorResponse(ssl, "Invalid authFile");
        return;
    }
    if (!isValidAccountName(account)) {
        sendErrorResponse(ssl, "Invalid account name");
        return;
    }

    Json::Value responseJson;

    if (operation == "create") {
        if (!requestJson.isMember("pin") || !requestJson.isMember("amount")) {
            sendErrorResponse(ssl, "Missing required field: pin or amount");
            return;
        }
        std::string pin = requestJson["pin"].asString();
        double amount = requestJson["amount"].asDouble();
        bool account_created = createAccount(account, amount, pin);
        if (!account_created) {
            sendErrorResponse(ssl, "Account already exists");
        }
        responseJson["status"] = "success";
        responseJson["message"] = "Account created successfully.";
    } else {
        if (!requestJson.isMember("cardFile")) {
            sendErrorResponse(ssl, "Missing required field: cardFile");
            return;
        }
        
        std::string cardFile = requestJson["cardFile"].asString();
        decryptFile(cardFile);
        std::pair<std::string, std::string> cardData = readCardFile(cardFile);
        encryptFile(cardFile);

        std::string accountName = cardData.first;
        std::string pin = cardData.second;

        if (operation == "deposit" || operation == "withdraw" || operation == "get_balance") {
            if (!requestJson.isMember("amount") && (operation == "deposit" || operation == "withdraw")) {
                sendErrorResponse(ssl, "Missing required field: amount");
                return;
            }

            if (verifyPin(account, pin, accountName)) {
                if (operation == "deposit") {
                    double amount = requestJson["amount"].asDouble();
                    // Update account balance logic
                    accountBalances[account] += amount; 
                    decryptFile("bank.data");
                    saveAccountBalancesToFile("bank.data");
                    encryptFile("bank.data");
                    responseJson["status"] = "success";
                    responseJson["message"] = "Deposit successful.";
                } else if (operation == "withdraw") {
                    double amount = requestJson["amount"].asDouble();
                    // Withdrawal logic
                    if (accountBalances[account] >= amount) {
                        accountBalances[account] -= amount;
                        decryptFile("bank.data");
                        saveAccountBalancesToFile("bank.data");
                        encryptFile("bank.data");
                        responseJson["status"] = "success";
                    } else {
                        responseJson["status"] = "failed";
                    }
                } else if (operation == "get_balance") {
                    // Send balance
                    responseJson["balance"] = accountBalances[account];
                }
            } else {
                sendErrorResponse(ssl, "Invalid PIN or cardFile.");
                return;
            }
        } else {
            sendErrorResponse(ssl, "Invalid operation.");
            return;
        }
    }

    // Send JSON response
    sendResponse(ssl, responseJson);
}

void sendErrorResponse(SSL* ssl, const std::string& message) {
    Json::Value responseJson;
    responseJson["status"] = "failed";
    responseJson["message"] = message;
    sendResponse(ssl, responseJson);
}

void sendResponse(SSL* ssl, const Json::Value& responseJson) {
    Json::StreamWriterBuilder writer;
    std::string responseMessage = Json::writeString(writer, responseJson);
    SSL_write(ssl, responseMessage.c_str(), responseMessage.size());
}

std::pair<std::string, std::string> readCardFile(const std::string& cardFile) {
    // decryptFile(cardFile); // Decrypt the file before reading
    std::ifstream infile(cardFile);
    std::string accountName, pin;

    if (infile.is_open()) {
        std::getline(infile, accountName);
        std::getline(infile, pin); // Read the PIN from the card file
        infile.close();
        return {accountName, pin};
    }
    std::cerr << "Failed to open card file after decryption." << std::endl;
    // encryptFile(cardFile); // Re-encrypt the file if read fails
    return {"", ""};
}

void signalHandler(int signum) {
    std::cout << "Caught signal " << signum << ", exiting gracefully." << std::endl;
    // Perform cleanup if necessary
    exit(signum);
}

int parseCommandLineArguments(int argc, char* argv[]) {
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "-p" && i + 1 < argc) { // Change from "-port" to "-p"
            PORT = std::stoi(argv[++i]);
        } else if (arg == "-s" && i + 1 < argc) { // Change from "-auth" to "-s"
            authFileName = argv[++i];
        } else {
            std::cerr << "Invalid argument: " << arg << std::endl;
            return -1; // Indicate parsing error
        }
    }
    return 0; // Indicate success
}

// Function to save accountBalances to bank.data
void saveAccountBalancesToFile(const std::string& fileName) {
    std::ofstream file(fileName);  // Use fileName here to open the file
    
    if (!file) {  // Check if the file was opened successfully
        std::cerr << "Error opening file for writing: " << fileName << std::endl;
        return;
    }
    
    // Iterate over the accountBalances map and write each key-value pair
    for (const auto& account : accountBalances) {
        file << account.first << "," << account.second << "\n";  // Write account number (key) and balance (value)
    }
    
    file.close();  // Close the file after writing
}

// Function to read account balances from bank.data and store them in accountBalances
void loadAccountBalancesFromFile(const std::string& fileName) {
    std::ifstream file(fileName);  // Open the file for reading
    
    if (!file) {  // Check if the file was opened successfully
        std::cerr << "Error opening file for reading: " << fileName << std::endl;
        return;
    }
    
    std::string line;
    while (std::getline(file, line)) {  // Read the file line by line
        size_t commaPos = line.find(',');  // Find the comma separating account number and balance
        
        if (commaPos != std::string::npos) {  // Ensure that a comma was found
            std::string accountNumber = line.substr(0, commaPos);  // Extract account number
            double balance = std::stod(line.substr(commaPos + 1));  // Extract balance and convert to double
            
            // Insert account number and balance into the map
            accountBalances[accountNumber] = balance;
        }
    }
    
    file.close();  // Close the file after reading
}

// Function to read account pins from bank_pins.data and store them in accountPins
void loadAccountPinsFromFile(const std::string& fileName) {
    std::ifstream file(fileName);  // Open the file for reading
    
    if (!file) {  // Check if the file was opened successfully
        std::cerr << "Error opening file for reading: " << fileName << std::endl;
        return;
    }
    
    std::string line;
    while (std::getline(file, line)) {  // Read the file line by line
        size_t commaPos = line.find(',');  // Find the comma separating account number and PIN
        
        if (commaPos != std::string::npos) {  // Ensure that a comma was found
            std::string accountNumber = line.substr(0, commaPos);  // Extract account number
            std::string pin = line.substr(commaPos + 1);  // Extract PIN
            
            // Insert account number and PIN into the map
            accountPins[accountNumber] = pin;
        }
    }
    
    file.close();  // Close the file after reading
}