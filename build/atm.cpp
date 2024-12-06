#include <iostream>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/hmac.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <json/json.h>
#include <fstream>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <limits>
#include <algorithm>
#include <unordered_set>
#include <regex>
#include "secret_key.h"  
#include "encryption.h"

const int DEFAULT_PORT = 3000;
const char* CLIENT_CERT = "client.crt";
const char* CLIENT_KEY = "client.key";
const char* CA_FILE = "ca.crt";

// Validation patterns
const std::regex ACCOUNT_PATTERN("^([a-z0-9_.-]{1,122})$"); // Account names must be 1 to 122 characters long without quotes
const std::regex FILENAME_PATTERN("^(?!\\.{1,2}$)[_\\-.0-9a-z]{1,127}$");
const std::regex IP_PATTERN("^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\."
                            "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\."
                            "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\."
                            "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$");
const std::regex AMOUNT_PATTERN(R"((0|[1-9]\d{0,9})(\.\d{2})?)");

SSL_CTX* InitClientCTX();
std::string generateHMAC(const std::string& message);
std::string sendRequest(Json::Value& request, const char* ip, int port);
bool createCardFile(const std::string& cardFile, int pin, std::string account);
std::string readCardFile(const std::string& cardFile);
int getPIN();
bool isValidAccountName(const std::string& account);
bool isValidFileName(const std::string& fileName);
bool isValidIPAddress(const std::string& ip);
bool isValidPort(int port);
bool isValidAmount(const std::string& amountStr);

int main(int argc, char* argv[]) {
    std::string account, operation, cardFile, ipAddress = "127.0.0.1";
    std::string amountStr = "0";
    double amount = 0.0;
    int port = DEFAULT_PORT;
    bool operationSpecified = false; // Initialize operationSpecified
    std::unordered_set<std::string> usedParams;
    std::string authFile = "bank.auth"; // Default auth file path

    // Parse command-line arguments
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "-a" && i + 1 < argc) {
            if (usedParams.count("-a")) {
                std::cerr << "Error: Duplicate parameter -a" << std::endl;
                return 255;
            }
            account = argv[++i];
            if (!isValidAccountName(account)) {
                std::cerr << "Error: Invalid account name" << std::endl;
                return 255;
            }
            usedParams.insert("-a");
        } else if (arg == "-n" && i + 1 < argc) {
            if (operationSpecified) {
                std::cerr << "Error: An operation has already been specified. Cannot use -n." << std::endl;
                return 255;
            }
            if (usedParams.count("-n")) {
                std::cerr << "Error: Duplicate parameter -n" << std::endl;
                return 255;
            }
            operation = "create";
            amountStr = argv[++i];
            amount = atof(amountStr.c_str());
            if (!isValidAmount(amountStr)) {
                std::cerr << "Error: Invalid amount for account creation" << std::endl;
                return 255;
            }
            if (amount < 10.0) {
                std::cerr << "Error: Amount for account creation must be >= 10.00" << std::endl;
                return 255;
            }
            operationSpecified = true;
            usedParams.insert("-n");
        } else if (arg == "-d" && i + 1 < argc) {
            if (operationSpecified) {
                std::cerr << "Error: An operation has already been specified. Cannot use -d." << std::endl;
                return 255;
            }
            if (usedParams.count("-d")) {
                std::cerr << "Error: Duplicate parameter -d" << std::endl;
                return 255;
            }
            operation = "deposit";
            amountStr = argv[++i];
            amount = atof(amountStr.c_str());
            if (!isValidAmount(amountStr)) {
                std::cerr << "Error: Invalid deposit amount" << std::endl;
                return 255;
            }
            if (amount <= 0.00) {
                std::cerr << "Error: Deposit amount must be > 0.00" << std::endl;
                return 255;
            }
            operationSpecified = true;
            usedParams.insert("-d");
        } else if (arg == "-w" && i + 1 < argc) {
            if (operationSpecified) {
                std::cerr << "Error: An operation has already been specified. Cannot use -w." << std::endl;
                return 255;
            }
            if (usedParams.count("-w")) {
                std::cerr << "Error: Duplicate parameter -w" << std::endl;
                return 255;
            }
            operation = "withdraw";
            amountStr = argv[++i];
            amount = atof(amountStr.c_str());
            if (!isValidAmount(amountStr)) {
                std::cerr << "Error: Invalid withdrawal amount" << std::endl;
                return 255;
            }
            if (amount <= 0.00) {
                std::cerr << "Error: Withdrawal amount must be > 0.00" << std::endl;
                return 255;
            }
            operationSpecified = true;
            usedParams.insert("-w");
        } else if (arg == "-g") {
            if (operationSpecified) {
                std::cerr << "Error: An operation has already been specified. Cannot use -g." << std::endl;
                return 255;
            }
            if (usedParams.count("-g")) {
                std::cerr << "Error: Duplicate parameter -g" << std::endl;
                return 255;
            }
            operation = "get_balance";
            operationSpecified = true;
            usedParams.insert("-g");
        } else if (arg == "-c" && i + 1 < argc) {
            if (i + 1 >= argc) {
                std::cerr << "Error: Missing card file name for parameter -c" << std::endl;
                return 255;
            }
            if (usedParams.count("-c")) {
                std::cerr << "Error: Duplicate parameter -c" << std::endl;
                return 255;
            }
            cardFile = argv[++i];
            if (!isValidFileName(cardFile)) {
                std::cerr << "Error: Invalid card file name" << std::endl;
                return 255;
            }
            usedParams.insert("-c");
        } else if (arg == "-i" && i + 1 < argc) {
            if (usedParams.count("-i")) {
                std::cerr << "Error: Duplicate parameter -i" << std::endl;
                return 255;
            }
            ipAddress = argv[++i];
            if (!isValidIPAddress(ipAddress)) {
                std::cerr << "Error: Invalid IP address" << std::endl;
                return 255;
            }
            usedParams.insert("-i");
        } else if (arg == "-p" && i + 1 < argc) {
            if (usedParams.count("-p")) {
                std::cerr << "Error: Duplicate parameter -p" << std::endl;
                return 255;
            }
            port = atoi(argv[++i]);
            if (!isValidPort(port)) {
                std::cerr << "Error: Invalid port number" << std::endl;
                return 255;
            }
            usedParams.insert("-p");
        } else if (arg == "-s" && i + 1 < argc) {
            if (usedParams.count("-s")) {
                std::cerr << "Error: Duplicate parameter -s" << std::endl;
                return 255;
            }
            authFile = argv[++i];
            usedParams.insert("-s");
        } else {
            std::cerr << "Error: Invalid argument" << std::endl;
            return 255;
        }
    }

    if (account.empty() || operation.empty()) {
        std::cerr << "Missing required parameters" << std::endl;
        return 255;
    }

    // Check if the auth file exists
    std::ifstream authFileStream(authFile);
    if (!authFileStream.is_open()) {
        std::cerr << "Error: Auth file '" << authFile << "' does not exist." << std::endl;
        return 255;
    }
    authFileStream.close();

    // Check for negative amount
    if ((operation == "create" && amount < 10) ||
        (operation == "deposit" && amount <= 0) ||
        (operation == "withdraw" && amount <= 0)) {
        std::cerr << "Error: Amount is invalid." << std::endl;
        return 255;
    }
    std::string responsefromServer;
    // Handle account creation
    if (operation == "create") {
        // Use provided card file name if specified; otherwise, default to account name
        cardFile = cardFile.empty() ? account + ".card" : cardFile;

        if (!isValidFileName(cardFile)) {
            std::cerr << "Invalid card file name" << std::endl;
            return 255;
        }

        std::ifstream cardStream(cardFile);
        if (cardStream.is_open()) {
            std::cerr << "Card file already exists. Account creation not allowed." << std::endl;
            return 255;
        } else {
            int pin = getPIN(); // Get PIN as an integer

            // Create the request to send to the bank
            Json::Value request;
            request["account"] = account;
            request["operation"] = operation;
            request["pin"] = pin; // Include the cardFile for corresponding account
            request["amount"] = amount; // Include initial amount
            request["authFile"] = authFile;

            // Generate HMAC
            std::string messageForHMAC = Json::writeString(Json::StreamWriterBuilder(), request);
            request["hmac"] = generateHMAC(messageForHMAC);

            // Send request to create account at the bank
            responsefromServer = sendRequest(request, ipAddress.c_str(), port);

            if (responsefromServer == "Account created successfully.") {
                if (createCardFile(cardFile, pin, account)) {
                    std::cout << "Card file created successfully: " << cardFile << std::endl;
                } else {
                    std::cerr << "Failed to create card file." << std::endl;
                    return 1;
                }
            } else {
                std::cerr << "Account creation failed." << std::endl;
            }
        }
    } else {
        // For transactions other than account creation, cardFile must be specified
        if (cardFile.empty()) {
            std::cerr << "Error: Missing card file. Please provide the card file for transactions." << std::endl;
            return 255;
        }
        
        std::ifstream cardStream(cardFile);
        if (!cardStream.is_open()) {
            std::cerr << "Error: Account does not exist. Please create an account first." << std::endl;
            return 255;
        }

        // Add card data to the request
        Json::Value request;
        request["account"] = account;
        request["cardFile"] = cardFile; // Send the cardFile to the bank
        request["operation"] = operation;

        if (operation == "deposit" || operation == "withdraw") {
            request["amount"] = amount;
        }

        request["authFile"] = authFile;

        // Generate HMAC
        std::string messageForHMAC = Json::writeString(Json::StreamWriterBuilder(), request);
        request["hmac"] = generateHMAC(messageForHMAC);

        // Send request to the bank server
        responsefromServer = sendRequest(request, ipAddress.c_str(), port);
    }

    return 0;
}

bool createCardFile(const std::string& cardFile, int pin, std::string account) {
    std::ofstream cardStream(cardFile);
    if (!cardStream) {
        std::cerr << "Error: Could not create card file " << cardFile << std::endl;
        return false;
    }
    cardStream << account << std::endl;
    cardStream << pin << std::endl; 
    cardStream.close(); 
    encryptFile(cardFile); 
    return true;
}

int getPIN() {
    std::string pinStr;
    while (true) {
        std::cout << "Enter a 4 to 6 digit PIN: ";
        std::cin >> pinStr;
        if (pinStr.length() >= 4 && pinStr.length() <= 6 && std::all_of(pinStr.begin(), pinStr.end(), ::isdigit)) {
            return std::stoi(pinStr);
        }
        std::cout << "Invalid PIN. Please try again." << std::endl;
    }
}

SSL_CTX* InitClientCTX() {
    const SSL_METHOD* method;
    SSL_CTX* ctx;

    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    method = TLS_client_method();
    ctx = SSL_CTX_new(method);

    if (ctx == nullptr) {
        ERR_print_errors_fp(stderr);
        abort();
    }

    // Load client certificate and private key
    if (SSL_CTX_use_certificate_file(ctx, CLIENT_CERT, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        abort();
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, CLIENT_KEY, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        abort();
    }

    // Load CA certificate for server validation
    if (!SSL_CTX_load_verify_locations(ctx, CA_FILE, nullptr)) {
        ERR_print_errors_fp(stderr);
        abort();
    }

    return ctx;
}

std::string generateHMAC(const std::string& message) {
    unsigned char hmacResult[EVP_MAX_MD_SIZE];
    unsigned int len = 0;

    HMAC(EVP_sha256(), SECRET_KEY.c_str(), SECRET_KEY.size(), 
         (unsigned char*)message.c_str(), message.size(), 
         hmacResult, &len);

    std::stringstream hmacHex;
    for (unsigned int i = 0; i < len; i++) {
        hmacHex << std::hex << std::setw(2) << std::setfill('0') << (int)hmacResult[i];
    }

    return hmacHex.str();
}

// Helper functions for validation
bool isValidAccountName(const std::string& account) {
    return std::regex_match(account, ACCOUNT_PATTERN);
    //  && account != "." && account != "..";
}

bool isValidFileName(const std::string& fileName) {
    return std::regex_match(fileName, FILENAME_PATTERN);
}

bool isValidIPAddress(const std::string& ip) {
    return std::regex_match(ip, IP_PATTERN);
}

bool isValidPort(int port) {
    return port >= 1024 && port <= 65535;
}

bool isValidAmount(const std::string& amountStr) {
    if (!std::regex_match(amountStr, AMOUNT_PATTERN)) {
        return false;
    }
    double amount = atof(amountStr.c_str());
    if (amount < 0.0 || amount > 4294967295.99) {
        return false;
    }
    return true;
}

std::string sendRequest(Json::Value& request, const char* ip, int port) {
    SSL_CTX* ctx;
    SSL* ssl;
    int sock = 0;
    struct sockaddr_in serv_addr;
    char buffer[1024] = {0};
    std::string return_message = "";

    ctx = InitClientCTX(); // Initialize SSL context

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        std::cerr << "Socket creation error" << std::endl;
        return return_message;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);

    if (inet_pton(AF_INET, ip, &serv_addr.sin_addr) <= 0) {
        std::cerr << "Invalid address/ Address not supported" << std::endl;
        return return_message;
    }

    if (connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        std::cerr << "Connection failed" << std::endl;
        return return_message;
    }

    // Create SSL connection
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);

    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        close(sock);
        return return_message;
    }

    // Convert request to JSON string
    Json::StreamWriterBuilder writer;
    std::string requestString = Json::writeString(writer, request);

    // Send request
    SSL_write(ssl, requestString.c_str(), requestString.size());

    // Read server response
    int bytes = SSL_read(ssl, buffer, sizeof(buffer) - 1);
    if (bytes > 0) {
        buffer[bytes] = '\0'; // Null-terminate the response
        Json::CharReaderBuilder reader;
        Json::Value response;
        std::istringstream ss(buffer);
        std::string errs;

        // Parse the response JSON
        if (Json::parseFromStream(reader, ss, &response, &errs)) {
            if (response.isMember("status") && response["status"].asString() == "success" &&
            response.isMember("message") && response["message"].asString() == "Account created successfully.") {
                return_message = response["message"].asString();
            }
            // Iterate over all the fields in the response object
            for (const auto& key : response.getMemberNames()) {
                // Skip the "hmac" field
                if (key != "hmac") {
                    // Print the key and its corresponding value
                    if (key == "balance") {
                        std::cout << std::fixed << std::setprecision(2) << key << ": " << response[key].asDouble() << std::endl;
                    } else {
                        std::cout << key << ": " << response[key].asString() << std::endl;
                    }
                }
            }
        } else {
            std::cerr << "Failed to parse server response: " << errs << std::endl;
        }
    } else {
        std::cerr << "Error reading response" << std::endl;
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx);

    return return_message;
}
