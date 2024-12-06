# ATM Communication Protocol

## Overview

This project implements a secure ATM communication protocol that enables customers to perform transactions like deposits, withdrawals, and balance inquiries. It ensures secure communication between the ATM client and the bank server using mutual authentication and encryption.

### Project Overview

The project is divided into two primary components:
1. **ATM (Client)**: Interacts with the server to perform banking operations.
2. **Bank (Server)**: Manages customer accounts, processes transactions, and interacts with the ATM clients.
   
## Project Structure

The project consists of the following files:

- `atm.cpp`: The client program that allows customers to interact with the ATM.
- `bank.cpp`: The server program that manages customer accounts and transactions.
- `ca.crt`: Certificate authority certificate for validating the server and client certificates.
- `client.crt`: Client certificate used for authentication with the server.
- `client.key`: Private key corresponding to the client certificate.
- `server.crt`: Server certificate used for authentication with the client.
- `server.key`: Private key corresponding to the server certificate.
- `secret_key.h`: Header file containing definitions and declarations for encryption keys.
- `encryption.cpp`: Implementation of AES encryption and decryption for securing data.
- `encryption.h`: Header file for encryption methods and definitions.
- `tr.cpp`: Utility program for creating and encrypting bank data (`bank.data`).
- `Makefile`: Compilation script to build the project.

## Features

- **Mutual Authentication**: The client and server authenticate each other using certificates to ensure both parties are trusted.
- **Secure Communication**: All data exchanged between the client and server is encrypted, ensuring privacy and preventing eavesdropping.
- **JSON Output**: Transaction results are displayed in JSON format, making it easy to parse and interpret program responses.
- **Error Handling**: The program handles various input and operational errors, ensuring robustness and preventing crashes in unexpected scenarios.

## Setup Instructions

### Prerequisites:

1. **OpenSSL**: Required for encryption and decryption operations.
2. **jsoncpp**: For handling JSON data.
3. **GCC/Clang**: C++ compiler.

### Clone the Repository

To get started, clone the repository to your local machine:

```bash
git clone https://github.com/ushasree-3/ATM-Communication-Protocol.git
cd ATM-Communication-Protocol/build
   ```

### Step 1: Compile the Project
First, you need to compile the utility program (`tr.cpp`) to create the encrypted bank data file. Use the following command to compile:

```bash
g++ -std=c++17 -Wall -Wextra -I/usr/include/jsoncpp -o tr tr.cpp encryption.cpp -lssl -lcrypto -ljsoncpp -pthread
   ```
After that, run the compiled `tr` program to create the encrypted `bank.data` file:

```bash
./tr
  ```
Then, compile the main server and client programs by running:

```bash
make
  ```

### Step 2: Running the Server (bank)
The bank server listens for client requests, handling account creation, deposits, withdrawals, and balance checks.

#### To start the server:
```bash
./bank -p <port> -s <auth-file>
  ```
Where:

- `<port>`: Port on which the server will listen (default: `3000`).
- `<auth-file>`: The authentication file (`bank.auth` by default) used by the ATM client for secure communication.
  
Example:
```bash
./bank -p 3000 -s bank.auth
  ```
This will start the bank server on port 3000 using the `bank.auth` authentication file.

### Step 3: Running the Client (atm)
The atm client simulates ATM operations like creating accounts, depositing funds, withdrawing money, and checking balances. Communication with the server is secured via AES encryption.

#### To run the ATM client:
```bash
./atm -s <auth-file> -i <ip-address> -p <port> -c <card-file> -a <account> [mode]
  ```
Where:

- `<auth-file>`: Authentication file (default: `bank.auth`).
- `<ip-address>`: IP address of the bank server (default: `127.0.0.1`).
- `<port>`: Port the bank server is listening on (default: `3000`).
- `<card-file>`: ATM card file (default: `<account>.card`).
- `<account>`: Customer’s account name.
- `[mode]`: Mode of operation (create account, deposit, withdraw, or check balance).

### Modes of Operation:
* **Create Account (`-n <balance>`)**: Create a new account with the specified balance (must be >= 10.00).
* **Deposit (`-d <amount>`)**: Deposit the specified amount into the account (must be > 0.00).
* **Withdraw (`-w <amount>`)**: Withdraw the specified amount from the account (balance must remain non-negative).
* **Get Balance (`-g`)**: Retrieve the current balance of the account.

Example:
```bash
./atm -s bank.auth -i 127.0.0.1 -p 3000 -c 55555.card -a 55555 -n 20.00
  ```
This command creates a new account `55555` with an initial balance of `20.00`.

### Exit Codes:

- `0`: Successful operation.
- `255`: Invalid operation or incorrect parameters.

### Error Handling

*   **Invalid Parameters**: If any required parameter is missing, duplicated, or incorrect, the program will exit with code `255` and no output.
*   **File Not Found**: If a specified file (e.g., `auth-file`, `card-file`) cannot be opened or doesn't exist, the program will exit with code `255`.
*   **Insufficient Funds**: For withdrawal operations, if the account balance is insufficient, the program will exit with code `255`.

## Acknowledgments
This project was developed as part of the Computer Network and Security course at IIT Gandhinagar under the guidance of Prof. Abhishek Bichawat. Special thanks to my team members for their collaboration and contributions to the successful completion of this work.
