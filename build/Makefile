# Compiler
CXX = g++

# Compiler flags
CXXFLAGS = -std=c++17 -Wall -Wextra -I/usr/include/jsoncpp

# Libraries
LIBS = -lssl -lcrypto -ljsoncpp -pthread

# Executable names
ATM = atm
BANK = bank

# Source files
ATM_SRC = atm.cpp encryption.cpp
BANK_SRC = bank.cpp encryption.cpp

# Files to clean
CLEAN_FILES = *.auth $(ATM) $(BANK)

# Default target to build both executables
all: $(ATM) $(BANK)

# Build ATM executable
$(ATM): $(ATM_SRC)
	$(CXX) $(CXXFLAGS) -o $(ATM) $(ATM_SRC) $(LIBS)

# Build Bank executable
$(BANK): $(BANK_SRC)
	$(CXX) $(CXXFLAGS) -o $(BANK) $(BANK_SRC) $(LIBS)

# Clean target to remove card and auth files and executables
clean:
	rm -f $(CLEAN_FILES)

.PHONY: all clean
