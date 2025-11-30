# Makefile for the vm-detect user-space application

# Compiler and flags
CC := gcc
CFLAGS := -g -Wall -Wextra
LDFLAGS := -lcrypto

# Target executable name
TARGET := vm-detect

# Source file
SRCS := vm-detect.c

# Default target
all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRCS) $(LDFLAGS)

# Clean up build files
clean:
	rm -f $(TARGET)

.PHONY: all clean
