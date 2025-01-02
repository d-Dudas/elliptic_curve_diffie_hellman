# Diffie-Hellman Playground

## Overview
This project demonstrates the Diffie-Hellman key exchange protocol through two implementations:
1. **Textbook Implementation** - A naive, straightforward implementation for learning purposes.
2. **Industry Standard Implementation** - A more advanced implementation utilizing the OpenSSL library for real-world applications.

---

## Features
- Demonstrates secure key exchange using Diffie-Hellman protocol.
- Provides both naive and OpenSSL-based implementations.
- Includes simple build and run instructions for ease of use.

---

## Requirements
- CMake 3.10 or later
- Ninja build system (optional but recommended)
- OpenSSL development libraries

---

## Setup and Installation

### Install Dependencies

**Debian-based systems:**
```bash
sudo apt install cmake ninja-build libssl-dev
```

**Fedora-based systems:**
```bash
sudo dnf install cmake ninja-build openssl-devel
```

**Arch-based systems:**
```bash
sudo pacman -S cmake ninja openssl
```

---

## Build Instructions

### Using Ninja Build System

1. Create and navigate to the build directory:
```bash
mkdir build && cd build
```

2. Configure the project using CMake:
```bash
cmake -GNinja ..
```

3. Build the project:
```bash
ninja
```

---

## Run Instructions

### Textbook Implementation
To execute the naive textbook implementation, run the following command from the `build` directory:
```bash
./textbook/textbook
```

### Industry Standard Implementation
To execute the industry-standard implementation using OpenSSL, run the following command from the `build` directory:
```bash
./industry_standard/industry_standard
```
