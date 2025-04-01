# **Learn OPENSSL**

A collection of C++ examples demonstrating cryptographic techniques using **OpenSSL 3**. This project includes implementations for AES, ECDH, RSA, and KEM (Key Encapsulation Mechanism).  

---

**Author:** Ali Poosti

**Contact:** <alipoosti01@gmail.com>

**Date:** Oct, 2024

---

## **Features**  

✅ **AES Encryption/Decryption**  
✅ **ECDH Key Exchange**  
✅ **ECDH with AES for Secure Messaging**  
✅ **ECDH with RSA for Hybrid Encryption**  
✅ **Key Encapsulation Mechanism (KEM) using RSA & AES**  

## **Prerequisites**  

Ensure you have the following installed before building:  

- CMake (≥ 3.10)  
- OpenSSL 3 (`openssl@3`)  
- A C++ compiler supporting C++14 or later (e.g., `g++` or `clang++`)  

### **Install OpenSSL 3 (if not already installed)**  

#### macOS (Homebrew)  

```sh
brew install openssl@3
```

#### Ubuntu  

```sh
sudo apt update
sudo apt install libssl-dev
```

#### Windows (vcpkg)  

```sh
vcpkg install openssl
```

## **Build Instructions**  

1️⃣ **Clone the repository**  

```sh
git clone https://github.com/alipoosti/Learn_OPENSSL.git
cd Learn_OPENSSL
```

2️⃣ **Create a build directory & configure CMake**  

```sh
cmake -B build .
```

3️⃣ **Compile the project**  

```sh
cmake --build build
```

4️⃣ **Run an example**  
Navigate to the `build` folder and execute any compiled binary:  

```sh
./build/aes_example
./build/ecdh_example
```

## **Project Structure**  

```txt
📂 Learn_OPENSSL
├── 📂 src                 # Source files
│   ├── aes_example.cpp    # AES encryption example
│   ├── ecdh_example.cpp   # ECDH key exchange example
│   ├── ecdh_w_aes_example.cpp  # ECDH + AES hybrid example
│   ├── ecdh_w_rsa_example.cpp  # ECDH + RSA example
│   ├── kem_example.cpp    # KEM framework example
|   ├── signature_example.cpp # Digital Signature example 
├── CMakeLists.txt         # CMake configuration
├── README.md              # This file
```

## **License**  

This project is licensed under the **MIT License**. See [LICENSE](LICENSE) for details.  
