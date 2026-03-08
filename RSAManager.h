#pragma once

#include <string>
#include <vector>
#include <stdexcept>
#include <openssl/evp.h>
#include <openssl/pem.h>

/// Exception RSA
class RSAException : public std::runtime_error {
public:
    explicit RSAException(const std::string& msg)
        : std::runtime_error(msg) {}
};

/// Quản lý RSA encrypt/decrypt (OAEP) dùng EVP_PKEY
class RSAManager {
public:
    RSAManager();
    ~RSAManager();

    /// Load public key PEM
    void loadPublicKey(const std::string& path);

    /// Load private key PEM, pwd nếu có
    void loadPrivateKey(const std::string& path,
        const std::string& pwd = "");

    /// RSA public encrypt (OAEP)
    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& data);

    /// RSA private decrypt (OAEP)
    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& data);

    /// Kích thước key (bytes)
    size_t keySize() const;

private:
    EVP_PKEY* pubKey_ = nullptr;
    EVP_PKEY* privKey_ = nullptr;

    RSAManager(const RSAManager&) = delete;
    RSAManager& operator=(const RSAManager&) = delete;
};
