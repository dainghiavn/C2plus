#pragma once
#include <string>
#include <vector>
#include <stdexcept>

/// Exception lớp Crypto
class CryptoException : public std::runtime_error {
public:
    explicit CryptoException(const std::string& msg)
        : std::runtime_error(msg) {}
};

/// Quản lý AES encrypt/decrypt, PBKDF2, SHA-256
class CryptoManager {
public:
    enum Mode { MODE_CBC = 0, MODE_GCM = 1 };

    CryptoManager();
    ~CryptoManager();

    /// Derive key từ password + salt (PBKDF2 only, không sinh IV)
    void deriveKey(const std::string& password,
        const std::vector<uint8_t>& salt,
        int iterations);

    /// Sinh random IV
    static std::vector<uint8_t> genIv(size_t len);

    /// Thiết lập sẵn key & iv
    void setKeyIv(const std::vector<uint8_t>& key,
        const std::vector<uint8_t>& iv);

    /// AES encrypt (GCM sẽ append tag 16 byte ở cuối)
    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& plain,
        Mode mode);

    /// AES decrypt (GCM sẽ verify tag 16 byte ở cuối)
    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& cipher,
        Mode mode);

    /// SHA-256 hash
    std::vector<uint8_t> hashSHA256(const std::vector<uint8_t>& data);

    /// Lấy key/iv vừa derive
    const std::vector<uint8_t>& getKey() const { return key_; }
    const std::vector<uint8_t>& getIv()  const { return iv_; }

private:
    std::vector<uint8_t> key_;  // 32 bytes
    std::vector<uint8_t> iv_;   // 16 bytes

    // Không copy được
    CryptoManager(const CryptoManager&) = delete;
    CryptoManager& operator=(const CryptoManager&) = delete;
};
