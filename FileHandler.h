#pragma once

#include <string>
#include <vector>

class CryptoManager;
class RSAManager;

struct AppSettings {
    int    pbkdf2Iterations = 100000;
    int    saltLength = 16;
    int    aesMode = 0; // 0=CBC,1=GCM
    std::string pubKeyPath;
    std::string privKeyPath;
};

/// Interface chung cho các handler file (.enc, .hyb, .pem…)
class FileHandler {
public:
    virtual ~FileHandler() = default;

    /// Có thể handle extension này không?
    virtual bool CanHandle(const std::string& ext) const = 0;

    /// Mã hóa in->out theo settings
    virtual bool Encrypt(const std::string& in,
        const std::string& out,
        const AppSettings& stgs,
        CryptoManager& crypto,
        RSAManager& rsa) = 0;

    /// Giải mã in->out theo settings
    virtual bool Decrypt(const std::string& in,
        const std::string& out,
        const AppSettings& stgs,
        CryptoManager& crypto,
        RSAManager& rsa) = 0;
};
