#pragma once
#include <string>
#include <vector>
#include "CryptoManager.h"
#include "RSAManager.h"

class HybridFileHandler {
public:
    bool Encrypt(const std::string& outPath,
        const std::vector<uint8_t>& plain,
        CryptoManager& crypto,
        RSAManager& rsa);

    bool Decrypt(const std::string& inPath,
        std::vector<uint8_t>& plain,
        CryptoManager& crypto,
        RSAManager& rsa);

    bool EncryptFile(const std::string& inPath,
        const std::string& outPath,
        CryptoManager& crypto,
        RSAManager& rsa);

    bool DecryptFile(const std::string& inPath,
        const std::string& outPath,
        CryptoManager& crypto,
        RSAManager& rsa);

private:
    bool EncryptStream(const std::string& inPath,
        const std::string& outPath,
        CryptoManager& crypto,
        RSAManager& rsa);
    bool DecryptStream(const std::string& inPath,
        const std::string& outPath,
        CryptoManager& crypto,
        RSAManager& rsa);

    static constexpr uint64_t STREAM_THRESHOLD = 5ULL * 1024 * 1024 * 1024; // 5 GiB

#pragma pack(push,1)
    struct Header {
        char     magic[4];   // "HYBR"
        uint8_t  version;
        uint8_t  aesMode;
        uint32_t ekLen;
        uint64_t timestamp;
    };
#pragma pack(pop)
};
