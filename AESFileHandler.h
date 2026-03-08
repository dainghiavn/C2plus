#pragma once
#include <string>
#include <vector>
#include "CryptoManager.h"

class AESFileHandler {
public:
    // existing in‑memory interface
    bool Encrypt(const std::string& outPath,
        const std::vector<uint8_t>& plain,
        CryptoManager& crypto);
    bool Decrypt(const std::string& inPath,
        std::vector<uint8_t>& plain,
        CryptoManager& crypto);

    // new: path‑based entrypoints that choose in‑memory vs streaming
    bool EncryptFile(const std::string& inPath,
        const std::string& outPath,
        CryptoManager& crypto);
    bool DecryptFile(const std::string& inPath,
        const std::string& outPath,
        CryptoManager& crypto);

private:
    // streaming implementations
    bool EncryptStream(const std::string& inPath,
        const std::string& outPath,
        CryptoManager& crypto);
    bool DecryptStream(const std::string& inPath,
        const std::string& outPath,
        CryptoManager& crypto);

    static constexpr uint64_t STREAM_THRESHOLD = 5ULL * 1024 * 1024 * 1024; // 5 GiB

    // internal header
#pragma pack(push,1)
    struct Header {
        char     magic[4];   // "SENC"
        uint8_t  version;
        uint8_t  aesMode;    // CryptoManager::Mode
        uint32_t iterations; // PBKDF2 rounds
        uint16_t saltLen;
        uint16_t ivLen;
        uint64_t timestamp;
    };
#pragma pack(pop)
};
