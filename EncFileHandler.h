#pragma once
#include <string>
#include <vector>
#include "CryptoManager.h"
#include "RSAManager.h"

/// .enc handler: tự phân định AES vs Hybrid, streaming cả encrypt & decrypt
class EncFileHandler {
public:
    /// Tương đương Save: mã hóa file inPath -> outPath
    bool Save(const std::string& inPath,
        const std::string& outPath,
        CryptoManager& crypto,
        RSAManager& rsa);

    /// Tương đương Load: giải mã file inPath -> nền RAM vector
    bool Load(const std::string& inPath,
        std::vector<uint8_t>& plain,
        CryptoManager& crypto,
        RSAManager& rsa);

    /// Thêm để giải mã thẳng ra file, không cần vector
    bool LoadToFile(const std::string& inPath,
        const std::string& outPath,
        CryptoManager& crypto,
        RSAManager& rsa);
};
