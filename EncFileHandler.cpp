#include "EncFileHandler.h"
#include "AESFileHandler.h"
#include "HybridFileHandler.h"
#include "Utils.h"
#include "Logger.h"

#include <fstream>
#include <filesystem>

bool EncFileHandler::Save(const std::string& inPath,
    const std::string& outPath,
    CryptoManager& crypto,
    RSAManager& rsa)
{
    auto& log = Logger::instance();
    log.log(Logger::INFO, "EncFileHandler::Save start: " + inPath + " -> " + outPath);

    int choice = Utils::PromptChoice(u8"Chọn thuật toán mã hóa:",
        { "AES", "AES + RSA (Hybrid)" });

    bool ok = false;
    if (choice == 0) {
        AESFileHandler aes;
        ok = aes.EncryptFile(inPath, outPath, crypto);
    }
    else {
        HybridFileHandler hyb;
        ok = hyb.EncryptFile(inPath, outPath, crypto, rsa);
    }

    log.log(ok ? Logger::INFO : Logger::LEVEL_ERROR,
        std::string("EncFileHandler::Save ") + (ok ? "OK" : "FAIL") + ": " + inPath);
    return ok;
}

bool EncFileHandler::LoadToFile(const std::string& inPath,
    const std::string& outPath,
    CryptoManager& crypto,
    RSAManager& rsa)
{
    // chỉ chọn logic theo magic, gọi thẳng decrypt ra file
    char magic[4];
    std::ifstream ifs(inPath, std::ios::binary);
    if (!ifs.read(magic, 4)) {
        Logger::instance().log(Logger::LEVEL_ERROR, u8"Không đọc được magic: " + inPath);
        return false;
    }
    std::string hdr(magic, 4);
    if (hdr == "SENC") {
        AESFileHandler aes;
        return aes.DecryptFile(inPath, outPath, crypto);
    }
    else if (hdr == "HYBR") {
        HybridFileHandler hyb;
        return hyb.DecryptFile(inPath, outPath, crypto, rsa);
    }
    else {
        Logger::instance().log(Logger::LEVEL_ERROR, u8"Unsupported format: " + hdr);
        return false;
    }
}

bool EncFileHandler::Load(const std::string& inPath,
    std::vector<uint8_t>& plain,
    CryptoManager& crypto,
    RSAManager& rsa)
{
    // tạo file tạm .dec
    auto outTmp = std::filesystem::path(inPath).replace_extension(".dec.tmp").string();
    if (!LoadToFile(inPath, outTmp, crypto, rsa))
        return false;
    // đọc toàn bộ vào vector
    plain = Utils::ReadAllBytes(outTmp);
    Utils::CleanupTemp(outTmp);
    return true;
}
