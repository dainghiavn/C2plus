#pragma once
// ============================================================
// MasterKeyProvider.hpp — FIXED v1.3
// FIX [BUG-15]: EVP_DecodeBlock called correctly (allocate buffer first,
//               not nullptr). Previous call was undefined behavior.
// Standards: OWASP Secrets Management CS, NIST SP 800-57
// ============================================================
#include "SecureCore.hpp"
#include "CryptoEngine.hpp"
#include <cstdlib>
#include <fstream>
#include <filesystem>
#include <iostream>
#include <openssl/evp.h>

#ifndef _WIN32
  #include <unistd.h>
#endif

namespace SecFW {

class MasterKeyProvider final {
public:
    [[nodiscard]] static Result<SecBytes> resolve(
        std::string_view envVarName = "APP_MASTER_KEY",
        std::string_view keyFileEnv = "APP_KEY_FILE")
    {
        // Strategy 1: ENV variable (base64-encoded 32 bytes)
        if (const char* envVal = std::getenv(envVarName.data())) {
            auto decoded = base64Decode(envVal);
            if (decoded.size() == CryptoEngine::AES_KEY_SIZE)
                return Result<SecBytes>::Success(std::move(decoded));
            else if (!decoded.empty())
                return Result<SecBytes>::Failure(SecurityStatus::ERR_CONFIG_INVALID,
                    "APP_MASTER_KEY decoded to wrong size: expected 32, got " +
                    std::to_string(decoded.size()));
        }
        // Strategy 2: Key file
        if (const char* keyFilePath = std::getenv(keyFileEnv.data())) {
            auto keyRes = loadKeyFile(keyFilePath);
            if (keyRes.ok()) return keyRes;
            // Propagate the specific error from the key file
            return keyRes;
        }
        return Result<SecBytes>::Failure(SecurityStatus::ERR_CONFIG_INVALID,
            "No master key found. Set APP_MASTER_KEY (base64) or "
            "APP_KEY_FILE (path to 32-byte binary file).");
    }

    [[nodiscard]] static Result<void> generateKeyFile(const std::string& outputPath) {
        auto keyRes = CryptoEngine::randomBytes(CryptoEngine::AES_KEY_SIZE);
        if (keyRes.fail()) return Result<void>::Failure(keyRes.status, keyRes.message);

        // Check parent directory
        namespace fs = std::filesystem;
        auto parent = fs::path(outputPath).parent_path();
        if (!parent.empty() && !fs::exists(parent))
            return Result<void>::Failure(SecurityStatus::ERR_CONFIG_INVALID,
                "Parent directory not found: " + parent.string());

        // Write to temp then rename
        std::string tmpPath = outputPath + ".tmp";
        {
            std::ofstream f(tmpPath, std::ios::binary | std::ios::trunc);
            if (!f.is_open())
                return Result<void>::Failure(SecurityStatus::ERR_CONFIG_INVALID,
                    "Cannot create key file: " + tmpPath);
            f.write(reinterpret_cast<const char*>(keyRes.value.data()),
                    static_cast<std::streamsize>(keyRes.value.size()));
            f.flush();
            if (!f.good()) {
                fs::remove(tmpPath);
                return Result<void>::Failure(SecurityStatus::ERR_CONFIG_INVALID,
                    "Write error on key file");
            }
        }

        std::error_code ec;
        fs::rename(tmpPath, outputPath, ec);
        if (ec) {
            fs::remove(tmpPath, ec);
            return Result<void>::Failure(SecurityStatus::ERR_CONFIG_INVALID,
                "Rename key file failed: " + ec.message());
        }

#ifndef _WIN32
        fs::permissions(outputPath, fs::perms::owner_read, fs::perm_options::replace);
#endif
        return Result<void>::Success();
    }

private:
    [[nodiscard]] static Result<SecBytes> loadKeyFile(const char* path) {
        namespace fs = std::filesystem;
        if (!fs::exists(path))
            return Result<SecBytes>::Failure(SecurityStatus::ERR_CONFIG_INVALID,
                "Key file not found: " + std::string(path));

        std::ifstream f(path, std::ios::binary);
        if (!f.is_open())
            return Result<SecBytes>::Failure(SecurityStatus::ERR_CONFIG_INVALID,
                "Cannot open key file: " + std::string(path));

        SecBytes key((std::istreambuf_iterator<char>(f)),
                      std::istreambuf_iterator<char>());
        if (key.size() != CryptoEngine::AES_KEY_SIZE)
            return Result<SecBytes>::Failure(SecurityStatus::ERR_CRYPTO_FAIL,
                "Key file must be exactly 32 bytes, got " + std::to_string(key.size()));
        return Result<SecBytes>::Success(std::move(key));
    }

    // FIX [BUG-15]: Correct EVP_DecodeBlock usage
    // EVP_DecodeBlock requires a pre-allocated output buffer, NOT nullptr.
    // Max decoded size = (input_len / 4) * 3 bytes (base64 ratio).
    static SecBytes base64Decode(const std::string& input) {
        if (input.empty()) return {};

        // Strip trailing whitespace/newlines that might come from env vars
        std::string cleaned = input;
        while (!cleaned.empty() && (cleaned.back() == '\n' ||
                                    cleaned.back() == '\r' ||
                                    cleaned.back() == ' '))
            cleaned.pop_back();

        if (cleaned.empty() || cleaned.size() % 4 != 0) return {};

        // Allocate output buffer: max size = (len/4)*3
        const std::size_t maxOutLen = (cleaned.size() / 4) * 3;
        SecBytes out(maxOutLen);

        // FIX: Pass allocated buffer as first argument
        int decodedLen = EVP_DecodeBlock(
            out.data(),
            reinterpret_cast<const unsigned char*>(cleaned.data()),
            static_cast<int>(cleaned.size()));

        if (decodedLen < 0) return {}; // decode error

        // Adjust for padding: each '=' at end reduces length by 1
        std::size_t actualLen = static_cast<std::size_t>(decodedLen);
        if (cleaned.size() >= 1 && cleaned.back() == '=') actualLen--;
        if (cleaned.size() >= 2 && cleaned[cleaned.size() - 2] == '=') actualLen--;

        out.resize(actualLen);
        return out;
    }
};

} // namespace SecFW
