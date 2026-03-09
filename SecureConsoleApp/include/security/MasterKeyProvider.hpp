#pragma once
// ============================================================
// MasterKeyProvider.hpp — FIXED: no unsafe interactive prompt
// Sources: ENV var → Key file only
// Standards: OWASP Secrets Management CS, NIST SP 800-57
// ============================================================
#include "SecureCore.hpp"
#include "CryptoEngine.hpp"
#include <cstdlib>
#include <fstream>
#include <filesystem>
#include <iostream>
#ifndef _WIN32
  #include <termios.h>
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
        }
        // Strategy 2: Key file
        if (const char* keyFilePath = std::getenv(keyFileEnv.data())) {
            auto keyRes = loadKeyFile(keyFilePath);
            if (keyRes.ok()) return keyRes;
        }
        // No safe method left
        return Result<SecBytes>::Failure(SecurityStatus::ERR_CONFIG_INVALID,
            "No master key found. Set APP_MASTER_KEY env or APP_KEY_FILE to a 32-byte key file.");
    }

    [[nodiscard]] static Result<void> generateKeyFile(const std::string& outputPath) {
        auto keyRes = CryptoEngine::randomBytes(CryptoEngine::AES_KEY_SIZE);
        if (keyRes.fail()) return Result<void>::Failure(keyRes.status, keyRes.message);

        std::ofstream f(outputPath, std::ios::binary | std::ios::trunc);
        if (!f.is_open())
            return Result<void>::Failure(SecurityStatus::ERR_CONFIG_INVALID,
                "Cannot create key file: " + outputPath);
        f.write(reinterpret_cast<const char*>(keyRes.value.data()),
                static_cast<std::streamsize>(keyRes.value.size()));

#ifndef _WIN32
        namespace fs = std::filesystem;
        fs::permissions(outputPath, fs::perms::owner_read, fs::perm_options::replace);
#endif
        return Result<void>::Success();
    }

private:
    [[nodiscard]] static Result<SecBytes> loadKeyFile(const char* path) {
        std::ifstream f(path, std::ios::binary);
        if (!f.is_open())
            return Result<SecBytes>::Failure(SecurityStatus::ERR_CONFIG_INVALID, "Cannot open key file");
        SecBytes key((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
        if (key.size() != CryptoEngine::AES_KEY_SIZE)
            return Result<SecBytes>::Failure(SecurityStatus::ERR_CRYPTO_FAIL,
                "Key file must be exactly 32 bytes");
        return Result<SecBytes>::Success(std::move(key));
    }

    // Use OpenSSL's base64 decoding
    static SecBytes base64Decode(const std::string& input) {
        if (input.empty()) return {};
        size_t len = 0;
        std::unique_ptr<unsigned char[]> out(EVP_DecodeBlock(nullptr, 
            reinterpret_cast<const unsigned char*>(input.data()), input.size()));
        if (!out) return {};
        len = (input.size() / 4) * 3;
        if (input.back() == '=') len--;
        if (input.size() > 1 && input[input.size()-2] == '=') len--;
        SecBytes result(len);
        std::copy(out.get(), out.get() + len, result.begin());
        return result;
    }
};

} // namespace SecFW
