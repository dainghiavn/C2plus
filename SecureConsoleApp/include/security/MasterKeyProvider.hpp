#pragma once
// ============================================================
// MasterKeyProvider.hpp — FIXED: includes at top level
// Sources: ENV var → Key file → Interactive prompt
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
        // Strategy 3: Interactive prompt (dev / first-run)
        return deriveFromPrompt();
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

    [[nodiscard]] static Result<SecBytes> deriveFromPrompt() {
        std::cout << "[Setup] Master password (derives encryption key): ";
        std::string masterPwd;
#ifndef _WIN32
        termios oldt{}, newt{};
        ::tcgetattr(STDIN_FILENO, &oldt);
        newt = oldt;
        newt.c_lflag &= ~static_cast<tcflag_t>(ECHO);
        ::tcsetattr(STDIN_FILENO, TCSANOW, &newt);
        std::getline(std::cin, masterPwd);
        ::tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
#else
        std::getline(std::cin, masterPwd);
#endif
        std::cout << "\n";

        if (masterPwd.size() < 12)
            return Result<SecBytes>::Failure(SecurityStatus::ERR_INPUT_INVALID,
                "Master password too short (min 12 chars)");

        const std::string saltStr = "SecFW_v1_KDF_SALT_2026";
        SecBytes salt(saltStr.begin(), saltStr.end());
        auto keyRes = CryptoEngine::hashPassword(masterPwd, salt, 600000);

        volatile char* p = masterPwd.data();
        for (std::size_t i = 0; i < masterPwd.size(); ++i) p[i] = 0;

        return keyRes;
    }

    static SecBytes base64Decode(const std::string& input) {
        static const std::string chars =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        SecBytes out;
        int val = 0, valb = -8;
        for (unsigned char c : input) {
            if (c == '=') break;
            auto pos = chars.find(c);
            if (pos == std::string::npos) continue;
            val = (val << 6) + static_cast<int>(pos);
            valb += 6;
            if (valb >= 0) {
                out.push_back(static_cast<byte_t>((val >> valb) & 0xFF));
                valb -= 8;
            }
        }
        return out;
    }
};

} // namespace SecFW
