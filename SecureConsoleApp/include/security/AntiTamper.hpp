#pragma once
// ============================================================
// AntiTamper.hpp — Runtime integrity & anti-debug checks
// Standards: OWASP MASVS-R, SEI CERT ENV30-C
// ============================================================
#include "SecureCore.hpp"
#include "CryptoEngine.hpp"
#include "SecureLogger.hpp"
#include <fstream>
#include <filesystem>
#include <functional>
#include <openssl/evp.h>

#ifndef _WIN32
  #include <sys/ptrace.h>
  #include <unistd.h>
#else
  #include <windows.h>
#endif

namespace SecFW {

enum class TamperPolicy { LOG_ONLY, WARN_USER, TERMINATE };

class AntiTamper final {
public:
    explicit AntiTamper(SecureLogger& logger,
                        TamperPolicy  policy = TamperPolicy::TERMINATE)
        : logger_(logger), policy_(policy) {}

    // 1. Debugger detection
    [[nodiscard]] Result<void> checkNoDebugger() const {
#ifndef _WIN32
        if (::ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) == -1)
            return handleTamper("Debugger detected via ptrace");
        ::ptrace(PTRACE_DETACH, 0, nullptr, nullptr);
#else
        if (IsDebuggerPresent())
            return handleTamper("Debugger detected via IsDebuggerPresent");
        BOOL remoteDbg = FALSE;
        CheckRemoteDebuggerPresent(GetCurrentProcess(), &remoteDbg);
        if (remoteDbg) return handleTamper("Remote debugger detected");
#endif
        return Result<void>::Success();
    }

    // 2. Environment sanity (LD_PRELOAD injection check)
    [[nodiscard]] Result<void> checkEnvironment() const {
#ifndef _WIN32
        if (::getuid() == 0)
            logger_.warn("[AntiTamper] Running as root — not recommended");
        if (const char* preload = std::getenv("LD_PRELOAD"))
            if (preload && std::strlen(preload) > 0)
                return handleTamper("LD_PRELOAD injection: " + std::string(preload));
#endif
#ifdef __APPLE__
        if (std::getenv("DYLD_INSERT_LIBRARIES"))
            return handleTamper("DYLD_INSERT_LIBRARIES injection detected");
#endif
        return Result<void>::Success();
    }

    // 3. File HMAC integrity (chunked)
    [[nodiscard]] Result<void> verifyFileIntegrity(
        const std::string& filePath,
        std::span<const byte_t> hmacKey,
        const std::string& expectedHmacHex) const
    {
        std::ifstream f(filePath, std::ios::binary);
        if (!f.is_open())
            return Result<void>::Failure(SecurityStatus::ERR_INTERNAL,
                "Cannot open: " + filePath);

        // Use EVP_MD_CTX for incremental hash
        std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(
            EVP_MD_CTX_new(), EVP_MD_CTX_free);
        if (!ctx)
            return Result<void>::Failure(SecurityStatus::ERR_INTERNAL, "HMAC ctx alloc failed");

        if (!HMAC_Init_ex(ctx.get(), hmacKey.data(), static_cast<int>(hmacKey.size()),
                          EVP_sha256(), nullptr))
            return Result<void>::Failure(SecurityStatus::ERR_CRYPTO_FAIL, "HMAC init failed");

        char buffer[8192];
        while (f.read(buffer, sizeof(buffer)) || f.gcount()) {
            if (!HMAC_Update(ctx.get(), reinterpret_cast<unsigned char*>(buffer),
                             static_cast<int>(f.gcount())))
                return Result<void>::Failure(SecurityStatus::ERR_CRYPTO_FAIL, "HMAC update failed");
        }

        unsigned char mac[EVP_MAX_MD_SIZE];
        unsigned int macLen = 0;
        if (!HMAC_Final(ctx.get(), mac, &macLen))
            return Result<void>::Failure(SecurityStatus::ERR_CRYPTO_FAIL, "HMAC final failed");

        SecBytes computed(mac, mac + macLen);
        if (CryptoEngine::toHex(computed) != expectedHmacHex)
            return handleTamper("File integrity check failed: " + filePath);

        return Result<void>::Success();
    }

    // 4. Run all checks at startup
    [[nodiscard]] Result<void> runAllChecks(bool checkDebugger = true) const {
        if (checkDebugger) {
            auto r = checkNoDebugger();
            if (r.fail() && policy_ == TamperPolicy::TERMINATE) return r;
        }
        auto r2 = checkEnvironment();
        if (r2.fail() && policy_ == TamperPolicy::TERMINATE) return r2;
        logger_.info("[AntiTamper] All integrity checks passed");
        return Result<void>::Success();
    }

private:
    [[nodiscard]] Result<void> handleTamper(const std::string& reason) const {
        logger_.critical("[AntiTamper] TAMPER DETECTED: " + reason);
        switch (policy_) {
        case TamperPolicy::LOG_ONLY:
            return Result<void>::Failure(SecurityStatus::ERR_TAMPER_DETECTED, reason);
        case TamperPolicy::WARN_USER:
            std::cerr << "\n[!] SECURITY WARNING: " << reason << "\n";
            return Result<void>::Failure(SecurityStatus::ERR_TAMPER_DETECTED, reason);
        case TamperPolicy::TERMINATE: default:
            std::cerr << "\n[CRITICAL] Integrity violation. Terminating.\n";
            std::terminate();
        }
    }

    SecureLogger& logger_;
    TamperPolicy  policy_;
};

} // namespace SecFW
