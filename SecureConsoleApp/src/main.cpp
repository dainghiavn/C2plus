// ============================================================
// main.cpp — Complete & Fixed
// Fixes: termios at top-level, runSecureMenu complete,
//        no unused variables, no hardcoded credentials
// ============================================================
#include "security/SecureCore.hpp"
#include "security/InputValidator.hpp"
#include "security/AuthManager.hpp"
#include "security/CryptoEngine.hpp"
#include "security/SecureLogger.hpp"
#include "security/ConfigManager.hpp"
#include "security/MemoryGuard.hpp"
#include "security/AntiTamper.hpp"
#include "security/UserDatabase.hpp"
#include "security/MasterKeyProvider.hpp"
#include <iostream>
#include <thread>

#ifndef _WIN32
  #include <termios.h>
  #include <unistd.h>
#else
  #include <conio.h>
#endif

using namespace SecFW;

// ── Secure password input ──
static std::string secureReadPassword(std::string_view prompt) {
    std::cout << prompt;
    std::cout.flush();
    std::string pwd;
#ifndef _WIN32
    termios oldt{}, newt{};
    ::tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~static_cast<tcflag_t>(ECHO);
    ::tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    std::getline(std::cin, pwd);
    ::tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
#else
    char ch;
    while ((ch = static_cast<char>(_getch())) != '\r') {
        if (ch == '\b' && !pwd.empty()) { pwd.pop_back(); std::cout << "\b \b"; }
        else if (ch != '\b') { pwd += ch; std::cout << '*'; }
    }
#endif
    std::cout << '\n';
    return pwd;
}

static void wipePwd(std::string& pwd) {
    volatile char* p = pwd.data();
    for (std::size_t i = 0; i < pwd.size(); ++i) p[i] = 0;
    pwd.clear();
}

// ── AppContext ──
struct AppContext {
    SecureLogger logger;
    UserDatabase userDB;
    RateLimiter  limiter;
    SecBytes     masterKey;

    AppContext()
        : logger("app_audit.log", LogLevel::INFO, true)
        , limiter(5, std::chrono::seconds(300))
    {}
};

// ── Secure Menu ──
static void runSecureMenu(AppContext& ctx, const SessionToken& session) {
    MemoryGuard guard;

    while (true) {
        auto gCheck = guard.checkIntegrity();
        if (gCheck.fail()) {
            ctx.logger.critical("Stack corruption detected!", session.userId);
            std::terminate();
        }

        std::cout << "\n╔══════════════════════════════╗\n"
                  << "║  User: " << session.userId
                  << std::string(22 - std::min(session.userId.size(), std::size_t(22)), ' ') << "║\n"
                  << "╠══════════════════════════════╣\n"
                  << "║  1. Encrypt Data              ║\n"
                  << "║  2. Admin Panel [ADMIN]        ║\n"
                  << "║  3. Change Password           ║\n"
                  << "║  0. Logout                    ║\n"
                  << "╚══════════════════════════════╝\n> ";

        std::string choice;
        std::getline(std::cin, choice);

        auto parsed = InputValidator::parseInteger<int>(choice, 0, 3);
        if (parsed.fail()) {
            ctx.logger.warn("Invalid menu input", session.userId);
            std::cout << "[-] Invalid option\n";
            continue;
        }

        switch (parsed.value) {
        case 1: {
            std::cout << "Data to encrypt: ";
            std::string data;
            std::getline(std::cin, data);
            ValidationRule r{ .minLen = 1, .maxLen = 4096 };
            auto v = InputValidator::validate(data, r, "data");
            if (v.fail()) { std::cout << "[-] " << v.message << "\n"; break; }

            auto keyRes = CryptoEngine::randomBytes(CryptoEngine::AES_KEY_SIZE);
            if (keyRes.fail()) { std::cout << "[-] RNG error\n"; break; }

            SecBytes plain(data.begin(), data.end());
            SecBytes aad(session.userId.begin(), session.userId.end());
            auto enc = CryptoEngine::encryptAESGCM(plain, keyRes.value, aad);
            if (enc.ok()) {
                std::cout << "[+] Encrypted (" << enc.value.size() << " bytes): "
                          << CryptoEngine::toHex(enc.value).substr(0, 48) << "...\n";
                ctx.logger.audit({ .userId = session.userId, .action = "ENCRYPT",
                    .resource = "user_data", .success = true,
                    .details = std::to_string(plain.size()) + " bytes" });
            } else {
                std::cout << "[-] " << enc.message << "\n";
            }
            break;
        }
        case 2: {
            if (!(session.roleFlags & Roles::ADMIN)) {
                ctx.logger.audit({ .userId = session.userId, .action = "ACCESS_ADMIN",
                    .success = false, .details = "Insufficient role" });
                std::cout << "[-] Access denied: ADMIN role required\n";
                break;
            }
            std::cout << "[+] Admin Panel — Total users: "
                      << ctx.userDB.userCount() << "\n";
            ctx.logger.audit({ .userId = session.userId,
                .action = "ACCESS_ADMIN", .success = true });
            break;
        }
        case 3: {
            auto oldPwd = secureReadPassword("Current password: ");
            auto verifyRes = ctx.userDB.verifyPassword(session.userId, oldPwd);
            wipePwd(oldPwd);
            if (verifyRes.fail()) {
                std::cout << "[-] Incorrect current password\n"; break;
            }
            auto newPwd = secureReadPassword("New password: ");
            auto pwdVal = InputValidator::validate(newPwd, Rules::PASSWORD, "password");
            if (pwdVal.fail()) {
                wipePwd(newPwd);
                std::cout << "[-] " << pwdVal.message << "\n"; break;
            }
            // Remove old, re-add with new password
            ctx.userDB.removeUser(session.userId);
            ctx.userDB.addUser(session.userId, newPwd, session.roleFlags);
            wipePwd(newPwd);
            std::cout << "[+] Password changed\n";
            ctx.logger.audit({ .userId = session.userId,
                .action = "CHANGE_PWD", .success = true });
            break;
        }
        case 0:
            ctx.logger.audit({ .userId = session.userId,
                .action = "LOGOUT", .success = true });
            std::cout << "[+] Logged out.\n";
            return;
        }
    }
}

// ── First-run setup ──
static int runSetup(AppContext& ctx, const std::string& dbPath) {
    std::cout << "\n=== First-Run Setup ===\n"
              << "This creates the initial admin account.\n\n";

    std::cout << "Admin username: ";
    std::string user;
    std::getline(std::cin, user);

    auto uVal = InputValidator::validate(user, Rules::USERNAME, "username");
    if (uVal.fail()) { std::cerr << "[-] " << uVal.message << "\n"; return 1; }

    auto pwd = secureReadPassword("Admin password: ");
    auto pVal = InputValidator::validate(pwd, Rules::PASSWORD, "password");
    if (pVal.fail()) { wipePwd(pwd); std::cerr << "[-] " << pVal.message << "\n"; return 1; }

    auto res = ctx.userDB.addUser(user, pwd, Roles::ADMIN | Roles::USER);
    wipePwd(pwd);
    if (res.fail()) { std::cerr << "[-] " << res.message << "\n"; return 1; }

    auto save = ctx.userDB.saveTo(dbPath, ctx.masterKey);
    if (save.fail()) { std::cerr << "[-] " << save.message << "\n"; return 1; }

    ctx.logger.audit({ .userId = user, .action = "SETUP_CREATE_ADMIN", .success = true });
    std::cout << "[+] Setup complete. Run without --setup to login.\n";
    return 0;
}

// ── main ──
int main(int argc, char* argv[]) {
    try {
        AppContext ctx;
        ctx.logger.info("Application starting");

        const std::string DB_PATH  = "users.udb";
        bool isSetup   = (argc > 1 && std::string(argv[1]) == "--setup");
        bool debugMode = (argc > 1 && std::string(argv[1]) == "--debug");
        bool genKey    = (argc > 1 && std::string(argv[1]) == "--generate-key");

        // Generate key file mode
        if (genKey) {
            std::string keyPath = (argc > 2) ? argv[2] : "master.key";
            auto r = MasterKeyProvider::generateKeyFile(keyPath);
            if (r.ok()) std::cout << "[+] Key file created: " << keyPath << "\n";
            else        std::cerr << "[-] " << r.message << "\n";
            return r.ok() ? 0 : 1;
        }

        // Anti-tamper checks
        AntiTamper antiTamper(ctx.logger,
            debugMode ? TamperPolicy::LOG_ONLY : TamperPolicy::TERMINATE);
        auto tamperRes = antiTamper.runAllChecks(!debugMode);
        if (tamperRes.fail() && !debugMode) {
            ctx.logger.critical("Tamper check: " + tamperRes.message);
            return 2;
        }

        // Resolve master key
        auto keyRes = MasterKeyProvider::resolve();
        if (keyRes.fail()) {
            std::cerr << "[CRITICAL] " << keyRes.message << "\n"; return 1;
        }
        ctx.masterKey = keyRes.value;

        if (isSetup) return runSetup(ctx, DB_PATH);

        // Load UserDB
        auto loadRes = ctx.userDB.loadFrom(DB_PATH, ctx.masterKey);
        if (loadRes.fail()) {
            std::cerr << "[-] " << loadRes.message
                      << "\n    Tip: Run with --setup first\n";
            return 1;
        }
        ctx.logger.info("Loaded " + std::to_string(ctx.userDB.userCount()) + " users");

        std::cout << "╔══════════════════════════════╗\n"
                  << "║   Secure Console App v1.0     ║\n"
                  << "║   CERT / OWASP / NIST / FIPS  ║\n"
                  << "╚══════════════════════════════╝\n\n";

        static constexpr int MAX_ATTEMPTS = 3;
        for (int attempt = 0; attempt < MAX_ATTEMPTS; ++attempt) {
            std::cout << "Username: ";
            std::string username;
            std::getline(std::cin, username);

            auto uVal = InputValidator::validate(username, Rules::USERNAME, "username");
            if (uVal.fail()) { std::cout << "[-] " << uVal.message << "\n"; continue; }

            if (ctx.limiter.isBlocked(username)) {
                auto rem = ctx.limiter.remainingLockout(username);
                std::cout << "[-] Account locked " << rem.count() << "s\n";
                continue;
            }

            auto pwd = secureReadPassword("Password: ");
            auto verRes = ctx.userDB.verifyPassword(username, pwd);
            wipePwd(pwd);

            if (verRes.ok()) {
                ctx.limiter.reset(username);
                ctx.logger.audit({ .userId = username, .action = "LOGIN", .success = true });

                SessionToken session{
                    .tokenId   = "sess_" + username + "_" +
                                 std::to_string(std::chrono::system_clock::now()
                                                .time_since_epoch().count()),
                    .userId    = username,
                    .roleFlags = verRes.value,
                    .createdAt = std::chrono::system_clock::now(),
                    .expiresAt = std::chrono::system_clock::now() + std::chrono::minutes(30)
                };

                std::cout << "[+] Welcome, " << username << "!\n";
                runSecureMenu(ctx, session);

                if (ctx.userDB.isDirty())
                    ctx.userDB.saveTo(DB_PATH, ctx.masterKey);
                break;
            } else {
                ctx.limiter.recordFailure(username);
                ctx.logger.audit({ .userId = username, .action = "LOGIN",
                    .success = false, .details = verRes.message });
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
                std::cout << "[-] Invalid credentials ("
                          << attempt + 1 << "/" << MAX_ATTEMPTS << ")\n";
            }
        }

        ctx.logger.info("Application shutdown");
        return 0;

    } catch (const std::exception& e) {
        std::cerr << "[CRITICAL] " << e.what() << "\n";
        return EXIT_FAILURE;
    }
}
