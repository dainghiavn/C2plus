// ============================================================
// main.cpp — Fixed v1.1
// Fix [2]: cross-platform env override (no raw ::setenv)
//          → MasterKeyProvider::resolveWithOverride()
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
#include "security/CliParser.hpp"
#include <iostream>
#include <thread>

#ifndef _WIN32
  #include <termios.h>
  #include <unistd.h>
#else
  #include <conio.h>
  #include <windows.h>
#endif

using namespace SecFW;
static constexpr std::string_view APP_VERSION = "1.0.0";

// ── Cross-platform env setter (FIX [2]) ──
static void setEnvVar(const std::string& key, const std::string& value) {
#ifndef _WIN32
    ::setenv(key.c_str(), value.c_str(), 1);
#else
    _putenv_s(key.c_str(), value.c_str());
#endif
}

static std::string secureReadPassword(std::string_view prompt) {
    std::cout << prompt; std::cout.flush();
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

struct AppContext {
    SecureLogger logger;
    UserDatabase userDB;
    RateLimiter  limiter;
    SecBytes     masterKey;

    explicit AppContext(const std::string& logPath, u32_t maxAttempts = 5)
        : logger(logPath, LogLevel::INFO, true)
        , limiter(maxAttempts, std::chrono::seconds(300)) {}
};

static void runSecureMenu(AppContext& ctx, const SessionToken& session) {
    MemoryGuard guard;
    while (true) {
        if (guard.checkIntegrity().fail()) {
            ctx.logger.critical("Stack canary corrupted!", session.userId);
            std::terminate();
        }
        std::cout << "\n╔══════════════════════════════╗\n"
                  << "║  User: " << session.userId
                  << std::string(22 - std::min(session.userId.size(), std::size_t(22)), ' ')
                  << "║\n"
                  << "╠══════════════════════════════╣\n"
                  << "║  1. Encrypt Data              ║\n"
                  << "║  2. Admin Panel [ADMIN]        ║\n"
                  << "║  3. Change Password           ║\n"
                  << "║  0. Logout                    ║\n"
                  << "╚══════════════════════════════╝\n> ";

        std::string choice; std::getline(std::cin, choice);
        auto parsed = InputValidator::parseInteger<int>(choice, 0, 3);
        if (parsed.fail()) { std::cout << "[-] Invalid option\n"; continue; }

        switch (parsed.value) {
        case 1: {
            std::cout << "Data to encrypt: ";
            std::string data; std::getline(std::cin, data);
            auto v = InputValidator::validate(data, {.minLen=1,.maxLen=4096}, "data");
            if (v.fail()) { std::cout << "[-] " << v.message << "\n"; break; }
            auto keyRes = CryptoEngine::randomBytes(CryptoEngine::AES_KEY_SIZE);
            if (keyRes.fail()) break;
            SecBytes plain(data.begin(), data.end());
            SecBytes aad(session.userId.begin(), session.userId.end());
            auto enc = CryptoEngine::encryptAESGCM(plain, keyRes.value, aad);
            if (enc.ok())
                std::cout << "[+] Encrypted (" << enc.value.size() << " bytes): "
                          << CryptoEngine::toHex(enc.value).substr(0, 48) << "...\n";
            ctx.logger.audit({.userId=session.userId, .action="ENCRYPT",
                .success=enc.ok(), .details=std::to_string(plain.size())+" bytes"});
            break;
        }
        case 2: {
            if (!(session.roleFlags & Roles::ADMIN)) {
                ctx.logger.audit({.userId=session.userId, .action="ACCESS_ADMIN",
                    .success=false, .details="Insufficient role"});
                std::cout << "[-] Access denied\n"; break;
            }
            std::cout << "[+] Admin Panel — Users: " << ctx.userDB.userCount() << "\n";
            ctx.logger.audit({.userId=session.userId,.action="ACCESS_ADMIN",.success=true});
            break;
        }
        case 3: {
            auto oldPwd = secureReadPassword("Current password: ");
            auto vr = ctx.userDB.verifyPassword(session.userId, oldPwd);
            wipePwd(oldPwd);
            if (vr.fail()) { std::cout << "[-] Incorrect password\n"; break; }
            auto newPwd = secureReadPassword("New password: ");
            auto pv = InputValidator::validate(newPwd, Rules::PASSWORD, "password");
            if (pv.fail()) { wipePwd(newPwd); std::cout<<"[-] "<<pv.message<<"\n"; break; }
            ctx.userDB.removeUser(session.userId);
            ctx.userDB.addUser(session.userId, newPwd, session.roleFlags);
            wipePwd(newPwd);
            std::cout << "[+] Password changed\n";
            ctx.logger.audit({.userId=session.userId,.action="CHANGE_PWD",.success=true});
            break;
        }
        case 0:
            ctx.logger.audit({.userId=session.userId,.action="LOGOUT",.success=true});
            std::cout << "[+] Logged out.\n";
            return;
        }
    }
}

static int runSetup(AppContext& ctx, const std::string& dbPath) {
    std::cout << "\n=== First-Run Setup ===\n";
    std::cout << "Admin username: ";
    std::string user; std::getline(std::cin, user);
    if (InputValidator::validate(user, Rules::USERNAME, "username").fail()) return 1;
    auto pwd = secureReadPassword("Admin password: ");
    auto pv = InputValidator::validate(pwd, Rules::PASSWORD, "password");
    if (pv.fail()) { wipePwd(pwd); std::cerr<<"[-] "<<pv.message<<"\n"; return 1; }
    auto r = ctx.userDB.addUser(user, pwd, Roles::ADMIN | Roles::USER);
    wipePwd(pwd);
    if (r.fail()) { std::cerr<<"[-] "<<r.message<<"\n"; return 1; }
    auto s = ctx.userDB.saveTo(dbPath, ctx.masterKey);
    if (s.fail()) { std::cerr<<"[-] "<<s.message<<"\n"; return 1; }
    ctx.logger.audit({.userId=user,.action="SETUP_ADMIN",.success=true});
    std::cout << "[+] Setup complete. Run without --setup to login.\n";
    return 0;
}

int main(int argc, char* argv[]) {
    try {
        // ── Step 1: Parse CLI (now includes conflict + path checks) ──
        auto cli = buildAppCli(argv[0]);
        auto argsRes = cli.parse(argc, argv);
        if (argsRes.fail()) {
            std::cerr << "[-] " << argsRes.message << "\n";
            cli.printHelp();
            return 1;
        }
        const auto& args = argsRes.value;

        if (args.has("help"))    { cli.printHelp();               return 0; }
        if (args.has("version")) { cli.printVersion(APP_VERSION); return 0; }

        // ── Step 2: Init services ──
        std::string logPath  = args.getOr("log",          "app_audit.log");
        std::string dbPath   = args.getOr("db",           "users.udb");
        auto maxAttRes       = InputValidator::parseInteger<u32_t>(
                                   args.getOr("max_attempts","5"), 1, 10);
        u32_t maxAttempts    = maxAttRes.ok() ? maxAttRes.value : 5u;
        auto ttlRes          = InputValidator::parseInteger<int>(
                                   args.getOr("session_ttl","30"), 1, 480);
        int sessionTTL       = ttlRes.ok() ? ttlRes.value : 30;

        AppContext ctx(logPath, maxAttempts);
        ctx.logger.info("Application starting v" + std::string(APP_VERSION));
        ctx.logger.info("db=" + dbPath + " ttl=" + std::to_string(sessionTTL) +
                        "min attempts=" + std::to_string(maxAttempts));

        // ── Step 3: Anti-tamper ──
        bool debugMode = args.has("debug");
        AntiTamper antiTamper(ctx.logger,
            debugMode ? TamperPolicy::LOG_ONLY : TamperPolicy::TERMINATE);
        auto tamperRes = antiTamper.runAllChecks(!debugMode);
        if (tamperRes.fail() && !debugMode) {
            ctx.logger.critical("Tamper: " + tamperRes.message); return 2;
        }

        // ── Step 4: Master key ──
        // FIX [2]: cross-platform env override, không dùng ::setenv trực tiếp
        if (auto kf = args.get("key_file"); kf.has_value())
            setEnvVar("APP_KEY_FILE", *kf);

        // --generate-key mode
        if (args.has("generate_key")) {
            std::string outPath = args.positional.empty()
                                  ? "master.key" : args.positional[0];
            auto r = MasterKeyProvider::generateKeyFile(outPath);
            if (r.ok()) std::cout << "[+] Key file: " << outPath << "\n";
            else        std::cerr << "[-] " << r.message << "\n";
            return r.ok() ? 0 : 1;
        }

        auto keyRes = MasterKeyProvider::resolve();
        if (keyRes.fail()) {
            std::cerr << "[CRITICAL] " << keyRes.message << "\n"; return 1;
        }
        ctx.masterKey = keyRes.value;

        // ── Step 5: Setup mode ──
        if (args.has("setup")) return runSetup(ctx, dbPath);

        // ── Step 6: Load UserDB ──
        auto loadRes = ctx.userDB.loadFrom(dbPath, ctx.masterKey);
        if (loadRes.fail()) {
            std::cerr << "[-] " << loadRes.message
                      << "\n    Tip: Run with --setup first\n";
            return 1;
        }
        ctx.logger.info("Loaded " + std::to_string(ctx.userDB.userCount()) + " users");

        // ── Step 7: Login loop ──
        std::cout << "╔══════════════════════════════╗\n"
                  << "║   Secure Console App v" << APP_VERSION << "   ║\n"
                  << "║   CERT / OWASP / NIST / FIPS  ║\n"
                  << "╚══════════════════════════════╝\n\n";

        for (int attempt = 0; attempt < static_cast<int>(maxAttempts); ++attempt) {
            std::cout << "Username: ";
            std::string username; std::getline(std::cin, username);
            auto uv = InputValidator::validate(username, Rules::USERNAME, "username");
            if (uv.fail()) { std::cout << "[-] " << uv.message << "\n"; continue; }
            if (ctx.limiter.isBlocked(username)) {
                auto rem = ctx.limiter.remainingLockout(username);
                std::cout << "[-] Locked " << rem.count() << "s\n"; continue;
            }
            auto pwd = secureReadPassword("Password: ");
            auto verRes = ctx.userDB.verifyPassword(username, pwd);
            wipePwd(pwd);

            if (verRes.ok()) {
                ctx.limiter.reset(username);
                ctx.logger.audit({.userId=username,.action="LOGIN",.success=true});
                SessionToken session{
                    .tokenId   = "sess_" + username + "_" +
                                 std::to_string(std::chrono::system_clock::now()
                                                .time_since_epoch().count()),
                    .userId    = username,
                    .roleFlags = verRes.value,
                    .createdAt = std::chrono::system_clock::now(),
                    .expiresAt = std::chrono::system_clock::now()
                                 + std::chrono::minutes(sessionTTL)
                };
                std::cout << "[+] Welcome, " << username << "!\n";
                runSecureMenu(ctx, session);
                if (ctx.userDB.isDirty()) ctx.userDB.saveTo(dbPath, ctx.masterKey);
                break;
            } else {
                ctx.limiter.recordFailure(username);
                ctx.logger.audit({.userId=username,.action="LOGIN",
                    .success=false,.details=verRes.message});
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
                std::cout << "[-] Invalid credentials ("
                          << attempt+1 << "/" << maxAttempts << ")\n";
            }
        }

        ctx.logger.info("Application shutdown");
        return 0;

    } catch (const std::exception& e) {
        std::cerr << "[CRITICAL] " << e.what() << "\n";
        return EXIT_FAILURE;
    }
}
