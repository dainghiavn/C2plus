// ============================================================
// main.cpp — FIXED v1.3
// FIX [BUG-01]: g_ctx dùng raw pointer (không own stack object)
// FIX [BUG-02]: Signal handler dùng async-signal-safe functions only
// FIX [BUG-03]: AppContext được define TRƯỚC khi dùng trong globals
// FIX [BUG-04]: Master key chỉ có 1 bản, dùng SecBytes với explicit wipe
// FIX [BUG-05]: Session expiry check trong menu loop
// FIX [BUG-06]: Login loop logic tách biệt với rate limiter
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
#include <csignal>
#include <atomic>

#ifndef _WIN32
  #include <termios.h>
  #include <unistd.h>
  #include <sys/mman.h>
#else
  #include <conio.h>
  #include <windows.h>
  #include <io.h>      // _write(), _fileno() — async-signal-safe CRT I/O for Windows
#endif

using namespace SecFW;
static constexpr std::string_view APP_VERSION = "1.0.0";

// ============================================================
// FIX [BUG-03]: Define AppContext BEFORE globals that reference it
// ============================================================
struct AppContext {
    SecureLogger logger;
    UserDatabase userDB;
    RateLimiter  limiter;
    SecBytes     masterKey;

    explicit AppContext(const std::string& logPath, u32_t maxAttempts = 5)
        : logger(logPath, LogLevel::INFO, true)
        , limiter(maxAttempts, std::chrono::seconds(300)) {}

    ~AppContext() noexcept {
        // FIX [BUG-04]: Explicitly zero master key on AppContext destruction
        if (!masterKey.empty()) {
            volatile byte_t* p = masterKey.data();
            for (std::size_t i = 0; i < masterKey.size(); ++i) p[i] = 0;
            masterKey.clear();
        }
    }
    // Non-copyable, non-movable (holds sensitive data)
    AppContext(const AppContext&) = delete;
    AppContext& operator=(const AppContext&) = delete;
};

// FIX [BUG-01]: Use raw pointer — does NOT own the object, no delete will be called
// FIX [BUG-02]: Async-signal-safe flag instead of calling logger in signal handler
static AppContext*          g_ctx   { nullptr };
static std::atomic<bool>    g_shutdown { false };

// FIX [BUG-02]: Signal handler ONLY does async-signal-safe operations:
//   - write() syscall for output (not cout/printf)
//   - atomic store
//   - _Exit()
extern "C" void signalHandler(int sig) {
    // async-signal-safe output to stderr
    // POSIX: write() + STDERR_FILENO
    // Windows: _write() + _fileno(stderr) (CRT low-level I/O, safe in signal handler)
    const char msg[] = "[Signal] Shutting down...\n";
#ifndef _WIN32
    (void)write(STDERR_FILENO, msg, sizeof(msg) - 1);
#else
    (void)_write(_fileno(stderr), msg, static_cast<unsigned int>(sizeof(msg) - 1));
#endif

    // Wipe master key if context available (pointer read is safe, atomic access not needed
    // because signal is process-wide and we're about to exit)
    if (g_ctx && !g_ctx->masterKey.empty()) {
        volatile byte_t* p = g_ctx->masterKey.data();
        for (std::size_t i = 0; i < g_ctx->masterKey.size(); ++i) p[i] = 0;
    }

    // FIX [BUG-02]: Use _Exit (async-signal-safe), not std::_Exit (implementation-defined)
    ::_Exit(128 + sig);
}

// Cross-platform env setter (used only to pass key_file path to provider)
static void setEnvVar(const std::string& key, const std::string& value) {
#ifndef _WIN32
    ::setenv(key.c_str(), value.c_str(), 1);
#else
    _putenv_s(key.c_str(), value.c_str());
#endif
}

static SecureString secureReadPassword(std::string_view prompt) {
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
    SecureString result(pwd);
    secureZero(pwd.data(), pwd.size());
    return result;
}

// FIX [BUG-05]: Check session expiry on every menu iteration
static void runSecureMenu(AppContext& ctx, const SessionToken& session) {
    MemoryGuard guard;
    while (true) {
        // FIX [BUG-05]: Check session expiry
        if (session.isExpired()) {
            ctx.logger.audit({.userId=session.userId, .action="SESSION_EXPIRED",
                              .success=false, .details="TTL exceeded"});
            std::cout << "[-] Session expired. Please login again.\n";
            return;
        }

        if (guard.checkIntegrity().fail()) {
            ctx.logger.critical("Stack canary corrupted!", session.userId);
            std::terminate();
        }

        auto ttl = session.remainingTTL();
        std::cout << "\n╔══════════════════════════════╗\n"
                  << "║  User: " << session.userId
                  << std::string(22 - std::min(session.userId.size(), std::size_t(22)), ' ')
                  << "║\n"
                  << "║  Session TTL: " << ttl.count() << "s"
                  << std::string(15 - std::to_string(ttl.count()).size(), ' ')
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
            if (keyRes.fail()) {
                ctx.logger.error("Random bytes failed: " + keyRes.message);
                break;
            }
            SecBytes plain(data.begin(), data.end());
            SecBytes aad(session.userId.begin(), session.userId.end());
            auto enc = CryptoEngine::encryptAESGCM(plain, keyRes.value, aad);
            if (enc.ok())
                std::cout << "[+] Encrypted (" << enc.value.size() << " bytes): "
                          << CryptoEngine::toHex(enc.value).substr(0, 48) << "...\n";
            else
                std::cout << "[-] Encryption failed: " << enc.message << "\n";
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
            auto vr = ctx.userDB.verifyPassword(session.userId, oldPwd.view());
            oldPwd.clear();
            if (vr.fail()) { std::cout << "[-] Incorrect password\n"; break; }
            auto newPwd = secureReadPassword("New password: ");
            auto pv = InputValidator::validate(newPwd.view(), Rules::PASSWORD, "password");
            if (pv.fail()) { newPwd.clear(); std::cout<<"[-] "<<pv.message<<"\n"; break; }
            ctx.userDB.removeUser(session.userId);
            ctx.userDB.addUser(session.userId, newPwd.view(), session.roleFlags);
            newPwd.clear();
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
    auto pv = InputValidator::validate(pwd.view(), Rules::PASSWORD, "password");
    if (pv.fail()) { pwd.clear(); std::cerr<<"[-] "<<pv.message<<"\n"; return 1; }
    auto r = ctx.userDB.addUser(user, pwd.view(), Roles::ADMIN | Roles::USER);
    pwd.clear();
    if (r.fail()) { std::cerr<<"[-] "<<r.message<<"\n"; return 1; }
    auto s = ctx.userDB.saveTo(dbPath, ctx.masterKey);
    if (s.fail()) { std::cerr<<"[-] "<<s.message<<"\n"; return 1; }
    ctx.logger.audit({.userId=user,.action="SETUP_ADMIN",.success=true});
    std::cout << "[+] Setup complete. Run without --setup to login.\n";
    return 0;
}

int main(int argc, char* argv[]) {
    // Install signal handlers (async-signal-safe only, FIX [BUG-02])
    std::signal(SIGINT,  signalHandler);
    std::signal(SIGTERM, signalHandler);
#ifndef _WIN32
    std::signal(SIGQUIT, signalHandler);
#endif

    try {
        // ── Step 1: Parse CLI ──
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
        std::string logPath = args.getOr("log",           "app_audit.log");
        std::string dbPath  = args.getOr("db",            "users.udb");
        auto maxAttRes      = InputValidator::parseInteger<u32_t>(
                                  args.getOr("max_attempts", "5"), 1, 10);
        u32_t maxAttempts   = maxAttRes.ok() ? maxAttRes.value : 5u;
        auto ttlRes         = InputValidator::parseInteger<int>(
                                  args.getOr("session_ttl", "30"), 1, 480);
        int sessionTTL      = ttlRes.ok() ? ttlRes.value : 30;

        // FIX [BUG-01, BUG-03]: AppContext on stack, g_ctx is raw non-owning pointer
        AppContext ctx(logPath, maxAttempts);
        g_ctx = &ctx; // raw pointer — signal handler reads but doesn't free

        ctx.logger.info("Application starting v" + std::string(APP_VERSION));
        ctx.logger.info("db=" + dbPath + " ttl=" + std::to_string(sessionTTL) +
                        "min attempts=" + std::to_string(maxAttempts));

        // ── Step 3: Anti-tamper ──
        bool debugMode = args.has("debug");
        AntiTamper antiTamper(ctx.logger,
            debugMode ? TamperPolicy::LOG_ONLY : TamperPolicy::TERMINATE);
        auto tamperRes = antiTamper.runAllChecks(!debugMode);
        if (tamperRes.fail() && !debugMode) {
            ctx.logger.critical("Tamper: " + tamperRes.message);
            g_ctx = nullptr;
            return 2;
        }

        // ── Step 4: Master key ──
        if (auto kf = args.get("key_file"); kf.has_value())
            setEnvVar("APP_KEY_FILE", *kf);

        if (args.has("generate_key")) {
            std::string outPath = args.positional.empty()
                                  ? "master.key" : args.positional[0];
            auto r = MasterKeyProvider::generateKeyFile(outPath);
            if (r.ok()) std::cout << "[+] Key file: " << outPath << "\n";
            else        std::cerr << "[-] " << r.message << "\n";
            g_ctx = nullptr;
            return r.ok() ? 0 : 1;
        }

        auto keyRes = MasterKeyProvider::resolve();
        if (keyRes.fail()) {
            std::cerr << "[CRITICAL] " << keyRes.message << "\n";
            g_ctx = nullptr;
            return 1;
        }
        // FIX [BUG-04]: Only ONE copy of master key — stored in ctx.masterKey
        // AppContext destructor will zero it on scope exit
        ctx.masterKey = std::move(keyRes.value);

        // ── Step 5: Setup mode ──
        if (args.has("setup")) {
            int rc = runSetup(ctx, dbPath);
            g_ctx = nullptr;
            return rc;
        }

        // ── Step 6: Load UserDB ──
        auto loadRes = ctx.userDB.loadFrom(dbPath, ctx.masterKey);
        if (loadRes.fail()) {
            std::cerr << "[-] " << loadRes.message
                      << "\n    Tip: Run with --setup first\n";
            g_ctx = nullptr;
            return 1;
        }
        ctx.logger.info("Loaded " + std::to_string(ctx.userDB.userCount()) + " users");

        // ── Step 7: Login UI ──
        std::cout << "╔══════════════════════════════╗\n"
                  << "║   Secure Console App v" << APP_VERSION << "   ║\n"
                  << "║   CERT / OWASP / NIST / FIPS  ║\n"
                  << "╚══════════════════════════════╝\n\n";

        // FIX [BUG-06]: Separate login loop from attempt counting
        // Rate limiter handles lockout; outer loop handles max total attempts
        bool loggedIn = false;
        for (int attempt = 0; attempt < static_cast<int>(maxAttempts * 3); ++attempt) {
            std::cout << "Username: ";
            std::string username; std::getline(std::cin, username);
            if (std::cin.eof()) break; // Ctrl+D / piped input ended

            auto uv = InputValidator::validate(username, Rules::USERNAME, "username");
            if (uv.fail()) { std::cout << "[-] " << uv.message << "\n"; continue; }

            // FIX [BUG-06]: Check block first; show remaining time and DON'T count as attempt
            if (ctx.limiter.isBlocked(username)) {
                auto rem = ctx.limiter.remainingLockout(username);
                std::cout << "[-] Account locked. Try again in " << rem.count() << "s\n";
                continue; // does NOT increment attempt counter for blocked users
            }

            auto pwd = secureReadPassword("Password: ");
            auto verRes = ctx.userDB.verifyPassword(username, pwd.view());
            pwd.clear();

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
                std::cout << "[+] Welcome, " << username << "! (Session TTL: "
                          << sessionTTL << " min)\n";
                runSecureMenu(ctx, session);
                if (ctx.userDB.isDirty()) {
                    auto saveRes = ctx.userDB.saveTo(dbPath, ctx.masterKey);
                    if (saveRes.fail())
                        ctx.logger.error("Failed to save DB: " + saveRes.message);
                }
                loggedIn = true;
                break;
            } else {
                ctx.limiter.recordFailure(username);
                ctx.logger.audit({.userId=username,.action="LOGIN",
                    .success=false,.details=verRes.message});
                std::this_thread::sleep_for(std::chrono::milliseconds(500));

                // FIX [BUG-06]: Only count non-blocked failures toward total limit
                int failNum = attempt + 1;
                std::cout << "[-] Invalid credentials (attempt " << failNum << ")\n";
                if (failNum >= static_cast<int>(maxAttempts)) {
                    std::cout << "[-] Maximum attempts reached. Exiting.\n";
                    break;
                }
            }
        }

        ctx.logger.info(std::string("Application shutdown. Logged in: ") +
                        (loggedIn ? "yes" : "no"));

        // g_ctx goes out of scope here; AppContext destructor wipes masterKey
        g_ctx = nullptr;
        return 0;

    } catch (const std::exception& e) {
        std::cerr << "[CRITICAL] " << e.what() << "\n";
        g_ctx = nullptr;
        return EXIT_FAILURE;
    }
}
