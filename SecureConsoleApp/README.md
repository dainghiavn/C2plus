# 🔐 SecureConsoleApp — C++ Security Framework

<p align="center">
  <img src="https://img.shields.io/badge/version-1.3-blue?style=flat-square" alt="Version">
  <img src="https://img.shields.io/badge/C%2B%2B-20-00599C?style=flat-square&logo=c%2B%2B" alt="C++">
  <img src="https://img.shields.io/badge/OpenSSL-3.x-red?style=flat-square" alt="OpenSSL">
  <img src="https://img.shields.io/badge/CMake-3.20+-064F8C?style=flat-square" alt="CMake">
  <img src="https://img.shields.io/badge/FIPS_140--3-Compliant-green?style=flat-square" alt="FIPS">
  <img src="https://img.shields.io/badge/Bugs_Fixed-18-orange?style=flat-square" alt="Bugs Fixed">
</p>

A production-ready C++ security framework — v1.3 hotfix release.

---

## 📋 Table of Contents

- [Hotfixes v1.3 — 18 Bugs Fixed](#-hotfixes-v13--18-bugs-fixed)
- [New Features v1.3](#-new-features-v13)
- [Project Structure](#-project-structure)
- [Security Standards](#-security-standards)
- [Build & Run](#-build--run)
- [Key Security Features](#-key-security-features)

---

## 🔥 Hotfixes v1.3 — 18 Bugs Fixed

### 🔴 CRITICAL (7)

| ID | File | Bug | Fix |
|---|---|---|---|
| BUG-01 | main.cpp | `g_ctx.reset(&ctx)` — `unique_ptr` on stack variable → double-free / UB | Changed to raw non-owning pointer |
| BUG-02 | main.cpp | Signal handler calls `mutex::lock`, `cout`, `std::string` — not async-signal-safe | Replaced with `write()` syscall + `sig_atomic_t` |
| BUG-03 | main.cpp | `AppContext` used as incomplete type in `unique_ptr` before definition | Moved `AppContext` definition before globals |
| BUG-07 | CliParser.hpp | `_` char rejected in `parseLong()` option validation → `--session_ttl` always fails | Added `c != '_'` to validation whitelist |
| BUG-08 | CliParser.hpp | Default values trigger conflict checks → `--generate-key` always conflicts with `--db` | Track `explicitlySet` args; conflicts only checked against user-supplied args |
| BUG-14 | AntiTamper.hpp | `HMAC_Init_ex` called with `EVP_MD_CTX*` instead of `HMAC_CTX*` → wrong type / crash | Switched to `EVP_MAC` API (OpenSSL 3.x) with `HMAC_CTX` fallback for 1.x |
| BUG-15 | MasterKeyProvider.hpp | `EVP_DecodeBlock(nullptr, ...)` → segfault (nullptr output not supported) | Pre-allocate buffer, pass to EVP_DecodeBlock correctly |

### 🟠 HIGH (5)

| ID | File | Bug | Fix |
|---|---|---|---|
| BUG-04 | main.cpp | Two copies of master key in memory (`ctx.masterKey` + `g_masterKeyCopy`) | Single copy in `AppContext`; destructor explicitly zeros it |
| BUG-05 | main.cpp | Session expiry never checked in `runSecureMenu()` | Added `session.isExpired()` check at top of every loop iteration |
| BUG-10 | UserDatabase.hpp | `(header[i] << (i*8))` — signed int shift → UB (CERT INT34-C) | Cast to `uint32_t` / `uint16_t` before shifting |
| BUG-12 | CryptoEngine.hpp | EVP encrypt/decrypt return values all unchecked — silent corruption | Added `!= 1` checks with error propagation on every EVP call |
| BUG-16 | AuthManager.hpp | `cleanup()` only removes locked+expired entries — unfailed attempts leak memory | Cleanup also removes entries older than `attemptWindow_` |

### 🟡 MEDIUM (6)

| ID | File | Bug | Fix |
|---|---|---|---|
| BUG-06 | main.cpp | Login loop `continue` increments attempt counter for blocked users | Restructured: blocked users skip without counting toward attempt limit |
| BUG-09 | CliParser.hpp | `ValueKind::INTEGER` defined but never handled in `validatePaths()` | Added INTEGER case with range validation |
| BUG-11 | UserDatabase.hpp | `dirty_` cleared before confirming rename success | `dirty_` only cleared after successful atomic rename |
| BUG-13 | CryptoEngine.hpp | Raw `EVP_MD_CTX*` in `sha256()` — leaked on exception | Converted to `unique_ptr<EVP_MD_CTX>` |
| BUG-17 | SecureLogger.hpp | `std::gmtime()` not thread-safe — data race on timestamp | Replaced with `gmtime_r()` (POSIX) / `gmtime_s()` (Windows) |
| BUG-18 | SecureLogger.hpp | User-controlled data written directly to log → log injection via `\n` | Added `sanitize()` function: escapes `\n`, `\r`, `\0`, control chars |

---

## ✨ New Features v1.3

### 1. `SecureTOTP.hpp` — Two-Factor Authentication (RFC 6238)
```cpp
// Generate TOTP secret
auto secret = SecureTOTP::generateSecret();

// Get otpauth:// URI for QR code display
std::string uri = SecureTOTP::buildOtpAuthUri("MyApp", "user@host", secret.value);

// Verify user input
auto ok = SecureTOTP::verify(userCode, secret.value);
```
- Full RFC 6238 / RFC 4226 compliance
- ±1 window tolerance (90-second grace period)  
- Compatible with Google Authenticator, Authy, 1Password
- Constant-time OTP comparison (prevents timing attacks)
- Base32 encoding + manual entry formatting

---

### 2. `ConsoleCommandRegistry.hpp` — REPL Command Framework
```cpp
CommandRegistry reg(ctx.logger, session);
reg.addBuiltins();  // adds: help, whoami, history, exit

reg.add({ .name         = "encrypt",
          .description  = "Encrypt a message",
          .requiredRole = Roles::USER,
          .handler      = [&](const CmdArgs& args) -> CmdResult {
              // ... do encryption ...
              return CmdResult::Ok("Encrypted: " + result);
          }
});
reg.runLoop();
```
- Role-based access per command
- Auto-generated help (`help` / `?`)
- Alias support (`quit,exit,q`)
- Typo suggestion (Levenshtein distance ≤ 2)
- Session expiry check on every input
- Quoted string tokenization
- Command history (last 100, redacted)

---

### 3. `SignedAuditLog.hpp` — HMAC-Chained Tamper-Evident Log
```cpp
SignedAuditLog auditLog("audit.log", auditKey);
auditLog.log("admin", "USER_CREATED", true, "username=bob");

// Verify integrity of entire log file
auto r = SignedAuditLog::verify("audit.log", auditKey);
if (r.fail()) std::cerr << "TAMPER DETECTED: " << r.message << "\n";

// Human-readable print
SignedAuditLog::printLog("audit.log");
```
- Each entry HMAC-signed with chain of previous entry
- Any modification/deletion/insertion → detected  
- Survives process restarts (loads last hash from file)
- PCI-DSS Requirement 10 compliant

---

### 4. `PrivilegeDrop.hpp` — Least Privilege / Hardening
```cpp
// Drop root after initialization
auto r = PrivilegeDrop::drop("appuser", "appgroup");

// Set resource limits (disable core dumps, limit fd count)
PrivilegeDrop::harden();

// Optionally chroot to a sandbox directory
PrivilegeDrop::chroot("/var/app/sandbox");
```
- Drop UID/GID after setup phase (CERT POS02-C)
- Verify re-escalation to root is impossible
- `setrlimit`: no core dumps, limited file descriptors
- `umask(0077)`: owner-only file permissions by default

---

### 5. `SecureKeyDerivation.hpp` — HKDF Key Derivation (RFC 5869)
```cpp
// Derive purpose-specific keys from one master key
auto bundle = KeyDerivation::deriveAll(masterKey);
// bundle.dbEncryptionKey  → for UserDatabase
// bundle.auditHmacKey     → for SignedAuditLog
// bundle.totpStorageKey   → for TOTP secret storage
// bundle.configEncryptKey → for ConfigManager
// bundle.sessionHmacKey   → for session tokens

// Or derive a single key
auto key = KeyDerivation::deriveKey(masterKey, "my-context-v1");
```
- Uses HKDF (OpenSSL 3.x EVP_KDF) with SHA-256
- Domain separation prevents key reuse attacks
- NIST SP 800-108 compliant

---

## 📁 Project Structure

```text
SecureConsoleApp/
├── include/security/
│   ├── SecureCore.hpp             # SecureBuffer, SecureString, Result<T>, Roles
│   ├── InputValidator.hpp         # Input validation, sanitize, SQLi detection
│   ├── AuthManager.hpp            # SessionToken, RateLimiter (fixed cleanup)
│   ├── CryptoEngine.hpp           # AES-256-GCM (all EVP checked), PBKDF2, HMAC
│   ├── SecureLogger.hpp           # Thread-safe logger, log injection prevention
│   ├── MemoryGuard.hpp            # mlock, SecureAllocator, canary
│   ├── ConfigManager.hpp          # Encrypted config, permission check
│   ├── AntiTamper.hpp             # Debugger detect, EVP_MAC HMAC (fixed)
│   ├── UserDatabase.hpp           # Encrypted UserDB (fixed bit-shift UB)
│   ├── MasterKeyProvider.hpp      # Env/file key (fixed base64 decode)
│   ├── CliParser.hpp              # CLI parser (fixed _ validation + conflicts)
│   │
│   ├── SecureTOTP.hpp             # [NEW] TOTP 2FA (RFC 6238)
│   ├── ConsoleCommandRegistry.hpp # [NEW] REPL command framework
│   ├── SignedAuditLog.hpp         # [NEW] HMAC-chained tamper-evident log
│   ├── PrivilegeDrop.hpp          # [NEW] Privilege drop, resource limits
│   └── SecureKeyDerivation.hpp    # [NEW] HKDF key derivation (RFC 5869)
└── src/
    └── main.cpp                   # Fixed: signal handler, session expiry, etc.
```

---

## 🛡️ Security Standards

| Standard | Coverage |
|---|---|
| **SEI CERT C++** | MEM03-C, MEM06-C, MSC41-C, MSC39-C, STR31-C, ENV01-C, INT34-C, POS02-C |
| **OWASP** | Input Validation, Password Storage, Secrets Mgmt, MFA CS, ASVS, MASVS-R |
| **NIST SP 800-63B** | Authentication, Session management, 2FA |
| **NIST SP 800-132** | PBKDF2 key derivation |
| **NIST SP 800-38D** | AES-GCM authenticated encryption |
| **NIST SP 800-92** | Audit logging |
| **NIST SP 800-108** | HKDF key derivation |
| **FIPS 140-3** | Via OpenSSL 3.x |
| **RFC 6238 / 4226** | TOTP / HOTP |
| **RFC 5869** | HKDF |
| **PCI-DSS Req 10** | Tamper-evident audit log |

---

## 🚀 Build & Run

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build

# Generate master key
./build/SecureConsoleApp --generate-key /secure/master.key
export APP_KEY_FILE=/secure/master.key

# First-time setup
./build/SecureConsoleApp --setup

# Run
./build/SecureConsoleApp
```

---

## 🔑 Key Security Features

| Feature | Implementation | Standard |
|---|---|---|
| **Memory wipe** | Volatile + `SecureAllocator` | CERT MEM03-C |
| **Memory lock** | `mlock` / `VirtualLock` | CERT MEM06-C |
| **Password hash** | PBKDF2-SHA256, 600K iter | OWASP / NIST SP 800-132 |
| **Encryption** | AES-256-GCM, all EVP checked | FIPS / NIST SP 800-38D |
| **2FA** | TOTP (RFC 6238), HMAC-SHA1 | NIST SP 800-63B |
| **Key separation** | HKDF domain separation | NIST SP 800-108 |
| **Audit integrity** | HMAC-chained log | PCI-DSS Req 10 |
| **Privilege drop** | setuid/setgid + verify | CERT POS02-C |
| **Session expiry** | Checked per menu action | NIST SP 800-63B |
| **Anti-debug** | ptrace + EVP_MAC (fixed) | OWASP MASVS-R |
| **Log injection** | `\n`/`\r`/control char sanitization | OWASP Logging CS |
| **CLI parsing** | `_` allowed, explicit-set conflicts | CERT ENV01-C |
