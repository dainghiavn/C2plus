# 🔐 SecureConsoleApp — C++ Security Framework

<p align="center">
  <img src="https://img.shields.io/badge/version-1.2-blue?style=flat-square" alt="Version">
  <img src="https://img.shields.io/badge/C%2B%2B-17%2F20-00599C?style=flat-square&logo=c%2B%2B" alt="C++">
  <img src="https://img.shields.io/badge/OpenSSL-3.x-red?style=flat-square&logo=openssl" alt="OpenSSL">
  <img src="https://img.shields.io/badge/CMake-3.x-064F8C?style=flat-square&logo=cmake" alt="CMake">
  <img src="https://img.shields.io/badge/FIPS_140--3-Compliant-green?style=flat-square" alt="FIPS">
  <img src="https://img.shields.io/badge/license-MIT-lightgrey?style=flat-square" alt="License">
</p>

A production-ready C++ security framework providing **AES-256-GCM encryption**, **PBKDF2 password hashing**, **session management**, **memory protection**, and **anti-tamper mechanisms** — all aligned to enterprise security standards.

---

## 📋 Table of Contents

- [Security Standards](#-security-standards)
- [Project Structure](#-project-structure)
- [Build & Run](#-build--run)
- [Key Security Features](#-key-security-features)
- [Changelog — v1.2 Hotfixes](#-changelog--v12-hotfixes)

---

## 🛡️ Security Standards

This framework is designed to comply with the following standards:

| Standard | Coverage |
|---|---|
| **SEI CERT C++** | MEM03-C, MEM06-C, MSC41-C, MSC39-C, STR31-C, ENV01-C |
| **OWASP** | Input Validation, Password Storage, Secrets Management, ASVS, MASVS-R |
| **NIST SP 800-63B** | Authentication & session management |
| **NIST SP 800-132** | PBKDF2 key derivation |
| **NIST SP 800-38D** | AES-GCM authenticated encryption |
| **NIST SP 800-92** | Audit logging |
| **FIPS 140-3** | Cryptographic modules via OpenSSL 3.x |

---

## 📁 Project Structure

```text
SecureConsoleApp/
├── include/security/
│   ├── SecureCore.hpp          # SecureBuffer, SecureString (with SecureAllocator), Result<T>, Roles
│   ├── InputValidator.hpp      # Input validation, path sanitize, SQL injection detect
│   ├── AuthManager.hpp         # SessionToken, RateLimiter (with auto cleanup)
│   ├── CryptoEngine.hpp        # AES-256-GCM, PBKDF2, HMAC-SHA256, CSPRNG, safe fromHex
│   ├── SecureLogger.hpp        # Structured audit logging (NIST SP 800-92)
│   ├── MemoryGuard.hpp         # mlock/VirtualLock, SecureAllocator, MemoryGuard
│   ├── ConfigManager.hpp       # Encrypted config loader (size limit, permission check)
│   ├── AntiTamper.hpp          # Debugger detect, LD_PRELOAD check, file HMAC verify (chunked)
│   ├── UserDatabase.hpp        # Encrypted credential store with header, temp file, version check
│   └── MasterKeyProvider.hpp   # ENV var / key file only (no unsafe interactive prompt)
├── src/
│   └── main.cpp                # Application entry point (signal handler, SecureString)
└── CMakeLists.txt              # Build with security flags (ASLR, DEP, CFG, ASAN)
```

---

## 🚀 Build & Run

### Prerequisites

```bash
# Ubuntu/Debian
sudo apt install cmake libssl-dev

# macOS
brew install cmake openssl@3
```

### Build

```bash
cd SecureConsoleApp
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

### First-time Setup

```bash
# Generate a master key file (32 random bytes) — recommended for production
./build/SecureConsoleApp --generate-key /path/to/master.key
export APP_KEY_FILE=/path/to/master.key

# Create initial admin account
./build/SecureConsoleApp --setup
```

### Run

```bash
./build/SecureConsoleApp
```

### Debug Mode

> ⚠️ Disables anti-tamper checks. **Do not use in production.**

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build
./build/SecureConsoleApp --debug
```

---

## 🔑 Key Security Features

| Feature | Implementation | Standard |
|---|---|---|
| **Memory wipe** | Volatile write on destruct + `SecureAllocator` clears entire capacity | SEI CERT MEM03-C |
| **Memory lock** | `mlock` / `VirtualLock` | SEI CERT MEM06-C |
| **Password hash** | PBKDF2-SHA256, 600K iterations | OWASP / NIST SP 800-132 |
| **Encryption** | AES-256-GCM with AAD | FIPS 140-3 / NIST SP 800-38D |
| **Auth token** | Session token with expiration | NIST SP 800-63B |
| **Rate limiting** | 5 attempts / 5 min lockout, auto‑cleanup of expired entries | NIST SP 800-63B §5.2.2 |
| **Input validation** | Whitelist regex, null‑byte, path traversal, basic SQLi detection | OWASP IVS |
| **Audit logging** | Structured JSON‑like events, thread‑safe | NIST SP 800-92 |
| **Anti‑debug** | `ptrace` / `IsDebuggerPresent`, `LD_PRELOAD` check | OWASP MASVS-R |
| **Anti‑tamper** | Chunked HMAC file integrity | — |
| **No hardcoded secrets** | Master key from env or key file only (no interactive fallback) | OWASP Secrets Mgmt CS |
| **Secure CLI parsing** | Supports `--opt=val` and `--opt val`, conflict detection, path validation | SEI CERT ENV01-C |
| **User database** | Encrypted with header, magic, version, temp‑file rename | — |
| **Signal handling** | Graceful shutdown with memory wipe on `SIGINT`/`SIGTERM` | — |

---

## 📝 Changelog — v1.2 Hotfixes

- **`MasterKeyProvider`** — Removed unsafe interactive password prompt; now strictly uses environment variable or key file.
- **`SecureString`** — Now backed by `SecureAllocator` to wipe entire allocated memory (including capacity), not just `size()`.
- **`UserDatabase`** — Added file header (magic + version); writes to a temporary file then renames to prevent corruption.
- **`AntiTamper`** — File HMAC now computed incrementally (chunked) to avoid loading large files into memory.
- **`CliParser`** — Now accepts both `--option value` and `--option=value` syntax.
- **`RateLimiter`** — Automatically cleans up expired lockout entries.
- **`ConfigManager`** — Enforces a maximum file size (16 MB) to prevent DoS.
- **`CryptoEngine`** — Fixed `fromHex` to avoid exceptions; added `RAND_status` check.
- **`main.cpp`** — Added signal handlers to wipe master key on termination; uses `SecureString` for passwords.

---

<p align="center">
  Built with ❤️ for secure C++ development
</p>
