# 🔐 SecureConsoleApp — C++ Security Framework

<p align="center">
  <img src="https://img.shields.io/badge/version-1.3-blue?style=flat-square" alt="Version">
  <img src="https://img.shields.io/badge/C%2B%2B-20-00599C?style=flat-square&logo=c%2B%2B" alt="C++">
  <img src="https://img.shields.io/badge/OpenSSL-3.x-red?style=flat-square" alt="OpenSSL">
  <img src="https://img.shields.io/badge/CMake-3.20+-064F8C?style=flat-square" alt="CMake">
  <img src="https://img.shields.io/badge/FIPS_140--3-Compliant-green?style=flat-square" alt="FIPS">
  <img src="https://img.shields.io/badge/Bugs_Fixed-20-orange?style=flat-square" alt="Bugs Fixed">
</p>

A production-ready C++ security framework providing **AES-256-GCM encryption**, **PBKDF2 password hashing**, **TOTP 2FA**, **session management**, **memory protection**, **privilege dropping**, and **anti-tamper mechanisms** — aligned to enterprise security standards (SEI CERT, OWASP, NIST, FIPS 140-3).

---

## 📋 Table of Contents

- [Security Standards](#-security-standards)
- [Project Structure](#-project-structure)
- [Build & Run](#-build--run)
- [Key Security Features](#-key-security-features)
- [Hotfixes v1.3 — 18 Bugs Fixed](#-hotfixes-v13--18-bugs-fixed)
- [New Features v1.3](#-new-features-v13)
- [Audit Round 2 — 4 Core Files](#-audit-round-2--4-core-files)

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

## 📁 Project Structure

```text
SecureConsoleApp/
├── include/security/
│   ├── SecureCore.hpp               # [AUDITED] byte_t, SecBytes, SecureString, Result<T>, Roles
│   ├── InputValidator.hpp           # [AUDITED] Validation, sanitize, SQLi/path check, parseInteger<T>
│   ├── AuthManager.hpp              # SessionToken, RateLimiter
│   ├── CryptoEngine.hpp             # AES-256-GCM, PBKDF2, HMAC-SHA256, CSPRNG
│   ├── SecureLogger.hpp             # Thread-safe structured audit logger
│   ├── MemoryGuard.hpp              # [AUDITED] mlock/VirtualLock, SecureAllocator, stack canary
│   ├── ConfigManager.hpp            # [AUDITED] AES-GCM encrypted config, HMAC verification
│   ├── AntiTamper.hpp               # Debugger detect, LD_PRELOAD check, file HMAC
│   ├── UserDatabase.hpp             # Encrypted credential store
│   ├── MasterKeyProvider.hpp        # Env/key-file based master key resolution
│   ├── CliParser.hpp                # Secure CLI argument parser
│   │
│   ├── SecureTOTP.hpp               # [NEW] TOTP 2FA — RFC 6238
│   ├── ConsoleCommandRegistry.hpp   # [NEW] REPL command framework
│   ├── SignedAuditLog.hpp           # [NEW] HMAC-chained tamper-evident log
│   ├── PrivilegeDrop.hpp            # [NEW] Privilege drop, resource limits
│   └── SecureKeyDerivation.hpp      # [NEW] HKDF key derivation — RFC 5869
└── src/
    └── main.cpp                     # Application entry point
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
./build/SecureConsoleApp --generate-key /secure/master.key
export APP_KEY_FILE=/secure/master.key
./build/SecureConsoleApp --setup
```

### Run

```bash
./build/SecureConsoleApp
```

### Debug Mode

> ⚠️ Disables anti-tamper. **Do not use in production.**

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Debug
./build/SecureConsoleApp --debug
```

---

## 🔑 Key Security Features

| Feature | Implementation | Standard |
|---|---|---|
| **Memory wipe** | Volatile write + `SecureAllocator` on destruct | CERT MEM03-C |
| **Memory lock** | `mlock` / `VirtualLock` | CERT MEM06-C |
| **Password hash** | PBKDF2-SHA256, 600K iterations | OWASP / NIST SP 800-132 |
| **Encryption** | AES-256-GCM, all EVP return values checked | FIPS 140-3 / NIST SP 800-38D |
| **2FA** | TOTP RFC 6238, constant-time verify | NIST SP 800-63B |
| **Key separation** | HKDF domain separation per purpose | NIST SP 800-108 / RFC 5869 |
| **Audit integrity** | HMAC-chained tamper-evident log | PCI-DSS Requirement 10 |
| **Privilege drop** | `setuid`/`setgid` + re-escalation verify | CERT POS02-C / CWE-250 |
| **Session expiry** | Checked on every menu/command action | NIST SP 800-63B |
| **Rate limiting** | 5 attempts / 5 min lockout, auto-cleanup | NIST SP 800-63B §5.2.2 |
| **Input validation** | Whitelist regex, null-byte, SQLi detect | OWASP IVS |
| **Anti-debug** | `ptrace`, `IsDebuggerPresent`, `LD_PRELOAD` | OWASP MASVS-R |
| **Anti-tamper** | Chunked HMAC file integrity via `EVP_MAC` | — |
| **Log injection** | Sanitize `\n` `\r` `\0` and control chars | OWASP Logging CS |
| **CLI parsing** | `--opt=val` and `--opt val`, explicit conflict detection | CERT ENV01-C |
| **Signal handling** | Async-signal-safe only (`write()` + `_Exit`) | POSIX |
| **No hardcoded secrets** | Master key from env or key file only | OWASP Secrets Mgmt CS |
| **Config encryption** | AES-256-GCM + HMAC-SHA256 on config file | OWASP ASVS V14.4 |
| **Typed validation** | `parseInteger<T>` via `std::from_chars`, no UB | CERT INT34-C |
| **Path traversal** | `isValidPath()` blocks `..`, NUL byte, shell metacharacters | OWASP A01 |
| **Locked allocator** | `LockedAllocator<T>` pins pages to RAM immediately on alloc | CERT MEM06-C |

---

## 🔥 Hotfixes v1.3 — 18 Bugs Fixed

### 🔴 Critical (7)

| ID | File | Bug Description | Root Cause |
|---|---|---|---|
| BUG-01 | `main.cpp` | `unique_ptr::reset()` trên stack variable → double-free / UB khi có exception | `g_ctx` không được own stack object |
| BUG-02 | `main.cpp` | Signal handler gọi `mutex::lock`, `cout`, `std::string` → deadlock / UB | Chỉ được dùng async-signal-safe functions trong signal handler |
| BUG-03 | `main.cpp` | `AppContext` dùng trong global trước khi được define → compile/link error | Sai thứ tự khai báo trong file |
| BUG-07 | `CliParser.hpp` | Ký tự `_` bị reject trong validation option name → `--session_ttl` luôn báo lỗi | Whitelist chỉ chấp nhận `-` mà thiếu `_` |
| BUG-08 | `CliParser.hpp` | Default values kích hoạt conflict rules → `--generate-key` luôn conflict với `--db` | Conflict check không phân biệt default value vs user-supplied value |
| BUG-14 | `AntiTamper.hpp` | `HMAC_Init_ex()` nhận `EVP_MD_CTX*` thay vì `HMAC_CTX*` → type mismatch / crash | Dùng sai context type; API bị deprecated trong OpenSSL 3.x |
| BUG-15 | `MasterKeyProvider.hpp` | `EVP_DecodeBlock(nullptr, ...)` → segfault | `EVP_DecodeBlock` không nhận `nullptr` làm output buffer |

### 🟠 High (5)

| ID | File | Bug Description | Root Cause |
|---|---|---|---|
| BUG-04 | `main.cpp` | Hai bản sao master key tồn tại song song trong RAM | `g_masterKeyCopy` dư thừa; chỉ một trong hai được zero khi thoát |
| BUG-05 | `main.cpp` | Session TTL không bao giờ được kiểm tra trong `runSecureMenu()` | Thiếu `session.isExpired()` check trong vòng lặp menu |
| BUG-10 | `UserDatabase.hpp` | `(header[i] << (i*8))` với signed `int` → Undefined Behavior (CERT INT34-C) | `uint8_t` được promote lên `int` trước khi shift; phải cast sang `uint32_t` trước |
| BUG-12 | `CryptoEngine.hpp` | Tất cả `EVP_Encrypt*` / `EVP_Decrypt*` không kiểm tra return value → dữ liệu lỗi im lặng | Thiếu kiểm tra `!= 1` trên mọi lời gọi OpenSSL EVP |
| BUG-16 | `AuthManager.hpp` | `cleanup()` không xóa entries có `count < maxAttempts` → memory leak không giới hạn | Chỉ xóa locked+expired entries; partial-failure entries tích lũy mãi |

### 🟡 Medium (6)

| ID | File | Bug Description | Root Cause |
|---|---|---|---|
| BUG-06 | `main.cpp` | `continue` khi bị block vẫn tăng biến đếm attempt → loop kết thúc sớm sai | Rate-limiter block và attempt counter dùng chung một vòng lặp |
| BUG-09 | `CliParser.hpp` | `ValueKind::INTEGER` được khai báo nhưng không có case xử lý trong `validatePaths()` | Dead code — thiếu nhánh `case` tương ứng |
| BUG-11 | `UserDatabase.hpp` | `dirty_` được clear trước khi xác nhận rename thành công | Reset flag quá sớm; nếu rename lỗi thì trạng thái không nhất quán |
| BUG-13 | `CryptoEngine.hpp` | Raw `EVP_MD_CTX*` trong `sha256()` bị leak khi có exception | Thiếu `unique_ptr` wrapper cho raw pointer |
| BUG-17 | `SecureLogger.hpp` | `std::gmtime()` trả về static pointer → data race trong môi trường đa luồng | Phải dùng `gmtime_r()` (POSIX) / `gmtime_s()` (Windows) |
| BUG-18 | `SecureLogger.hpp` | User-controlled data ghi thẳng vào log → log injection qua ký tự `\n`, `\r` | Thiếu sanitization trước khi ghi vào file |

---

## ✨ New Features v1.3

### 1. `SecureTOTP.hpp` — Two-Factor Authentication (RFC 6238)
Triển khai đầy đủ TOTP (RFC 6238) và HOTP (RFC 4226), tương thích với Google Authenticator, Authy, 1Password. Tạo `otpauth://` URI để hiển thị QR code, cung cấp Base32 secret cho nhập tay, xác minh OTP bằng constant-time comparison để chống timing attack, hỗ trợ dung sai ±1 window (90 giây).

### 2. `ConsoleCommandRegistry.hpp` — REPL Command Framework
Registry và run-loop để xây dựng console application dạng lệnh có cấu trúc. Mỗi command khai báo `requiredRole`; truy cập trái phép bị từ chối và ghi audit log. Tích hợp sẵn các lệnh `help`, `whoami`, `history`, `exit`. Hỗ trợ gợi ý lệnh khi gõ sai (Levenshtein distance ≤ 2), alias, quoted-string tokenization, và kiểm tra session expiry trên mỗi lần nhập.

### 3. `SignedAuditLog.hpp` — HMAC-Chained Tamper-Evident Log
Mỗi entry được ký bằng `HMAC-SHA256(entry_data || prev_hmac, key)` tạo thành một hash chain. Bất kỳ sửa đổi, xóa, hay chèn entry nào vào quá khứ đều bị phát hiện bởi `verify()`. Chain được khôi phục khi khởi động lại process bằng cách đọc HMAC cuối cùng từ file. Thiết kế đáp ứng PCI-DSS Requirement 10.

### 4. `PrivilegeDrop.hpp` — Least Privilege Hardening
Cung cấp `drop(user, group)` để shed root privileges sau giai đoạn khởi tạo, kèm bước xác minh không thể re-escalate (CERT POS02-C). Đặt `RLIMIT_CORE=0` để vô hiệu hóa core dump (tránh lộ key), giới hạn số file descriptor, và áp dụng `umask(0077)` để mọi file tạo ra mặc định chỉ owner được đọc/ghi.

### 5. `SecureKeyDerivation.hpp` — HKDF Domain-Separated Keys (RFC 5869)
Dùng HKDF (`EVP_KDF` API của OpenSSL 3.x, với fallback RFC 5869 thuần HMAC cho OpenSSL 1.x) để derive các key độc lập có mục đích riêng từ một master key duy nhất. `deriveAll()` trả về `KeyBundle` gồm key riêng cho: database encryption, audit HMAC, TOTP storage, config encryption, session HMAC — loại bỏ hoàn toàn key reuse giữa các subsystem.

---

---

## 🔍 Audit Round 2 — 4 Core Files

Phiên audit thứ hai hoàn thành toàn bộ phủ sóng project bằng cách viết và kiểm tra 4 file core vốn bị thiếu.

### Files được viết mới hoàn toàn

| File | Dòng | Nội dung chính |
|---|---|---|
| `SecureCore.hpp` | 247 | `byte_t`, `u32_t`, `SecureAllocator<T>`, `SecBytes`, `SecureString`, `SecurityStatus`, `Result<T>`, `Result<void>`, `Roles::` namespace |
| `InputValidator.hpp` | 354 | `ValidationRule`, `Rules::USERNAME/PASSWORD/TEXT/FILE_PATH`, `validate()`, `parseInteger<T>`, `sanitize()`, `detectSQLi()`, `isValidPath()` |
| `MemoryGuard.hpp` | 228 | `lockMemory()`, `unlockMemory()`, `MemoryGuard` RAII (stack canary), `LockedAllocator<T>`, `LockedBytes` |
| `ConfigManager.hpp` | 337 | `set()`, `get()`, `getOr()`, `saveTo()`, `loadFrom()`, HMAC verify, AES-GCM decrypt, constant-time compare |

### BUG-19 — ConfigManager: `validateKey()` throw thay vì `Result<>`

File: `ConfigManager.hpp` — Severity: **Medium**

`validateKey()` dùng `throw std::invalid_argument` không nhất quán với error model `Result<>` của toàn framework. Trong các security path, exception có thể bị catch nhầm hoặc bị suppress bởi `noexcept` context, gây mất thông báo lỗi.

Fix: `validateKey()` đổi signature thành `Result<void>`, `set()` đổi thành `[[nodiscard]] Result<void>`. Xóa `#include <stdexcept>` vì không còn dùng exception. (CERT ERR50-CPP)

### BUG-20 — Duplicate `sanitize()` — 3 phiên bản mâu thuẫn

Files: `SecureLogger.hpp`, `SignedAuditLog.hpp`, `InputValidator.hpp` — Severity: **Medium**

Ba class tự định nghĩa riêng `sanitize()` với logic khác nhau. `SecureLogger` thay control chars bằng `?`, `SignedAuditLog` HTML-escape pipe nhưng bỏ qua các byte < 0x20, `InputValidator` escape đúng chuẩn sang `\xHH`. Sự không nhất quán tạo ra lỗ hổng log injection tùy theo code path được gọi.

Fix: `SecureLogger` và `SignedAuditLog` đều delegate về `InputValidator::sanitize()` — một implementation duy nhất, đúng chuẩn. `SignedAuditLog` bổ sung thêm bước escape pipe (`|` → `&#124;`) sau khi sanitize xong.

### Tổng kết phủ sóng

| Hạng mục | Kết quả |
|---|---|
| Tổng file được audit | 16 / 16 ✅ |
| Tổng bug đã fix | 20 (18 round 1 + 2 round 2) ✅ |
| File mới (features) | 5 ✅ |
| File mới (core, round 2) | 4 ✅ |
| Cross-platform Windows patches | 3 ✅ |
| CMakeLists.txt issues | 7 ✅ |

<p align="center">
  Built with ❤️ for secure C++ development — v1.3
</p>
