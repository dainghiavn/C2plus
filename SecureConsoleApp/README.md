# SecureConsoleApp — C++ Security Framework v1.0

## Chuẩn bảo mật tuân thủ
- **SEI CERT C++** (MEM03-C, MEM06-C, MSC41-C, MSC39-C, STR31-C)
- **OWASP** (Input Validation, Password Storage, Secrets Management, ASVS)
- **NIST SP 800-63B** (Authentication), **SP 800-132** (PBKDF2), **SP 800-38D** (AES-GCM)
- **FIPS 140-3** (Cryptographic modules via OpenSSL 3.x)

## Cấu trúc
```
SecureConsoleApp/
├── include/security/
│   ├── SecureCore.hpp          # SecureBuffer, SecureString, Result<T>, Roles
│   ├── InputValidator.hpp      # Input validation, path sanitize, SQL injection detect
│   ├── AuthManager.hpp         # SessionToken, RateLimiter
│   ├── CryptoEngine.hpp        # AES-256-GCM, PBKDF2, HMAC-SHA256, CSPRNG
│   ├── SecureLogger.hpp        # Structured audit logging (NIST SP 800-92)
│   ├── MemoryGuard.hpp         # mlock/VirtualLock, SecureAllocator, MemoryGuard
│   ├── ConfigManager.hpp       # Encrypted config loader
│   ├── AntiTamper.hpp          # Debugger detect, LD_PRELOAD check, file HMAC verify
│   ├── UserDatabase.hpp        # Encrypted credential store, no hardcoded passwords
│   └── MasterKeyProvider.hpp   # ENV var / key file / interactive key resolution
├── src/
│   └── main.cpp                # Complete application entry point
└── CMakeLists.txt              # Build with security flags (ASLR, DEP, CFG, ASAN)
```

## Build & Run

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

### First-time setup
```bash
# Optional: generate key file (recommended for production)
./build/SecureConsoleApp --generate-key /path/to/master.key
export APP_KEY_FILE=/path/to/master.key

# Create admin account
./build/SecureConsoleApp --setup
```

### Run
```bash
./build/SecureConsoleApp
```

### Debug mode (disable anti-tamper for development)
```bash
cmake -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build
./build/SecureConsoleApp --debug
```

## Key Security Features

| Feature | Implementation | Standard |
|---------|---------------|----------|
| Memory wipe | Volatile write on destruct | SEI CERT MEM03-C |
| Memory lock | mlock/VirtualLock | SEI CERT MEM06-C |
| Password hash | PBKDF2-SHA256, 600K iter | OWASP / NIST SP 800-132 |
| Encryption | AES-256-GCM | FIPS 140-3 / NIST SP 800-38D |
| Auth token | HMAC-signed, 30min TTL | NIST SP 800-63B |
| Rate limiting | 5 attempts / 5min lockout | NIST SP 800-63B §5.2.2 |
| Input validation | Whitelist regex + null-byte | OWASP IVS |
| Audit logging | Structured events | NIST SP 800-92 |
| Anti-debug | ptrace/IsDebuggerPresent | OWASP MASVS-R |
| No hardcoded secrets | ENV/file key resolution | OWASP Secrets Mgmt CS |
