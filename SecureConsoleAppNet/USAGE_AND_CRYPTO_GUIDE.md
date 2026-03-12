# 📘 SecureConsoleApp — Hướng Dẫn Sử Dụng & Tài Liệu Mã Hoá

---

## 📋 Mục Lục

1. [Cách Sử Dụng Dự Án](#1-cách-sử-dụng-dự-án)
2. [Kiến Trúc Crypto Pipeline](#2-kiến-trúc-crypto-pipeline)
3. [Các Phương Pháp Mã Hoá](#3-các-phương-pháp-mã-hoá)
4. [Cơ Chế Salt](#4-cơ-chế-salt)
5. [Quản Lý Master Key (Private Key)](#5-quản-lý-master-key-private-key)
6. [Key Derivation — HKDF](#6-key-derivation--hkdf)
7. [Luồng Dữ Liệu Mã Hoá Tổng Quan](#7-luồng-dữ-liệu-mã-hoá-tổng-quan)
8. [Câu Hỏi Thường Gặp](#8-câu-hỏi-thường-gặp)

---

## 1. Cách Sử Dụng Dự Án

### 1.1 Cài Đặt Dependencies

```bash
# Ubuntu / Debian
sudo apt install cmake libssl-dev build-essential

# macOS
brew install cmake openssl@3

# Windows (vcpkg)
vcpkg install openssl:x64-windows
```

### 1.2 Build

```bash
git clone <repo>
cd SecureConsoleApp

# Release build (production)
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)

# Debug build (có AddressSanitizer + UBSan, KHÔNG dùng production)
cmake -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build
```

### 1.3 Khởi Tạo Lần Đầu (First-Run)

**Bước 1 — Tạo Master Key:**
```bash
./build/SecureConsoleApp --generate-key /secure/master.key
# Tạo ra file 32-byte ngẫu nhiên (AES-256 key)
# Permissions tự động được set 400 (owner read-only)
```

**Bước 2 — Cung cấp Master Key cho app (chọn 1 trong 2 cách):**
```bash
# Cách A: Qua environment variable (base64 encoded)
export APP_MASTER_KEY=$(base64 -w0 /secure/master.key)

# Cách B: Qua đường dẫn file (khuyên dùng)
export APP_KEY_FILE=/secure/master.key
```

**Bước 3 — Setup tài khoản admin:**
```bash
./build/SecureConsoleApp --setup
# → Nhập username admin
# → Nhập password (tối thiểu 12 ký tự, phải có HOA/thường/số/ký tự đặc biệt)
# → Tạo file users.udb (encrypted)
```

**Bước 4 — Chạy ứng dụng:**
```bash
./build/SecureConsoleApp
# Hoặc chỉ định rõ paths:
./build/SecureConsoleApp --db /data/users.udb --log /var/log/app.log --session-ttl 60
```

### 1.4 Tất Cả CLI Options

| Option | Short | Mặc định | Mô tả |
|---|---|---|---|
| `--setup` | `-s` | — | First-run: tạo admin account |
| `--generate-key [PATH]` | `-g` | `master.key` | Tạo master key file |
| `--key-file PATH` | `-k` | `APP_KEY_FILE` env | Đường dẫn tới master key file |
| `--db PATH` | — | `users.udb` | Đường dẫn database người dùng |
| `--log PATH` | `-l` | `app_audit.log` | Đường dẫn audit log |
| `--session-ttl N` | — | `30` | Session timeout (phút, 1–480) |
| `--max-attempts N` | — | `5` | Số lần login thất bại trước khi lock |
| `--debug` | `-d` | — | Tắt anti-tamper, bật verbose log |
| `--version` | `-v` | — | Hiển thị phiên bản |
| `--help` | `-h` | — | Hiển thị help |

### 1.5 Sử Dụng Trong Menu

Sau khi đăng nhập thành công, menu hiển thị theo role:

```
╔══════════════════════════════╗
║  User: alice                 ║
║  Session TTL: 1742s          ║
╠══════════════════════════════╣
║  1. Encrypt Data             ║
║  2. Admin Panel [ADMIN]      ║
║  3. Change Password          ║
║  0. Logout                   ║
╚══════════════════════════════╝
```

- **Option 1** — Mã hoá dữ liệu bằng AES-256-GCM với random key mỗi lần
- **Option 2** — Chỉ hiện với role ADMIN; xem số lượng users
- **Option 3** — Đổi mật khẩu (yêu cầu nhập mật khẩu cũ, validate policy mới)
- **Option 0** — Logout, lưu DB nếu có thay đổi

### 1.6 Tích Hợp ConsoleCommandRegistry (REPL mode)

Thay vì dùng menu số, bạn có thể xây dựng app console dạng lệnh:

```
Type 'help' for available commands, 'exit' to quit.
[alice]> encrypt "Hello World"
[alice]> whoami
[alice]> history
[alice]> exit
```

Đăng ký lệnh tùy chỉnh trong code của bạn bằng cách gọi `CommandRegistry::add()` với `CommandDef` chứa tên, role yêu cầu và handler function.

---

## 2. Kiến Trúc Crypto Pipeline

```
┌─────────────────────────────────────────────────────────┐
│                    MASTER KEY (32 bytes)                 │
│             (từ file hoặc APP_MASTER_KEY env)            │
└──────────────────────────┬──────────────────────────────┘
                           │ HKDF-SHA256
          ┌────────────────┼────────────────┐
          │                │                │
    ┌─────▼─────┐   ┌──────▼──────┐  ┌─────▼──────┐
    │  DB Key   │   │  Audit Key  │  │  TOTP Key  │  ...
    │ (AES-256) │   │ (HMAC-SHA256)│  │ (AES-256)  │
    └─────┬─────┘   └──────┬──────┘  └─────┬──────┘
          │                │                │
    ┌─────▼─────┐   ┌──────▼──────┐  ┌─────▼──────┐
    │ Encrypt   │   │  Sign each  │  │  Encrypt   │
    │ users.udb │   │  log entry  │  │  TOTP      │
    │ (AES-GCM) │   │  (chained)  │  │  secrets   │
    └───────────┘   └─────────────┘  └────────────┘

Password Storage (KHÔNG dùng master key):
┌──────────────┐
│   Password   │──PBKDF2-SHA256──► Hash (32 bytes)
│              │  600K iterations   stored in users.udb
│ Random Salt  │──────────────────► stored alongside hash
│  (32 bytes)  │
└──────────────┘
```

---

## 3. Các Phương Pháp Mã Hoá

### 3.1 AES-256-GCM — Mã Hoá Dữ Liệu Chính

**Dùng cho:** UserDatabase, ConfigManager, dữ liệu người dùng mã hoá trực tiếp.

| Tham số | Giá trị |
|---|---|
| Thuật toán | AES (Advanced Encryption Standard) |
| Độ dài key | 256-bit (32 bytes) |
| Chế độ | GCM (Galois/Counter Mode) |
| IV (Nonce) | 96-bit (12 bytes), random mỗi lần encrypt |
| Authentication Tag | 128-bit (16 bytes) |
| Padding | Không cần (GCM là stream cipher) |
| Chuẩn | NIST SP 800-38D, FIPS 140-3 |

**Cấu trúc output blob:**

```
┌─────────────┬─────────────┬─────────────────────┐
│  IV (12B)   │  TAG (16B)  │  CIPHERTEXT (N bytes)│
└─────────────┴─────────────┴─────────────────────┘
  Random mỗi    Auth tag để    Dữ liệu thực sự
  lần encrypt   detect tamper  được mã hoá
```

**Tại sao dùng GCM thay vì CBC?**

GCM là AEAD (Authenticated Encryption with Associated Data) — vừa mã hoá vừa đảm bảo toàn vẹn. Nếu ciphertext bị sửa đổi dù chỉ 1 bit, `EVP_DecryptFinal_ex` sẽ trả về lỗi ngay lập tức. CBC không có tính năng này và dễ bị padding oracle attack.

**AAD (Additional Authenticated Data):**

Một số nơi trong code truyền AAD vào `encryptAESGCM()`. AAD là dữ liệu không bị mã hoá nhưng được xác thực — ví dụ `userId` được dùng làm AAD khi mã hoá dữ liệu của user đó. Điều này đảm bảo ciphertext của user A không thể bị ghép vào user B.

---

### 3.2 PBKDF2-HMAC-SHA256 — Hash Mật Khẩu

**Dùng cho:** Lưu trữ mật khẩu người dùng trong UserDatabase.

| Tham số | Giá trị |
|---|---|
| Thuật toán | PBKDF2 (Password-Based Key Derivation Function 2) |
| PRF bên trong | HMAC-SHA256 |
| Iterations | 600.000 (theo khuyến nghị OWASP 2024) |
| Salt length | 256-bit (32 bytes), random per user |
| Output length | 256-bit (32 bytes) |
| Chuẩn | NIST SP 800-132, OWASP Password Storage CS |

**Tại sao 600.000 iterations?**

Mỗi iteration làm chậm quá trình hash xuống. Trên phần cứng thông thường (2024), 600K iterations mất khoảng 300–500ms — đủ chậm để brute-force không khả thi, nhưng không ảnh hưởng UX vì user chỉ login 1 lần.

---

### 3.3 HMAC-SHA256 — Xác Thực Toàn Vẹn

**Dùng cho:** SignedAuditLog (chain HMAC), AntiTamper (file integrity), SecureKeyDerivation.

| Tham số | Giá trị |
|---|---|
| Thuật toán | HMAC (Hash-based Message Authentication Code) |
| Hash function | SHA-256 |
| Output | 256-bit (32 bytes) |
| Chuẩn | RFC 2104, FIPS 198-1 |

HMAC không phải mã hoá — không thể "giải mã" lại. Nó tạo ra một fingerprint của dữ liệu + key. Nếu dữ liệu thay đổi hoặc key sai → fingerprint khác → phát hiện tamper.

---

### 3.4 SHA-256 — Hash Đơn Thuần

**Dùng cho:** Kiểm tra nhanh tính toàn vẹn, internal use.

Là one-way hash function — không có key, không có authentication. Dùng SHA-256 trực tiếp cho dữ liệu nhạy cảm là **không an toàn** (rainbow table attack). Trong project này SHA-256 chỉ được dùng ở vai trò internal, không bao giờ dùng để hash password.

---

### 3.5 HMAC-SHA1 — TOTP (RFC 4226)

**Dùng cho:** Tính toán OTP code trong SecureTOTP.

RFC 4226 (HOTP) và RFC 6238 (TOTP) đặc tả bắt buộc dùng HMAC-SHA1. Mặc dù SHA-1 đã deprecated cho nhiều mục đích khác, trong context TOTP nó vẫn an toàn vì HMAC-SHA1 không có lỗ hổng đã biết với HMAC construction, và output chỉ là 6 chữ số (không lộ raw hash). Tất cả authenticator apps (Google, Authy, 1Password) đều dùng SHA-1 cho TOTP.

---

### 3.6 CSPRNG — Tạo Số Ngẫu Nhiên

**Dùng cho:** IV, Salt, Master Key, TOTP secret.

Dùng `RAND_bytes()` của OpenSSL — là CSPRNG (Cryptographically Secure Pseudo-Random Number Generator) đạt chuẩn FIPS 140-3. Trước khi gọi, code kiểm tra `RAND_status() == 1` để đảm bảo entropy pool đã được seeded.

---

## 4. Cơ Chế Salt

### 4.1 Salt là gì và tại sao cần?

Salt là một chuỗi bytes ngẫu nhiên được thêm vào password trước khi hash. Mục đích:

- **Chống Rainbow Table Attack:** Attacker không thể tính sẵn hash cho tất cả mật khẩu phổ biến vì mỗi user có salt khác nhau.
- **Chống duplicate detection:** Hai user cùng password "123456" sẽ có hash hoàn toàn khác nhau do salt khác nhau.
- **Không cần bí mật:** Salt được lưu công khai cùng hash — bảo mật đến từ tính ngẫu nhiên, không phải bí mật.

### 4.2 Cách Salt Được Tạo Và Lưu

```
addUser("alice", "MyP@ssw0rd123"):
  1. salt = CSPRNG(32 bytes)         → ví dụ: a3f7c2...e91b (ngẫu nhiên)
  2. hash = PBKDF2(password, salt, 600K iterations)
  3. Lưu vào CredentialRecord: { userId, salt, hash, roles }
  4. Serialize: "alice|<salt_hex>|<hash_hex>|2"
  5. Encrypt toàn bộ serialized data bằng AES-256-GCM với DB key
  6. Ghi vào users.udb
```

### 4.3 Salt Trong File Lưu Trữ

Salt KHÔNG bị mã hoá riêng — nó được lưu trong plaintext của UserDatabase, sau đó **cả database** được mã hoá bằng AES-256-GCM. Điều này có nghĩa:

- Kẻ tấn công không có master key → không đọc được salt
- Kẻ tấn công có master key → đọc được salt, nhưng vẫn phải brute-force PBKDF2 với 600K iterations

### 4.4 Dummy Salt — Chống Timing Attack

```
verifyPassword("alice", password):
  it = records_.find("alice")
  
  // Luôn hash dù user tồn tại hay không
  const SecBytes& salt = (it != end) ? it->second.salt : dummySalt_
  hash = PBKDF2(password, salt, 600K)
  
  if (it == end) return FAIL  // trả về sau khi đã hash xong
```

Nếu code trả về ngay lập tức khi user không tồn tại (không hash), attacker có thể đo thời gian response để biết username hợp lệ hay không (timing side-channel). `dummySalt_` là random 32 bytes được tạo một lần khi `UserDatabase` được khởi tạo — đảm bảo thời gian response giống nhau dù user có tồn tại hay không.

---

## 5. Quản Lý Master Key (Private Key)

### 5.1 Master Key Là Gì?

Master Key là một chuỗi 32 bytes ngẫu nhiên (256-bit) — đây là **bí mật gốc** của toàn bộ hệ thống. Tất cả các key khác đều được derive từ master key này thông qua HKDF. Nếu master key bị lộ, toàn bộ dữ liệu mã hoá có thể bị giải mã.

### 5.2 Lifecycle của Master Key

```
[Disk: master.key]
       │  read
       ▼
[RAM: MasterKeyProvider::resolve()]
       │  move (không copy)
       ▼
[AppContext::masterKey  ←  SecBytes (vector với SecureAllocator)]
       │
       ├──► HKDF → dbEncryptionKey  → encrypt/decrypt users.udb
       ├──► HKDF → auditHmacKey     → sign audit log entries
       ├──► HKDF → totpStorageKey   → encrypt TOTP secrets
       ├──► HKDF → configEncryptKey → decrypt config files
       └──► HKDF → sessionHmacKey   → sign session tokens
       │
       ▼ (khi AppContext bị destroy hoặc signal SIGINT/SIGTERM)
[Explicit zero: volatile byte_t* p = masterKey.data();
                for each byte: p[i] = 0]
```

### 5.3 Bảo Vệ Master Key Trong RAM

**SecureAllocator:** `SecBytes` dùng custom allocator — khi `vector` bị deallocate, allocator tự động zero toàn bộ memory trước khi gọi `operator delete`. Ngăn secret còn sót lại trong heap sau khi free.

**Explicit zero trước destroy:** Ngoài `SecureAllocator`, `AppContext` destructor còn tự viết zero lên từng byte qua volatile pointer — đảm bảo compiler không optimize-away việc này.

**Signal handler safety:** Khi nhận `SIGINT`/`SIGTERM`, signal handler chỉ dùng `write()` syscall (async-signal-safe) để zero key, rồi gọi `_Exit()` — không gọi bất kỳ C++ function nào có thể deadlock.

**Không duplicate:** Chỉ có MỘT bản sao master key trong RAM (trong `AppContext::masterKey`). Không tạo copy, không truyền by value — chỉ truyền `std::span<const byte_t>` khi cần dùng.

### 5.4 Hai Phương Thức Cung Cấp Master Key

**Phương thức 1 — Key File (khuyến nghị production):**

```bash
# Tạo key file
./build/SecureConsoleApp --generate-key /etc/myapp/master.key

# Key file được set permissions 400 (chỉ owner đọc)
ls -la /etc/myapp/master.key
# -r-------- 1 appuser appgroup 32 ... master.key

export APP_KEY_FILE=/etc/myapp/master.key
```

Key file là 32 bytes binary thuần — không encode. Khi load, code kiểm tra đúng 32 bytes, không thêm không bớt.

**Phương thức 2 — Environment Variable:**

```bash
# Base64 encode key file để truyền qua env var
export APP_MASTER_KEY=$(base64 -w0 /etc/myapp/master.key)
```

App decode base64 lại, kiểm tra decoded size == 32 bytes. Cách này phù hợp môi trường container (Docker, K8s Secrets) nhưng env var có thể bị log bởi process monitor — key file an toàn hơn.

### 5.5 Bảo Vệ Key File Trên Disk

Khi `generateKeyFile()` tạo key file:

1. Ghi vào file tạm `master.key.tmp` trước
2. Flush và kiểm tra `file.good()` — đảm bảo ghi thành công
3. Atomic rename `.tmp` → `master.key` — tránh partial write
4. Set permissions `0400` (owner read-only) — file không thể bị ghi đè ngẫu nhiên
5. Trên Linux: chạy app với user khác (qua `PrivilegeDrop::drop()`) sau khi đã đọc key — app dropped process không thể đọc lại file

**Khuyến nghị production:**
- Lưu key file trên ổ đĩa riêng hoặc HSM (Hardware Security Module)
- Sử dụng `mlock()` (đã có trong `GuardedRegion` và `MemoryLocker`) để key không bị swap ra đĩa
- Xoá key khỏi RAM ngay sau khi đã derive tất cả subkeys (nếu không cần decrypt lại)

---

## 6. Key Derivation — HKDF

### 6.1 Tại Sao Cần Derive Keys?

Dùng cùng một key cho cả database encryption lẫn HMAC audit log là **key reuse** — vi phạm nguyên tắc cryptography cơ bản. Nếu một subsystem bị tấn công và lộ key, các subsystem khác cũng bị ảnh hưởng. HKDF giải quyết bằng cách tạo ra các key độc lập từ một nguồn duy nhất.

### 6.2 HKDF — Cơ Chế Hoạt Động

HKDF (RFC 5869) gồm 2 bước:

**Bước 1 — Extract:**
```
PRK = HMAC-SHA256(salt, masterKey)
```
Tạo ra một "pseudorandom key" có entropy tốt, độc lập với format của masterKey.

**Bước 2 — Expand:**
```
T(1) = HMAC-SHA256(PRK, context || 0x01)
T(2) = HMAC-SHA256(PRK, T(1) || context || 0x02)
...
Output = T(1) || T(2) || ... (cắt đến outputLen)
```
Context ("info") là label như `"secfw-db-encryption-v1"` — đây là **domain separation**. Hai context khác nhau → output hoàn toàn khác nhau dù cùng masterKey.

### 6.3 Các Key Được Derive

| Label | Dùng cho | Độ dài |
|---|---|---|
| `secfw-db-encryption-v1` | Encrypt/decrypt `users.udb` | 32 bytes |
| `secfw-audit-hmac-v1` | HMAC chain trong `SignedAuditLog` | 32 bytes |
| `secfw-totp-storage-v1` | Encrypt TOTP secrets | 32 bytes |
| `secfw-config-encryption-v1` | Encrypt/decrypt config files | 32 bytes |
| `secfw-session-hmac-v1` | Sign session tokens | 32 bytes |

Hậu tố `-v1` trong label cho phép rotate key schema mà không đổi masterKey — chỉ cần thay đổi label sang `-v2` là ra key hoàn toàn khác.

### 6.4 OpenSSL 3.x vs OpenSSL 1.x

Code tự động chọn implementation phù hợp:

- **OpenSSL ≥ 3.0:** Dùng `EVP_KDF` API chính thức (`EVP_KDF_fetch("HKDF")`)
- **OpenSSL 1.x:** Fallback tự implement HKDF theo RFC 5869 thuần HMAC

---

## 7. Luồng Dữ Liệu Mã Hoá Tổng Quan

### 7.1 Khi Tạo User Mới

```
Input: username="alice", password="MyP@ss!23Word"

1. Validate password policy (uppercase, lowercase, digit, special char, ≥12 chars)
2. salt     = CSPRNG(32 bytes)
3. hash     = PBKDF2-HMAC-SHA256(password, salt, 600000 iterations)
4. Lưu vào records_["alice"] = { salt, hash, roles }

5. Khi save:
   plaintext = serialize(all records)          // "alice|salt_hex|hash_hex|2\n..."
   dbKey     = HKDF(masterKey, "secfw-db-encryption-v1")
   iv        = CSPRNG(12 bytes)
   ciphertext, tag = AES-256-GCM(plaintext, dbKey, iv)
   file      = MAGIC(4B) + VERSION(2B) + reserved(2B) + iv + tag + ciphertext
```

### 7.2 Khi Verify Password

```
Input: username="alice", password="MyP@ss!23Word"

1. Tìm record của "alice" → lấy salt (nếu không có dùng dummySalt_)
2. computed = PBKDF2-HMAC-SHA256(password, salt, 600000)
3. Constant-time compare: computed == stored.hash
   (dùng volatile int diff = 0; for each byte: diff |= a[i] ^ b[i])
4. diff == 0 → SUCCESS; trả về roleFlags
```

### 7.3 Khi Ghi Audit Log

```
Input: "alice logged in successfully"

1. lineData  = seqId + "|" + timestamp + "|" + ... (các fields)
2. chainInput = lineData + "|" + prevHash
3. hmac      = HMAC-SHA256(chainInput, auditKey)  // auditKey từ HKDF
4. prevHash  = hmac  (cập nhật cho entry tiếp theo)
5. finalLine = lineData + "|" + hmac + "\n"
6. Append vào file
```

### 7.4 Khi Verify TOTP

```
Input: userCode="123456", secret (20 bytes binary)

1. counter = unix_time / 30  (30-second window)
2. For delta in [-1, 0, +1]:
   a. counterBytes = (counter + delta) in big-endian 8 bytes
   b. mac    = HMAC-SHA1(secret, counterBytes)
   c. offset = mac[19] & 0x0F
   d. binCode = ((mac[offset] & 0x7F) << 24) | ... (4 bytes)
   e. otp    = binCode % 10^6  → zero-pad to 6 digits
   f. Constant-time compare: otp == userCode
3. Any match → SUCCESS
```

---

## 8. Câu Hỏi Thường Gặp

**Q: Nếu mất master key thì sao?**

Không thể recover dữ liệu. AES-256-GCM với key đúng chuẩn không có backdoor. Phải tạo lại toàn bộ database với key mới. Đây là lý do nên backup master key ở nơi an toàn (offline, encrypted USB, HSM).

**Q: Salt có cần bí mật không?**

Không. Salt được thiết kế để lưu cùng hash — bảo mật đến từ tính ngẫu nhiên và PBKDF2 iterations, không phải từ bí mật của salt.

**Q: Tại sao không dùng bcrypt hay Argon2?**

PBKDF2-SHA256 với 600K iterations đạt chuẩn NIST SP 800-132 và FIPS 140-3 — yêu cầu bắt buộc của nhiều môi trường enterprise/government. Argon2 (memory-hard) mạnh hơn với GPU attack nhưng chưa được NIST chứng nhận chính thức. Trong future version có thể thêm Argon2 option cho non-FIPS environment.

**Q: IV có cần lưu không?**

Có và đã được lưu. IV (12 bytes) được prepend vào đầu mỗi encrypted blob — `IV || TAG || CIPHERTEXT`. Khi decrypt, code đọc 12 bytes đầu làm IV. IV không cần bí mật nhưng phải **duy nhất mỗi lần encrypt** với cùng key. Code dùng CSPRNG để đảm bảo điều này.

**Q: Tại sao output AES-GCM có TAG?**

TAG (16 bytes) là Authentication Tag — bằng chứng rằng ciphertext không bị sửa đổi. Nếu ai đó thay đổi 1 bit trong ciphertext và bạn cố decrypt → `EVP_DecryptFinal_ex` trả về lỗi ngay lập tức (`Authentication tag mismatch`). Đây là điểm khác biệt quan trọng giữa GCM và CBC.

**Q: HKDF có cần salt không?**

Có nhưng không bắt buộc bí mật. Trong code hiện tại khi không truyền salt thì dùng 32 zero bytes. Nếu muốn tăng security có thể truyền một random salt và lưu cùng với key bundle. Với HKDF, `context` (domain label) mới là yếu tố tạo ra sự khác biệt giữa các key, không phải salt.

---

*SecureConsoleApp v1.3 — Documentation*
