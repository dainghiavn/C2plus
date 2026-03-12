// ============================================================
// test_ipc.cpp — Integration tests for UnixSocketChannel v2.1.1
//
// ── v2.1.1 Fixes ─────────────────────────────────────────────
//
//   [BUG-NET-04] CRITICAL — makeTestKey() deterministic → T05 always FAIL:
//     v2.1.0 changed makeTestKey() to return {1,2,...,32} for all calls.
//     test_crypto_wrong_key() (T05) calls:
//       auto key1 = makeTestKey(), key2 = makeTestKey();  // key1 == key2 always!
//     GCM decryption with the "wrong" (identical) key succeeds.
//     Test reports "T05 wrong key accepted" → test suite exits with code 1.
//     Fix: makeTestKey() accepts an optional `offset` byte. T05 uses
//     makeTestKey(0) and makeTestKey(1) which produce distinct 32-byte keys.
//     T18 (HKDF determinism) uses a fixed masterKey directly — no longer
//     depends on makeTestKey() being deterministic.
//     T04 still uses a single randomised key (CSPRNG) for uniqueness test.
//     makeTestKey(0) = {1,2,...,32}; makeTestKey(1) = {2,3,...,33}.
//
//   [BUG-NET-05] MEDIUM — T15 regression: isRetryable() checks removed:
//     v2.1.0 dropped the isRetryable() assertions that were present in
//     v2.0.1. This left a security coverage gap:
//       - ERR_PEER_REJECTED must NOT be retryable (it is a security
//         decision; retrying would allow brute-forcing peer auth).
//       - ERR_TIMEOUT and ERR_CONN_CLOSED ARE retryable (transient).
//       - ERR_NETWORK_FAIL is NOT retryable (syscall failure, not transient).
//     Restored all four isRetryable() assertions.
//
//   [BUG-NET-07] LOW — T19 failure message uses decimal, not octal:
//     `std::to_string(fileMode >> 6 & 7)` produces decimal "6", "4", "4"
//     for mode 0644. This is coincidentally readable but misleading.
//     Fix: use `fmtOctalMode()` helper which formats via `std::oct` stream.
//
// ── v2.1.0 Fixes ─────────────────────────────────────────────
//
//   [TEST-01] LOW — Temp log files not cleaned up after tests.
//   [TEST-02] INFO — test_ipc not in CMakeLists.txt (fixed there).
//   [NET-01]  T16: writeFull() platform flag — closed peer, no crash.
//   [NET-02]  T17: stop() from thread — run() exits cleanly.
//   [NET-03]  T18: IpcChannelKey::derive() → 32-byte key, deterministic.
//   [NET-04]  T19: socket file created with mode 0600.
//
// ── v2.0.1 Fixes ─────────────────────────────────────────────
//
//   [BUG-TEST-01] CRITICAL — T10 waitpid() DEADLOCK.
//   [BUG-TEST-02] CRITICAL — T12 waitpid() DEADLOCK.
//   [BUG-TEST-03] MEDIUM   — Missing #include <sys/select.h>.
//   [BUG-TEST-04] MEDIUM   — SecureLogger toConsole=true in children.
//   [BUG-TEST-05] MEDIUM   — SecureLogger ctor throws in child.
//   [BUG-TEST-06] LOW      — Sync pipe: select() not consuming byte.
//
// Tests (19 total):
//   T01  IpcMessage serialise/deserialise — empty body
//   T02  IpcMessage serialise/deserialise — normal body
//   T03  IpcMessage: body too large → serialise returns Failure
//   T04  Crypto roundtrip: encryptMessage → decryptMessage, unique IV
//   T05  Crypto: wrong key → decryptMessage Failure
//   T06  Crypto: tampered ciphertext → GCM tag rejects
//   T07  Frame: bad magic → recvMessage ERR_INPUT_INVALID
//   T08  Frame: payload_len > 1 MiB → ERR_INPUT_INVALID (before alloc)
//   T09  Frame: payload_len < IPC_MIN → ERR_INPUT_INVALID [BUG-IPC-04]
//   T10  Server/Client: single send/recv/echo roundtrip (fork)
//   T11  Server: rejects connection from non-allowed UID
//   T12  Server: 100 sequential messages, all bodies verified
//   T13  Socket file cleaned up after UnixSocketServer destructor
//   T14  Socket path ≥ 108 bytes → create() ERR_INPUT_INVALID [BUG-E04]
//   T15  SecurityStatus network error codes + isRetryable() [BUG-E01]
//   T16  [NET-01] writeFull() on closed peer → ERR_CONN_CLOSED, no crash
//   T17  [NET-02] stop() from thread — run() exits, no extra connection
//   T18  [NET-03] IpcChannelKey::derive() produces 32-byte derived key
//   T19  [NET-04] Socket file created with mode 0600 (umask+chmod fix)
//
// Build (manual — or use CMakeLists.txt target 'test_ipc'):
//   g++ -std=c++20 -O2 -Wall -Wextra \
//       -Iinclude src/test_ipc.cpp \
//       -lssl -lcrypto -lpthread -o build/test_ipc
//
// Run (as a normal user — not root, for T11 UID rejection to work):
//   ./build/test_ipc
// ============================================================

// ── Project headers ───────────────────────────────────────────────────────────
#include "security/SecureCore.hpp"
#include "security/CryptoEngine.hpp"
#include "security/InputValidator.hpp"
#include "security/SecureLogger.hpp"
#include "security/UnixSocketChannel.hpp"

// ── Standard library ─────────────────────────────────────────────────────────
#include <iostream>
#include <sstream>
#include <iomanip>
#include <string>
#include <vector>
#include <thread>
#include <chrono>
#include <cstring>
#include <cstdint>

// ── POSIX / platform ─────────────────────────────────────────────────────────
#include <sys/socket.h>
#include <sys/select.h>      // [BUG-TEST-03 FIX]: explicit include
#include <sys/un.h>
#include <sys/wait.h>
#include <sys/stat.h>        // T19: stat() for mode check
#include <signal.h>          // [BUG-TEST-03 FIX]: SIGTERM, SIGKILL
#include <unistd.h>
#include <fcntl.h>

using namespace SecFW;
using namespace std::chrono_literals;

// ══════════════════════════════════════════════════════════════════════════════
// Test harness
// ══════════════════════════════════════════════════════════════════════════════

static int g_pass = 0;
static int g_fail = 0;
static std::vector<std::string> g_failures;

#define PASS(msg) do { \
    std::cout << "  \033[32m[PASS]\033[0m  " << (msg) << "\n"; \
    ++g_pass; \
} while(0)

#define FAIL(test, detail) do { \
    std::string _m = std::string("[FAIL]  ") + (test); \
    if (!std::string(detail).empty()) _m += ": " + std::string(detail); \
    std::cout << "  \033[31m" << _m << "\033[0m\n"; \
    ++g_fail; \
    g_failures.push_back(_m); \
    return; \
} while(0)

static void SECTION(const std::string& title) {
    std::cout << "\n\033[1m── " << title << " ──\033[0m\n";
}

// ══════════════════════════════════════════════════════════════════════════════
// Temp log cleanup [TEST-01 FIX]
// ══════════════════════════════════════════════════════════════════════════════

static std::vector<std::string> g_tempLogs;

static void registerTempLog(const std::string& path) { g_tempLogs.push_back(path); }

static void cleanupTempLogs() noexcept {
    for (const auto& p : g_tempLogs) ::unlink(p.c_str());
}

// ══════════════════════════════════════════════════════════════════════════════
// Helpers
// ══════════════════════════════════════════════════════════════════════════════

// [BUG-NET-04 FIX]: makeTestKey() accepts an offset so callers can produce
// distinct keys. makeTestKey(0) = {1,2,...,32}; makeTestKey(1) = {2,3,...,33}.
// This lets T05 use two different keys without relying on CSPRNG.

static SecBytes makeTestKey(uint8_t offset = 0) {
    SecBytes k(32);
    for (std::size_t i = 0; i < 32; ++i)
        k[i] = static_cast<byte_t>(static_cast<uint8_t>(i + 1) + offset);
    return k;
}

// Unique socket path per test — counter prevents same-PID reuse within a run
static std::string testSocketPath(const std::string& suffix = "") {
    static int counter = 0;
    return "/tmp/secfw_t" + std::to_string(::getpid()) +
           "_" + std::to_string(++counter) +
           (suffix.empty() ? "" : "_" + suffix) + ".sock";
}

// [BUG-NET-07 FIX]: Format a mode_t as 4-character octal string (e.g. "0600")
static std::string fmtOctalMode(mode_t m) {
    std::ostringstream oss;
    oss << "0" << std::oct << (m & 0777);
    return oss.str();
}

// Write raw bytes to a socket (bypasses sendMessage framing — for negative tests)
static void writeRaw(int fd, const void* data, std::size_t len) {
    const uint8_t* p = static_cast<const uint8_t*>(data);
    std::size_t   rem = len;
    while (rem > 0) {
        ssize_t n = ::send(fd, p, rem, MSG_NOSIGNAL);
        if (n <= 0) break;
        p += n; rem -= static_cast<std::size_t>(n);
    }
}

// ── Sync pipe helper ──────────────────────────────────────────────────────────
// Child writes 1 byte to signal server-ready; parent reads it.
// [BUG-TEST-06 FIX]: read() actually consumes the byte.

static bool waitReady(int readFd, int timeoutSec = 4) {
    struct timeval tv{ timeoutSec, 0 };
    fd_set fds; FD_ZERO(&fds); FD_SET(readFd, &fds);
    if (::select(readFd + 1, &fds, nullptr, nullptr, &tv) <= 0) return false;
    uint8_t byte = 0;
    return (::read(readFd, &byte, 1) == 1);
}

// Kill a child and reap it — prevents waitpid() deadlock [BUG-TEST-01/02 FIX]
static void killAndWait(pid_t child, int sig = SIGTERM) {
    ::kill(child, sig);
    ::waitpid(child, nullptr, 0);
}

// ══════════════════════════════════════════════════════════════════════════════
// T01–T03: IpcMessage serialise / deserialise
// ══════════════════════════════════════════════════════════════════════════════

static void test_message_roundtrip_empty() {
    IpcMessage msg; msg.body = "";
    auto ser = msg.serialise();
    if (ser.fail()) { FAIL("T01 serialise", ser.message); }
    if (ser.value.size() != 4) { FAIL("T01 size", std::to_string(ser.value.size())); }
    auto des = IpcMessage::deserialise(ser.value);
    if (des.fail()) { FAIL("T01 deserialise", des.message); }
    if (!des.value.body.empty()) { FAIL("T01 body not empty", des.value.body); }
    PASS("T01  IpcMessage roundtrip — empty body (4-byte prefix only)");
}

static void test_message_roundtrip_normal() {
    IpcMessage msg; msg.body = R"({"action":"ping","seq":42})";
    auto ser = msg.serialise();
    if (ser.fail()) { FAIL("T02 serialise", ser.message); }
    auto des = IpcMessage::deserialise(ser.value);
    if (des.fail()) { FAIL("T02 deserialise", des.message); }
    if (des.value.body != msg.body) { FAIL("T02 body mismatch", des.value.body); }
    PASS("T02  IpcMessage roundtrip — normal JSON body");
}

static void test_message_too_large() {
    IpcMessage msg;
    msg.body = std::string(IpcMessage::MAX_BODY_BYTES + 1, 'X');
    auto ser = msg.serialise();
    if (ser.ok()) { FAIL("T03 oversized body accepted", ""); }
    if (ser.status != SecurityStatus::ERR_INPUT_INVALID) {
        FAIL("T03 wrong status", std::to_string(static_cast<int>(ser.status))); }
    PASS("T03  IpcMessage serialise — oversized body → ERR_INPUT_INVALID");
}

// ══════════════════════════════════════════════════════════════════════════════
// T04–T06: Crypto
// ══════════════════════════════════════════════════════════════════════════════

static void test_crypto_roundtrip() {
    // Use CSPRNG for T04 — the randomness test requires two independently
    // random encryptions of the same plaintext.
    auto rk = CryptoEngine::randomBytes(32);
    if (rk.fail()) { FAIL("T04 randomBytes", rk.message); }
    auto& key = rk.value;

    IpcMessage msg; msg.body = R"({"action":"list-users"})";
    auto ser = msg.serialise();
    if (ser.fail()) { FAIL("T04 serialise", ser.message); }

    auto enc1 = detail::encryptMessage(ser.value, key);
    if (enc1.fail()) { FAIL("T04 encrypt1", enc1.message); }
    auto enc2 = detail::encryptMessage(ser.value, key);
    if (enc2.fail()) { FAIL("T04 encrypt2", enc2.message); }

    // Different IVs per message — same plaintext must produce different ciphertext
    if (enc1.value == enc2.value) {
        FAIL("T04 IV reuse", "identical ciphertext for same plaintext"); }

    auto dec = detail::decryptMessage(enc1.value, key);
    if (dec.fail()) { FAIL("T04 decrypt", dec.message); }
    if (dec.value != ser.value) { FAIL("T04 plaintext mismatch", ""); }
    PASS("T04  Crypto roundtrip — unique IV per message, correct decrypt");
}

static void test_crypto_wrong_key() {
    // [BUG-NET-04 FIX]: makeTestKey(0) = {1,...,32}; makeTestKey(1) = {2,...,33}.
    // These are distinct keys → GCM tag must fail → test correctly verifies rejection.
    auto key1 = makeTestKey(0);
    auto key2 = makeTestKey(1);   // different from key1
    if (key1 == key2) { FAIL("T05 keys identical", "makeTestKey offset broken"); }

    IpcMessage msg; msg.body = "secret";
    auto ser = msg.serialise();
    if (ser.fail()) { FAIL("T05 serialise", ser.message); }
    auto enc = detail::encryptMessage(ser.value, key1);
    if (enc.fail()) { FAIL("T05 encrypt", enc.message); }
    auto dec = detail::decryptMessage(enc.value, key2);
    if (dec.ok()) { FAIL("T05 wrong key accepted", "GCM should reject"); }
    if (dec.status != SecurityStatus::ERR_CRYPTO_FAIL) {
        FAIL("T05 wrong status", std::to_string(static_cast<int>(dec.status))); }
    PASS("T05  Crypto: wrong key → ERR_CRYPTO_FAIL (GCM tag mismatch)");
}

static void test_crypto_tampered_ciphertext() {
    auto key = makeTestKey();
    IpcMessage msg; msg.body = "tamper-me";
    auto ser = msg.serialise();
    if (ser.fail()) { FAIL("T06 serialise", ser.message); }
    auto enc = detail::encryptMessage(ser.value, key);
    if (enc.fail()) { FAIL("T06 encrypt", enc.message); }
    if (enc.value.size() <= IPC_GCM_OVERHEAD) { FAIL("T06 too short", ""); }
    enc.value[IPC_GCM_OVERHEAD] ^= 0xFF;  // flip bits in ciphertext region
    auto dec = detail::decryptMessage(enc.value, key);
    if (dec.ok()) { FAIL("T06 tamper accepted", "GCM must reject modified ciphertext"); }
    PASS("T06  Crypto: tampered ciphertext → GCM authentication Failure");
}

// ══════════════════════════════════════════════════════════════════════════════
// T07–T09: Frame validation via socketpair
// ══════════════════════════════════════════════════════════════════════════════

static void test_frame_bad_magic() {
    auto key = makeTestKey();
    int sv[2];
    if (::socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        FAIL("T07 socketpair", ::strerror(errno)); }
    uint8_t badFrame[8] = { 0xDE, 0xAD, 0xBE, 0xEF, 0x20, 0x00, 0x00, 0x00 };
    writeRaw(sv[1], badFrame, 8);
    SecBytes garbage(32, 0xAB);
    writeRaw(sv[1], garbage.data(), garbage.size());
    ::close(sv[1]);

    struct timeval tv{2, 0};
    ::setsockopt(sv[0], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    auto r = recvMessage(sv[0], key);
    ::close(sv[0]);

    if (r.ok()) { FAIL("T07 bad magic accepted", ""); }
    if (r.status != SecurityStatus::ERR_INPUT_INVALID) {
        FAIL("T07 wrong status", std::to_string(static_cast<int>(r.status))); }
    PASS("T07  Frame: bad magic → ERR_INPUT_INVALID");
}

static void test_frame_payload_too_large() {
    auto key = makeTestKey();
    int sv[2];
    if (::socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        FAIL("T08 socketpair", ::strerror(errno)); }
    uint32_t bigLen = static_cast<uint32_t>(IPC_MAX_PAYLOAD_BYTES + 1);
    uint8_t header[8];
    std::memcpy(header, IPC_MAGIC, 4);
    header[4] = static_cast<uint8_t>( bigLen        & 0xFF);
    header[5] = static_cast<uint8_t>((bigLen >>  8) & 0xFF);
    header[6] = static_cast<uint8_t>((bigLen >> 16) & 0xFF);
    header[7] = static_cast<uint8_t>((bigLen >> 24) & 0xFF);
    writeRaw(sv[1], header, 8);
    ::close(sv[1]);

    struct timeval tv{2, 0};
    ::setsockopt(sv[0], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    auto r = recvMessage(sv[0], key);
    ::close(sv[0]);

    if (r.ok()) { FAIL("T08 oversized frame accepted", ""); }
    if (r.status != SecurityStatus::ERR_INPUT_INVALID) {
        FAIL("T08 wrong status", std::to_string(static_cast<int>(r.status))); }
    PASS("T08  Frame: payload_len > 1 MiB → ERR_INPUT_INVALID (no alloc)");
}

static void test_frame_payload_too_small() {
    // [BUG-IPC-04]: values 28–31 must be rejected (IPC_MIN = 32)
    auto key = makeTestKey();
    int sv[2];
    if (::socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        FAIL("T09 socketpair", ::strerror(errno)); }
    uint32_t shortLen = IPC_GCM_OVERHEAD; // 28 — below IPC_MIN_PAYLOAD_BYTES (32)
    uint8_t header[8];
    std::memcpy(header, IPC_MAGIC, 4);
    header[4] = static_cast<uint8_t>( shortLen        & 0xFF);
    header[5] = static_cast<uint8_t>((shortLen >>  8) & 0xFF);
    header[6] = static_cast<uint8_t>((shortLen >> 16) & 0xFF);
    header[7] = static_cast<uint8_t>((shortLen >> 24) & 0xFF);
    writeRaw(sv[1], header, 8);
    ::close(sv[1]);

    struct timeval tv{2, 0};
    ::setsockopt(sv[0], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    auto r = recvMessage(sv[0], key);
    ::close(sv[0]);

    if (r.ok()) { FAIL("T09 below-minimum frame accepted", ""); }
    if (r.status != SecurityStatus::ERR_INPUT_INVALID) {
        FAIL("T09 wrong status", std::to_string(static_cast<int>(r.status))); }
    PASS("T09  Frame: payload_len=" + std::to_string(shortLen) +
         " < IPC_MIN=" + std::to_string(IPC_MIN_PAYLOAD_BYTES) +
         " → ERR_INPUT_INVALID [BUG-IPC-04]");
}

// ══════════════════════════════════════════════════════════════════════════════
// T10: Server/Client roundtrip (fork)
// ══════════════════════════════════════════════════════════════════════════════

static void test_server_client_roundtrip() {
    const std::string path    = testSocketPath("t10");
    const std::string logPath = "/tmp/secfw_t10.log";
    registerTempLog(logPath);
    auto key = makeTestKey();

    int rp[2];
    if (::pipe(rp) != 0) { FAIL("T10 pipe", ::strerror(errno)); }

    pid_t child = ::fork();
    if (child < 0) { FAIL("T10 fork", ::strerror(errno)); }

    if (child == 0) {
        ::close(rp[0]);
        try {
            // [BUG-TEST-04 FIX]: toConsole=false — don't pollute parent stdout
            SecureLogger slog(logPath, LogLevel::WARNING, false);
            auto srvRes = UnixSocketServer::create(path, key, slog);
            if (srvRes.fail()) { ::write(rp[1], "E", 1); ::close(rp[1]); std::exit(2); }
            ::write(rp[1], "\x01", 1); ::close(rp[1]);

            srvRes.value->run([](detail::SocketFd fd, const IpcPeerInfo&,
                                  const SecBytes& k, SecureLogger&) {
                auto msgRes = recvMessage(fd, k);
                if (!msgRes.ok()) return;
                IpcMessage reply; reply.body = "echo:" + msgRes.value.body;
                sendMessage(fd, reply, k);
                // After return → run() loops to accept() → parent kills via SIGTERM
            });
        } catch (const std::exception& e) {
            std::cerr << "[T10 child] " << e.what() << "\n"; std::exit(2);
        }
        std::exit(0);
    }

    ::close(rp[1]);
    if (!waitReady(rp[0])) { ::close(rp[0]); killAndWait(child, SIGKILL);
        FAIL("T10 server timeout", ""); }
    ::close(rp[0]);

    auto cliRes = UnixSocketClient::connect(path, key);
    if (cliRes.fail()) { killAndWait(child, SIGKILL); FAIL("T10 connect", cliRes.message); }

    IpcMessage req; req.body = R"({"action":"ping"})";
    auto snd = cliRes.value->send(req);
    if (snd.fail()) { killAndWait(child, SIGKILL); FAIL("T10 send", snd.message); }

    auto rcv = cliRes.value->recv();
    if (rcv.fail()) { killAndWait(child, SIGKILL); FAIL("T10 recv", rcv.message); }
    cliRes.value.reset();

    // [BUG-TEST-01 FIX]: kill before waitpid — child stuck in accept()
    killAndWait(child, SIGTERM);

    const std::string expected = "echo:" + req.body;
    if (rcv.value.body != expected) {
        FAIL("T10 body mismatch", "got '" + rcv.value.body + "'"); }
    PASS("T10  Server/Client: single send/recv/echo via Unix socket");
}

// ══════════════════════════════════════════════════════════════════════════════
// T11: Server rejects wrong-UID connection
// ══════════════════════════════════════════════════════════════════════════════

static void test_server_uid_rejection() {
    if (::getuid() == 0) {
        std::cout << "  [SKIP]  T11  (running as root — UID rejection inapplicable)\n";
        ++g_pass; return;
    }

    const std::string path    = testSocketPath("t11");
    const std::string logPath = "/tmp/secfw_t11.log";
    registerTempLog(logPath);
    auto key = makeTestKey();
    int rp[2];
    if (::pipe(rp) != 0) { FAIL("T11 pipe", ::strerror(errno)); }

    pid_t child = ::fork();
    if (child < 0) { FAIL("T11 fork", ::strerror(errno)); }

    if (child == 0) {
        ::close(rp[0]);
        try {
            SecureLogger slog(logPath, LogLevel::WARNING, false);
            auto srvRes = UnixSocketServer::create(path, key, slog, 0); // root only
            if (srvRes.fail()) { ::write(rp[1], "E", 1); ::close(rp[1]); std::exit(2); }
            ::write(rp[1], "\x01", 1); ::close(rp[1]);

            std::thread stopper([&]() {
                std::this_thread::sleep_for(3s);
                srvRes.value->stop();
            });
            srvRes.value->run([](detail::SocketFd, const IpcPeerInfo&,
                                  const SecBytes&, SecureLogger&) {});
            stopper.join();
        } catch (const std::exception& e) {
            std::cerr << "[T11 child] " << e.what() << "\n"; std::exit(2);
        }
        std::exit(0);
    }

    ::close(rp[1]);
    if (!waitReady(rp[0])) { ::close(rp[0]); killAndWait(child, SIGKILL);
        FAIL("T11 server timeout", ""); }
    ::close(rp[0]);
    std::this_thread::sleep_for(100ms);

    auto cliRes = UnixSocketClient::connect(path, key);
    if (cliRes.fail()) {
        killAndWait(child, SIGKILL);
        PASS("T11  Server: UID-mismatched connection rejected at OS level"); return;
    }
    IpcMessage req; req.body = "should-be-rejected";
    cliRes.value->send(req);
    auto rcv = cliRes.value->recv();
    cliRes.value.reset();
    killAndWait(child, SIGKILL);
    if (rcv.ok()) { FAIL("T11 rejected connection returned data", rcv.value.body); }
    PASS("T11  Server: non-allowed UID connection closed before data exchange");
}

// ══════════════════════════════════════════════════════════════════════════════
// T12: 100 sequential messages
// ══════════════════════════════════════════════════════════════════════════════

static void test_100_messages() {
    const std::string path    = testSocketPath("t12");
    const std::string logPath = "/tmp/secfw_t12.log";
    registerTempLog(logPath);
    auto key = makeTestKey();
    constexpr int N = 100;

    int rp[2];
    if (::pipe(rp) != 0) { FAIL("T12 pipe", ::strerror(errno)); }

    pid_t child = ::fork();
    if (child < 0) { FAIL("T12 fork", ::strerror(errno)); }

    if (child == 0) {
        ::close(rp[0]);
        try {
            SecureLogger slog(logPath, LogLevel::WARNING, false);
            auto srvRes = UnixSocketServer::create(path, key, slog);
            if (srvRes.fail()) { ::write(rp[1], "E", 1); ::close(rp[1]); std::exit(2); }
            ::write(rp[1], "\x01", 1); ::close(rp[1]);

            int failures = 0;
            srvRes.value->run([&](detail::SocketFd fd, const IpcPeerInfo&,
                                   const SecBytes& k, SecureLogger&) {
                for (int i = 0; i < N; ++i) {
                    auto m = recvMessage(fd, k);
                    if (m.fail()) { ++failures; break; }
                    IpcMessage reply; reply.body = "pong:" + std::to_string(i);
                    if (sendMessage(fd, reply, k).fail()) { ++failures; break; }
                }
            });
            std::exit(failures == 0 ? 0 : 1);
        } catch (const std::exception& e) {
            std::cerr << "[T12 child] " << e.what() << "\n"; std::exit(2);
        }
    }

    ::close(rp[1]);
    if (!waitReady(rp[0])) { ::close(rp[0]); killAndWait(child, SIGKILL);
        FAIL("T12 server timeout", ""); }
    ::close(rp[0]);

    auto cliRes = UnixSocketClient::connect(path, key);
    if (cliRes.fail()) { killAndWait(child, SIGKILL); FAIL("T12 connect", cliRes.message); }

    bool allOk = true;
    for (int i = 0; i < N && allOk; ++i) {
        IpcMessage msg; msg.body = "ping:" + std::to_string(i);
        auto snd = cliRes.value->send(msg);
        if (snd.fail()) { FAIL("T12 send #" + std::to_string(i), snd.message); allOk=false; break; }
        auto rcv = cliRes.value->recv();
        if (rcv.fail()) { FAIL("T12 recv #" + std::to_string(i), rcv.message); allOk=false; break; }
        if (rcv.value.body != "pong:" + std::to_string(i)) {
            FAIL("T12 body #" + std::to_string(i), rcv.value.body); allOk=false;
        }
    }
    cliRes.value.reset();

    // [BUG-TEST-02 FIX]: kill before waitpid
    int status = 0;
    ::kill(child, SIGTERM);
    ::waitpid(child, &status, 0);

    if (!allOk) return;
    bool serverOk = WIFSIGNALED(status) || (WIFEXITED(status) && WEXITSTATUS(status) == 0);
    if (!serverOk) { FAIL("T12 server error", "exit " + std::to_string(WEXITSTATUS(status))); }
    PASS("T12  100 sequential messages — all bodies verified");
}

// ══════════════════════════════════════════════════════════════════════════════
// T13: Socket file RAII cleanup
// ══════════════════════════════════════════════════════════════════════════════

static void test_socket_cleanup() {
    const std::string path    = testSocketPath("t13");
    const std::string logPath = "/tmp/secfw_t13.log";
    registerTempLog(logPath);
    auto key = makeTestKey();
    SecureLogger slog(logPath, LogLevel::WARNING, false);
    { auto srvRes = UnixSocketServer::create(path, key, slog);
      if (srvRes.fail()) { FAIL("T13 create", srvRes.message); }
    } // destructor here
    if (::access(path.c_str(), F_OK) == 0) {
        FAIL("T13 socket not cleaned up", path); }
    PASS("T13  [N07] Socket file removed by UnixSocketServer destructor");
}

// ══════════════════════════════════════════════════════════════════════════════
// T14: Path too long [BUG-E04]
// ══════════════════════════════════════════════════════════════════════════════

static void test_socket_path_too_long() {
    // 108 characters — requires 109 bytes with NUL → exceeds UNIX_PATH_MAX
    std::string longPath = "/tmp/" + std::string(108 - 5, 'x');
    auto key = makeTestKey();
    const std::string logPath = "/tmp/secfw_t14.log";
    registerTempLog(logPath);
    SecureLogger slog(logPath, LogLevel::WARNING, false);
    auto r = UnixSocketServer::create(longPath, key, slog);
    if (r.ok()) { FAIL("T14 long path accepted", "must be rejected"); }
    if (r.status != SecurityStatus::ERR_INPUT_INVALID) {
        FAIL("T14 wrong status", std::to_string(static_cast<int>(r.status))); }
    PASS("T14  [BUG-E04] Socket path ≥108 bytes → ERR_INPUT_INVALID");
}

// ══════════════════════════════════════════════════════════════════════════════
// T15: SecurityStatus network error codes + isRetryable() [BUG-E01]
// ══════════════════════════════════════════════════════════════════════════════

static void test_new_error_codes() {
    // ── 1. Four codes must exist and be distinct, non-zero ──────────────────
    const int n1 = static_cast<int>(SecurityStatus::ERR_NETWORK_FAIL);
    const int n2 = static_cast<int>(SecurityStatus::ERR_TIMEOUT);
    const int n3 = static_cast<int>(SecurityStatus::ERR_PEER_REJECTED);
    const int n4 = static_cast<int>(SecurityStatus::ERR_CONN_CLOSED);

    if (n1==0 || n2==0 || n3==0 || n4==0) { FAIL("T15 code=0 (collides with OK)", ""); }
    if (n1==n2 || n1==n3 || n1==n4 || n2==n3 || n2==n4 || n3==n4) {
        FAIL("T15 duplicate codes", ""); }

    // ── 2. statusMessage() must return a meaningful string ───────────────────
    for (auto code : { SecurityStatus::ERR_NETWORK_FAIL,
                       SecurityStatus::ERR_TIMEOUT,
                       SecurityStatus::ERR_PEER_REJECTED,
                       SecurityStatus::ERR_CONN_CLOSED }) {
        std::string msg = statusMessage(code);
        if (msg.empty() || msg == "Unknown error") {
            FAIL("T15 statusMessage code=" +
                 std::to_string(static_cast<int>(code)), "'" + msg + "'"); }
    }

    // ── 3. isNetworkError() = true for all four network codes ───────────────
    for (auto code : { SecurityStatus::ERR_NETWORK_FAIL,
                       SecurityStatus::ERR_TIMEOUT,
                       SecurityStatus::ERR_PEER_REJECTED,
                       SecurityStatus::ERR_CONN_CLOSED }) {
        if (!isNetworkError(code)) {
            FAIL("T15 isNetworkError false for network code",
                 std::to_string(static_cast<int>(code))); }
    }
    // Must NOT be true for non-network codes
    if (isNetworkError(SecurityStatus::OK) ||
        isNetworkError(SecurityStatus::ERR_CRYPTO_FAIL)) {
        FAIL("T15 isNetworkError true for non-network code", ""); }

    // ── 4. isRetryable() semantics [BUG-NET-05 FIX] ─────────────────────────
    //
    //  ERR_TIMEOUT      → true  (transient; retry after back-off)
    //  ERR_CONN_CLOSED  → true  (peer may have restarted; retry is safe)
    //  ERR_NETWORK_FAIL → false (syscall failed; not transient)
    //  ERR_PEER_REJECTED→ false (SECURITY DECISION — never retry:
    //                            retrying a rejected peer connection is an
    //                            auth bypass attempt and must be denied)
    if (!isRetryable(SecurityStatus::ERR_TIMEOUT)) {
        FAIL("T15 ERR_TIMEOUT not retryable", ""); }
    if (!isRetryable(SecurityStatus::ERR_CONN_CLOSED)) {
        FAIL("T15 ERR_CONN_CLOSED not retryable", ""); }
    if (isRetryable(SecurityStatus::ERR_NETWORK_FAIL)) {
        FAIL("T15 ERR_NETWORK_FAIL incorrectly retryable", ""); }
    if (isRetryable(SecurityStatus::ERR_PEER_REJECTED)) {
        FAIL("T15 ERR_PEER_REJECTED retryable — auth bypass risk", ""); }

    PASS("T15  [BUG-E01] 4 network codes: distinct, statusMessage, isNetworkError, isRetryable");
}

// ══════════════════════════════════════════════════════════════════════════════
// T16: [NET-01] writeFull() on closed peer → ERR_CONN_CLOSED, no crash
// ══════════════════════════════════════════════════════════════════════════════

static void test_write_to_closed_peer() {
    int sv[2];
    if (::socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        FAIL("T16 socketpair", ::strerror(errno)); }

    detail::setSoPeerNosigpipe(sv[0]);  // macOS: set SO_NOSIGPIPE
    ::close(sv[1]);                     // close the peer
    std::this_thread::sleep_for(10ms);  // let close propagate

    const char payload[] = "test";
    auto r = detail::writeFull(sv[0], payload, sizeof(payload));
    ::close(sv[0]);

    if (r.ok()) {
        // First send may be buffered before kernel detects peer close — acceptable.
        PASS("T16  [NET-01] writeFull() to closed peer — buffered, no crash"); return;
    }
    if (r.status != SecurityStatus::ERR_CONN_CLOSED &&
        r.status != SecurityStatus::ERR_NETWORK_FAIL) {
        FAIL("T16 unexpected status", statusMessage(r.status)); }
    PASS("T16  [NET-01] writeFull() to closed peer → " +
         std::string(statusMessage(r.status)) + ", no crash/SIGPIPE");
}

// ══════════════════════════════════════════════════════════════════════════════
// T17: [NET-02] stop() from thread — run() exits cleanly, no extra connection
// ══════════════════════════════════════════════════════════════════════════════

static void test_stop_from_thread() {
    const std::string path    = testSocketPath("t17");
    const std::string logPath = "/tmp/secfw_t17.log";
    registerTempLog(logPath);
    auto key = makeTestKey();

    SecureLogger slog(logPath, LogLevel::WARNING, false);
    auto srvRes = UnixSocketServer::create(path, key, slog);
    if (srvRes.fail()) { FAIL("T17 create", srvRes.message); }

    std::atomic<int>  connectionsHandled{ 0 };
    std::atomic<bool> runExited         { false };

    std::thread runThread([&]() {
        srvRes.value->run([&](detail::SocketFd fd, const IpcPeerInfo&,
                               const SecBytes& k, SecureLogger&) {
            ++connectionsHandled;
            IpcMessage dummy; dummy.body = "ok";
            recvMessage(fd, k);
            sendMessage(fd, dummy, k);
        });
        runExited.store(true, std::memory_order_release);
    });

    std::thread stopThread([&]() {
        std::this_thread::sleep_for(100ms);
        srvRes.value->stop();
    });
    stopThread.join();

    // run() must exit within 2 seconds after stop()
    for (int i = 0; i < 200; ++i) {
        if (runExited.load(std::memory_order_acquire)) break;
        std::this_thread::sleep_for(10ms);
    }
    runThread.join();

    if (!runExited.load()) { FAIL("T17 run() did not exit after stop()", ""); }
    if (connectionsHandled.load() != 0) {
        FAIL("T17 unexpected connections", std::to_string(connectionsHandled.load())); }
    PASS("T17  [NET-02] stop() from thread — run() exits cleanly, 0 connections");
}

// ══════════════════════════════════════════════════════════════════════════════
// T18: [NET-03] IpcChannelKey::derive() → 32-byte key, deterministic, ≠ master
// ══════════════════════════════════════════════════════════════════════════════

static void test_channel_key_derivation() {
    // Use a fixed master key — T18 tests HKDF determinism, not randomness.
    // makeTestKey() no longer needs to be deterministic for this to work.
    const SecBytes masterKey = makeTestKey(0); // {1,2,...,32}

    auto res = IpcChannelKey::derive(masterKey);
    if (res.fail()) { FAIL("T18 derive", res.message); }
    if (res.value.size() != 32) {
        FAIL("T18 key size", std::to_string(res.value.size())); }
    if (res.value == masterKey) {
        FAIL("T18 derived == master key", "HKDF must transform the key"); }

    // Determinism check (same input → same output)
    auto res2 = IpcChannelKey::derive(masterKey);
    if (res2.fail()) { FAIL("T18 derive2", res2.message); }
    if (res.value != res2.value) {
        FAIL("T18 not deterministic", ""); }

    PASS("T18  [NET-03] IpcChannelKey::derive() → 32-byte key, deterministic, ≠ master");
}

// ══════════════════════════════════════════════════════════════════════════════
// T19: [NET-04] Socket file created with mode 0600
// ══════════════════════════════════════════════════════════════════════════════

static void test_socket_file_permissions() {
    const std::string path    = testSocketPath("t19");
    const std::string logPath = "/tmp/secfw_t19.log";
    registerTempLog(logPath);
    auto key = makeTestKey();

    SecureLogger slog(logPath, LogLevel::WARNING, false);
    {
        auto srvRes = UnixSocketServer::create(path, key, slog);
        if (srvRes.fail()) { FAIL("T19 create", srvRes.message); }

        struct stat st{};
        if (::stat(path.c_str(), &st) != 0) { FAIL("T19 stat", ::strerror(errno)); }

        mode_t fileMode = st.st_mode & 0777;
        if (fileMode != 0600) {
            // [BUG-NET-07 FIX]: use octal formatting for the mode display
            FAIL("T19 wrong mode",
                 "expected " + fmtOctalMode(0600) +
                 ", got "    + fmtOctalMode(fileMode));
        }
        // Destructor removes socket file
    }
    PASS("T19  [NET-04] Socket file permissions = 0600 (umask + chmod fix)");
}

// ══════════════════════════════════════════════════════════════════════════════
// main
// ══════════════════════════════════════════════════════════════════════════════

int main() {
    std::cout << "\n\033[1m╔══════════════════════════════════════════════════╗\033[0m\n"
              << "\033[1m║  SecureConsoleAppNet — IPC Test Suite v2.1.1   ║\033[0m\n"
              << "\033[1m╚══════════════════════════════════════════════════╝\033[0m\n";

    SECTION("IpcMessage serialise / deserialise");
    test_message_roundtrip_empty();
    test_message_roundtrip_normal();
    test_message_too_large();

    SECTION("Crypto: encrypt / decrypt / tamper");
    test_crypto_roundtrip();
    test_crypto_wrong_key();
    test_crypto_tampered_ciphertext();

    SECTION("Frame validation (socketpair, no server)");
    test_frame_bad_magic();
    test_frame_payload_too_large();
    test_frame_payload_too_small();

    SECTION("Server / Client integration (fork)");
    test_server_client_roundtrip();
    test_server_uid_rejection();
    test_100_messages();

    SECTION("RAII and path validation");
    test_socket_cleanup();
    test_socket_path_too_long();

    SECTION("SecurityStatus — error codes and semantics");
    test_new_error_codes();

    SECTION("v2.1.x coverage: NET-01/02/03/04");
    test_write_to_closed_peer();
    test_stop_from_thread();
    test_channel_key_derivation();
    test_socket_file_permissions();

    // ── Summary ───────────────────────────────────────────────────────────────
    std::cout << "\n\033[1m── Results ──────────────────────────────────────\033[0m\n"
              << "  Total : " << (g_pass + g_fail) << "\n"
              << "  \033[32mPass  : " << g_pass << "\033[0m\n";
    if (g_fail > 0) {
        std::cout << "  \033[31mFail  : " << g_fail << "\033[0m\n\nFailed:\n";
        for (const auto& f : g_failures)
            std::cout << "  " << f << "\n";
    } else {
        std::cout << "  Fail  : 0\n";
    }
    std::cout << "\n";

    // [TEST-01 FIX]: Remove temp log files
    cleanupTempLogs();

    return (g_fail == 0) ? 0 : 1;
}
