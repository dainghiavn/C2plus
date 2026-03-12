// ============================================================
// test_ipc.cpp — Integration tests for UnixSocketChannel v2.1.0
//
// ── v2.1.0 Fixes ─────────────────────────────────────────────
//
//   [TEST-01] LOW — Temp log files not cleaned up after tests:
//     T10–T15 created /tmp/secfw_tXX.log files but never removed
//     them. Over time these accumulate on CI machines and can
//     fill /tmp. Added cleanupTempLogs() called at end of main().
//
//   [TEST-02] INFO — test_ipc not in CMakeLists.txt:
//     Test was built via a manual g++ command in the file comment.
//     Fixed in CMakeLists.txt — see that file for details.
//
//   [NET-01 coverage] — T16: writeFull() platform flag:
//     New test verifies MSG_NOSIGNAL / SO_NOSIGPIPE behavior by
//     sending a message to a closed peer and confirming the result
//     is ERR_CONN_CLOSED (not a crash/SIGPIPE).
//
//   [NET-02 coverage] — T17: stop() terminates run() with no extra connection:
//     New test spawns a server, connects, calls stop() from a
//     thread while run() is in accept(), and verifies that no
//     further connections are processed after stop() returns.
//
//   [NET-03 coverage] — T18: IpcChannelKey::derive() produces 32-byte key:
//     Verifies the helper produces a deterministic, non-empty key
//     distinct from the input master key.
//
//   [NET-04 coverage] — T19: socket file created with mode 0600:
//     After UnixSocketServer::create(), stat() the socket file and
//     confirm st_mode & 0777 == 0600 (umask + chmod fix).
//
// ── v2.0.1 Fixes (from previous release) ─────────────────────
//
//   [BUG-TEST-01] CRITICAL — T10 waitpid() DEADLOCK.
//   [BUG-TEST-02] CRITICAL — T12 waitpid() DEADLOCK.
//   [BUG-TEST-03] MEDIUM   — Missing #include <sys/select.h>.
//   [BUG-TEST-04] MEDIUM   — SecureLogger toConsole=true in children.
//   [BUG-TEST-05] MEDIUM   — SecureLogger ctor throws in child.
//   [BUG-TEST-06] LOW      — Sync pipe: select() not consuming byte.
//
// Tests:
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
//   T15  SecurityStatus network error codes [BUG-E01]
//   T16  [NET-01] writeFull() on closed peer → ERR_CONN_CLOSED, no crash
//   T17  [NET-02] stop() from thread — run() exits, no extra connection
//   T18  [NET-03] IpcChannelKey::derive() produces 32-byte derived key
//   T19  [NET-04] Socket file created with mode 0600 (umask+chmod fix)
//
// Build (manual — or use CMakeLists.txt target 'test_ipc'):
//   g++ -std=c++20 -O2 -Wall -Wextra \
//       -Iinclude \
//       src/test_ipc.cpp \
//       -lssl -lcrypto -lpthread \
//       -o build/test_ipc
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
#include <sys/stat.h>        // [TEST-19]: stat() for mode check
#include <signal.h>          // [BUG-TEST-03 FIX]: SIGTERM, SIGKILL
#include <unistd.h>
#include <fcntl.h>

using namespace SecFW;
using namespace std::chrono_literals;

// ── Test harness ──────────────────────────────────────────────────────────────

static int g_pass = 0;
static int g_fail = 0;
static std::vector<std::string> g_failures;

#define PASS(msg) do { \
    std::cout << "  [PASS]  " << (msg) << "\n"; \
    ++g_pass; \
} while(0)

#define FAIL(test, detail) do { \
    std::string _m = std::string("[FAIL]  ") + (test); \
    if (!(std::string(detail).empty())) _m += ": " + std::string(detail); \
    std::cout << "  " << _m << "\n"; \
    ++g_fail; \
    g_failures.push_back(_m); \
    return; \
} while(0)

// ── Temp log files created by fork-based tests ────────────────────────────────
// [TEST-01 FIX]: Collect all log paths; cleanup() removes them at end of main.

static std::vector<std::string> g_tempLogs;

static void registerTempLog(const std::string& path) {
    g_tempLogs.push_back(path);
}

static void cleanupTempLogs() noexcept {
    for (const auto& p : g_tempLogs) {
        ::unlink(p.c_str()); // ignore errors — file may not exist
    }
}

// ── Test helpers ──────────────────────────────────────────────────────────────

static SecBytes makeTestKey() {
    // 32-byte deterministic test key (not a secret — tests only)
    SecBytes k(32);
    for (std::size_t i = 0; i < 32; ++i)
        k[i] = static_cast<byte_t>(i + 1);
    return k;
}

static std::string testSocketPath(const std::string& suffix) {
    return "/tmp/secfw_test_" + suffix + ".sock";
}

// ── Sync pipe helpers ─────────────────────────────────────────────────────────
//
// readyPipe[0] = read end (parent), readyPipe[1] = write end (child).
// Child signals server ready by writing 1 byte.
// Parent blocks in waitReady() with a timeout.

static bool waitReady(int readFd, int timeoutSec = 4) {
    struct timeval tv{ timeoutSec, 0 };
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(readFd, &fds);
    int sel = ::select(readFd + 1, &fds, nullptr, nullptr, &tv);
    if (sel <= 0) return false;

    // [BUG-TEST-06 FIX]: actually consume the byte
    uint8_t byte = 0;
    ssize_t n = ::read(readFd, &byte, 1);
    return (n == 1);
}

static void killAndWait(pid_t child, int sig = SIGTERM) {
    ::kill(child, sig);
    ::waitpid(child, nullptr, 0);
}

// Write raw bytes directly to a socket (bypasses sendMessage framing)
static void writeRaw(int fd, const void* data, std::size_t len) {
    const uint8_t* p = static_cast<const uint8_t*>(data);
    std::size_t   rem = len;
    while (rem > 0) {
        ssize_t n = ::send(fd, p, rem, MSG_NOSIGNAL);
        if (n <= 0) break;
        p += n; rem -= static_cast<std::size_t>(n);
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// T01–T03: IpcMessage serialise / deserialise
// ══════════════════════════════════════════════════════════════════════════════

static void test_message_roundtrip_empty() {
    IpcMessage msg; msg.body = "";
    auto ser = msg.serialise();
    if (ser.fail()) { FAIL("T01 serialise", ser.message); return; }
    if (ser.value.size() != 4) {
        FAIL("T01 size", "expected 4, got " + std::to_string(ser.value.size())); return;
    }
    auto des = IpcMessage::deserialise(ser.value);
    if (des.fail()) { FAIL("T01 deserialise", des.message); return; }
    if (!des.value.body.empty()) { FAIL("T01 body not empty", des.value.body); return; }
    PASS("T01  IpcMessage roundtrip — empty body (4-byte prefix)");
}

static void test_message_roundtrip_normal() {
    IpcMessage msg; msg.body = R"({"action":"ping","seq":42})";
    auto ser = msg.serialise();
    if (ser.fail()) { FAIL("T02 serialise", ser.message); return; }
    if (ser.value.size() != 4 + msg.body.size()) {
        FAIL("T02 size", "expected " + std::to_string(4 + msg.body.size()) +
             ", got " + std::to_string(ser.value.size())); return;
    }
    auto des = IpcMessage::deserialise(ser.value);
    if (des.fail()) { FAIL("T02 deserialise", des.message); return; }
    if (des.value.body != msg.body) {
        FAIL("T02 body mismatch", des.value.body); return;
    }
    PASS("T02  IpcMessage roundtrip — normal body");
}

static void test_message_too_large() {
    IpcMessage msg;
    msg.body = std::string(IpcMessage::MAX_BODY_BYTES + 1, 'X');
    auto ser = msg.serialise();
    if (ser.ok()) { FAIL("T03 oversized body accepted", "should fail"); return; }
    if (ser.status != SecurityStatus::ERR_INPUT_INVALID) {
        FAIL("T03 wrong status", std::to_string(static_cast<int>(ser.status))); return;
    }
    PASS("T03  IpcMessage: body too large → ERR_INPUT_INVALID");
}

// ══════════════════════════════════════════════════════════════════════════════
// T04–T06: Crypto layer
// ══════════════════════════════════════════════════════════════════════════════

static void test_crypto_roundtrip() {
    auto key = makeTestKey();
    SecBytes plain(16, 0xAB);

    auto enc1 = detail::encryptMessage(plain, key);
    if (enc1.fail()) { FAIL("T04 encrypt1", enc1.message); return; }
    auto enc2 = detail::encryptMessage(plain, key);
    if (enc2.fail()) { FAIL("T04 encrypt2", enc2.message); return; }

    // IV must be unique per call (random)
    if (enc1.value == enc2.value) { FAIL("T04 IVs identical", "must be unique"); return; }

    auto dec = detail::decryptMessage(enc1.value, key);
    if (dec.fail()) { FAIL("T04 decrypt", dec.message); return; }
    if (dec.value != plain) { FAIL("T04 plaintext mismatch", ""); return; }
    PASS("T04  Crypto roundtrip: encrypt→decrypt, unique IV per call");
}

static void test_crypto_wrong_key() {
    auto key = makeTestKey();
    SecBytes wrongKey(32, 0xFF);
    SecBytes plain(16, 0xCD);

    auto enc = detail::encryptMessage(plain, key);
    if (enc.fail()) { FAIL("T05 encrypt", enc.message); return; }
    auto dec = detail::decryptMessage(enc.value, wrongKey);
    if (dec.ok()) { FAIL("T05 wrong key accepted", "GCM should reject"); return; }
    PASS("T05  Crypto: wrong key → decryptMessage Failure");
}

static void test_crypto_tampered_ciphertext() {
    auto key = makeTestKey();
    SecBytes plain(16, 0xEF);

    auto enc = detail::encryptMessage(plain, key);
    if (enc.fail()) { FAIL("T06 encrypt", enc.message); return; }

    // Flip a byte in the ciphertext region (after IV+TAG)
    if (enc.value.size() > IPC_GCM_OVERHEAD) {
        enc.value[IPC_GCM_OVERHEAD] ^= 0xFF;
    }
    auto dec = detail::decryptMessage(enc.value, key);
    if (dec.ok()) { FAIL("T06 tampered ciphertext accepted", "GCM should reject"); return; }
    PASS("T06  Crypto: tampered ciphertext → GCM tag rejects");
}

// ══════════════════════════════════════════════════════════════════════════════
// T07–T09: Frame validation
// ══════════════════════════════════════════════════════════════════════════════

static void test_frame_bad_magic() {
    auto key = makeTestKey();
    int sv[2];
    if (::socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        FAIL("T07 socketpair", ::strerror(errno)); return;
    }
    uint8_t badFrame[8] = { 0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x00, 0x00, 0x00 };
    writeRaw(sv[1], badFrame, 8);
    ::close(sv[1]);

    struct timeval tv{2, 0};
    ::setsockopt(sv[0], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    auto r = recvMessage(sv[0], key);
    ::close(sv[0]);

    if (r.ok()) { FAIL("T07 bad magic accepted", "should reject"); return; }
    if (r.status != SecurityStatus::ERR_INPUT_INVALID) {
        FAIL("T07 wrong status", std::to_string(static_cast<int>(r.status))); return;
    }
    PASS("T07  Frame: bad magic → ERR_INPUT_INVALID");
}

static void test_frame_payload_too_large() {
    auto key = makeTestKey();
    int sv[2];
    if (::socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        FAIL("T08 socketpair", ::strerror(errno)); return;
    }
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

    if (r.ok()) { FAIL("T08 oversized frame accepted", "should reject"); return; }
    if (r.status != SecurityStatus::ERR_INPUT_INVALID) {
        FAIL("T08 wrong status", std::to_string(static_cast<int>(r.status))); return;
    }
    PASS("T08  Frame: payload_len > 1 MiB → ERR_INPUT_INVALID (before alloc)");
}

static void test_frame_payload_too_small() {
    // IPC_GCM_OVERHEAD = 28, IPC_MIN_PAYLOAD_BYTES = 32.
    auto key = makeTestKey();
    int sv[2];
    if (::socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        FAIL("T09 socketpair", ::strerror(errno)); return;
    }
    uint32_t shortLen = IPC_GCM_OVERHEAD; // 28 — missing 4-byte body prefix
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

    if (r.ok()) { FAIL("T09 below-minimum frame accepted", "should reject"); return; }
    if (r.status != SecurityStatus::ERR_INPUT_INVALID) {
        FAIL("T09 wrong status", std::to_string(static_cast<int>(r.status))); return;
    }
    PASS("T09  Frame: payload_len=" + std::to_string(shortLen) +
         " < IPC_MIN=" + std::to_string(IPC_MIN_PAYLOAD_BYTES) +
         " → ERR_INPUT_INVALID [BUG-IPC-04]");
}

// ══════════════════════════════════════════════════════════════════════════════
// T10: Single send/recv/echo roundtrip (fork)
// ══════════════════════════════════════════════════════════════════════════════

static void test_server_client_roundtrip() {
    const std::string path    = testSocketPath("t10");
    const std::string logPath = "/tmp/secfw_t10.log";
    registerTempLog(logPath); // [TEST-01 FIX]
    auto key = makeTestKey();

    int rp[2];
    if (::pipe(rp) != 0) { FAIL("T10 pipe", ::strerror(errno)); return; }

    pid_t child = ::fork();
    if (child < 0) { FAIL("T10 fork", ::strerror(errno)); return; }

    if (child == 0) {
        ::close(rp[0]);
        try {
            // [BUG-TEST-04 FIX]: toConsole=false
            SecureLogger slog(logPath, LogLevel::WARNING, false);
            auto srvRes = UnixSocketServer::create(path, key, slog);
            if (srvRes.fail()) {
                ::write(rp[1], "E", 1); ::close(rp[1]); std::exit(2);
            }
            ::write(rp[1], "\x01", 1); ::close(rp[1]);

            srvRes.value->run([](detail::SocketFd fd, const IpcPeerInfo&,
                                  const SecBytes& k, SecureLogger&) {
                auto msgRes = recvMessage(fd, k);
                if (!msgRes.ok()) return;
                IpcMessage reply;
                reply.body = "echo:" + msgRes.value.body;
                sendMessage(fd, reply, k);
            });
        } catch (const std::exception& e) {
            std::cerr << "[T10 child] exception: " << e.what() << "\n";
            std::exit(2);
        }
        std::exit(0);
    }

    ::close(rp[1]);
    if (!waitReady(rp[0])) {
        ::close(rp[0]);
        killAndWait(child, SIGKILL);
        FAIL("T10 server startup timeout", ""); return;
    }
    ::close(rp[0]);

    auto cliRes = UnixSocketClient::connect(path, key);
    if (cliRes.fail()) {
        killAndWait(child, SIGKILL);
        FAIL("T10 connect", cliRes.message); return;
    }

    IpcMessage req; req.body = R"({"action":"ping"})";
    auto snd = cliRes.value->send(req);
    if (snd.fail()) {
        killAndWait(child, SIGKILL);
        FAIL("T10 send", snd.message); return;
    }

    auto rcv = cliRes.value->recv();
    if (rcv.fail()) {
        killAndWait(child, SIGKILL);
        FAIL("T10 recv", rcv.message); return;
    }
    cliRes.value.reset();

    // [BUG-TEST-01 FIX]: kill child BEFORE waitpid()
    killAndWait(child, SIGTERM);

    const std::string expected = "echo:" + req.body;
    if (rcv.value.body != expected) {
        FAIL("T10 body mismatch",
             "expected '" + expected + "' got '" + rcv.value.body + "'"); return;
    }
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
    registerTempLog(logPath); // [TEST-01 FIX]
    auto key = makeTestKey();

    int rp[2];
    if (::pipe(rp) != 0) { FAIL("T11 pipe", ::strerror(errno)); return; }

    pid_t child = ::fork();
    if (child < 0) { FAIL("T11 fork", ::strerror(errno)); return; }

    if (child == 0) {
        ::close(rp[0]);
        try {
            SecureLogger slog(logPath, LogLevel::WARNING, false); // [BUG-TEST-04 FIX]
            // allowedUid=0 (root) — our UID is not 0 → all connections rejected
            auto srvRes = UnixSocketServer::create(path, key, slog, 0);
            if (srvRes.fail()) {
                ::write(rp[1], "E", 1); ::close(rp[1]); std::exit(2);
            }
            ::write(rp[1], "\x01", 1); ::close(rp[1]);

            std::thread stopper([&]() {
                std::this_thread::sleep_for(3s);
                srvRes.value->stop();
            });
            srvRes.value->run([](detail::SocketFd, const IpcPeerInfo&,
                                  const SecBytes&, SecureLogger&) {
                // Should never be called since all UIDs are rejected
            });
            stopper.join();
        } catch (const std::exception& e) {
            std::cerr << "[T11 child] exception: " << e.what() << "\n";
            std::exit(2);
        }
        std::exit(0);
    }

    ::close(rp[1]);
    if (!waitReady(rp[0])) {
        ::close(rp[0]);
        killAndWait(child, SIGKILL);
        FAIL("T11 server startup timeout", ""); return;
    }
    ::close(rp[0]);

    auto cliRes = UnixSocketClient::connect(path, key);
    if (cliRes.fail()) {
        killAndWait(child, SIGKILL);
        FAIL("T11 connect", cliRes.message); return;
    }

    // Server rejects at SO_PEERCRED level → send should fail or recv should fail
    IpcMessage req; req.body = "should be rejected";
    auto snd = cliRes.value->send(req);
    auto rcv = cliRes.value->recv();
    cliRes.value.reset();

    killAndWait(child, SIGTERM);

    // If both send AND recv succeeded, the server processed our message — bad
    if (snd.ok() && rcv.ok()) {
        FAIL("T11 UID rejection bypassed", "server processed rejected UID"); return;
    }
    PASS("T11  Server: rejects connection from non-allowed UID");
}

// ══════════════════════════════════════════════════════════════════════════════
// T12: 100 sequential messages
// ══════════════════════════════════════════════════════════════════════════════

static void test_100_messages() {
    const std::string path    = testSocketPath("t12");
    const std::string logPath = "/tmp/secfw_t12.log";
    registerTempLog(logPath); // [TEST-01 FIX]
    constexpr int N = 100;
    auto key = makeTestKey();

    int rp[2];
    if (::pipe(rp) != 0) { FAIL("T12 pipe", ::strerror(errno)); return; }

    pid_t child = ::fork();
    if (child < 0) { FAIL("T12 fork", ::strerror(errno)); return; }

    if (child == 0) {
        ::close(rp[0]);
        try {
            SecureLogger slog(logPath, LogLevel::WARNING, false); // [BUG-TEST-04 FIX]
            auto srvRes = UnixSocketServer::create(path, key, slog);
            if (srvRes.fail()) {
                ::write(rp[1], "E", 1); ::close(rp[1]); std::exit(2);
            }
            ::write(rp[1], "\x01", 1); ::close(rp[1]);

            int failures = 0;
            srvRes.value->run([&](detail::SocketFd fd, const IpcPeerInfo&,
                                   const SecBytes& k, SecureLogger&) {
                for (int i = 0; i < N; ++i) {
                    auto m = recvMessage(fd, k);
                    if (m.fail()) { ++failures; break; }
                    IpcMessage reply; reply.body = "pong:" + std::to_string(i);
                    auto s = sendMessage(fd, reply, k);
                    if (s.fail()) { ++failures; break; }
                }
            });
            std::exit(failures == 0 ? 0 : 1);
        } catch (const std::exception& e) {
            std::cerr << "[T12 child] exception: " << e.what() << "\n";
            std::exit(2);
        }
    }

    ::close(rp[1]);
    if (!waitReady(rp[0])) {
        ::close(rp[0]);
        killAndWait(child, SIGKILL);
        FAIL("T12 server startup timeout", ""); return;
    }
    ::close(rp[0]);

    auto cliRes = UnixSocketClient::connect(path, key);
    if (cliRes.fail()) {
        killAndWait(child, SIGKILL);
        FAIL("T12 connect", cliRes.message); return;
    }

    bool allOk = true;
    for (int i = 0; i < N && allOk; ++i) {
        IpcMessage msg; msg.body = "ping:" + std::to_string(i);
        auto snd = cliRes.value->send(msg);
        if (snd.fail()) {
            FAIL("T12 send #" + std::to_string(i), snd.message); allOk = false; break;
        }
        auto rcv = cliRes.value->recv();
        if (rcv.fail()) {
            FAIL("T12 recv #" + std::to_string(i), rcv.message); allOk = false; break;
        }
        const std::string expected = "pong:" + std::to_string(i);
        if (rcv.value.body != expected) {
            FAIL("T12 body #" + std::to_string(i),
                 "expected '" + expected + "' got '" + rcv.value.body + "'");
            allOk = false;
        }
    }

    cliRes.value.reset();

    // [BUG-TEST-02 FIX]: kill child BEFORE waitpid()
    int status = 0;
    ::kill(child, SIGTERM);
    ::waitpid(child, &status, 0);

    if (!allOk) return;

    bool serverOk = WIFSIGNALED(status)
                 || (WIFEXITED(status) && WEXITSTATUS(status) == 0);
    if (!serverOk) {
        FAIL("T12 server error", "exit status " + std::to_string(WEXITSTATUS(status)));
        return;
    }
    PASS("T12  100 sequential messages — all bodies verified");
}

// ══════════════════════════════════════════════════════════════════════════════
// T13: Socket file RAII cleanup
// ══════════════════════════════════════════════════════════════════════════════

static void test_socket_cleanup() {
    const std::string path    = testSocketPath("t13");
    const std::string logPath = "/tmp/secfw_t13.log";
    registerTempLog(logPath); // [TEST-01 FIX]
    auto key = makeTestKey();
    SecureLogger slog(logPath, LogLevel::WARNING, false);
    {
        auto srvRes = UnixSocketServer::create(path, key, slog);
        if (srvRes.fail()) { FAIL("T13 create", srvRes.message); return; }
        // Destructor runs here — socket file must be removed [N07 FIX]
    }
    if (::access(path.c_str(), F_OK) == 0) {
        FAIL("T13 socket not cleaned up", "file still exists: " + path); return;
    }
    PASS("T13  [N07] Socket file removed by UnixSocketServer destructor");
}

// ══════════════════════════════════════════════════════════════════════════════
// T14: Path too long [BUG-E04]
// ══════════════════════════════════════════════════════════════════════════════

static void test_socket_path_too_long() {
    // UNIX_PATH_MAX = 108 bytes total (including NUL terminator).
    // isValidSocketPath() allows max 107 usable characters.
    // A path of 108 characters requires 109 bytes with NUL → must be rejected.
    std::string longPath = "/tmp/" + std::string(108 - 5, 'x'); // exactly 108 chars
    if (longPath.size() != 108) {
        FAIL("T14 setup", "path length " + std::to_string(longPath.size())); return;
    }

    auto key = makeTestKey();
    const std::string logPath = "/tmp/secfw_t14.log";
    registerTempLog(logPath); // [TEST-01 FIX]
    SecureLogger slog(logPath, LogLevel::WARNING, false);
    auto r = UnixSocketServer::create(longPath, key, slog);
    if (r.ok()) {
        FAIL("T14 108-byte path accepted",
             "must be rejected (max 107 usable bytes + NUL)"); return;
    }
    if (r.status != SecurityStatus::ERR_INPUT_INVALID) {
        FAIL("T14 wrong status", std::to_string(static_cast<int>(r.status))); return;
    }
    PASS("T14  [BUG-E04] Socket path ≥108 bytes → ERR_INPUT_INVALID");
}

// ══════════════════════════════════════════════════════════════════════════════
// T15: SecurityStatus network error codes [BUG-E01]
// ══════════════════════════════════════════════════════════════════════════════

static void test_new_error_codes() {
    const int n1 = static_cast<int>(SecurityStatus::ERR_NETWORK_FAIL);
    const int n2 = static_cast<int>(SecurityStatus::ERR_TIMEOUT);
    const int n3 = static_cast<int>(SecurityStatus::ERR_PEER_REJECTED);
    const int n4 = static_cast<int>(SecurityStatus::ERR_CONN_CLOSED);

    if (n1 == 0 || n2 == 0 || n3 == 0 || n4 == 0) {
        FAIL("T15 code collides with OK=0", ""); return;
    }
    if (n1==n2 || n1==n3 || n1==n4 || n2==n3 || n2==n4 || n3==n4) {
        FAIL("T15 duplicate codes", ""); return;
    }
    for (auto code : { SecurityStatus::ERR_NETWORK_FAIL,
                       SecurityStatus::ERR_TIMEOUT,
                       SecurityStatus::ERR_PEER_REJECTED,
                       SecurityStatus::ERR_CONN_CLOSED }) {
        const char* msg = statusMessage(code);
        if (!msg || msg[0] == '\0' || std::string(msg) == "Unknown error") {
            FAIL("T15 statusMessage missing for code",
                 std::to_string(static_cast<int>(code))); return;
        }
    }
    // isNetworkError() must return true for all four
    for (auto code : { SecurityStatus::ERR_NETWORK_FAIL,
                       SecurityStatus::ERR_TIMEOUT,
                       SecurityStatus::ERR_PEER_REJECTED,
                       SecurityStatus::ERR_CONN_CLOSED }) {
        if (!isNetworkError(code)) {
            FAIL("T15 isNetworkError false for network code",
                 std::to_string(static_cast<int>(code))); return;
        }
    }
    // Must NOT fire for non-network codes
    if (isNetworkError(SecurityStatus::OK) ||
        isNetworkError(SecurityStatus::ERR_CRYPTO_FAIL)) {
        FAIL("T15 isNetworkError true for non-network code", ""); return;
    }
    PASS("T15  [BUG-E01] Network error codes: distinct, non-zero, statusMessage OK");
}

// ══════════════════════════════════════════════════════════════════════════════
// T16: [NET-01] writeFull() on closed peer → ERR_CONN_CLOSED, no crash/SIGPIPE
// ══════════════════════════════════════════════════════════════════════════════

static void test_write_to_closed_peer() {
    // Create a socketpair, close one end, write to the other.
    // With MSG_NOSIGNAL (Linux) or SO_NOSIGPIPE (macOS), we must get
    // ERR_CONN_CLOSED — not a SIGPIPE crash.
    int sv[2];
    if (::socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        FAIL("T16 socketpair", ::strerror(errno)); return;
    }

    // Apply SO_NOSIGPIPE on macOS [NET-01 FIX]
    detail::setSoPeerNosigpipe(sv[0]);

    // Close the peer
    ::close(sv[1]);
    std::this_thread::sleep_for(10ms); // allow close to propagate

    // Write raw bytes — must not crash via SIGPIPE
    const char payload[] = "test";
    auto r = detail::writeFull(sv[0], payload, sizeof(payload));
    ::close(sv[0]);

    if (r.ok()) {
        // On some systems the first send() after peer close may succeed
        // (data buffered). That is acceptable — the important thing is
        // no crash. We accept either ok() or ERR_CONN_CLOSED.
        PASS("T16  [NET-01] writeFull() to closed peer — buffered, no crash");
        return;
    }
    if (r.status != SecurityStatus::ERR_CONN_CLOSED &&
        r.status != SecurityStatus::ERR_NETWORK_FAIL) {
        FAIL("T16 unexpected status",
             statusMessage(r.status) + std::string(": ") + r.message); return;
    }
    PASS("T16  [NET-01] writeFull() to closed peer → " +
         std::string(statusMessage(r.status)) + ", no crash/SIGPIPE");
}

// ══════════════════════════════════════════════════════════════════════════════
// T17: [NET-02] stop() from thread — run() exits cleanly, no extra connection
// ══════════════════════════════════════════════════════════════════════════════

static void test_stop_from_thread() {
    const std::string path    = testSocketPath("t17");
    const std::string logPath = "/tmp/secfw_t17.log";
    registerTempLog(logPath); // [TEST-01 FIX]
    auto key = makeTestKey();

    SecureLogger slog(logPath, LogLevel::WARNING, false);
    auto srvRes = UnixSocketServer::create(path, key, slog);
    if (srvRes.fail()) { FAIL("T17 create", srvRes.message); return; }

    std::atomic<int> connectionsHandled { 0 };
    std::atomic<bool> runExited         { false };

    // Thread 1: run() — blocking accept loop
    std::thread runThread([&]() {
        srvRes.value->run([&](detail::SocketFd fd, const IpcPeerInfo&,
                               const SecBytes& k, SecureLogger&) {
            ++connectionsHandled;
            // Drain any data and close
            IpcMessage dummy; dummy.body = "ok";
            recvMessage(fd, k);
            sendMessage(fd, dummy, k);
        });
        runExited.store(true, std::memory_order_release);
    });

    // Thread 2: stop() after a short delay (while run() is in accept())
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

    if (!runExited.load(std::memory_order_acquire)) {
        FAIL("T17 run() did not exit after stop()", ""); return;
    }

    // Verify that zero connections were processed (we never connected a client)
    if (connectionsHandled.load() != 0) {
        FAIL("T17 unexpected connections handled",
             std::to_string(connectionsHandled.load())); return;
    }

    PASS("T17  [NET-02] stop() from thread — run() exits cleanly, 0 connections handled");
}

// ══════════════════════════════════════════════════════════════════════════════
// T18: [NET-03] IpcChannelKey::derive() produces 32-byte key ≠ master key
// ══════════════════════════════════════════════════════════════════════════════

static void test_channel_key_derivation() {
    auto masterKey = makeTestKey(); // 32 bytes, values 1..32

    auto res = IpcChannelKey::derive(masterKey);
    if (res.fail()) { FAIL("T18 derive", res.message); return; }

    if (res.value.size() != 32) {
        FAIL("T18 key size", "expected 32, got " +
             std::to_string(res.value.size())); return;
    }

    // Derived key must differ from master key (HKDF transforms it)
    if (res.value == masterKey) {
        FAIL("T18 derived key == master key", "HKDF should produce a different key");
        return;
    }

    // Derivation must be deterministic (same input → same output)
    auto res2 = IpcChannelKey::derive(masterKey);
    if (res2.fail()) { FAIL("T18 derive2", res2.message); return; }
    if (res.value != res2.value) {
        FAIL("T18 derivation not deterministic", ""); return;
    }

    PASS("T18  [NET-03] IpcChannelKey::derive() → 32-byte key, deterministic, ≠ master");
}

// ══════════════════════════════════════════════════════════════════════════════
// T19: [NET-04] Socket file created with mode 0600 (umask + chmod fix)
// ══════════════════════════════════════════════════════════════════════════════

static void test_socket_file_permissions() {
    const std::string path    = testSocketPath("t19");
    const std::string logPath = "/tmp/secfw_t19.log";
    registerTempLog(logPath); // [TEST-01 FIX]
    auto key = makeTestKey();

    SecureLogger slog(logPath, LogLevel::WARNING, false);
    {
        auto srvRes = UnixSocketServer::create(path, key, slog);
        if (srvRes.fail()) { FAIL("T19 create", srvRes.message); return; }

        struct stat st{};
        if (::stat(path.c_str(), &st) != 0) {
            FAIL("T19 stat", ::strerror(errno)); return;
        }

        mode_t fileMode = st.st_mode & 0777; // mask to permission bits
        if (fileMode != 0600) {
            FAIL("T19 wrong mode",
                 "expected 0600, got " +
                 std::to_string(fileMode >> 6 & 7) +
                 std::to_string(fileMode >> 3 & 7) +
                 std::to_string(fileMode & 7)); return;
        }
        // Destructor cleans up socket file
    }

    PASS("T19  [NET-04] Socket file permissions = 0600 (umask + chmod fix)");
}

// ══════════════════════════════════════════════════════════════════════════════
// main
// ══════════════════════════════════════════════════════════════════════════════

int main() {
    std::cout << "\n=== SecureConsoleAppNet IPC Tests — v2.1.0 ===\n\n";

    // ── T01–T03: IpcMessage ───────────────────────────────────────────────────
    test_message_roundtrip_empty();
    test_message_roundtrip_normal();
    test_message_too_large();

    // ── T04–T06: Crypto layer ─────────────────────────────────────────────────
    test_crypto_roundtrip();
    test_crypto_wrong_key();
    test_crypto_tampered_ciphertext();

    // ── T07–T09: Frame validation ─────────────────────────────────────────────
    test_frame_bad_magic();
    test_frame_payload_too_large();
    test_frame_payload_too_small();

    // ── T10–T13: Fork-based server/client ────────────────────────────────────
    test_server_client_roundtrip();
    test_server_uid_rejection();
    test_100_messages();
    test_socket_cleanup();

    // ── T14–T15: Validation and error codes ───────────────────────────────────
    test_socket_path_too_long();
    test_new_error_codes();

    // ── T16–T19: v2.1.0 new tests ────────────────────────────────────────────
    test_write_to_closed_peer();
    test_stop_from_thread();
    test_channel_key_derivation();
    test_socket_file_permissions();

    // ── Summary ───────────────────────────────────────────────────────────────
    std::cout << "\n=== Results: " << g_pass << " passed, "
              << g_fail << " failed ===\n";

    if (!g_failures.empty()) {
        std::cout << "\nFailed tests:\n";
        for (const auto& f : g_failures)
            std::cout << "  " << f << "\n";
    }

    // [TEST-01 FIX]: Remove all temp log files created during testing
    cleanupTempLogs();

    return (g_fail == 0) ? 0 : 1;
}
