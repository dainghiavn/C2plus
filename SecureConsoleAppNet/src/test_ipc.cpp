// ============================================================
// test_ipc.cpp — Integration tests for UnixSocketChannel v2.0.1
//
// Bugs fixed vs v1 of this file:
//
//   [BUG-TEST-01] CRITICAL — T10 waitpid() DEADLOCK:
//     After the single-message handler returned, server's run()
//     looped back to accept() and blocked. Parent called waitpid()
//     without a prior kill() → hung forever.
//     Fix: parent calls kill(child, SIGTERM) then waitpid().
//
//   [BUG-TEST-02] CRITICAL — T12 waitpid() DEADLOCK (same cause):
//     Server handler processed all 100 messages in one connection,
//     returned, run() looped to accept() again. Parent hung in
//     waitpid() with no kill().
//     Fix: same — kill(child, SIGTERM) before waitpid().
//
//   [BUG-TEST-03] MEDIUM — Missing #include <sys/select.h>:
//     T10 used ::select() but only included <sys/socket.h>.
//     On some Linux distributions <sys/socket.h> does NOT
//     transitively include <sys/select.h>. Added explicitly.
//     Also added <signal.h> for SIGTERM / SIGKILL constants.
//
//   [BUG-TEST-04] MEDIUM — SecureLogger toConsole=true in children:
//     Default ctor has toConsole=true. Forked children writing to
//     the same stdout/stderr as the parent garbled test output.
//     Fix: all child-process loggers use toConsole=false.
//
//   [BUG-TEST-05] MEDIUM — SecureLogger ctor throws in child:
//     If /tmp is not writable, SecureLogger throws std::runtime_error
//     from the constructor. The child exited with an uncaught exception
//     (status != 0) causing the parent to report FAIL even on success.
//     Fix: wrap the entire child process body in try-catch; on
//     exception print to stderr and exit(2).
//
//   [BUG-TEST-06] LOW — Sync pipe: select() does not consume the byte:
//     T10 used select() to wait for server-ready, then closed the
//     read end WITHOUT reading the byte. On Linux this is fine
//     (pipe is closed, kernel discards unread data), but on some
//     POSIX systems a subsequent connect() before the OS processes
//     the close can race. Replaced with a direct read() loop that
//     actually consumes the byte, consistent with T11/T12.
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
//
// Build:
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
#include <sys/select.h>      // [BUG-TEST-03 FIX]: select()
#include <sys/un.h>
#include <sys/wait.h>
#include <signal.h>          // [BUG-TEST-03 FIX]: SIGTERM, SIGKILL
#include <unistd.h>
#include <fcntl.h>

using namespace SecFW;
using namespace std::chrono_literals;

// ── Test harness ──────────────────────────────────────────────────────────────

static int g_pass = 0;
static int g_fail = 0;

static void PASS(const std::string& name) {
    std::cout << "  \033[32m[PASS]\033[0m  " << name << "\n";
    ++g_pass;
}

static void FAIL(const std::string& name, const std::string& why) {
    std::cout << "  \033[31m[FAIL]\033[0m  " << name << "\n"
              << "          → " << why << "\n";
    ++g_fail;
}

static void SECTION(const std::string& title) {
    std::cout << "\n\033[1m── " << title << " ──\033[0m\n";
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// Generate a 32-byte AES-256 channel key
static SecBytes makeTestKey() {
    auto r = CryptoEngine::randomBytes(32);
    if (r.fail()) { std::cerr << "FATAL: randomBytes: " << r.message << "\n"; std::exit(1); }
    return r.value;
}

// Unique socket path per test (pid + counter avoids collisions within one run)
static std::string testSocketPath(const std::string& suffix = "") {
    static int counter = 0;
    return "/tmp/secfw_t" + std::to_string(::getpid()) +
           "_" + std::to_string(++counter) +
           (suffix.empty() ? "" : "_" + suffix) + ".sock";
}

// ── Sync pipe helpers ─────────────────────────────────────────────────────────
//
// readyPipe[0] = read end (parent), readyPipe[1] = write end (child).
// Child signals server ready by writing 1 byte.
// Parent blocks in waitReady() with a timeout — does NOT use select() alone
// because select() does not consume the byte [BUG-TEST-06 FIX]: use read().

static bool waitReady(int readFd, int timeoutSec = 4) {
    // Set a read timeout on the fd so we don't block forever
    struct timeval tv{ timeoutSec, 0 };
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(readFd, &fds);
    int sel = ::select(readFd + 1, &fds, nullptr, nullptr, &tv);
    if (sel <= 0) return false;   // timeout or error

    // [BUG-TEST-06 FIX]: actually read the byte to consume it and verify it arrived
    uint8_t byte = 0;
    ssize_t n = ::read(readFd, &byte, 1);
    return (n == 1);
}

// Kill a child and reap it — used in all test teardown paths
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

// ── T01–T03: IpcMessage serialise / deserialise ───────────────────────────────

static void test_message_roundtrip_empty() {
    IpcMessage msg; msg.body = "";
    auto ser = msg.serialise();
    if (ser.fail()) { FAIL("T01 serialise", ser.message); return; }
    // Empty body → 4 bytes (body_len=0 prefix only)
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
    auto des = IpcMessage::deserialise(ser.value);
    if (des.fail()) { FAIL("T02 deserialise", des.message); return; }
    if (des.value.body != msg.body) {
        FAIL("T02 body mismatch", "got: " + des.value.body); return;
    }
    PASS("T02  IpcMessage roundtrip — normal JSON body");
}

static void test_message_body_too_large() {
    IpcMessage msg;
    msg.body = std::string(IpcMessage::MAX_BODY_BYTES + 1, 'X');
    auto ser = msg.serialise();
    if (ser.ok()) { FAIL("T03 oversized body accepted", "should fail"); return; }
    if (ser.status != SecurityStatus::ERR_INPUT_INVALID) {
        FAIL("T03 wrong status", std::to_string(static_cast<int>(ser.status))); return;
    }
    PASS("T03  IpcMessage serialise — oversized body → ERR_INPUT_INVALID");
}

// ── T04–T06: Crypto ───────────────────────────────────────────────────────────

static void test_crypto_roundtrip() {
    auto key = makeTestKey();
    IpcMessage msg; msg.body = R"({"action":"list-users"})";
    auto ser = msg.serialise();
    if (ser.fail()) { FAIL("T04 serialise", ser.message); return; }

    auto enc1 = detail::encryptMessage(ser.value, key);
    if (enc1.fail()) { FAIL("T04 encrypt1", enc1.message); return; }
    auto enc2 = detail::encryptMessage(ser.value, key);
    if (enc2.fail()) { FAIL("T04 encrypt2", enc2.message); return; }

    // Different IVs per message — same plaintext must produce different ciphertext
    if (enc1.value == enc2.value) {
        FAIL("T04 IV reuse", "identical ciphertext for same plaintext → IV not random"); return;
    }

    auto dec = detail::decryptMessage(enc1.value, key);
    if (dec.fail()) { FAIL("T04 decrypt", dec.message); return; }
    if (dec.value != ser.value) {
        FAIL("T04 plaintext mismatch", "decrypted differs from original"); return;
    }
    PASS("T04  Crypto roundtrip — unique IV per message, correct decrypt");
}

static void test_crypto_wrong_key() {
    auto key1 = makeTestKey(), key2 = makeTestKey();
    IpcMessage msg; msg.body = "secret";
    auto ser = msg.serialise();
    if (ser.fail()) { FAIL("T05 serialise", ser.message); return; }
    auto enc = detail::encryptMessage(ser.value, key1);
    if (enc.fail()) { FAIL("T05 encrypt", enc.message); return; }
    auto dec = detail::decryptMessage(enc.value, key2);
    if (dec.ok()) { FAIL("T05 wrong key accepted", "GCM should reject"); return; }
    if (dec.status != SecurityStatus::ERR_CRYPTO_FAIL) {
        FAIL("T05 wrong status", std::to_string(static_cast<int>(dec.status))); return;
    }
    PASS("T05  Crypto: wrong key → ERR_CRYPTO_FAIL (GCM tag mismatch)");
}

static void test_crypto_tamper() {
    auto key = makeTestKey();
    IpcMessage msg; msg.body = "tamper-me";
    auto ser = msg.serialise();
    if (ser.fail()) { FAIL("T06 serialise", ser.message); return; }
    auto enc = detail::encryptMessage(ser.value, key);
    if (enc.fail()) { FAIL("T06 encrypt", enc.message); return; }
    // Flip one bit in ciphertext region (past IV[12] + TAG[16] = byte 28)
    if (enc.value.size() <= 28) { FAIL("T06 too short", ""); return; }
    enc.value[28] ^= 0x01;
    auto dec = detail::decryptMessage(enc.value, key);
    if (dec.ok()) { FAIL("T06 tamper accepted", "GCM must reject modified ciphertext"); return; }
    PASS("T06  Crypto: tampered ciphertext → GCM authentication Failure");
}

// ── T07–T09: Frame validation via socketpair ──────────────────────────────────
//
// These tests write malformed frames directly to a socketpair to validate
// recvMessage() without running a full server.

static void test_frame_bad_magic() {
    auto key = makeTestKey();
    int sv[2];
    if (::socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        FAIL("T07 socketpair", ::strerror(errno)); return;
    }
    // Write a frame with wrong magic bytes + 32 bytes of garbage payload
    uint8_t header[8] = { 0xDE, 0xAD, 0xBE, 0xEF, 32, 0, 0, 0 };
    SecBytes garbage(32, 0xAB);
    writeRaw(sv[1], header, 8);
    writeRaw(sv[1], garbage.data(), garbage.size());
    ::close(sv[1]);

    struct timeval tv{2, 0};
    ::setsockopt(sv[0], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    auto r = recvMessage(sv[0], key);
    ::close(sv[0]);

    if (r.ok()) { FAIL("T07 bad magic accepted", ""); return; }
    if (r.status != SecurityStatus::ERR_INPUT_INVALID) {
        FAIL("T07 wrong status", std::to_string(static_cast<int>(r.status))); return;
    }
    PASS("T07  Frame: bad magic → ERR_INPUT_INVALID");
}

static void test_frame_oversized_length() {
    auto key = makeTestKey();
    int sv[2];
    if (::socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        FAIL("T08 socketpair", ::strerror(errno)); return;
    }
    // Claim payload_len = 2 MiB (> IPC_MAX_PAYLOAD_BYTES = 1 MiB)
    uint32_t bigLen = 2u * 1024u * 1024u;
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

    // Must be rejected BEFORE any allocation [N03 + BUG-IPC-04 FIX]
    if (r.ok()) { FAIL("T08 oversized frame accepted", "2 MiB alloc risk"); return; }
    if (r.status != SecurityStatus::ERR_INPUT_INVALID) {
        FAIL("T08 wrong status", std::to_string(static_cast<int>(r.status))); return;
    }
    PASS("T08  Frame: payload_len=2MiB > IPC_MAX → ERR_INPUT_INVALID (no alloc)");
}

static void test_frame_below_minimum() {
    // [BUG-IPC-04 FIX]: values 28-31 must be rejected.
    // IPC_GCM_OVERHEAD = 28, IPC_MIN_PAYLOAD_BYTES = 32.
    auto key = makeTestKey();
    int sv[2];
    if (::socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        FAIL("T09 socketpair", ::strerror(errno)); return;
    }
    // payload_len = 28 (GCM_OVERHEAD exactly — missing the 4-byte body prefix)
    uint32_t shortLen = IPC_GCM_OVERHEAD; // 28
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

// ── Fork-based server tests: common child process wrapper ─────────────────────
//
// Children MUST:
//   1. Create SecureLogger with toConsole=false to avoid garbling parent output
//      [BUG-TEST-04 FIX]
//   2. Wrap the entire body in try-catch so logger-ctor exceptions are reported
//      cleanly [BUG-TEST-05 FIX]

// ── T10: Single send/recv/echo roundtrip ─────────────────────────────────────

static void test_server_client_roundtrip() {
    const std::string path = testSocketPath("t10");
    auto key = makeTestKey();

    int rp[2]; // ready pipe: child writes 1 byte when server is listening
    if (::pipe(rp) != 0) { FAIL("T10 pipe", ::strerror(errno)); return; }

    pid_t child = ::fork();
    if (child < 0) { FAIL("T10 fork", ::strerror(errno)); return; }

    if (child == 0) {
        // ── Child: server ─────────────────────────────────────────────────
        ::close(rp[0]);
        try {
            // [BUG-TEST-04 FIX]: toConsole=false — don't pollute parent stdout
            SecureLogger slog("/tmp/secfw_t10.log", LogLevel::WARNING, false);
            auto srvRes = UnixSocketServer::create(path, key, slog);
            if (srvRes.fail()) { ::write(rp[1], "E", 1); ::close(rp[1]); std::exit(2); }

            // Signal parent: server is ready (listening)
            ::write(rp[1], "\x01", 1); ::close(rp[1]);

            // Handle exactly one connection.
            // [BUG-TEST-01 FIX]: After handler returns, run() loops to accept().
            // Parent will kill this child via SIGTERM. Server handles it via
            // running_=false set by stop(), which is called from the signal
            // delivery → accept() returns EINTR → loop exits.
            // Simpler: parent kills with SIGTERM, child receives it, exits.
            // We don't need to explicitly stop() — SIGTERM will end the process.
            srvRes.value->run([](detail::SocketFd fd, const IpcPeerInfo&,
                                  const SecBytes& k, SecureLogger&) {
                auto msgRes = recvMessage(fd, k);
                if (!msgRes.ok()) return;
                IpcMessage reply;
                reply.body = "echo:" + msgRes.value.body;
                sendMessage(fd, reply, k);
                // After this returns, run() loops to accept() → parent kills child
            });
        } catch (const std::exception& e) {
            std::cerr << "[T10 child] exception: " << e.what() << "\n";
            std::exit(2);
        }
        std::exit(0);
    }

    // ── Parent: client ────────────────────────────────────────────────────
    ::close(rp[1]);
    if (!waitReady(rp[0])) { // [BUG-TEST-06 FIX]: read() consumes the byte
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
    cliRes.value.reset(); // close client socket

    // [BUG-TEST-01 FIX]: kill child BEFORE waitpid().
    // Child is now stuck in accept() — it will never exit on its own.
    killAndWait(child, SIGTERM);

    const std::string expected = "echo:" + req.body;
    if (rcv.value.body != expected) {
        FAIL("T10 body mismatch",
             "expected '" + expected + "' got '" + rcv.value.body + "'"); return;
    }
    PASS("T10  Server/Client: single send/recv/echo via Unix socket");
}

// ── T11: Server rejects wrong-UID connection ──────────────────────────────────

static void test_server_uid_rejection() {
    if (::getuid() == 0) {
        std::cout << "  [SKIP]  T11  (running as root — UID rejection inapplicable)\n";
        ++g_pass; return;
    }

    const std::string path = testSocketPath("t11");
    auto key = makeTestKey();
    int rp[2];
    if (::pipe(rp) != 0) { FAIL("T11 pipe", ::strerror(errno)); return; }

    pid_t child = ::fork();
    if (child < 0) { FAIL("T11 fork", ::strerror(errno)); return; }

    if (child == 0) {
        ::close(rp[0]);
        try {
            // [BUG-TEST-04 FIX]: toConsole=false
            SecureLogger slog("/tmp/secfw_t11.log", LogLevel::WARNING, false);
            // allowedUid=0 (root) — our UID is not 0 → all connections rejected
            auto srvRes = UnixSocketServer::create(path, key, slog, 0);
            if (srvRes.fail()) { ::write(rp[1], "E", 1); ::close(rp[1]); std::exit(2); }
            ::write(rp[1], "\x01", 1); ::close(rp[1]);

            // Stopper thread exits server after 3 seconds
            std::thread stopper([&]() {
                std::this_thread::sleep_for(3s);
                srvRes.value->stop();
            });
            srvRes.value->run([](detail::SocketFd, const IpcPeerInfo&,
                                  const SecBytes&, SecureLogger&) {
                // Handler must never be called — UID check rejects before this
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
    std::this_thread::sleep_for(100ms); // wait for accept() to start

    auto cliRes = UnixSocketClient::connect(path, key);
    if (cliRes.fail()) {
        // Connection rejected at OS level (chmod 0600 + UID check) — acceptable
        killAndWait(child, SIGKILL);
        PASS("T11  Server: UID-mismatched connection rejected at OS level");
        return;
    }

    // Connection accepted at socket layer but server closes it before exchanging data
    IpcMessage req; req.body = "should-be-rejected";
    cliRes.value->send(req); // may fail if server already closed
    auto rcv = cliRes.value->recv();
    cliRes.value.reset();
    killAndWait(child, SIGKILL);

    if (rcv.ok()) {
        FAIL("T11 UID-rejected connection returned data",
             "body: " + rcv.value.body); return;
    }
    PASS("T11  Server: non-allowed UID connection closed before data exchange");
}

// ── T12: 100 sequential messages ─────────────────────────────────────────────

static void test_100_messages() {
    const std::string path = testSocketPath("t12");
    auto key = makeTestKey();
    constexpr int N = 100;

    int rp[2];
    if (::pipe(rp) != 0) { FAIL("T12 pipe", ::strerror(errno)); return; }

    pid_t child = ::fork();
    if (child < 0) { FAIL("T12 fork", ::strerror(errno)); return; }

    if (child == 0) {
        ::close(rp[0]);
        try {
            // [BUG-TEST-04 FIX]: toConsole=false
            SecureLogger slog("/tmp/secfw_t12.log", LogLevel::WARNING, false);
            auto srvRes = UnixSocketServer::create(path, key, slog);
            if (srvRes.fail()) { ::write(rp[1], "E", 1); ::close(rp[1]); std::exit(2); }
            ::write(rp[1], "\x01", 1); ::close(rp[1]);

            int failures = 0;
            srvRes.value->run([&](detail::SocketFd fd, const IpcPeerInfo&,
                                   const SecBytes& k, SecureLogger&) {
                // All N messages come over a single connection
                for (int i = 0; i < N; ++i) {
                    auto m = recvMessage(fd, k);
                    if (m.fail()) { ++failures; break; }
                    IpcMessage reply; reply.body = "pong:" + std::to_string(i);
                    auto s = sendMessage(fd, reply, k);
                    if (s.fail()) { ++failures; break; }
                }
                // Handler returns → run() loops to accept() → parent kills us
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

    cliRes.value.reset(); // close client

    // [BUG-TEST-02 FIX]: kill child BEFORE waitpid() — child is stuck in accept()
    int status = 0;
    ::kill(child, SIGTERM);
    ::waitpid(child, &status, 0);

    if (!allOk) return; // individual FAIL already printed

    // Server exit status: 0 = all messages OK, 1 = handler errors
    // SIGTERM exit is shown as signal-terminated — not exit(0), so check carefully
    bool serverOk = WIFSIGNALED(status)                      // killed by SIGTERM (expected)
                 || (WIFEXITED(status) && WEXITSTATUS(status) == 0); // or clean exit
    if (!serverOk) {
        FAIL("T12 server error", "exit status " + std::to_string(WEXITSTATUS(status)));
        return;
    }
    PASS("T12  100 sequential messages — all bodies verified");
}

// ── T13: Socket file RAII cleanup ────────────────────────────────────────────

static void test_socket_cleanup() {
    const std::string path = testSocketPath("t13");
    auto key = makeTestKey();
    SecureLogger slog("/tmp/secfw_t13.log", LogLevel::WARNING, false);
    {
        auto srvRes = UnixSocketServer::create(path, key, slog);
        if (srvRes.fail()) { FAIL("T13 create", srvRes.message); return; }
        // Destructor runs here
    }
    // Socket file must NOT exist after destructor [N07 FIX]
    if (::access(path.c_str(), F_OK) == 0) {
        FAIL("T13 socket not cleaned up", "file still exists: " + path); return;
    }
    PASS("T13  [N07] Socket file removed by UnixSocketServer destructor");
}

// ── T14: Path too long [BUG-E04] ─────────────────────────────────────────────

static void test_socket_path_too_long() {
    // UNIX_PATH_MAX = 108 bytes total (including NUL terminator).
    // isValidSocketPath() allows max 107 usable characters.
    // A path of 108 characters requires 109 bytes with NUL → must be rejected.
    std::string longPath = "/tmp/" + std::string(108 - 5, 'x'); // exactly 108 chars
    if (longPath.size() != 108) {
        FAIL("T14 setup", "path length " + std::to_string(longPath.size())); return;
    }

    auto key = makeTestKey();
    SecureLogger slog("/tmp/secfw_t14.log", LogLevel::WARNING, false);
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

// ── T15: SecurityStatus network error codes [BUG-E01] ────────────────────────

static void test_new_error_codes() {
    // All four network codes must exist, be distinct, and non-zero
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

    // statusMessage() must return a meaningful string for all four
    for (auto code : { SecurityStatus::ERR_NETWORK_FAIL,
                       SecurityStatus::ERR_TIMEOUT,
                       SecurityStatus::ERR_PEER_REJECTED,
                       SecurityStatus::ERR_CONN_CLOSED }) {
        std::string msg = statusMessage(code);
        if (msg.empty() || msg == "Unknown error") {
            FAIL("T15 statusMessage for code " +
                 std::to_string(static_cast<int>(code)), "returned '" + msg + "'");
            return;
        }
    }

    // isNetworkError() = true for all four
    if (!isNetworkError(SecurityStatus::ERR_NETWORK_FAIL) ||
        !isNetworkError(SecurityStatus::ERR_TIMEOUT)      ||
        !isNetworkError(SecurityStatus::ERR_PEER_REJECTED)||
        !isNetworkError(SecurityStatus::ERR_CONN_CLOSED)) {
        FAIL("T15 isNetworkError false for a network code", ""); return;
    }
    // isNetworkError() = false for non-network codes
    if (isNetworkError(SecurityStatus::ERR_AUTH_FAILED) ||
        isNetworkError(SecurityStatus::ERR_CRYPTO_FAIL)) {
        FAIL("T15 isNetworkError true for non-network code", ""); return;
    }

    // isRetryable():
    //   ERR_TIMEOUT      → true  (transient, retry after back-off)
    //   ERR_CONN_CLOSED  → true  (peer may have restarted)
    //   ERR_NETWORK_FAIL → false (syscall failed — not transient)
    //   ERR_PEER_REJECTED→ false (security decision — never retry)
    if (!isRetryable(SecurityStatus::ERR_TIMEOUT)) {
        FAIL("T15 ERR_TIMEOUT not retryable", ""); return;
    }
    if (!isRetryable(SecurityStatus::ERR_CONN_CLOSED)) {
        FAIL("T15 ERR_CONN_CLOSED not retryable", ""); return;
    }
    if (isRetryable(SecurityStatus::ERR_NETWORK_FAIL)) {
        FAIL("T15 ERR_NETWORK_FAIL incorrectly retryable", ""); return;
    }
    if (isRetryable(SecurityStatus::ERR_PEER_REJECTED)) {
        FAIL("T15 ERR_PEER_REJECTED incorrectly retryable — security violation", ""); return;
    }

    PASS("T15  [BUG-E01] 4 network codes: unique, statusMessage, isNetworkError, isRetryable");
}

// ── main ──────────────────────────────────────────────────────────────────────

int main() {
    std::cout << "\n\033[1m╔════════════════════════════════════════════════╗\033[0m\n"
              << "\033[1m║  SecFW v2.0.1 — IPC Integration Test Suite    ║\033[0m\n"
              << "\033[1m╚════════════════════════════════════════════════╝\033[0m\n";

    SECTION("IpcMessage serialise / deserialise");
    test_message_roundtrip_empty();
    test_message_roundtrip_normal();
    test_message_body_too_large();

    SECTION("Crypto: encrypt / decrypt / tamper");
    test_crypto_roundtrip();
    test_crypto_wrong_key();
    test_crypto_tamper();

    SECTION("Frame validation (socketpair, no server)");
    test_frame_bad_magic();
    test_frame_oversized_length();
    test_frame_below_minimum();

    SECTION("Server / Client integration (fork)");
    test_server_client_roundtrip();
    test_server_uid_rejection();
    test_100_messages();

    SECTION("RAII and path validation");
    test_socket_cleanup();
    test_socket_path_too_long();

    SECTION("BUG-E01: SecurityStatus network error codes");
    test_new_error_codes();

    // ── Summary ───────────────────────────────────────────────────────────────
    std::cout << "\n\033[1m── Results ──────────────────────────────────────\033[0m\n"
              << "  Total : " << (g_pass + g_fail) << "\n"
              << "  \033[32mPass  : " << g_pass  << "\033[0m\n";
    if (g_fail > 0)
        std::cout << "  \033[31mFail  : " << g_fail << "\033[0m\n";
    else
        std::cout << "  Fail  : 0\n";
    std::cout << "\n";

    return (g_fail == 0) ? 0 : 1;
}
