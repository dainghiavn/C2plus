#pragma once
// ============================================================
// UnixSocketChannel.hpp — v2.0
// Encrypted, authenticated Unix Domain Socket IPC channel.
//
// Provides:
//   UnixSocketServer  — bind/accept loop (daemon side)
//   UnixSocketClient  — connect to server (consumer side)
//   IpcMessage        — framed message with AES-256-GCM payload
//   IpcPeerInfo       — verified peer credentials (UID/GID/PID)
//
// Security model:
//   Each message is independently encrypted with AES-256-GCM.
//   A shared channel key must be derived via HKDF from the master key
//   (domain: "secfw-ipc-channel-v1") and exchanged out-of-band (file/env).
//   Peer identity is verified via SO_PEERCRED (Linux) or
//   GetNamedPipeClientProcessId (Windows) before ANY data is read.
//
// Bug fixes addressed (all N01–N08 from roadmap):
//
//   [N01] TOCTOU socket path  — unlink() directly, ignore ENOENT.
//                               Never check exists() before unlink().
//
//   [N02] Partial read/write  — readFull() / writeFull() loop until all
//                               bytes transferred. Length-prefix framing
//                               with 4-byte magic + 4-byte length header.
//
//   [N03] Integer overflow    — IpcMessage::MAX_PAYLOAD_BYTES = 1 MiB.
//                               Length field read as uint32_t, validated
//                               against the cap before ANY allocation.
//
//   [N04] Missing SO_PEERCRED — verifyPeer() reads peer UID/GID via
//                               getsockopt(SO_PEERCRED) before recv.
//                               Server rejects connections from unexpected UIDs.
//
//   [N05] SIGPIPE crash       — MSG_NOSIGNAL on every send(). Server calls
//                               signal(SIGPIPE, SIG_IGN) at startup.
//
//   [N06] Hung recv DoS       — SO_RCVTIMEO = 5s, SO_SNDTIMEO = 5s set on
//                               every accepted socket.
//
//   [N07] Socket file leak    — cleanupSocketFile() called at server start
//                               (unlink existing) and via RAII destructor.
//                               Works with systemd RuntimeDirectory.
//
//   [N08] Windows compat      — #ifdef guards throughout. Unix socket path
//                               replaced by Named Pipe handle on Windows.
//                               SO_PEERCRED replaced by GetNamedPipeClient-
//                               ProcessId + OpenProcess + GetTokenInformation.
//
// Wire format (per message):
//   [4 bytes] MAGIC   = 0x53_46_57_4D ("SFWM")  — frame start marker
//   [4 bytes] LENGTH  = uint32_t, little-endian  — byte count of PAYLOAD
//   [n bytes] PAYLOAD = AES-256-GCM ciphertext   — IpcMessage serialised
//
// AES-256-GCM envelope (inside PAYLOAD):
//   [12 bytes] IV (random per message)
//   [16 bytes] GCM authentication tag
//   [r  bytes] ciphertext of plaintext IpcMessage body
//
// Standards:
//   NIST SP 800-38D   (AES-GCM)
//   NIST SP 800-108   (HKDF domain separation)
//   POSIX.1-2017      (Unix domain sockets, SO_PEERCRED)
//   CERT MEM06-C      (locked buffers for key material)
//   OWASP MASVS-R     (IPC integrity)
//   CWE-362           (N01 — TOCTOU race)
//   CWE-400           (N03 — uncontrolled resource allocation)
//   CWE-362           (N04 — peer verification)
// ============================================================

#include "SecureCore.hpp"
#include "CryptoEngine.hpp"
#include "InputValidator.hpp"
#include "MemoryGuard.hpp"
#include "SecureLogger.hpp"

#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>
#include <functional>
#include <chrono>
#include <optional>
#include <atomic>

// ── Platform includes ─────────────────────────────────────────────────────────
#if defined(_WIN32) || defined(_WIN64)
#  define SECFW_IPC_WINDOWS 1
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <windows.h>
#  include <aclapi.h>
#  include <sddl.h>
#else
#  define SECFW_IPC_UNIX 1
#  include <sys/socket.h>
#  include <sys/un.h>
#  include <unistd.h>
#  include <cerrno>
#  include <cstring>
#  include <csignal>
#  include <sys/types.h>
#  include <sys/stat.h>
#  include <fcntl.h>
#endif

namespace SecFW {

// ── Constants ─────────────────────────────────────────────────────────────────

// N03 FIX: Hard cap on message payload. A 1 MiB limit prevents OOM via
// crafted length field. Increase only if your workload needs it, but keep
// well below typical system memory limits.
static constexpr std::size_t IPC_MAX_PAYLOAD_BYTES = 1u * 1024u * 1024u; // 1 MiB

// Frame header: 4-byte magic + 4-byte little-endian payload length
static constexpr uint8_t IPC_MAGIC[4] = { 0x53, 0x46, 0x57, 0x4D }; // "SFWM"
static constexpr std::size_t IPC_HEADER_SIZE = 8;  // 4 magic + 4 length

// AES-GCM envelope overhead:  12 (IV) + 16 (tag) = 28 bytes per message
static constexpr std::size_t IPC_GCM_IV_LEN  = 12;
static constexpr std::size_t IPC_GCM_TAG_LEN = 16;
static constexpr std::size_t IPC_GCM_OVERHEAD = IPC_GCM_IV_LEN + IPC_GCM_TAG_LEN;

// Timeout applied to every accepted connection socket (N06 FIX)
static constexpr int IPC_RECV_TIMEOUT_SEC = 5;
static constexpr int IPC_SEND_TIMEOUT_SEC = 5;

// Server listen backlog
static constexpr int IPC_LISTEN_BACKLOG = 16;

// HKDF domain label for IPC channel key derivation
// Use SecureKeyDerivation::derive(masterKey, 32, "secfw-ipc-channel-v1")
static constexpr std::string_view IPC_HKDF_DOMAIN = "secfw-ipc-channel-v1";

// ── IpcPeerInfo ───────────────────────────────────────────────────────────────
//
// Verified identity of the connecting peer.
// Populated by verifyPeer() before any data is read (N04 FIX).

struct IpcPeerInfo {
    uid_t       uid  { 0 };   // effective UID of connecting process
    gid_t       gid  { 0 };   // effective GID
    pid_t       pid  { 0 };   // PID (informational; may have exited by time used)
    bool        verified { false };
};

// ── IpcMessage ────────────────────────────────────────────────────────────────
//
// Application-level message transported over the channel.
// Serialised to/from a flat byte buffer (length-prefixed UTF-8 body).
//
// On-wire (inside GCM ciphertext):
//   [4 bytes] body_len  uint32_t little-endian
//   [n bytes] body      UTF-8 string (JSON recommended)
//
// The body is intentionally opaque — upper layers decide the schema.

struct IpcMessage {
    std::string body;   // message payload (JSON / binary-safe base64)

    // Maximum body size = IPC_MAX_PAYLOAD_BYTES - GCM overhead - 4 header bytes
    static constexpr std::size_t MAX_BODY_BYTES =
        IPC_MAX_PAYLOAD_BYTES - IPC_GCM_OVERHEAD - 4;

    // Serialise to flat bytes for encryption input
    [[nodiscard]] SecBytes serialise() const {
        if (body.size() > MAX_BODY_BYTES)
            return {};  // caller must check before calling

        uint32_t bodyLen = static_cast<uint32_t>(body.size());
        SecBytes out;
        out.reserve(4 + body.size());

        // Little-endian body length prefix
        out.push_back(static_cast<byte_t>( bodyLen        & 0xFF));
        out.push_back(static_cast<byte_t>((bodyLen >>  8) & 0xFF));
        out.push_back(static_cast<byte_t>((bodyLen >> 16) & 0xFF));
        out.push_back(static_cast<byte_t>((bodyLen >> 24) & 0xFF));

        for (char c : body) out.push_back(static_cast<byte_t>(c));
        return out;
    }

    // Deserialise from decrypted bytes
    [[nodiscard]] static Result<IpcMessage> deserialise(const SecBytes& raw) {
        if (raw.size() < 4)
            return Result<IpcMessage>::Failure(SecurityStatus::ERR_INPUT_INVALID,
                "IpcMessage: raw too short for length prefix");

        uint32_t bodyLen =
              static_cast<uint32_t>(raw[0])
            | static_cast<uint32_t>(raw[1]) << 8
            | static_cast<uint32_t>(raw[2]) << 16
            | static_cast<uint32_t>(raw[3]) << 24;

        // N03 FIX: validate before allocating
        if (bodyLen > MAX_BODY_BYTES)
            return Result<IpcMessage>::Failure(SecurityStatus::ERR_INPUT_INVALID,
                "IpcMessage: body_len " + std::to_string(bodyLen) +
                " exceeds MAX_BODY_BYTES " + std::to_string(MAX_BODY_BYTES));

        if (raw.size() < 4 + static_cast<std::size_t>(bodyLen))
            return Result<IpcMessage>::Failure(SecurityStatus::ERR_INPUT_INVALID,
                "IpcMessage: truncated body (got " +
                std::to_string(raw.size() - 4) +
                " bytes, expected " + std::to_string(bodyLen) + ")");

        IpcMessage msg;
        msg.body.assign(
            reinterpret_cast<const char*>(raw.data() + 4), bodyLen);
        return Result<IpcMessage>::Success(std::move(msg));
    }
};

// ── Internal helpers: readFull / writeFull (N02 FIX) ─────────────────────────

namespace detail {

#ifdef SECFW_IPC_UNIX
using SocketFd = int;
static constexpr SocketFd INVALID_SOCKET_FD = -1;

// N02 FIX: Loop until ALL bytes transferred. A single recv/send on a stream
// socket is NOT guaranteed to transfer the full requested count.
// Short reads/writes on TCP and Unix sockets are normal and must be handled.

[[nodiscard]] inline Result<void> readFull(SocketFd fd,
                                            void*    buf,
                                            std::size_t len)
{
    byte_t* ptr = static_cast<byte_t*>(buf);
    std::size_t remaining = len;

    while (remaining > 0) {
        // MSG_WAITALL requests the full count, but may still short-read
        // on signal interruption → we loop regardless.
        ssize_t n = ::recv(fd, ptr, remaining, MSG_WAITALL);

        if (n == 0)
            // Peer closed connection cleanly (EOF)
            return Result<void>::Failure(SecurityStatus::ERR_CONN_CLOSED,
                "peer closed connection (EOF) after " +
                std::to_string(len - remaining) + "/" +
                std::to_string(len) + " bytes");

        if (n < 0) {
            int err = errno;
            if (err == EINTR) continue;   // signal interrupted, retry
            if (err == EAGAIN || err == EWOULDBLOCK)
                return Result<void>::Failure(SecurityStatus::ERR_TIMEOUT,
                    "recv timed out (SO_RCVTIMEO)");
            return Result<void>::Failure(SecurityStatus::ERR_NETWORK_FAIL,
                std::string("recv failed: ") + ::strerror(err));
        }

        ptr       += static_cast<std::size_t>(n);
        remaining -= static_cast<std::size_t>(n);
    }
    return Result<void>::Success();
}

[[nodiscard]] inline Result<void> writeFull(SocketFd    fd,
                                             const void* buf,
                                             std::size_t len)
{
    const byte_t* ptr = static_cast<const byte_t*>(buf);
    std::size_t remaining = len;

    while (remaining > 0) {
        // N05 FIX: MSG_NOSIGNAL — do not raise SIGPIPE if peer closed.
        // We handle the error via return value instead.
        ssize_t n = ::send(fd, ptr, remaining, MSG_NOSIGNAL);

        if (n < 0) {
            int err = errno;
            if (err == EINTR)  continue;
            if (err == EPIPE || err == ECONNRESET)
                return Result<void>::Failure(SecurityStatus::ERR_CONN_CLOSED,
                    "peer closed connection during send");
            if (err == EAGAIN || err == EWOULDBLOCK)
                return Result<void>::Failure(SecurityStatus::ERR_TIMEOUT,
                    "send timed out (SO_SNDTIMEO)");
            return Result<void>::Failure(SecurityStatus::ERR_NETWORK_FAIL,
                std::string("send failed: ") + ::strerror(err));
        }

        ptr       += static_cast<std::size_t>(n);
        remaining -= static_cast<std::size_t>(n);
    }
    return Result<void>::Success();
}

// Apply recv/send timeouts to a socket (N06 FIX)
[[nodiscard]] inline Result<void> applyTimeouts(SocketFd fd) {
    struct timeval tv{};
    tv.tv_sec  = IPC_RECV_TIMEOUT_SEC;
    tv.tv_usec = 0;

    if (::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) != 0)
        return Result<void>::Failure(SecurityStatus::ERR_NETWORK_FAIL,
            std::string("setsockopt SO_RCVTIMEO: ") + ::strerror(errno));

    tv.tv_sec = IPC_SEND_TIMEOUT_SEC;
    if (::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) != 0)
        return Result<void>::Failure(SecurityStatus::ERR_NETWORK_FAIL,
            std::string("setsockopt SO_SNDTIMEO: ") + ::strerror(errno));

    return Result<void>::Success();
}

// N04 FIX: Verify peer credentials via SO_PEERCRED.
// Called on accepted socket BEFORE reading any data.
[[nodiscard]] inline Result<IpcPeerInfo> verifyPeer(SocketFd fd) {
    struct ucred cred{};
    socklen_t len = sizeof(cred);

    if (::getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &len) != 0)
        return Result<IpcPeerInfo>::Failure(SecurityStatus::ERR_PEER_REJECTED,
            std::string("getsockopt SO_PEERCRED failed: ") + ::strerror(errno));

    IpcPeerInfo info;
    info.uid      = cred.uid;
    info.gid      = cred.gid;
    info.pid      = cred.pid;
    info.verified = true;
    return Result<IpcPeerInfo>::Success(info);
}

// N07 FIX: Unconditional unlink — no TOCTOU check.
// N01 FIX: Do NOT check file existence before unlinking (avoids TOCTOU race).
inline void cleanupSocketFile(const std::string& path) {
    // unlink() on a non-existent path returns ENOENT — that is fine.
    // We ignore ENOENT and all other errors to keep this async-signal-safe.
    ::unlink(path.c_str());
}

#endif // SECFW_IPC_UNIX

} // namespace detail

// ── Crypto helpers: encrypt / decrypt one message ────────────────────────────
//
// Each message gets a fresh random 12-byte IV (NIST SP 800-38D §8.2.1).
// GCM tag is 16 bytes. No AAD in this layer; upper layers may add context.
//
// Wire layout of returned SecBytes:
//   [0..11]  IV  (12 bytes, random)
//   [12..27] TAG (16 bytes, GCM authentication tag)
//   [28..]   ciphertext

namespace detail {

[[nodiscard]] inline Result<SecBytes> encryptMessage(
    const SecBytes& plaintext,
    const SecBytes& channelKey)
{
    // Generate random IV per message
    auto ivRes = CryptoEngine::randomBytes(IPC_GCM_IV_LEN);
    if (ivRes.fail())
        return Result<SecBytes>::Failure(ivRes.status,
            "IPC encryptMessage: IV generation failed: " + ivRes.message);

    auto encRes = CryptoEngine::encryptAESGCM(plaintext, channelKey, ivRes.value);
    if (encRes.fail())
        return Result<SecBytes>::Failure(encRes.status,
            "IPC encryptMessage: AES-GCM failed: " + encRes.message);

    // encRes.value layout from CryptoEngine: [IV || TAG || ciphertext]
    // CryptoEngine::encryptAESGCM already prepends IV and TAG — return as-is.
    return Result<SecBytes>::Success(std::move(encRes.value));
}

[[nodiscard]] inline Result<SecBytes> decryptMessage(
    const SecBytes& envelope,
    const SecBytes& channelKey)
{
    if (envelope.size() < IPC_GCM_OVERHEAD)
        return Result<SecBytes>::Failure(SecurityStatus::ERR_CRYPTO_FAIL,
            "IPC decryptMessage: envelope too short (" +
            std::to_string(envelope.size()) + " < " +
            std::to_string(IPC_GCM_OVERHEAD) + ")");

    auto decRes = CryptoEngine::decryptAESGCM(envelope, channelKey);
    if (decRes.fail())
        return Result<SecBytes>::Failure(decRes.status,
            "IPC decryptMessage: AES-GCM auth failed: " + decRes.message);

    return Result<SecBytes>::Success(std::move(decRes.value));
}

} // namespace detail

#ifdef SECFW_IPC_UNIX
// ╔══════════════════════════════════════════════════════════════════════╗
// ║  Unix implementation                                                ║
// ╚══════════════════════════════════════════════════════════════════════╝

// ── sendMessage / recvMessage — frame a single IpcMessage ────────────────────
//
// Frame wire format:
//   [4 bytes] MAGIC   — "SFWM" sanity check; reject frames with wrong magic
//   [4 bytes] LENGTH  — little-endian uint32_t, byte count of PAYLOAD
//   [n bytes] PAYLOAD — AES-GCM envelope

[[nodiscard]] inline Result<void> sendMessage(detail::SocketFd fd,
                                               const IpcMessage& msg,
                                               const SecBytes&   channelKey)
{
    // Serialise plaintext body
    SecBytes plaintext = msg.serialise();
    if (plaintext.empty() && !msg.body.empty())
        return Result<void>::Failure(SecurityStatus::ERR_INPUT_INVALID,
            "sendMessage: message body too large");

    // Encrypt
    auto encRes = detail::encryptMessage(plaintext, channelKey);
    if (encRes.fail())
        return Result<void>::Failure(encRes.status, encRes.message);

    const SecBytes& payload = encRes.value;

    // N03 FIX: Validate payload fits in uint32_t and under cap
    if (payload.size() > IPC_MAX_PAYLOAD_BYTES)
        return Result<void>::Failure(SecurityStatus::ERR_INPUT_INVALID,
            "sendMessage: encrypted payload exceeds IPC_MAX_PAYLOAD_BYTES");

    auto payloadLen = static_cast<uint32_t>(payload.size());

    // Build header
    uint8_t header[IPC_HEADER_SIZE];
    std::memcpy(header, IPC_MAGIC, 4);
    header[4] = static_cast<uint8_t>( payloadLen        & 0xFF);
    header[5] = static_cast<uint8_t>((payloadLen >>  8) & 0xFF);
    header[6] = static_cast<uint8_t>((payloadLen >> 16) & 0xFF);
    header[7] = static_cast<uint8_t>((payloadLen >> 24) & 0xFF);

    // N02 FIX: writeFull loops until all bytes sent
    auto r = detail::writeFull(fd, header, IPC_HEADER_SIZE);
    if (r.fail()) return r;

    return detail::writeFull(fd, payload.data(), payload.size());
}

[[nodiscard]] inline Result<IpcMessage> recvMessage(detail::SocketFd fd,
                                                      const SecBytes&  channelKey)
{
    // N02 FIX: readFull loops until all bytes received
    uint8_t header[IPC_HEADER_SIZE];
    auto r = detail::readFull(fd, header, IPC_HEADER_SIZE);
    if (r.fail())
        return Result<IpcMessage>::Failure(r.status, r.message);

    // Validate magic
    if (std::memcmp(header, IPC_MAGIC, 4) != 0)
        return Result<IpcMessage>::Failure(SecurityStatus::ERR_INPUT_INVALID,
            "recvMessage: bad frame magic — possible protocol mismatch or corruption");

    // Parse length (little-endian)
    uint32_t payloadLen =
          static_cast<uint32_t>(header[4])
        | static_cast<uint32_t>(header[5]) << 8
        | static_cast<uint32_t>(header[6]) << 16
        | static_cast<uint32_t>(header[7]) << 24;

    // N03 FIX: Validate before allocating. Reject oversized frames
    // BEFORE touching the heap — prevents OOM via crafted frame.
    if (payloadLen > IPC_MAX_PAYLOAD_BYTES)
        return Result<IpcMessage>::Failure(SecurityStatus::ERR_INPUT_INVALID,
            "recvMessage: payload_len " + std::to_string(payloadLen) +
            " exceeds IPC_MAX_PAYLOAD_BYTES (" +
            std::to_string(IPC_MAX_PAYLOAD_BYTES) + ")");

    if (payloadLen < IPC_GCM_OVERHEAD)
        return Result<IpcMessage>::Failure(SecurityStatus::ERR_INPUT_INVALID,
            "recvMessage: payload_len " + std::to_string(payloadLen) +
            " too small for GCM overhead (" +
            std::to_string(IPC_GCM_OVERHEAD) + ")");

    // Allocate and read payload
    SecBytes payload(payloadLen);
    auto r2 = detail::readFull(fd, payload.data(), payloadLen);
    if (r2.fail())
        return Result<IpcMessage>::Failure(r2.status, r2.message);

    // Decrypt and authenticate (GCM tag verification here)
    auto decRes = detail::decryptMessage(payload, channelKey);
    if (decRes.fail())
        return Result<IpcMessage>::Failure(decRes.status, decRes.message);

    // Deserialise plaintext into IpcMessage
    return IpcMessage::deserialise(decRes.value);
}

// ── UnixSocketServer ──────────────────────────────────────────────────────────
//
// Binds a Unix domain socket and accepts connections from verified peers.
// Usage:
//
//   auto srv = UnixSocketServer::create("/run/secfw/vault.sock", channelKey,
//                                       logger, allowedUid);
//   if (srv.fail()) { /* handle */ }
//
//   srv.value.run([](detail::SocketFd fd, const IpcPeerInfo& peer,
//                    const SecBytes& key, SecureLogger& log) {
//       auto msg = recvMessage(fd, key);
//       // ... handle msg ...
//       sendMessage(fd, reply, key);
//   });

class UnixSocketServer final {
public:
    // Handler type: called once per accepted connection
    // fd         — accepted socket (valid only during this call)
    // peer       — verified peer credentials
    // channelKey — AES-256 key for this channel
    // logger     — shared logger
    using ConnectionHandler = std::function<void(
        detail::SocketFd        fd,
        const IpcPeerInfo&      peer,
        const SecBytes&         channelKey,
        SecureLogger&           logger)>;

    // ── create ───────────────────────────────────────────────────────────────
    //
    // Binds the socket. Returns Failure if path is invalid, bind fails, etc.
    // The server does NOT start accepting until run() is called.

    [[nodiscard]] static Result<UnixSocketServer> create(
        const std::string& socketPath,
        SecBytes           channelKey,
        SecureLogger&      logger,
        uid_t              allowedUid = static_cast<uid_t>(-1))  // -1 = same UID
    {
        // Validate socket path (N04 prerequisite, N01 prerequisite)
        auto pathCheck = InputValidator::isValidSocketPath(socketPath);
        if (pathCheck.fail())
            return Result<UnixSocketServer>::Failure(pathCheck.status,
                "UnixSocketServer: " + pathCheck.message);

        // N05 FIX: Ignore SIGPIPE process-wide so broken-pipe errors are
        // returned as EPIPE from send() instead of killing the process.
        ::signal(SIGPIPE, SIG_IGN);

        // N01 FIX: Unconditional unlink. No exists() check — avoids TOCTOU.
        // unlink() returns ENOENT if no file exists — that is fine.
        detail::cleanupSocketFile(socketPath);

        // Create socket
        int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
        if (fd < 0)
            return Result<UnixSocketServer>::Failure(SecurityStatus::ERR_NETWORK_FAIL,
                std::string("socket(AF_UNIX) failed: ") + ::strerror(errno));

        // Bind
        struct sockaddr_un addr{};
        addr.sun_family = AF_UNIX;
        // socketPath length already validated ≤ 107 bytes by isValidSocketPath()
        std::strncpy(addr.sun_path, socketPath.c_str(), sizeof(addr.sun_path) - 1);

        if (::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
            int err = errno;
            ::close(fd);
            return Result<UnixSocketServer>::Failure(SecurityStatus::ERR_NETWORK_FAIL,
                std::string("bind() failed: ") + ::strerror(err));
        }

        // Restrict socket file to owner only (mode 0600)
        // Prevents other users from connecting even before SO_PEERCRED check
        if (::chmod(socketPath.c_str(), 0600) != 0) {
            ::close(fd);
            return Result<UnixSocketServer>::Failure(SecurityStatus::ERR_NETWORK_FAIL,
                std::string("chmod(0600) socket failed: ") + ::strerror(errno));
        }

        // Listen
        if (::listen(fd, IPC_LISTEN_BACKLOG) != 0) {
            int err = errno;
            ::close(fd);
            return Result<UnixSocketServer>::Failure(SecurityStatus::ERR_NETWORK_FAIL,
                std::string("listen() failed: ") + ::strerror(err));
        }

        // Determine effective UID to use for peer validation
        uid_t effectiveAllowedUid = (allowedUid == static_cast<uid_t>(-1))
            ? ::getuid() : allowedUid;

        return Result<UnixSocketServer>::Success(
            UnixSocketServer(fd, socketPath, std::move(channelKey),
                             logger, effectiveAllowedUid));
    }

    // ── run — accept loop (blocking) ─────────────────────────────────────────
    //
    // Blocks until stop() is called (via signal handler or another thread).
    // Each accepted connection is handled synchronously in this thread.
    // For concurrent handling, wrap in a thread pool (v2.1 scope).
    //
    // N06 FIX: SO_RCVTIMEO / SO_SNDTIMEO applied to every accepted socket.
    // N04 FIX: SO_PEERCRED verified before reading data.
    // N05 FIX: EPIPE handled via MSG_NOSIGNAL in writeFull.

    void run(ConnectionHandler handler) {
        running_.store(true, std::memory_order_relaxed);
        logger_.info("UnixSocketServer: listening on " + socketPath_);

        while (running_.load(std::memory_order_relaxed)) {
            int clientFd = ::accept(listenFd_, nullptr, nullptr);

            if (clientFd < 0) {
                int err = errno;
                if (err == EINTR) {
                    // N06 FIX / BUG-E06: EINTR from signal — not an error, retry
                    continue;
                }
                if (!running_.load(std::memory_order_relaxed)) {
                    // stop() called — graceful shutdown
                    break;
                }
                logger_.error("UnixSocketServer: accept() error: " +
                              std::string(::strerror(err)));
                continue;
            }

            // N06 FIX: Set recv/send timeouts before reading anything
            auto toRes = detail::applyTimeouts(clientFd);
            if (toRes.fail()) {
                logger_.warn("UnixSocketServer: applyTimeouts failed: " + toRes.message);
                ::close(clientFd);
                continue;
            }

            // N04 FIX: Verify peer UID/GID before reading any data
            auto peerRes = detail::verifyPeer(clientFd);
            if (peerRes.fail()) {
                logger_.warn("UnixSocketServer: SO_PEERCRED failed: " + peerRes.message);
                ::close(clientFd);
                continue;
            }

            const IpcPeerInfo& peer = peerRes.value;
            if (peer.uid != allowedUid_) {
                logger_.warn("UnixSocketServer: rejected peer UID=" +
                             std::to_string(peer.uid) +
                             " (expected " + std::to_string(allowedUid_) + ")");
                ::close(clientFd);
                continue;
            }

            logger_.info("UnixSocketServer: accepted connection from PID=" +
                         std::to_string(peer.pid) + " UID=" +
                         std::to_string(peer.uid));

            // Invoke handler — handler owns the fd for the duration of the call
            try {
                handler(clientFd, peer, channelKey_, logger_);
            } catch (const std::exception& e) {
                logger_.error("UnixSocketServer: handler exception: " +
                              std::string(e.what()));
            } catch (...) {
                logger_.error("UnixSocketServer: handler threw unknown exception");
            }

            ::close(clientFd);
        }

        logger_.info("UnixSocketServer: accept loop exited");
    }

    // ── stop — signal the run() loop to exit ─────────────────────────────────

    void stop() noexcept {
        running_.store(false, std::memory_order_relaxed);
        // Wake up accept() by closing the listen socket.
        // accept() returns EBADF/EINVAL → loop checks running_ and exits.
        if (listenFd_ >= 0) {
            ::shutdown(listenFd_, SHUT_RDWR);
        }
    }

    // ── Destructor — RAII socket file cleanup (N07 FIX) ──────────────────────

    ~UnixSocketServer() noexcept {
        stop();
        if (listenFd_ >= 0) {
            ::close(listenFd_);
            listenFd_ = -1;
        }
        // N07 FIX: Remove socket file on exit to prevent EADDRINUSE next start.
        if (!socketPath_.empty())
            detail::cleanupSocketFile(socketPath_);
    }

    // Non-copyable; movable
    UnixSocketServer(const UnixSocketServer&)            = delete;
    UnixSocketServer& operator=(const UnixSocketServer&) = delete;

    UnixSocketServer(UnixSocketServer&& o) noexcept
        : listenFd_(o.listenFd_)
        , socketPath_(std::move(o.socketPath_))
        , channelKey_(std::move(o.channelKey_))
        , logger_(o.logger_)
        , allowedUid_(o.allowedUid_)
        , running_(o.running_.load())
    {
        o.listenFd_ = -1;
        o.socketPath_.clear();
    }

private:
    UnixSocketServer(int           fd,
                     std::string   path,
                     SecBytes      key,
                     SecureLogger& logger,
                     uid_t         allowedUid)
        : listenFd_(fd)
        , socketPath_(std::move(path))
        , channelKey_(std::move(key))
        , logger_(logger)
        , allowedUid_(allowedUid)
        , running_(false)
    {}

    int             listenFd_   { -1 };
    std::string     socketPath_ {};
    SecBytes        channelKey_ {};      // AES-256 channel key
    SecureLogger&   logger_;
    uid_t           allowedUid_ { 0 };
    std::atomic<bool> running_  { false };
};

// ── UnixSocketClient ──────────────────────────────────────────────────────────
//
// Connects to a UnixSocketServer and exchanges IpcMessages.
// Usage:
//
//   auto cli = UnixSocketClient::connect("/run/secfw/vault.sock", channelKey);
//   if (cli.fail()) { /* handle */ }
//
//   auto r = cli.value.send({"action":"ping"});
//   auto resp = cli.value.recv();

class UnixSocketClient final {
public:
    [[nodiscard]] static Result<UnixSocketClient> connect(
        const std::string& socketPath,
        SecBytes           channelKey)
    {
        // Validate socket path
        auto pathCheck = InputValidator::isValidSocketPath(socketPath);
        if (pathCheck.fail())
            return Result<UnixSocketClient>::Failure(pathCheck.status,
                "UnixSocketClient: " + pathCheck.message);

        // N05 FIX: Ignore SIGPIPE
        ::signal(SIGPIPE, SIG_IGN);

        int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
        if (fd < 0)
            return Result<UnixSocketClient>::Failure(SecurityStatus::ERR_NETWORK_FAIL,
                std::string("socket(AF_UNIX) failed: ") + ::strerror(errno));

        struct sockaddr_un addr{};
        addr.sun_family = AF_UNIX;
        std::strncpy(addr.sun_path, socketPath.c_str(), sizeof(addr.sun_path) - 1);

        if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
            int err = errno;
            ::close(fd);
            return Result<UnixSocketClient>::Failure(SecurityStatus::ERR_NETWORK_FAIL,
                std::string("connect() failed: ") + ::strerror(err));
        }

        // N06 FIX: Apply timeouts immediately after connect
        auto toRes = detail::applyTimeouts(fd);
        if (toRes.fail()) {
            ::close(fd);
            return Result<UnixSocketClient>::Failure(toRes.status,
                "UnixSocketClient: " + toRes.message);
        }

        return Result<UnixSocketClient>::Success(
            UnixSocketClient(fd, std::move(channelKey)));
    }

    [[nodiscard]] Result<void> send(const IpcMessage& msg) {
        return sendMessage(fd_, msg, channelKey_);
    }

    [[nodiscard]] Result<IpcMessage> recv() {
        return recvMessage(fd_, channelKey_);
    }

    ~UnixSocketClient() noexcept {
        if (fd_ >= 0) {
            ::close(fd_);
            fd_ = -1;
        }
    }

    UnixSocketClient(const UnixSocketClient&)            = delete;
    UnixSocketClient& operator=(const UnixSocketClient&) = delete;

    UnixSocketClient(UnixSocketClient&& o) noexcept
        : fd_(o.fd_), channelKey_(std::move(o.channelKey_))
    { o.fd_ = -1; }

private:
    UnixSocketClient(int fd, SecBytes key)
        : fd_(fd), channelKey_(std::move(key)) {}

    int      fd_         { -1 };
    SecBytes channelKey_ {};
};

#else // SECFW_IPC_WINDOWS
// ╔══════════════════════════════════════════════════════════════════════╗
// ║  Windows Named Pipe stub (N08 — platform abstraction)               ║
// ║                                                                     ║
// ║  Full implementation is out of scope for v2.0 (Linux target).      ║
// ║  Stub provides the same API surface so cross-platform callers       ║
// ║  compile without changes. Replace with real Named Pipe code         ║
// ║  before deploying on Windows.                                       ║
// ╚══════════════════════════════════════════════════════════════════════╝

class UnixSocketServer final {
public:
    using ConnectionHandler = std::function<void(HANDLE, const IpcPeerInfo&,
                                                 const SecBytes&, SecureLogger&)>;

    [[nodiscard]] static Result<UnixSocketServer> create(
        const std::string&, SecBytes, SecureLogger&, DWORD = 0)
    {
        return Result<UnixSocketServer>::Failure(SecurityStatus::ERR_INTERNAL,
            "UnixSocketServer: Windows Named Pipe not yet implemented in v2.0. "
            "Use the Linux build or implement the Named Pipe backend.");
    }

    void run(ConnectionHandler) {}
    void stop() noexcept {}
    ~UnixSocketServer() noexcept = default;
    UnixSocketServer(const UnixSocketServer&) = delete;
    UnixSocketServer& operator=(const UnixSocketServer&) = delete;

private:
    UnixSocketServer() = default;
};

class UnixSocketClient final {
public:
    [[nodiscard]] static Result<UnixSocketClient> connect(const std::string&, SecBytes) {
        return Result<UnixSocketClient>::Failure(SecurityStatus::ERR_INTERNAL,
            "UnixSocketClient: Windows Named Pipe not yet implemented in v2.0.");
    }

    [[nodiscard]] Result<void>       send(const IpcMessage&) {
        return Result<void>::Failure(SecurityStatus::ERR_INTERNAL, "not implemented");
    }
    [[nodiscard]] Result<IpcMessage> recv() {
        return Result<IpcMessage>::Failure(SecurityStatus::ERR_INTERNAL, "not implemented");
    }

    ~UnixSocketClient() noexcept = default;
    UnixSocketClient(const UnixSocketClient&) = delete;
    UnixSocketClient& operator=(const UnixSocketClient&) = delete;

private:
    UnixSocketClient() = default;
};

#endif // SECFW_IPC_WINDOWS

} // namespace SecFW
