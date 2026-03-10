#pragma once
// ============================================================
// PrivilegeDrop.hpp — NEW FEATURE v1.3
//
// Principle of Least Privilege: Drop root/elevated privileges
// after startup (before handling user input).
//
// Usage:
//   if (auto r = PrivilegeDrop::drop("appuser", "appgroup"); r.fail())
//       { /* handle error */ }
//
// Also provides:
//   - SecureChroot: change root to a sandboxed directory
//   - SecureFileLimits: set resource limits (RLIMIT_NOFILE, etc.)
//
// Standards: SEI CERT POS02-C, CWE-250, OWASP Configuration
// ============================================================
#include "SecureCore.hpp"
#include <string>
#include <iostream>

#ifndef _WIN32
  #include <pwd.h>
  #include <grp.h>
  #include <unistd.h>
  #include <sys/resource.h>
  #include <sys/stat.h>
#endif

namespace SecFW {

class PrivilegeDrop final {
public:
#ifndef _WIN32
    // ── Drop to specified user/group ──
    [[nodiscard]] static Result<void> drop(
        const std::string& username,
        const std::string& groupname = "")
    {
        if (::getuid() != 0 && ::geteuid() != 0) {
            // Already non-root — nothing to do (not an error)
            return Result<void>::Success();
        }

        // Resolve group
        if (!groupname.empty()) {
            struct group* gr = ::getgrnam(groupname.c_str());
            if (!gr)
                return Result<void>::Failure(SecurityStatus::ERR_CONFIG_INVALID,
                    "Group not found: " + groupname);
            if (::setgid(gr->gr_gid) != 0)
                return Result<void>::Failure(SecurityStatus::ERR_CONFIG_INVALID,
                    "setgid failed for group: " + groupname);
        }

        // Resolve user
        struct passwd* pw = ::getpwnam(username.c_str());
        if (!pw)
            return Result<void>::Failure(SecurityStatus::ERR_CONFIG_INVALID,
                "User not found: " + username);

        // Set supplementary groups
        if (::initgroups(username.c_str(), pw->pw_gid) != 0)
            return Result<void>::Failure(SecurityStatus::ERR_CONFIG_INVALID,
                "initgroups failed for: " + username);

        // Set GID (if group not explicitly specified)
        if (groupname.empty()) {
            if (::setgid(pw->pw_gid) != 0)
                return Result<void>::Failure(SecurityStatus::ERR_CONFIG_INVALID,
                    "setgid failed");
        }

        // Drop UID
        if (::setuid(pw->pw_uid) != 0)
            return Result<void>::Failure(SecurityStatus::ERR_CONFIG_INVALID,
                "setuid failed for user: " + username);

        // Verify we can't re-escalate (CERT POS02-C)
        if (::setuid(0) == 0)
            return Result<void>::Failure(SecurityStatus::ERR_INTERNAL,
                "CRITICAL: Re-escalation to root succeeded — privilege drop failed!");

        return Result<void>::Success();
    }

    // ── Get current effective user info ──
    [[nodiscard]] static std::string currentUser() {
        struct passwd* pw = ::getpwuid(::geteuid());
        if (!pw) return std::to_string(::geteuid());
        return std::string(pw->pw_name);
    }

    [[nodiscard]] static bool isRoot() noexcept {
        return ::getuid() == 0 || ::geteuid() == 0;
    }

    // ── Chroot to a sandboxed directory ──
    [[nodiscard]] static Result<void> chroot(const std::string& dir) {
        if (::chdir(dir.c_str()) != 0)
            return Result<void>::Failure(SecurityStatus::ERR_CONFIG_INVALID,
                "chdir to sandbox failed: " + dir);
        if (::chroot(dir.c_str()) != 0)
            return Result<void>::Failure(SecurityStatus::ERR_CONFIG_INVALID,
                "chroot failed: " + dir);
        // chdir to "/" inside the chroot (important!)
        if (::chdir("/") != 0)
            return Result<void>::Failure(SecurityStatus::ERR_INTERNAL,
                "chdir to / inside chroot failed");
        return Result<void>::Success();
    }

    // ── Set resource limits ──
    struct ResourceLimits {
        rlim_t maxOpenFiles   { 256 };
        rlim_t maxCoreDump    { 0 };       // 0 = disable core dumps (security)
        rlim_t maxStackSize   { 8 * 1024 * 1024 }; // 8 MB
        rlim_t maxProcesses   { 64 };
        rlim_t maxFileSize    { 100 * 1024 * 1024 }; // 100 MB max file write
    };

    [[nodiscard]] static Result<void> setLimits(const ResourceLimits& limits = {}) {
        auto setLimit = [](int resource, rlim_t soft, rlim_t hard) -> bool {
            struct rlimit rl { soft, hard };
            return ::setrlimit(resource, &rl) == 0;
        };

        if (!setLimit(RLIMIT_NOFILE, limits.maxOpenFiles, limits.maxOpenFiles))
            return Result<void>::Failure(SecurityStatus::ERR_INTERNAL,
                "setrlimit(NOFILE) failed");

        if (!setLimit(RLIMIT_CORE, limits.maxCoreDump, limits.maxCoreDump))
            return Result<void>::Failure(SecurityStatus::ERR_INTERNAL,
                "setrlimit(CORE) failed");

        if (!setLimit(RLIMIT_STACK, limits.maxStackSize, limits.maxStackSize))
            return Result<void>::Failure(SecurityStatus::ERR_INTERNAL,
                "setrlimit(STACK) failed");

        if (!setLimit(RLIMIT_NPROC, limits.maxProcesses, limits.maxProcesses))
            return Result<void>::Failure(SecurityStatus::ERR_INTERNAL,
                "setrlimit(NPROC) failed");

        if (!setLimit(RLIMIT_FSIZE, limits.maxFileSize, limits.maxFileSize))
            return Result<void>::Failure(SecurityStatus::ERR_INTERNAL,
                "setrlimit(FSIZE) failed");

        return Result<void>::Success();
    }

    // ── Set umask for file creation ──
    static void setSecureUmask() {
        // 0077 = owner-only rw (files: 600, dirs: 700)
        ::umask(0077);
    }

    // ── Combined hardening: limits + umask (call before processing user data) ──
    [[nodiscard]] static Result<void> harden() {
        setSecureUmask();
        auto r = setLimits();
        if (r.fail()) return r;
        return Result<void>::Success();
    }

#else
    // Windows stubs
    [[nodiscard]] static Result<void> drop(
        const std::string&, const std::string& = "") {
        return Result<void>::Success(); // TODO: Windows token manipulation
    }
    [[nodiscard]] static bool isRoot() noexcept { return false; }
    [[nodiscard]] static Result<void> harden() { return Result<void>::Success(); }
    [[nodiscard]] static std::string currentUser() { return "unknown"; }
#endif
};

} // namespace SecFW
