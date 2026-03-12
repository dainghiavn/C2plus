cmake_minimum_required(VERSION 3.20)
project(SecureConsoleApp VERSION 1.0.0 LANGUAGES CXX)

# ── C++20 Standard ──
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# FIX [G]: Export compile commands for clang-tidy / IDE integration
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# ── Dependencies ──
find_package(OpenSSL 3.0 REQUIRED)
find_package(Threads REQUIRED)

# ══════════════════════════════════════════════════════════════════════════════
# Shared compile/link flags helper — applied to ALL targets via a helper macro
# Centralising avoids copy-paste drift between the main binary and test targets.
# ══════════════════════════════════════════════════════════════════════════════

macro(apply_security_flags TARGET_NAME)
    # FIX [B]: Security flags scoped to target (not global add_compile_options)
    # FIX [F]: Platform guards for compiler/linker-specific flags
    if (MSVC)
        target_compile_options(${TARGET_NAME} PRIVATE
            /W4 /WX
            /GS           # Buffer security checks
            /GL           # FIX [D]: Whole-program optimization (required for /LTCG)
            /DYNAMICBASE  # ASLR
            /NXCOMPAT     # DEP
            /sdl          # Additional SDL checks
            /guard:cf     # Control Flow Guard
            /Qspectre     # Spectre mitigations
        )
        target_link_options(${TARGET_NAME} PRIVATE
            /LTCG         # Link-Time Code Generation (pairs with /GL)
            /OPT:REF      # Remove unreferenced functions/data
            /OPT:ICF      # Identical COMDAT folding
        )
    else()
        # ── Flags supported by both GCC and Clang ──
        target_compile_options(${TARGET_NAME} PRIVATE
            -Wall -Wextra -Werror
            -Wformat=2
            -Wstack-protector
            -fstack-protector-strong
            -fPIE
        )

        # FIX [F]: GCC-only flags
        if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
            target_compile_options(${TARGET_NAME} PRIVATE
                -Warray-bounds=2         # GCC: =2 enables stricter checks
                -fstack-clash-protection # GCC 8+; not available on Apple Clang
            )
        endif()

        # FIX [F]: Clang-only flags
        if (CMAKE_CXX_COMPILER_ID MATCHES "Clang")
            target_compile_options(${TARGET_NAME} PRIVATE
                -Warray-bounds           # Clang variant (no =2)
            )
        endif()

        # FIX [F]: x86/x86_64 only (Control-Flow Enforcement Technology)
        if (CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|i[3-6]86|AMD64")
            target_compile_options(${TARGET_NAME} PRIVATE
                -fcf-protection=full
            )
        endif()

        # FIX [F]: Linux GNU ld only (not macOS, not lld by default)
        if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
            target_link_options(${TARGET_NAME} PRIVATE
                -pie
                -Wl,-z,relro             # Read-only relocations
                -Wl,-z,now               # Resolve all symbols at load (full RELRO)
                -Wl,-z,noexecstack       # Non-executable stack
            )
        elseif (APPLE)
            target_link_options(${TARGET_NAME} PRIVATE
                -pie
            )
        else()
            target_link_options(${TARGET_NAME} PRIVATE -pie)
        endif()
    endif()

    # ── _FORTIFY_SOURCE: only when optimization is active ──
    # FIX: Do NOT inject _FORTIFY_SOURCE globally — let each config handle it.
    # Debug: no FORTIFY (incompatible with -O0 on some compilers/warnings).
    # Release/RelWithDebInfo: FORTIFY=3/2 (requires -O1+).
    # FIX [C]: Use generator expressions — works with multi-config generators.
    if (NOT MSVC)
        target_compile_options(${TARGET_NAME} PRIVATE
            $<$<CONFIG:Release>:-U_FORTIFY_SOURCE>
            $<$<CONFIG:Release>:-D_FORTIFY_SOURCE=3>
            $<$<CONFIG:RelWithDebInfo>:-D_FORTIFY_SOURCE=2>
        )
    endif()

    # ── Debug: Sanitizers ──
    # FIX [C]: Use generator expressions
    if (NOT MSVC)
        target_compile_options(${TARGET_NAME} PRIVATE
            $<$<CONFIG:Debug>:-fsanitize=address,undefined,leak>
            $<$<CONFIG:Debug>:-g>
            $<$<CONFIG:Debug>:-O0>
            $<$<CONFIG:Debug>:-fno-omit-frame-pointer>  # Better ASan stack traces
        )
        target_link_options(${TARGET_NAME} PRIVATE
            $<$<CONFIG:Debug>:-fsanitize=address,undefined,leak>
        )
    endif()

    # ── Release: LTO + strip ──
    # FIX [A]: Remove -O2 — CMake Release already injects -O3 -DNDEBUG.
    # FIX [C]: Use generator expressions.
    if (NOT MSVC)
        target_compile_options(${TARGET_NAME} PRIVATE
            $<$<CONFIG:Release>:-flto>
        )
        target_link_options(${TARGET_NAME} PRIVATE
            $<$<CONFIG:Release>:-flto>
            $<$<CONFIG:Release>:-s>     # Strip symbols
        )
    endif()

    # ── RelWithDebInfo: LTO with debug info, no strip ──
    if (NOT MSVC)
        target_compile_options(${TARGET_NAME} PRIVATE
            $<$<CONFIG:RelWithDebInfo>:-flto>
        )
        target_link_options(${TARGET_NAME} PRIVATE
            $<$<CONFIG:RelWithDebInfo>:-flto>
        )
    endif()
endmacro()

# ══════════════════════════════════════════════════════════════════════════════
# Main application target
# ══════════════════════════════════════════════════════════════════════════════

add_executable(${PROJECT_NAME} src/main.cpp)
target_include_directories(${PROJECT_NAME} PRIVATE include)

# FIX [E]: Remove OpenSSL::SSL — project only uses libcrypto
target_link_libraries(${PROJECT_NAME} PRIVATE
    OpenSSL::Crypto
    Threads::Threads
)

apply_security_flags(${PROJECT_NAME})

# ══════════════════════════════════════════════════════════════════════════════
# [TEST-02 FIX]: IPC integration test target
#
# Previously test_ipc.cpp had to be built manually via a g++ command embedded
# in a source comment. This broke CI and made it easy to accidentally skip.
#
# The test binary intentionally uses RELAXED flags compared to the production
# binary:
#   - No LTO (faster iteration)
#   - No -s strip (stack traces in CI output)
#   - -Werror kept (catch test-code regressions)
#   - ASan/UBSan in Debug mode (same as main target)
#
# CTest integration:
#   cmake -B build -DCMAKE_BUILD_TYPE=Debug
#   cmake --build build --target test_ipc
#   ctest --test-dir build -R test_ipc --output-on-failure
#
# OR run directly:
#   ./build/test_ipc          (as a normal user — T11 requires non-root)
#
# Note: T11 (UID rejection) is automatically skipped when running as root.
# ══════════════════════════════════════════════════════════════════════════════

enable_testing()

add_executable(test_ipc src/test_ipc.cpp)
target_include_directories(test_ipc PRIVATE include)

# test_ipc links the same libraries as the main binary.
# OpenSSL::Crypto: AES-GCM, HMAC, HKDF (CryptoEngine, SecureKeyDerivation)
# Threads::Threads: T17 (stop-from-thread test) uses std::thread
target_link_libraries(test_ipc PRIVATE
    OpenSSL::Crypto
    Threads::Threads
)

# Apply same security flags (sanitizers, warnings, hardening)
apply_security_flags(test_ipc)

# Register with CTest
# WORKING_DIRECTORY: set to build dir so socket paths in /tmp are accessible
# PASS_REGULAR_EXPRESSION: CTest marks the test as passed only when the
#   summary line says "0 failed". This is belt-and-suspenders on top of the
#   exit code (test_ipc returns 0 on success, 1 on failure).
add_test(
    NAME    test_ipc
    COMMAND test_ipc
)
set_tests_properties(test_ipc PROPERTIES
    TIMEOUT             120            # 2 min max — fork-based tests can be slow on CI
    PASS_REGULAR_EXPRESSION "0 failed" # belt-and-suspenders on exit code
    FAIL_REGULAR_EXPRESSION "[1-9][0-9]* failed"
    LABELS              "ipc;networking;integration"
)

# ── Build-only convenience target ─────────────────────────────────────────────
# `cmake --build build --target check` builds and runs test_ipc immediately.
# Equivalent to: cmake --build build --target test_ipc && ctest -R test_ipc

add_custom_target(check
    COMMAND ${CMAKE_CTEST_COMMAND} --test-dir "${CMAKE_BINARY_DIR}"
            -R test_ipc --output-on-failure
    DEPENDS test_ipc
    COMMENT "Building and running IPC integration tests"
    VERBATIM
)

# ══════════════════════════════════════════════════════════════════════════════
# Install (optional — production deployments)
# ══════════════════════════════════════════════════════════════════════════════

install(TARGETS ${PROJECT_NAME} RUNTIME DESTINATION bin)
# Do NOT install test_ipc — it is a development/CI artifact only.
