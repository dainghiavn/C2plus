cmake_minimum_required(VERSION 3.20)

# [BUG-NET-06 FIX]: Project name corrected from "SecureConsoleApp" to
# "SecureConsoleAppNet". Previously ${PROJECT_NAME} expanded to the wrong
# name everywhere — install target, binary name, version string.
project(SecureConsoleAppNet VERSION 2.1.1 LANGUAGES CXX)

# ── C++20 Standard ──
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Export compile commands for clang-tidy / IDE integration
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# ── Dependencies ──
find_package(OpenSSL 3.0 REQUIRED)
find_package(Threads REQUIRED)

# ══════════════════════════════════════════════════════════════════════════════
# Shared security flags — applied to ALL targets via macro
# Centralising avoids copy-paste drift between main binary and test targets.
# ══════════════════════════════════════════════════════════════════════════════

macro(apply_security_flags TARGET_NAME)
    if (MSVC)
        target_compile_options(${TARGET_NAME} PRIVATE
            /W4 /WX
            /GS           # Buffer security checks
            /GL           # Whole-program optimization (required for /LTCG)
            /DYNAMICBASE  # ASLR
            /NXCOMPAT     # DEP
            /sdl          # Additional SDL checks
            /guard:cf     # Control Flow Guard
            /Qspectre     # Spectre mitigations
        )
        target_link_options(${TARGET_NAME} PRIVATE
            /LTCG         # Link-Time Code Generation
            /OPT:REF
            /OPT:ICF
        )
    else()
        target_compile_options(${TARGET_NAME} PRIVATE
            -Wall -Wextra -Werror
            -Wformat=2
            -Wstack-protector
            -fstack-protector-strong
            -fPIE
        )

        if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
            target_compile_options(${TARGET_NAME} PRIVATE
                -Warray-bounds=2
                -fstack-clash-protection
            )
        endif()

        if (CMAKE_CXX_COMPILER_ID MATCHES "Clang")
            target_compile_options(${TARGET_NAME} PRIVATE
                -Warray-bounds
            )
        endif()

        if (CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|i[3-6]86|AMD64")
            target_compile_options(${TARGET_NAME} PRIVATE
                -fcf-protection=full
            )
        endif()

        if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
            target_link_options(${TARGET_NAME} PRIVATE
                -pie
                -Wl,-z,relro
                -Wl,-z,now
                -Wl,-z,noexecstack
            )
        elseif (APPLE)
            target_link_options(${TARGET_NAME} PRIVATE -pie)
        else()
            target_link_options(${TARGET_NAME} PRIVATE -pie)
        endif()
    endif()

    # _FORTIFY_SOURCE — only when optimization is active
    if (NOT MSVC)
        target_compile_options(${TARGET_NAME} PRIVATE
            $<$<CONFIG:Release>:-U_FORTIFY_SOURCE>
            $<$<CONFIG:Release>:-D_FORTIFY_SOURCE=3>
            $<$<CONFIG:RelWithDebInfo>:-D_FORTIFY_SOURCE=2>
        )
    endif()

    # Debug: Sanitizers
    if (NOT MSVC)
        target_compile_options(${TARGET_NAME} PRIVATE
            $<$<CONFIG:Debug>:-fsanitize=address,undefined,leak>
            $<$<CONFIG:Debug>:-g>
            $<$<CONFIG:Debug>:-O0>
            $<$<CONFIG:Debug>:-fno-omit-frame-pointer>
        )
        target_link_options(${TARGET_NAME} PRIVATE
            $<$<CONFIG:Debug>:-fsanitize=address,undefined,leak>
        )
    endif()

    # Release: LTO + strip
    if (NOT MSVC)
        target_compile_options(${TARGET_NAME} PRIVATE
            $<$<CONFIG:Release>:-flto>
        )
        target_link_options(${TARGET_NAME} PRIVATE
            $<$<CONFIG:Release>:-flto>
            $<$<CONFIG:Release>:-s>
        )
    endif()

    # RelWithDebInfo: LTO with debug info, no strip
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

# Only libcrypto — project does not use TLS (libssl)
target_link_libraries(${PROJECT_NAME} PRIVATE
    OpenSSL::Crypto
    Threads::Threads
)

apply_security_flags(${PROJECT_NAME})

# ══════════════════════════════════════════════════════════════════════════════
# IPC integration test target
#
# [TEST-02 FIX]: test_ipc was previously built via a manual g++ command
# embedded in a source comment. This broke CI and made it easy to skip.
#
# Test binary uses RELAXED flags vs production:
#   - No LTO (faster iteration)
#   - No -s strip (stack traces in CI output)
#   - -Werror kept (catch test-code regressions)
#   - ASan/UBSan in Debug mode (same as main target)
#
# Build and run:
#   cmake -B build -DCMAKE_BUILD_TYPE=Debug
#   cmake --build build --target test_ipc
#   ctest --test-dir build -R test_ipc --output-on-failure
#
# OR direct:
#   ./build/test_ipc      (run as normal user — T11 requires non-root)
# ══════════════════════════════════════════════════════════════════════════════

enable_testing()

add_executable(test_ipc src/test_ipc.cpp)
target_include_directories(test_ipc PRIVATE include)

# OpenSSL::Crypto: AES-GCM, HMAC, HKDF
# Threads::Threads: T17 (stop-from-thread) uses std::thread
target_link_libraries(test_ipc PRIVATE
    OpenSSL::Crypto
    Threads::Threads
)

apply_security_flags(test_ipc)

add_test(
    NAME    test_ipc
    COMMAND test_ipc
)
set_tests_properties(test_ipc PROPERTIES
    TIMEOUT             120
    PASS_REGULAR_EXPRESSION "Fail  : 0"
    FAIL_REGULAR_EXPRESSION "Fail  : [1-9]"
    LABELS              "ipc;networking;integration"
)

# `cmake --build build --target check` → build + run immediately
add_custom_target(check
    COMMAND ${CMAKE_CTEST_COMMAND} --test-dir "${CMAKE_BINARY_DIR}"
            -R test_ipc --output-on-failure
    DEPENDS test_ipc
    COMMENT "Building and running IPC integration tests"
    VERBATIM
)

# ══════════════════════════════════════════════════════════════════════════════
# Install
# ══════════════════════════════════════════════════════════════════════════════

install(TARGETS ${PROJECT_NAME} RUNTIME DESTINATION bin)
# Do NOT install test_ipc — CI/dev artifact only.
