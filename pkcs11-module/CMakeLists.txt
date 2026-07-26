# SPDX-License-Identifier: LGPL-2.1-or-later

# librescrs-pkcs11-agent.so — a standalone, Qt-free, libcrypto-free PKCS#11
# module that brokers the C_* ABI to the per-user agent over D-Bus. The ONLY
# real dependency is sdbus-c++ (the same transport the agent uses); it links
# NEITHER Qt NOR OpenSSL — it performs no crypto itself.

add_library(librescrs-pkcs11-agent MODULE
    src/Module.cpp
    src/ObjectModel.cpp
    src/AgentClient.cpp
    src/SessionState.cpp)

set_target_properties(librescrs-pkcs11-agent PROPERTIES
    PREFIX ""
    OUTPUT_NAME "librescrs-pkcs11-agent")

target_include_directories(librescrs-pkcs11-agent PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src)

target_compile_features(librescrs-pkcs11-agent PRIVATE cxx_std_23)

# Qt-free: only sdbus-c++ + threads. NO Qt, NO libcrypto link.
target_link_libraries(librescrs-pkcs11-agent PRIVATE SDBusCpp::sdbus-c++ librelinux-common)

# Export ONLY the PKCS#11 entry point (C_GetFunctionList); every internal
# symbol stays hidden — mirrors LM's pkcs11 module export discipline.
target_link_options(librescrs-pkcs11-agent PRIVATE
    "-Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/src/exports.map")

if(LIBRELINUX_WERROR)
    target_compile_options(librescrs-pkcs11-agent PRIVATE -Wall -Wextra -Werror)
endif()

# Install to the p11-kit default module dir (resolved by the top-level CMake).
install(TARGETS librescrs-pkcs11-agent LIBRARY DESTINATION ${LIBRESCRS_P11_MODULE_DIR})

# --- p11-kit .module registration + deployment (b) server unit --------------
# The .module file goes into p11-kit's module-config dir (pkg-config
# p11-kit-1 --variable p11_module_configs; /usr/share/p11-kit/modules fallback).
# Under a per-user dogfood install the absolute system dir is unwritable, so fall
# back to a prefix-relative path the user can point P11_KIT_MODULES at.
find_package(PkgConfig REQUIRED)
pkg_get_variable(LIBRESCRS_P11_MODULE_CONFIGS p11-kit-1 p11_module_configs)
if(NOT LIBRESCRS_P11_MODULE_CONFIGS OR LIBRELINUX_USER_INSTALL)
    set(LIBRESCRS_P11_MODULE_CONFIGS ${CMAKE_INSTALL_DATADIR}/p11-kit/modules)
endif()

configure_file(data/librescrs-agent.module.in librescrs-agent.module @ONLY)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/librescrs-agent.module
    DESTINATION ${LIBRESCRS_P11_MODULE_CONFIGS})

# Deployment (b) systemd USER unit for `p11-kit server` (out-of-process
# isolation). Mirrors the agent's --user install pattern: under
# LIBRELINUX_USER_INSTALL it lands in the per-user XDG systemd dir, otherwise the
# pkg-config system user-unit dir.
if(LIBRELINUX_USER_INSTALL)
    set(LIBRESCRS_P11_SYSTEMD_USER_DIR ${LIBRELINUX_USER_SYSTEMD_UNIT_DIR})
else()
    pkg_get_variable(LIBRESCRS_P11_SYSTEMD_USER_DIR systemd systemd_user_unit_dir)
    if(NOT LIBRESCRS_P11_SYSTEMD_USER_DIR)
        set(LIBRESCRS_P11_SYSTEMD_USER_DIR ${CMAKE_INSTALL_FULL_LIBDIR}/systemd/user)
    endif()
endif()
configure_file(data/librescrs-p11-server.service.in librescrs-p11-server.service @ONLY)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/librescrs-p11-server.service
    DESTINATION ${LIBRESCRS_P11_SYSTEMD_USER_DIR})

add_subdirectory(tests)
