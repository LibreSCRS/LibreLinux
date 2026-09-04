# SPDX-License-Identifier: LGPL-2.1-or-later

# librescrs-pkcs11-agent.so — a standalone, Qt-free, libcrypto-free PKCS#11
# module that brokers the C_* ABI to the per-user agent over D-Bus.
#
# What is built HERE is only what is actually this platform's: the bus client,
# its error-name vocabulary, the tuple that client marshals, and the factory
# that names it. The Cryptoki surface itself comes from LibreAgent::Pkcs11Facade,
# shared with the other platform backend, so the two cannot answer a loader
# differently by drifting.

add_library(librescrs-pkcs11-agent MODULE
    src/DBusAgentClient.cpp
    src/DBusAgentClientFactory.cpp)

set_target_properties(librescrs-pkcs11-agent PROPERTIES
    PREFIX ""
    OUTPUT_NAME "librescrs-pkcs11-agent")

target_include_directories(librescrs-pkcs11-agent PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src)

target_compile_features(librescrs-pkcs11-agent PRIVATE cxx_std_23)

# Qt-free: only sdbus-c++ + threads. NO Qt, NO libcrypto link.
target_link_libraries(librescrs-pkcs11-agent PRIVATE SDBusCpp::sdbus-c++ librelinux-common)

# The facade, pulled WHOLE, plus the one exported name -- both come from the
# shared package's own helper. Linking LibreAgent::Pkcs11Facade by bare name
# instead would build, install and dlopen a module with no entry point in it.
librescrs_pkcs11_module_link(librescrs-pkcs11-agent)

if(LIBRELINUX_WERROR)
    target_compile_options(librescrs-pkcs11-agent PRIVATE -Wall -Wextra -Werror)
endif()

# Install to the p11-kit default module dir (resolved by the top-level CMake).
install(TARGETS librescrs-pkcs11-agent LIBRARY DESTINATION ${LIBRESCRS_P11_MODULE_DIR})

# --- p11-kit .module registration + deployment (b) server unit --------------
# The .module file goes into p11-kit's module-config dir (pkg-config
# p11-kit-1 --variable p11_module_configs; /usr/share/p11-kit/modules fallback).
# Under a per-user dogfood install the system dir is unwritable, and the data
# dir under the prefix is NOT one of the three directories p11-kit reads — a
# declaration there is installed, correct and completely inert. The per-user
# destination is therefore the config dir p11-kit does read, computed beside the
# other per-user destinations in the top-level CMakeLists.
find_package(PkgConfig REQUIRED)
pkg_get_variable(LIBRESCRS_P11_MODULE_CONFIGS p11-kit-1 p11_module_configs)
if(LIBRELINUX_USER_INSTALL)
    set(LIBRESCRS_P11_MODULE_CONFIGS "${LIBRELINUX_USER_P11_MODULE_CONFIG_DIR}")
elseif(NOT LIBRESCRS_P11_MODULE_CONFIGS)
    set(LIBRESCRS_P11_MODULE_CONFIGS ${CMAKE_INSTALL_DATADIR}/p11-kit/modules)
endif()

# Where the .so actually lands, as an absolute path, whether
# LIBRESCRS_P11_MODULE_DIR came back absolute from pkg-config or relative to the
# prefix under a per-user install.
if(IS_ABSOLUTE "${LIBRESCRS_P11_MODULE_DIR}")
    set(LIBRESCRS_P11_MODULE_DIR_ABS "${LIBRESCRS_P11_MODULE_DIR}")
else()
    set(LIBRESCRS_P11_MODULE_DIR_ABS "${CMAKE_INSTALL_PREFIX}/${LIBRESCRS_P11_MODULE_DIR}")
endif()

# How the declaration names the library. p11-kit resolves a BARE name against
# its own module directory, never against the prefix this was installed into, so
# a bare name is correct only when the two are the same directory. Anywhere else
# — a per-user prefix, or a distribution whose libdir differs from p11-kit's —
# the reference dangles and p11-kit drops the module without a word. Keep the
# bare form where it is right, because that is what lets a packager do a
# 32/64-bit parallel install, which is the same reason stock opensc.module is
# relative.
pkg_get_variable(_ll_p11_module_path p11-kit-1 p11_module_path)
if(_ll_p11_module_path AND "${LIBRESCRS_P11_MODULE_DIR_ABS}" STREQUAL "${_ll_p11_module_path}")
    set(LIBRESCRS_P11_MODULE_REF "librescrs-pkcs11-agent.so")
else()
    set(LIBRESCRS_P11_MODULE_REF "${LIBRESCRS_P11_MODULE_DIR_ABS}/librescrs-pkcs11-agent.so")
endif()
message(STATUS "p11-kit module reference: ${LIBRESCRS_P11_MODULE_REF}")

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
        set(LIBRESCRS_P11_SYSTEMD_USER_DIR ${CMAKE_INSTALL_PREFIX}/lib/systemd/user)
    endif()
endif()
configure_file(data/librescrs-p11-server.service.in librescrs-p11-server.service @ONLY)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/librescrs-p11-server.service
    DESTINATION ${LIBRESCRS_P11_SYSTEMD_USER_DIR})

add_subdirectory(tests)
