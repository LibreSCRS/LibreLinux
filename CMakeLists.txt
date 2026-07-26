# SPDX-License-Identifier: LGPL-2.1-or-later
cmake_minimum_required(VERSION 3.24)

# Derives PROJECT_VERSION + GIT_VERSION_* from git tags (0.0.1 default when untagged).
# Must run before project() — see the module's own note.
include(cmake/GitVersion.cmake)

project(LibreLinux
    VERSION ${GIT_VERSION_MAJOR}.${GIT_VERSION_MINOR}.${GIT_VERSION_PATCH}
    LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

include(GNUInstallDirs)

# --- Per-user (XDG) dogfood install ---------------------------------------
# The default install resolves the systemd user-unit dir and the D-Bus
# session service/policy dirs from pkg-config, which return ABSOLUTE system
# paths (e.g. /usr/lib/systemd/user, /usr/share/dbus-1/services) that ignore
# CMAKE_INSTALL_PREFIX and are unwritable for a non-root, user-prefix install.
# That layout is correct for distro packaging (packaging/{arch,debian,rpm}).
#
# LIBRELINUX_USER_INSTALL=ON instead targets the XDG per-user locations the
# session bus and `systemctl --user` actually read, so a developer can
#   cmake --preset user && cmake --build --preset user && cmake --install build/user
# straight into $HOME without root. ExecStart/Exec still derive from
# CMAKE_INSTALL_FULL_LIBEXECDIR, so set CMAKE_INSTALL_PREFIX=$HOME/.local.
#
# The agent and prompter subdirs read LIBRELINUX_USER_*_DIR below; when the
# option is OFF these stay empty and each subdir keeps its pkg-config result.
option(LIBRELINUX_USER_INSTALL
    "Install systemd/D-Bus units into per-user XDG dirs (dogfooding, no root)" OFF)
if(LIBRELINUX_USER_INSTALL)
    if(DEFINED ENV{XDG_CONFIG_HOME} AND NOT "$ENV{XDG_CONFIG_HOME}" STREQUAL "")
        set(_ll_xdg_config "$ENV{XDG_CONFIG_HOME}")
    else()
        set(_ll_xdg_config "$ENV{HOME}/.config")
    endif()
    if(DEFINED ENV{XDG_DATA_HOME} AND NOT "$ENV{XDG_DATA_HOME}" STREQUAL "")
        set(_ll_xdg_data "$ENV{XDG_DATA_HOME}")
    else()
        set(_ll_xdg_data "$ENV{HOME}/.local/share")
    endif()
    # systemctl --user reads $XDG_CONFIG_HOME/systemd/user (highest precedence
    # generator-free location for user-installed units).
    set(LIBRELINUX_USER_SYSTEMD_UNIT_DIR "${_ll_xdg_config}/systemd/user"
        CACHE PATH "Per-user systemd unit dir")
    # The session bus auto-activates services described under
    # $XDG_DATA_HOME/dbus-1/services.
    set(LIBRELINUX_USER_DBUS_SERVICE_DIR "${_ll_xdg_data}/dbus-1/services"
        CACHE PATH "Per-user D-Bus session service dir")
    message(STATUS "LIBRELINUX_USER_INSTALL=ON — per-user XDG install:")
    message(STATUS "  systemd units : ${LIBRELINUX_USER_SYSTEMD_UNIT_DIR}")
    message(STATUS "  dbus services : ${LIBRELINUX_USER_DBUS_SERVICE_DIR}")
    # The D-Bus session-bus policy is NOT installed under user-install: stock
    # dbus does not scan a $XDG_CONFIG_HOME/dbus-1/session.d/ directory, so a
    # per-user drop-in there is a silent no-op. It is defense-in-depth only and
    # ships solely with the system packages — see agent/CMakeLists.txt.
    #
    # polkit has NO per-user actions dir (reads only /usr/share/polkit-1 and
    # /etc/polkit-1). The action is therefore NOT installed by the user build;
    # because the daemon uses PolkitAuthorizer whenever polkitd is reachable and
    # polkit denies unregistered action ids, the dogfood flow requires a
    # one-time `sudo install` of the action into the system dir before signing
    # and trust-config work — see docs/dogfooding.md.
endif()

# Qt-free, desktop-agnostic daemon: D-Bus via sdbus-c++, loop/notify via libsystemd.
find_package(sdbus-c++ 2.0 CONFIG REQUIRED) # provides SDBusCpp::sdbus-c++
find_package(PkgConfig REQUIRED)
pkg_check_modules(Systemd REQUIRED IMPORTED_TARGET libsystemd)
find_package(LibreMiddleware 4.2 REQUIRED CONFIG)

# The platform-neutral agent core (flows, scheduler, presence model, caches,
# lease/broker policy, LM-backed seams, the 5 backend interfaces). The Linux
# backend below implements those interfaces and builds the librescrs-agent
# daemon on top of LibreAgent::Core.
include(cmake/FindOrUseLibreAgent.cmake)

enable_testing()

# Header-only utilities shared across the daemon, prompter, and module (pure
# POSIX, no Qt/sdbus/LM): the sealed-memfd creator, the pidfd-pinned /proc
# readers, and the agent/prompter wire vocabularies.
add_library(librelinux-common INTERFACE)
target_include_directories(librelinux-common INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/common)
target_compile_features(librelinux-common INTERFACE cxx_std_23)

add_subdirectory(agent)

# --- PKCS#11 agent-proxy module -------------------------------------------
# Standalone, Qt-free, libcrypto-free .so that maps the PKCS#11 C_* ABI to the
# agent's Pkcs11_1 D-Bus surface. Installs into the p11-kit default module dir
# (resolved from pkg-config; /usr/lib/pkcs11 fallback). Under a per-user
# dogfood install (CMAKE_INSTALL_PREFIX=$HOME/.local) the absolute system path
# is unwritable, so fall back to the prefix-relative libdir.
pkg_get_variable(LIBRESCRS_P11_MODULE_DIR p11-kit-1 p11_module_path)
if(NOT LIBRESCRS_P11_MODULE_DIR OR LIBRELINUX_USER_INSTALL)
    set(LIBRESCRS_P11_MODULE_DIR ${CMAKE_INSTALL_LIBDIR}/pkcs11)
endif()
add_subdirectory(pkcs11-module)

# The prompter is the Qt-OK boundary: a KDE-styled secure-input binary that
# the headless agent calls over a private session-bus interface. Optional so
# downstream packagers (e.g. minimal-server profiles) can drop Qt/KF6 entirely.
option(LIBRELINUX_BUILD_PROMPTER_KDE "Build the KDE pinentry prompter" ON)
if(LIBRELINUX_BUILD_PROMPTER_KDE)
    add_subdirectory(prompter)
endif()
