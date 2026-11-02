# SPDX-License-Identifier: LGPL-2.1-or-later
cmake_minimum_required(VERSION 3.28)

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
    # p11-kit reads exactly three directories, in ascending precedence:
    # /usr/share/p11-kit/modules, /etc/pkcs11/modules and
    # $XDG_CONFIG_HOME/pkcs11/modules. The data dir under the install prefix is
    # not one of them, so a declaration installed there registers nothing while
    # satisfying every install rule. Like the two destinations above, this one
    # is deliberately OUTSIDE CMAKE_INSTALL_PREFIX: it is where the consumer
    # looks, not where this project puts its files.
    set(LIBRELINUX_USER_P11_MODULE_CONFIG_DIR "${_ll_xdg_config}/pkcs11/modules"
        CACHE PATH "Per-user p11-kit module config dir")
    message(STATUS "LIBRELINUX_USER_INSTALL=ON — per-user XDG install:")
    message(STATUS "  systemd units : ${LIBRELINUX_USER_SYSTEMD_UNIT_DIR}")
    message(STATUS "  dbus services : ${LIBRELINUX_USER_DBUS_SERVICE_DIR}")
    message(STATUS "  p11-kit modules: ${LIBRELINUX_USER_P11_MODULE_CONFIG_DIR}")
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
find_package(LibreMiddleware 5.0 REQUIRED CONFIG)

# Strict warnings everywhere; errors only when asked (CI). The option carries
# the name every LibreSCRS repository uses, so one -DLIBRESCRS_WERROR=ON means
# the same thing in each of them -- the agent library built from source below
# included.
option(LIBRESCRS_WERROR "Treat compiler warnings as errors" OFF)

# The one warning set every target this repository ships compiles with, plus
# -Werror under LIBRESCRS_WERROR. NO_CONVERSION leaves out -Wconversion and
# -Wsign-conversion, for the two targets that have never been built with them
# (the prompter, whose generated sdbus-c++ headers trip them, and the PKCS#11
# module).
function(librelinux_strict_warnings target)
    cmake_parse_arguments(PARSE_ARGV 1 arg "NO_CONVERSION" "" "")
    set(conversion -Wconversion -Wsign-conversion)
    if(arg_NO_CONVERSION)
        set(conversion)
    endif()
    target_compile_options(${target} PRIVATE
        -Wall -Wextra -Wpedantic
        -Wshadow -Wnon-virtual-dtor -Wold-style-cast -Wcast-align
        -Woverloaded-virtual ${conversion} -Wnull-dereference
        -Wdouble-promotion -Wformat=2)
    if(LIBRESCRS_WERROR)
        target_compile_options(${target} PRIVATE -Werror)
    endif()
endfunction()

# Bound every test. ctest's built-in default is 1500 seconds and nothing in this
# tree overrode it, so a single wedged test could hold a hosted runner for
# twenty-five minutes without ever being named; a handful of them consume the
# whole job. A hung job is also the one job that cannot say what hung: the
# runner serves no log until the run is cancelled, so the deadlocked test stays
# unnameable for exactly as long as it holds the runner.
#
# include(CTest) rather than a bare enable_testing(): DART_TESTING_TIMEOUT is
# read by the CTest MODULE, which is what writes DartConfiguration.tcl, and a
# bare enable_testing() never writes that file. Measured on a twelve-second
# test with a three-second declared timeout, the bare call reports the suite
# passing after twelve seconds and the module form times the test out after
# three — so declaring the value next to a bare call would have had no effect
# at all, silently. include(CTest) calls enable_testing() itself. Set BEFORE the
# include, which would otherwise cache 1500. Included before the agent below,
# which asks for its test-only components only when BUILD_TESTING is on.
set(DART_TESTING_TIMEOUT 300 CACHE STRING
    "Default per-test ctest timeout, in seconds")
include(CTest)

# The platform-neutral agent core (flows, scheduler, presence model, caches,
# lease/broker policy, LM-backed seams, the 5 backend interfaces). The Linux
# backend below implements those interfaces and builds the librescrs-agent
# daemon on top of LibreAgent::Core. By default it is built from the revision
# deps.lock names; packaging passes -DLIBRESCRS_AGENT_FROM_SOURCE=OFF and takes
# the installed librescrs-agent-core instead. What ships needs the core and the
# PKCS#11 facade the module is built from; only the tests need the wire
# vocabulary the error-name parity test links and the master-list fixture the
# anchor-import test links, so a build without tests does not ask for them.
set(LIBRESCRS_AGENT_FROM_SOURCE_DEFAULT ON)
include(cmake/FindOrUseLibreAgent.cmake)
set(_librelinux_agent_components Core Pkcs11Facade Wire)
if(BUILD_TESTING)
    list(APPEND _librelinux_agent_components TestSupport)
endif()
librescrs_use_libreagent(COMPONENTS ${_librelinux_agent_components})

# The bus contract is the agent library's: every interface this tree serves or
# calls is generated from its D-Bus XML (LIBREAGENT_DBUS_XML_DIR), and no copy
# lives here. A subproject build publishes the directory in the cache; an
# installed package sets it in its config file, which the call above read inside
# a function, so it is read once more here where the variable stays.
if(NOT LIBREAGENT_DBUS_XML_DIR)
    find_package(LibreAgent ${PROJECT_VERSION_MAJOR}.0 REQUIRED CONFIG COMPONENTS ${_librelinux_agent_components})
endif()
if(NOT EXISTS "${LIBREAGENT_DBUS_XML_DIR}/org.librescrs.Agent.Manager1.xml")
    message(FATAL_ERROR "LibreAgent's D-Bus XML not found in \"${LIBREAGENT_DBUS_XML_DIR}\"")
endif()

# --- one ctest entry per GoogleTest case ---------------------------------
# With one entry per binary, ctest counts binaries: `ctest -R` cannot select a
# case, the manifest check compares file names so a case deleted inside a
# surviving binary passes, and the skip ledger reads the ctest log and therefore
# records nothing for a binary whose cases all skipped.
if(BUILD_TESTING)
    include(GoogleTest)

    # PRE_TEST, not the default POST_BUILD: POST_BUILD runs each freshly linked
    # binary in the middle of a parallel build, and on a loaded runner that
    # yields an empty test-list and kills the build, naming a different target
    # each time. The failure reads as a regression and is not one.
    set(CMAKE_GTEST_DISCOVER_TESTS_DISCOVERY_MODE PRE_TEST)

    # Each D-Bus suite gets its own session bus through the target property
    # GoogleTest's discovery module reads. It reads that property only while
    # CMP0158 is unset or OLD; under NEW -- which arrives with the first bump of
    # cmake_minimum_required to 3.29 or later -- the emulator stops being
    # consulted without cross-compiling, the wrapper silently falls off, and
    # these suites go to whatever session bus the runner is on. The guard is
    # required because cmake_policy(SET CMP0158 ...) is an error on CMake 3.28,
    # which this project still declares as its minimum. The behaviour is
    # asserted separately, because this line cannot fail.
    if(POLICY CMP0158)
        cmake_policy(SET CMP0158 OLD)
    endif()

    find_program(DBUS_RUN_SESSION dbus-run-session REQUIRED)

    # Each bus-backed suite runs on its own session bus through the agent
    # library's libreagent_private_session_bus() and LIBREAGENT_PRIVATE_BUS_ENV
    # (LibreAgentGTest.cmake), which also compile in the case asserting that the
    # wrapper ran.
endif()

# Header-only utilities shared across the daemon, prompter, and module (pure
# POSIX, no Qt/sdbus/LM): the sealed-memfd creator, the pidfd-pinned /proc
# readers, and the agent/prompter wire vocabularies.
add_library(librelinux-common INTERFACE)
# The agent library's include directory comes along for the standard-library
# only vocabulary headers common/ names (prompter kinds and reply status,
# reader-interface tokens). Only the directory: linking the core would hand
# the prompter and the PKCS#11 module the middleware it depends on.
target_include_directories(librelinux-common INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/common
    $<TARGET_PROPERTY:LibreAgent::Core,INTERFACE_INCLUDE_DIRECTORIES>)
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
