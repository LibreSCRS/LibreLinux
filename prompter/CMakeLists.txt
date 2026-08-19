# SPDX-License-Identifier: LGPL-2.1-or-later

# --- Dependencies --------------------------------------------------------
# Qt6: the prompter is the explicit Qt-OK boundary of the LibreLinux stack.
# DBus component pulled in only so sdbus-c++-generated headers that mention
# QtCore-style types compile cleanly; actual D-Bus traffic goes through
# sdbus-c++ to share marshalling code with the agent daemon.
find_package(Qt6 6.6 REQUIRED COMPONENTS Core Gui Widgets DBus Test)

# KF6 ships as individual `KF6<Component>` find_package targets on most
# distributions; the umbrella `find_package(KF6 COMPONENTS …)` form is
# only provided by the metapackage and not guaranteed to be installed
# alongside the individual frameworks. Find each component explicitly.
find_package(KF6I18n 6.0 REQUIRED)
find_package(KF6CoreAddons 6.0 REQUIRED)

# sdbus-c++ is already required at project root via the agent build; pull in
# the imported target explicitly here so this directory is self-contained
# when LIBRELINUX_BUILD_PROMPTER_KDE is toggled in isolation.
find_package(sdbus-c++ 2.0 CONFIG REQUIRED)

# --- sdbus-c++ adaptor codegen ------------------------------------------
# Mirror agent/CMakeLists.txt: codegen the adaptor from the SAME XML the
# agent consumes as a proxy, so both sides stay in lock-step at the build
# layer (a stale rebuild can only break compile, never wire-protocol skew).
find_program(SDBUS_CPP_XML2CPP sdbus-c++-xml2cpp REQUIRED)
set(_xml ${CMAKE_CURRENT_SOURCE_DIR}/../agent/dbus/org.librescrs.Prompter1.xml)
set(_gen_dir ${CMAKE_CURRENT_BINARY_DIR}/generated)
file(MAKE_DIRECTORY ${_gen_dir})
set(_gen_header ${_gen_dir}/org.librescrs.Prompter1_adaptor.h)
add_custom_command(
    OUTPUT ${_gen_header}
    COMMAND ${SDBUS_CPP_XML2CPP} ${_xml} --adaptor=${_gen_header}
    DEPENDS ${_xml}
    VERBATIM)

# --- Qt project setup ----------------------------------------------------
qt_standard_project_setup()

# Install path of the agent binary the prompter authenticates as its only
# legitimate caller (CallerAuthorizer trust gate). Mirrors agent/CMakeLists
# which installs `librescrs-agent` to ${CMAKE_INSTALL_LIBEXECDIR}. Injected
# as the compile-time value; the LIBRESCRS_PROMPTER_EXPECTED_PEER env
# override exists only in test targets (LIBRELINUX_TESTING), never here.
set(LIBRESCRS_AGENT_BINARY_PATH
    "${CMAKE_INSTALL_FULL_LIBEXECDIR}/librescrs-agent")

qt_add_executable(librescrs-pinentry-kde
    src/main.cpp
    src/InputWidgetBase.h
    src/InputWidgetBase.cpp
    src/PinInputWidget.h
    src/PinInputWidget.cpp
    src/CanInputWidget.h
    src/CanInputWidget.cpp
    src/MrzInputWidget.h
    src/MrzInputWidget.cpp
    src/ChangePinInputWidget.h
    src/ChangePinInputWidget.cpp
    src/PromptDialog.h
    src/PromptDialog.cpp
    src/PrompterService.h
    src/PrompterService.cpp
    src/PromptRegistry.h
    src/PromptRegistry.cpp
    src/CallerAuthorizer.h
    src/CallerAuthorizer.cpp
    src/SecretMemfd.h
    src/SecretMemfd.cpp
    ${_gen_header})

target_include_directories(librescrs-pinentry-kde PRIVATE
    src
    ${_gen_dir})

target_link_libraries(librescrs-pinentry-kde PRIVATE
    Qt6::Core
    Qt6::Gui
    Qt6::Widgets
    KF6::I18n
    KF6::CoreAddons
    SDBusCpp::sdbus-c++
    LibreMiddleware::Secure
    librelinux-common) # shared sealed-memfd creator + pinned /proc readers

target_compile_definitions(librescrs-pinentry-kde PRIVATE
    LIBRELINUX_VERSION_STR="${PROJECT_VERSION}"
    LIBRESCRS_AGENT_BINARY_PATH="${LIBRESCRS_AGENT_BINARY_PATH}"
    # Binds the i18n*() macros in this target to the gettext catalog installed
    # from po/ (librescrs-pinentry-kde.mo), matching the runtime domain set via
    # KLocalizedString::setApplicationDomain() in main.cpp.
    TRANSLATION_DOMAIN="librescrs-pinentry-kde")

# Strict warnings, mirroring the agent. Generated sdbus-c++ headers have
# unavoidable -Wsign-conversion noise; gate -Werror behind the same opt-in.
target_compile_options(librescrs-pinentry-kde PRIVATE
    -Wall -Wextra -Wpedantic
    -Wshadow -Wnon-virtual-dtor -Wold-style-cast -Wcast-align
    -Woverloaded-virtual -Wnull-dereference
    -Wdouble-promotion -Wformat=2)
if(LIBRELINUX_WERROR)
    target_compile_options(librescrs-pinentry-kde PRIVATE -Werror)
endif()

# --- Install -------------------------------------------------------------
# libexec — the prompter is internal infrastructure invoked by the agent
# (and indirectly by graphical sessions via D-Bus activation); end users
# never run it from a shell.
install(TARGETS librescrs-pinentry-kde
    DESTINATION ${CMAKE_INSTALL_LIBEXECDIR})

# systemd user unit + D-Bus session activation, parallel to the agent.
# LIBRELINUX_USER_INSTALL (project root) overrides to per-user XDG dirs.
if(LIBRELINUX_USER_INSTALL)
    set(SYSTEMD_USER_UNIT_DIR ${LIBRELINUX_USER_SYSTEMD_UNIT_DIR})
    set(DBUS_SESSION_SERVICE_DIR ${LIBRELINUX_USER_DBUS_SERVICE_DIR})
else()
    pkg_get_variable(SYSTEMD_USER_UNIT_DIR systemd systemd_user_unit_dir)
    pkg_get_variable(DBUS_SESSION_SERVICE_DIR dbus-1 session_bus_services_dir)
    if(NOT SYSTEMD_USER_UNIT_DIR)
        set(SYSTEMD_USER_UNIT_DIR ${CMAKE_INSTALL_FULL_LIBDIR}/systemd/user)
    endif()
    if(NOT DBUS_SESSION_SERVICE_DIR)
        set(DBUS_SESSION_SERVICE_DIR ${CMAKE_INSTALL_FULL_DATADIR}/dbus-1/services)
    endif()
endif()
configure_file(data/librescrs-pinentry-kde.service.in librescrs-pinentry-kde.service @ONLY)
# dbus activation requires the .service file basename to equal the bus name it
# activates (Name=org.librescrs.Prompter1 inside), so the installed file is
# org.librescrs.Prompter1.service — dbus-broker will not activate a mismatched name.
configure_file(data/org.librescrs.Prompter1.service.in org.librescrs.Prompter1.service @ONLY)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/librescrs-pinentry-kde.service
    DESTINATION ${SYSTEMD_USER_UNIT_DIR})
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/org.librescrs.Prompter1.service
    DESTINATION ${DBUS_SESSION_SERVICE_DIR})

# D-Bus session-bus policy (defense-in-depth). Restricts owning + sending to
# org.librescrs.Prompter1 to the local user; the binary-level CallerAuthorizer
# check above is the real gate, since session-bus policy cannot distinguish
# between two binaries owned by the same user. Installed into the dbus-1
# session policy dir alongside the system default policies.
#
# SYSTEM (package) install only: stock dbus does not scan a
# $XDG_CONFIG_HOME/dbus-1/session.d/ directory, so a per-user drop-in there is a
# silent no-op. Under LIBRELINUX_USER_INSTALL we therefore skip it (the
# CallerAuthorizer binary gate is unaffected — this file is defense-in-depth).
if(NOT LIBRELINUX_USER_INSTALL)
    pkg_get_variable(DBUS_SESSION_POLICY_DIR dbus-1 session_bus_policydir)
    if(NOT DBUS_SESSION_POLICY_DIR)
        set(DBUS_SESSION_POLICY_DIR ${CMAKE_INSTALL_FULL_DATADIR}/dbus-1/session.d)
    endif()
    install(FILES data/org.librescrs.Prompter1.conf
        DESTINATION ${DBUS_SESSION_POLICY_DIR})
endif()

# --- Translations --------------------------------------------------------
# ki18n catalogs under po/<lang>/librescrs-pinentry-kde.po. ki18n_install()
# compiles each .po to a .mo and installs it into
# ${KDE_INSTALL_LOCALEDIR}/<lang>/LC_MESSAGES (falls back to share/locale).
# Kept in the prompter directory because this is the only Qt/KF6 component and
# the catalog is gated behind LIBRELINUX_BUILD_PROMPTER_KDE with it.
if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/po)
    ki18n_install(po)
endif()

add_subdirectory(tests)
