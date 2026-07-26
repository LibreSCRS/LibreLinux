# SPDX-License-Identifier: LGPL-2.1-or-later

# --- sdbus-c++ adaptor codegen from interface XML --------------------------
find_program(SDBUS_CPP_XML2CPP sdbus-c++-xml2cpp REQUIRED)
set(_xml_dir ${CMAKE_CURRENT_SOURCE_DIR}/dbus)
set(_gen_dir ${CMAKE_CURRENT_BINARY_DIR}/generated)
file(MAKE_DIRECTORY ${_gen_dir})

# Interfaces the agent HOSTS — generate adaptors.
set(LL_DBUS_ADAPTOR_XMLS
    ${_xml_dir}/org.librescrs.Agent.Manager1.xml
    ${_xml_dir}/org.librescrs.Agent.Reader1.xml
    ${_xml_dir}/org.librescrs.Agent.Card1.xml
    ${_xml_dir}/org.librescrs.Agent.Credentials1.xml
    ${_xml_dir}/org.librescrs.Agent.Config1.xml
    ${_xml_dir}/org.librescrs.Agent.Operation1.xml
    ${_xml_dir}/org.librescrs.Agent.Operation.Identity1.xml
    ${_xml_dir}/org.librescrs.Agent.Operation.Photo1.xml
    ${_xml_dir}/org.librescrs.Agent.Operation.Certificates1.xml
    ${_xml_dir}/org.librescrs.Agent.Operation.Sign1.xml
    ${_xml_dir}/org.librescrs.Agent.Operation.SignBatch1.xml
    ${_xml_dir}/org.librescrs.Agent.Operation.Credentials1.xml
    ${_xml_dir}/org.librescrs.Agent.Pkcs11_1.xml)

# Interfaces the agent CONSUMES from another service — generate proxies.
set(LL_DBUS_PROXY_XMLS
    ${_xml_dir}/org.librescrs.Prompter1.xml)

set(LL_DBUS_GENERATED_HEADERS)
foreach(xml ${LL_DBUS_ADAPTOR_XMLS})
    get_filename_component(name ${xml} NAME_WLE) # strips only ".xml"
    set(out ${_gen_dir}/${name}_adaptor.h)
    add_custom_command(
        OUTPUT ${out}
        COMMAND ${SDBUS_CPP_XML2CPP} ${xml} --adaptor=${out}
        DEPENDS ${xml}
        VERBATIM)
    list(APPEND LL_DBUS_GENERATED_HEADERS ${out})
endforeach()
foreach(xml ${LL_DBUS_PROXY_XMLS})
    get_filename_component(name ${xml} NAME_WLE)
    set(out ${_gen_dir}/${name}_proxy.h)
    add_custom_command(
        OUTPUT ${out}
        COMMAND ${SDBUS_CPP_XML2CPP} ${xml} --proxy=${out}
        DEPENDS ${xml}
        VERBATIM)
    list(APPEND LL_DBUS_GENERATED_HEADERS ${out})
endforeach()

# Expose the codegen directory + tool path to the tests subdirectory so the
# integration test can generate its mock-side adaptor headers without
# repeating the find_program / mkdir dance.
set(LL_DBUS_XML_DIR ${_xml_dir})
set(LL_DBUS_GEN_DIR ${_gen_dir})

# --- Linux backend static lib ---------------------------------------------
# The platform-neutral half (flows, scheduler, presence model, caches,
# lease/broker policy, value types, LM-backed seams, the 5 backend interfaces)
# now lives in the sibling librescrs-agent repo and is linked in below as
# LibreAgent::Core. What remains here is the Linux backend: the sdbus
# frontend (Manager/Card/Reader/Operation objects), the interface
# implementations (BusExporter=AgentTransport, PolkitAuthorizer=Authorizer,
# PrompterClient=Prompter, Operation1Adaptor=OperationChannel,
# EventLoopPoster=post/postAfter), the memfd secret/result transport, and the
# composition root.
add_library(LibreLinuxAgentCore STATIC
    src/AgentService.h
    src/AgentService.cpp
    src/CardRemovalCaches.h
    src/BusExporter.h
    src/BusExporter.cpp
    src/AgentFrontend.h
    src/AgentFrontend.cpp
    src/AgentCoreSeams.h
    src/EventLoopPoster.h
    src/EventLoopPoster.cpp
    src/CallerIdentity.h
    src/CallerIdentity.cpp
    src/PolkitAuthorizer.h
    src/PolkitAuthorizer.cpp
    src/PrompterClient.h
    src/PrompterClient.cpp
    src/SecretMemfdReader.h
    src/SecretMemfdReader.cpp
    src/SealedMemfd.h
    src/SealedMemfd.cpp
    src/ConfigPaths.h
    src/ConfigPaths.cpp
    src/AuthMethodName.h
    src/operations/Operation1Adaptor.h
    src/operations/Operation1Adaptor.cpp
    src/operations/ReadIdentityOperation.h
    src/operations/ReadIdentityOperation.cpp
    src/operations/GetPhotoOperation.h
    src/operations/GetPhotoOperation.cpp
    src/operations/ReadCertificatesOperation.h
    src/operations/ReadCertificatesOperation.cpp
    src/operations/ReadTokenInfoOperation.h
    src/operations/ReadTokenInfoOperation.cpp
    src/operations/SignOperation.h
    src/operations/SignOperation.cpp
    src/operations/SignBatchOperation.h
    src/operations/SignBatchOperation.cpp
    src/operations/ListCredentialsOperation.h
    src/operations/ListCredentialsOperation.cpp
    src/operations/ManagePinOperation.h
    src/operations/ManagePinOperation.cpp
    src/operations/ActivateSigningKeyOperation.h
    src/operations/ActivateSigningKeyOperation.cpp
    src/dbus/ManagerObject.h
    src/dbus/ManagerObject.cpp
    src/dbus/Pkcs11OutcomeNames.h
    src/dbus/Pkcs11OutcomeNames.cpp
    src/dbus/CredentialOutcomeNames.h
    src/dbus/CredentialOutcomeNames.cpp
    src/dbus/ReaderObject.h
    src/dbus/CardObject.h
    src/dbus/CardObject.cpp
    src/dbus/OperationPath.h
    src/dbus/OperationAdaptorFactory.h
    src/dbus/OperationAdaptorFactory.cpp
    src/dbus/TypedResultStore.h
    src/dbus/TypedResultStore.cpp
    ${LL_DBUS_GENERATED_HEADERS})
target_include_directories(LibreLinuxAgentCore PUBLIC
    src
    ${_gen_dir})
target_link_libraries(LibreLinuxAgentCore
    PUBLIC
        SDBusCpp::sdbus-c++
        LibreAgent::Core # imported neutral core (re-exports SmartCard/Plugin PUBLIC)
        librelinux-common # shared sealed-memfd creator + pinned /proc readers (header-only)
    PRIVATE
        PkgConfig::Systemd) # sd_notify / sd-event in EventLoopPoster + AgentService
set_target_properties(LibreLinuxAgentCore PROPERTIES POSITION_INDEPENDENT_CODE ON)

# Strict warnings by default; treat as errors in CI builds.
option(LIBRELINUX_WERROR "Treat compiler warnings as errors" OFF)
target_compile_options(LibreLinuxAgentCore PRIVATE
    -Wall -Wextra -Wpedantic
    -Wshadow -Wnon-virtual-dtor -Wold-style-cast -Wcast-align
    -Woverloaded-virtual -Wconversion -Wsign-conversion -Wnull-dereference
    -Wdouble-promotion -Wformat=2)
if(LIBRELINUX_WERROR)
    target_compile_options(LibreLinuxAgentCore PRIVATE -Werror)
endif()
# Generated sdbus-c++ adaptor headers have unavoidable -Wsign-conversion noise;
# suppress only for the generated TU surface (we include them but they're
# header-only). No need to disable for our own code.

# --- Daemon executable -----------------------------------------------------
add_executable(librescrs-agent src/main.cpp)
target_link_libraries(librescrs-agent PRIVATE LibreLinuxAgentCore)
target_compile_definitions(librescrs-agent PRIVATE
    LIBRELINUX_VERSION_STR="${PROJECT_VERSION}"
    LIBRESCRS_DEFAULT_PLUGIN_DIR="${CMAKE_INSTALL_FULL_LIBDIR}/librescrs/plugins")
install(TARGETS librescrs-agent
    DESTINATION ${CMAKE_INSTALL_LIBEXECDIR})

# --- systemd user unit + D-Bus activation ---------------------------------
# LIBRELINUX_USER_INSTALL (set at project root) overrides the pkg-config
# system dirs with per-user XDG locations so a non-root user-prefix install
# lands where `systemctl --user` and the session bus actually read.
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

# Resolve the LM PKCS#11 module path for the native AdES signing path (see the
# matching comment in data/librescrs-agent.service.in). Only the dogfood/user
# install needs it baked in: LM installs under its OWN prefix
# (~/.local/librescrs) that is not exe-relative to the agent, so
# SigningService::resolvePkcs11Module()'s relative probing misses it and dlopen
# falls back to a bare name that cannot be found -> every Card1.Sign fails. A
# system (FHS) install keeps the module exe-relative (agent in libexec, module
# in the sibling lib/pkcs11), so the resolver finds it and this stays empty.
if(LIBRELINUX_USER_INSTALL)
    # LibreMiddleware_DIR = <lm-prefix>/lib/cmake/LibreMiddleware; two dirs up is
    # LM's libdir (reading LM's own layout honours lib vs lib64), and the module
    # is the sibling pkcs11/ subdir. The unversioned .so symlink is exactly what
    # the resolver looks for.
    get_filename_component(_ll_lm_libdir "${LibreMiddleware_DIR}/../.." ABSOLUTE)
    set(_ll_pkcs11_module "${_ll_lm_libdir}/pkcs11/librescrs-pkcs11.so")
    if(NOT EXISTS "${_ll_pkcs11_module}")
        message(WARNING
            "LIBRELINUX_USER_INSTALL: LM PKCS#11 module not found at "
            "'${_ll_pkcs11_module}' — Card1.Sign will fail until "
            "LIBRESCRS_PKCS11_MODULE is set by hand. Is librescrs-middleware "
            "installed under the prefix on CMAKE_PREFIX_PATH?")
    endif()
    set(LIBRESCRS_PKCS11_MODULE_ENV
        "Environment=LIBRESCRS_PKCS11_MODULE=${_ll_pkcs11_module}")
else()
    set(LIBRESCRS_PKCS11_MODULE_ENV "")
endif()
configure_file(data/librescrs-agent.service.in librescrs-agent.service @ONLY)
configure_file(data/org.librescrs.Agent.service.in org.librescrs.Agent.service @ONLY)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/librescrs-agent.service
    DESTINATION ${SYSTEMD_USER_UNIT_DIR})
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/org.librescrs.Agent.service
    DESTINATION ${DBUS_SESSION_SERVICE_DIR})

# --- D-Bus introspection contracts ----------------------------------------
install(FILES
    dbus/org.librescrs.Agent.Manager1.xml
    dbus/org.librescrs.Agent.Reader1.xml
    dbus/org.librescrs.Agent.Card1.xml
    dbus/org.librescrs.Agent.Credentials1.xml
    dbus/org.librescrs.Agent.Config1.xml
    dbus/org.librescrs.Agent.Operation1.xml
    dbus/org.librescrs.Agent.Operation.Identity1.xml
    dbus/org.librescrs.Agent.Operation.Photo1.xml
    dbus/org.librescrs.Agent.Operation.Certificates1.xml
    dbus/org.librescrs.Agent.Operation.Sign1.xml
    dbus/org.librescrs.Agent.Operation.SignBatch1.xml
    dbus/org.librescrs.Agent.Operation.Credentials1.xml
    dbus/org.librescrs.Agent.Pkcs11_1.xml
    dbus/org.librescrs.Prompter1.xml
    DESTINATION ${CMAKE_INSTALL_DATADIR}/dbus-1/interfaces)

# --- D-Bus session-bus policy (defense-in-depth) + polkit actions ----------
# The session-bus policy is pure defense-in-depth: the session bus default
# policy already permits owning a name and sending to services, so the agent
# works without it. It is installed only for SYSTEM (package) installs into the
# dbus session_bus_policydir. Under LIBRELINUX_USER_INSTALL we do NOT install
# it: stock dbus reads supplementary session policy from the system dirs
# ($datadir + /etc/dbus-1/session.d) plus the single XDG file
# $XDG_CONFIG_HOME/dbus-1/session-local.conf — it does NOT scan a
# $XDG_CONFIG_HOME/dbus-1/session.d/ directory, so a per-user drop-in there is a
# silent no-op. It is a system-package-only layer.
if(NOT LIBRELINUX_USER_INSTALL)
    pkg_get_variable(DBUS_SESSION_POLICY_DIR dbus-1 session_bus_policydir)
    if(NOT DBUS_SESSION_POLICY_DIR)
        set(DBUS_SESSION_POLICY_DIR ${CMAKE_INSTALL_FULL_DATADIR}/dbus-1/session.d)
    endif()
    install(FILES data/org.librescrs.Agent.conf
        DESTINATION ${DBUS_SESSION_POLICY_DIR})
endif()
# polkit actions for Config1 mutation + Card1.Sign
# (org.librescrs.agent.configure[.trust], org.librescrs.agent.sign). The agent
# routes client authorization through polkit's CheckAuthorization whenever
# polkitd is reachable (PolkitAuthorizer is selected at startup unless the
# system bus / polkit is absent, in which case it falls back to
# DefaultAuthorizer). polkit returns FALSE for any action id it does not know,
# and it reads action files ONLY from the system dir /usr/share/polkit-1/actions
# (there is no per-user actions location). So this file MUST land in the system
# dir for signing and trust-config to be authorized on any box where polkitd is
# running (the normal desktop case). A LIBRELINUX_USER_INSTALL=ON dogfood build
# skips the CMake install here (the user prefix actions dir would be dead — not
# read by polkit) and instead requires a one-time `sudo install` of this file
# into the system dir — see docs/dogfooding.md.
if(NOT LIBRELINUX_USER_INSTALL)
    install(FILES data/org.librescrs.agent.configure.policy
        DESTINATION ${CMAKE_INSTALL_FULL_DATADIR}/polkit-1/actions)
endif()

add_subdirectory(tests)
