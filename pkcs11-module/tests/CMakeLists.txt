# SPDX-License-Identifier: LGPL-2.1-or-later
find_package(GTest REQUIRED)

# DBusAgentClientTest compiles ../src/DBusAgentClient.cpp, which includes the
# shared wire-name header; give every target here its (header-only) include dir.
link_libraries(librelinux-common)

# Every target here reaches the Cryptoki surface, and after the move it reaches
# it through the shared component's INTERFACE include property rather than
# through a relative path into a directory that no longer exists.
link_libraries(LibreAgent::Pkcs11Facade)

# Wire-shape pin: the shared CertResultEntry marshals to the frozen
# a(sba{sa{s(ssv)}}uasasu) (no .so, no D-Bus, no card).
add_executable(CertResultWireSignatureTest CertResultWireSignatureTest.cpp)
target_include_directories(CertResultWireSignatureTest PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../src)
target_compile_features(CertResultWireSignatureTest PRIVATE cxx_std_23)
target_link_libraries(CertResultWireSignatureTest PRIVATE SDBusCpp::sdbus-c++ GTest::gtest GTest::gtest_main)
gtest_discover_tests(CertResultWireSignatureTest)

# The D-Bus AgentClient implementation against a fake agent on a private session
# bus. It stayed here because the implementation stayed here: 501 lines of
# sdbus-c++ that no other repository builds, and code that keeps its
# implementation must keep its tests.
find_program(DBUS_RUN_SESSION dbus-run-session REQUIRED)
add_executable(DBusAgentClientTest DBusAgentClientTest.cpp ../src/DBusAgentClient.cpp)
target_include_directories(DBusAgentClientTest PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../src)
target_compile_features(DBusAgentClientTest PRIVATE cxx_std_23)
target_link_libraries(DBusAgentClientTest PRIVATE SDBusCpp::sdbus-c++ GTest::gtest GTest::gtest_main)
librelinux_private_session_bus(DBusAgentClientTest)
# A wedged test under dbus-run-session must fail in minutes, not consume the
# runner's whole wall: every dbus-run-session test here carries an explicit
# timeout.
gtest_discover_tests(DBusAgentClientTest PROPERTIES
    ENVIRONMENT "${LIBRELINUX_PRIVATE_BUS_ENV}" TIMEOUT 120)

# The same contract suite the agent's own tree instantiates over the socket
# transport, instantiated here over the bus one. The claims are NOT copied: the
# header arrives through LibreAgent::Pkcs11Facade's interface include property,
# the same way AgentClient.h does, on both the FetchContent and the
# find_package path.
add_executable(DBusAgentClientContractTest DBusAgentClientContractTest.cpp ../src/DBusAgentClient.cpp)
target_include_directories(DBusAgentClientContractTest PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../src)
target_compile_features(DBusAgentClientContractTest PRIVATE cxx_std_23)
target_link_libraries(DBusAgentClientContractTest PRIVATE SDBusCpp::sdbus-c++ GTest::gtest GTest::gtest_main)
librelinux_private_session_bus(DBusAgentClientContractTest)
# One claim in that suite is what the client answers when the agent is ABSENT,
# and on this transport "nobody owns the name" is not the same thing: the bus
# will try to START the agent from a service file, and a developer machine that
# has one installed gets a spawn failure -- a different error name, a different
# Status -- where a clean container gets ServiceUnknown. That is a real
# difference between two machines, not between two transports, so the search
# path is emptied rather than inherited and absent means absent everywhere.
file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/no-bus-services)
gtest_discover_tests(DBusAgentClientContractTest PROPERTIES
    TIMEOUT 120
    ENVIRONMENT "XDG_DATA_HOME=${CMAKE_CURRENT_BINARY_DIR}/no-bus-services;XDG_DATA_DIRS=${CMAKE_CURRENT_BINARY_DIR}/no-bus-services;${LIBRELINUX_PRIVATE_BUS_ENV}")

# Pure-text assertions on the configured .module + deployment-(b) server unit
# (no p11-kit, no D-Bus). The configured files are produced by the parent
# CMakeLists into ${CMAKE_CURRENT_BINARY_DIR}/.. (the pkcs11-module build dir).
add_executable(ModuleConfigTest ModuleConfigTest.cpp)
target_compile_features(ModuleConfigTest PRIVATE cxx_std_23)
target_link_libraries(ModuleConfigTest PRIVATE GTest::gtest GTest::gtest_main)
target_compile_definitions(ModuleConfigTest PRIVATE
    LIBRESCRS_MODULE_CONFIG_PATH="${CMAKE_CURRENT_BINARY_DIR}/../librescrs-agent.module"
    LIBRESCRS_SERVER_UNIT_PATH="${CMAKE_CURRENT_BINARY_DIR}/../librescrs-p11-server.service"
    # Where this build puts the .so, and where p11-kit looks for a bare name.
    # The declaration may use the bare form only when the two are equal.
    LIBRESCRS_MODULE_DIR_ABS="${LIBRESCRS_P11_MODULE_DIR_ABS}"
    LIBRESCRS_P11_KIT_MODULE_PATH="${_ll_p11_module_path}")
gtest_discover_tests(ModuleConfigTest)

# RPC integration: drive the EXTERNAL consumer pkcs11-tool against the real .so
# with the FakeAgent as the card backend (in-process deployment-a path). Needs a
# standalone fake-agent process + pkcs11-tool; SKIPs (ctest 77) if pkcs11-tool is
# absent. A full p11-kit-routed / out-of-process `p11-kit server` run is the
# documented manual smoke.
add_executable(FakeAgentMain FakeAgentMain.cpp)
target_include_directories(FakeAgentMain PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../src)
target_compile_features(FakeAgentMain PRIVATE cxx_std_23)
target_link_libraries(FakeAgentMain PRIVATE SDBusCpp::sdbus-c++)
add_dependencies(FakeAgentMain librescrs-pkcs11-agent)

add_test(NAME Pkcs11ToolRpcTest
    COMMAND ${DBUS_RUN_SESSION} -- bash ${CMAKE_CURRENT_SOURCE_DIR}/pkcs11_tool_rpc.sh
            $<TARGET_FILE:FakeAgentMain> $<TARGET_FILE:librescrs-pkcs11-agent>)
set_tests_properties(Pkcs11ToolRpcTest PROPERTIES
    SKIP_RETURN_CODE 77
    TIMEOUT 120)
