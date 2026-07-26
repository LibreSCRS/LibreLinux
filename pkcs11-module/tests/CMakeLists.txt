# SPDX-License-Identifier: LGPL-2.1-or-later
find_package(GTest REQUIRED)

# AgentClientTest compiles ../src/AgentClient.cpp, which includes the shared
# wire-name header; give every target here its (header-only) include dir.
link_libraries(librelinux-common)

# dlopen the built module and exercise the C ABI surface standalone.
add_executable(LoadModuleTest LoadModuleTest.cpp)
target_include_directories(LoadModuleTest PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../include)
target_link_libraries(LoadModuleTest PRIVATE GTest::gtest GTest::gtest_main ${CMAKE_DL_LIBS})
target_compile_definitions(LoadModuleTest PRIVATE
    LIBRESCRS_PKCS11_MODULE_PATH="$<TARGET_FILE:librescrs-pkcs11-agent>")
add_dependencies(LoadModuleTest librescrs-pkcs11-agent)
add_test(NAME LoadModuleTest COMMAND LoadModuleTest)

# Wire-shape pin: the shared CertResultEntry marshals to the frozen
# a(sba{sa{s(ssv)}}uasasu) (no .so, no D-Bus, no card).
add_executable(CertResultWireSignatureTest CertResultWireSignatureTest.cpp)
target_include_directories(CertResultWireSignatureTest PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../src)
target_compile_features(CertResultWireSignatureTest PRIVATE cxx_std_23)
target_link_libraries(CertResultWireSignatureTest PRIVATE SDBusCpp::sdbus-c++ GTest::gtest GTest::gtest_main)
add_test(NAME CertResultWireSignatureTest COMMAND CertResultWireSignatureTest)

# Pure slot/token/object/mechanism mapping — compiles ObjectModel.cpp directly
# (no .so, no D-Bus, no card).
add_executable(ObjectModelTest ObjectModelTest.cpp ../src/ObjectModel.cpp)
target_include_directories(ObjectModelTest PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
    ${CMAKE_CURRENT_SOURCE_DIR}/../src)
target_compile_features(ObjectModelTest PRIVATE cxx_std_23)
target_link_libraries(ObjectModelTest PRIVATE GTest::gtest GTest::gtest_main)
add_test(NAME ObjectModelTest COMMAND ObjectModelTest)

# AgentClient proxy against a fake agent on a private session bus.
find_program(DBUS_RUN_SESSION dbus-run-session REQUIRED)
add_executable(AgentClientTest AgentClientTest.cpp ../src/AgentClient.cpp ../src/ObjectModel.cpp)
target_include_directories(AgentClientTest PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
    ${CMAKE_CURRENT_SOURCE_DIR}/../src)
target_compile_features(AgentClientTest PRIVATE cxx_std_23)
target_link_libraries(AgentClientTest PRIVATE SDBusCpp::sdbus-c++ GTest::gtest GTest::gtest_main)
add_test(NAME AgentClientTest COMMAND ${DBUS_RUN_SESSION} -- $<TARGET_FILE:AgentClientTest>)

# Pure-text assertions on the configured .module + deployment-(b) server unit
# (no p11-kit, no D-Bus). The configured files are produced by the parent
# CMakeLists into ${CMAKE_CURRENT_BINARY_DIR}/.. (the pkcs11-module build dir).
add_executable(ModuleConfigTest ModuleConfigTest.cpp)
target_compile_features(ModuleConfigTest PRIVATE cxx_std_23)
target_link_libraries(ModuleConfigTest PRIVATE GTest::gtest GTest::gtest_main)
target_compile_definitions(ModuleConfigTest PRIVATE
    LIBRESCRS_MODULE_CONFIG_PATH="${CMAKE_CURRENT_BINARY_DIR}/../librescrs-agent.module"
    LIBRESCRS_SERVER_UNIT_PATH="${CMAKE_CURRENT_BINARY_DIR}/../librescrs-p11-server.service")
add_test(NAME ModuleConfigTest COMMAND ModuleConfigTest)

# Full C_* ABI driven against the built .so + a fake agent on a private bus.
add_executable(ModuleAbiTest ModuleAbiTest.cpp)
target_include_directories(ModuleAbiTest PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
    ${CMAKE_CURRENT_SOURCE_DIR}/../src
    ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_features(ModuleAbiTest PRIVATE cxx_std_23)
target_link_libraries(ModuleAbiTest PRIVATE SDBusCpp::sdbus-c++ GTest::gtest GTest::gtest_main ${CMAKE_DL_LIBS})
target_compile_definitions(ModuleAbiTest PRIVATE
    LIBRESCRS_PKCS11_MODULE_PATH="$<TARGET_FILE:librescrs-pkcs11-agent>")
add_dependencies(ModuleAbiTest librescrs-pkcs11-agent)
add_test(NAME ModuleAbiTest COMMAND ${DBUS_RUN_SESSION} -- $<TARGET_FILE:ModuleAbiTest>)

# Module-side security properties (no-PIN-on-wire, mechanism rejection,
# non-extractable keys, NAM gating) over the real C_* ABI + fake agent.
add_executable(SecurityTest SecurityTest.cpp)
target_include_directories(SecurityTest PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
    ${CMAKE_CURRENT_SOURCE_DIR}/../src
    ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_features(SecurityTest PRIVATE cxx_std_23)
target_link_libraries(SecurityTest PRIVATE SDBusCpp::sdbus-c++ GTest::gtest GTest::gtest_main ${CMAKE_DL_LIBS})
target_compile_definitions(SecurityTest PRIVATE
    LIBRESCRS_PKCS11_MODULE_PATH="$<TARGET_FILE:librescrs-pkcs11-agent>")
add_dependencies(SecurityTest librescrs-pkcs11-agent)
add_test(NAME SecurityTest COMMAND ${DBUS_RUN_SESSION} -- $<TARGET_FILE:SecurityTest>)

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
set_tests_properties(Pkcs11ToolRpcTest PROPERTIES SKIP_RETURN_CODE 77)

# Env-gated MANUAL real-card smoke. Talks to the LIVE session bus + agent + card;
# SKIPs entirely unless LIBRESCRS_HW_SMOKE=1, so it never blocks CI/dev runs and
# never burns a card retry counter. Built here; run manually (see the file head).
# This TU is libcrypto-FREE by policy (it mirrors the module's no-crypto stance).
add_executable(RealCardSmokeTest RealCardSmokeTest.cpp)
target_include_directories(RealCardSmokeTest PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../include)
target_compile_features(RealCardSmokeTest PRIVATE cxx_std_23)
target_link_libraries(RealCardSmokeTest PRIVATE GTest::gtest GTest::gtest_main ${CMAKE_DL_LIBS})
target_compile_definitions(RealCardSmokeTest PRIVATE
    LIBRESCRS_PKCS11_MODULE_PATH="$<TARGET_FILE:librescrs-pkcs11-agent>")
add_dependencies(RealCardSmokeTest librescrs-pkcs11-agent)
add_test(NAME RealCardSmokeTest COMMAND RealCardSmokeTest)

# Env-gated MANUAL real-card FAITHFUL crypto verification — the libcrypto-LINKING
# companion to RealCardSmokeTest. Same HW gate (LIBRESCRS_HW_SMOKE=1), same PIN
# latch; it links OpenSSL so it can do the real arithmetic (encrypt a probe for
# the decrypt round-trip, EVP_PKEY_verify the signature). Kept SEPARATE from the
# libcrypto-free smoke TU on purpose.
find_package(OpenSSL REQUIRED COMPONENTS Crypto)
add_executable(RealCardCryptoVerifyTest RealCardCryptoVerifyTest.cpp)
target_include_directories(RealCardCryptoVerifyTest PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../include)
target_compile_features(RealCardCryptoVerifyTest PRIVATE cxx_std_23)
target_link_libraries(RealCardCryptoVerifyTest PRIVATE
    OpenSSL::Crypto GTest::gtest GTest::gtest_main ${CMAKE_DL_LIBS})
target_compile_definitions(RealCardCryptoVerifyTest PRIVATE
    LIBRESCRS_PKCS11_MODULE_PATH="$<TARGET_FILE:librescrs-pkcs11-agent>")
add_dependencies(RealCardCryptoVerifyTest librescrs-pkcs11-agent)
add_test(NAME RealCardCryptoVerifyTest COMMAND RealCardCryptoVerifyTest)
