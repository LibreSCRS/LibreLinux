# SPDX-License-Identifier: LGPL-2.1-or-later
find_package(GTest REQUIRED)

# D-Bus tests run on a private session bus; resolve dbus-run-session up front so
# any test below can wrap its command in ${DBUS_RUN_SESSION}.
find_program(DBUS_RUN_SESSION dbus-run-session REQUIRED)

# The platform-neutral unit tests (flows, scheduler, presence model, caches,
# lease/broker policy, value types, the 5 backend fakes) moved with the core to
# the librescrs-agent repo and run there. What remains here exercises the Linux
# backend: the sdbus frontend, the interface implementations, the memfd
# transport, and the D-Bus integration surface. Each still links
# LibreLinuxAgentCore, which transitively pulls the imported LibreAgent::Core.

add_executable(ConfigPathsTest ConfigPathsTest.cpp)
target_link_libraries(ConfigPathsTest PRIVATE
    LibreLinuxAgentCore
    GTest::gtest
    GTest::gtest_main)
add_test(NAME ConfigPathsTest COMMAND ConfigPathsTest)

# The plugin-directory cascade and the report it produces. Bus-free: the
# resolution is injected (no mutated environment) and the end-to-end cases drive
# a real CardPluginService over a temp directory with an injected log sink.
add_executable(PluginDirectoryTest PluginDirectoryTest.cpp)
target_link_libraries(PluginDirectoryTest PRIVATE
    LibreLinuxAgentCore
    GTest::gtest
    GTest::gtest_main)
add_test(NAME PluginDirectoryTest COMMAND PluginDirectoryTest)

add_executable(CallerIdentityTest CallerIdentityTest.cpp)
target_link_libraries(CallerIdentityTest PRIVATE
    LibreLinuxAgentCore
    GTest::gtest
    GTest::gtest_main)
add_test(NAME CallerIdentityTest COMMAND CallerIdentityTest)

# The card-path -> reader inverse behind a prompt's reader label. Pure: drives
# the seam over a hand-built presence snapshot, no bus and no reader.
add_executable(ReaderIdentitySeamTest ReaderIdentitySeamTest.cpp)
target_link_libraries(ReaderIdentitySeamTest PRIVATE
    LibreLinuxAgentCore
    GTest::gtest
    GTest::gtest_main)
add_test(NAME ReaderIdentitySeamTest COMMAND ReaderIdentitySeamTest)

# The version guard in front of every prompt: pure policy over a single read.
add_executable(PrompterCapabilityTest PrompterCapabilityTest.cpp)
target_link_libraries(PrompterCapabilityTest PRIVATE
    LibreLinuxAgentCore
    GTest::gtest
    GTest::gtest_main)
add_test(NAME PrompterCapabilityTest COMMAND PrompterCapabilityTest)

# Pure helpers of the polkit authorizer (no live polkit daemon required).
add_executable(PolkitAuthorizerTest PolkitAuthorizerTest.cpp)
target_link_libraries(PolkitAuthorizerTest PRIVATE
    LibreLinuxAgentCore
    GTest::gtest
    GTest::gtest_main)
add_test(NAME PolkitAuthorizerTest COMMAND PolkitAuthorizerTest)

# AgentTransport backend interface: a fake records the typed presence deltas +
# loop-post + disconnect handler, and a bus-backed case drives the real
# BusExporter loop-marshaling impl (needs a private session bus).
add_executable(AgentTransportTest AgentTransportTest.cpp)
target_link_libraries(AgentTransportTest PRIVATE
    LibreLinuxAgentCore
    PkgConfig::Systemd # the post/postAfter marshal test drives an sd-event loop directly
    GTest::gtest
    GTest::gtest_main)
add_test(NAME AgentTransportTest
    COMMAND ${DBUS_RUN_SESSION} -- $<TARGET_FILE:AgentTransportTest>)
# A wedged test under dbus-run-session must fail in minutes, not consume the
# runner's whole wall: every bus-backed test below carries an explicit timeout.
set_tests_properties(AgentTransportTest PROPERTIES TIMEOUT 120)

# Static/source guard: the deferred-publish worker hop must marshal back through the
# transport-handed-out post sink, never a concrete transport poster member. Reads the
# shipped source, so it needs no bus and no link against the agent core.
add_executable(TransportCaptureGuardTest TransportCaptureGuardTest.cpp)
target_compile_definitions(TransportCaptureGuardTest PRIVATE
    LIBRELINUX_AGENTFRONTEND_CPP="${CMAKE_CURRENT_SOURCE_DIR}/../src/AgentFrontend.cpp"
    LIBRELINUX_BUSEXPORTER_CPP="${CMAKE_CURRENT_SOURCE_DIR}/../src/BusExporter.cpp"
    LIBRELINUX_BUSEXPORTER_H="${CMAKE_CURRENT_SOURCE_DIR}/../src/BusExporter.h"
    LIBRELINUX_AGENTSERVICE_CPP="${CMAKE_CURRENT_SOURCE_DIR}/../src/AgentService.cpp"
    LIBRELINUX_CARDOBJECT_CPP="${CMAKE_CURRENT_SOURCE_DIR}/../src/dbus/CardObject.cpp")
target_link_libraries(TransportCaptureGuardTest PRIVATE
    GTest::gtest
    GTest::gtest_main)
add_test(NAME TransportCaptureGuardTest COMMAND TransportCaptureGuardTest)

# Ordered-teardown regression for AgentService::quiesce(): the inbound presence
# source stops before the core observers are severed, and crypto workers wedged in
# a blocking prompt drain on the quiesce cancel so teardown stays bounded (no bus —
# it drives the core registry + OperationManager collaborators directly).
add_executable(AgentShutdownUnderLoadTest AgentShutdownUnderLoadTest.cpp)
target_link_libraries(AgentShutdownUnderLoadTest PRIVATE
    LibreLinuxAgentCore
    GTest::gtest
    GTest::gtest_main)
add_test(NAME AgentShutdownUnderLoadTest COMMAND AgentShutdownUnderLoadTest)

# Teeth test for the qualified-sign path's LM-seam keep-alive (the last
# abandoned-worker gap): an abandoned sign op must co-own its signing seam share so
# the seam's post-unblock vtable dispatch + engine/config deref touch live memory.
# Bus-less worker path with a fake channel; meaningful under a thread-sanitizer build.
add_executable(SignSeamWedgeDrainTest SignSeamWedgeDrainTest.cpp)
target_link_libraries(SignSeamWedgeDrainTest PRIVATE
    LibreLinuxAgentCore
    GTest::gtest
    GTest::gtest_main)
add_test(NAME SignSeamWedgeDrainTest COMMAND SignSeamWedgeDrainTest)

# Wire-ordering contract of the credential-management operation adaptors
# (Operation.Credentials1.xml): a typed Result for EVERY completed attempt —
# including cancelled/failed lists — always before Finished, and a failed
# Result delivery fails the op closed. Bus-less: fake channel + fake seams,
# ops run synchronously via runOnWorker().
add_executable(CredentialOperationContractTest CredentialOperationContractTest.cpp)
target_link_libraries(CredentialOperationContractTest PRIVATE
    LibreLinuxAgentCore
    GTest::gtest
    GTest::gtest_main)
add_test(NAME CredentialOperationContractTest COMMAND CredentialOperationContractTest)

# Teeth test for the typed zombie op's OWN sdbus channel/adaptor resource class:
# an abandoned typed op must co-own the agent bus connection so its REAL adaptor
# unregister + emit at zombie drain touch live memory. Uses a private session bus
# (the adaptor binds a real connection); meaningful under a thread-sanitizer build.
add_executable(TypedChannelWedgeDrainTest TypedChannelWedgeDrainTest.cpp)
target_link_libraries(TypedChannelWedgeDrainTest PRIVATE
    LibreLinuxAgentCore
    GTest::gtest
    GTest::gtest_main)
add_test(NAME TypedChannelWedgeDrainTest
    COMMAND ${DBUS_RUN_SESSION} -- $<TARGET_FILE:TypedChannelWedgeDrainTest>)
set_tests_properties(TypedChannelWedgeDrainTest PROPERTIES TIMEOUT 120)

# Cross-stack wire-contract drift guard: static_asserts tying the canonical
# Card1.Capabilities + ErrorCode wire literals to the upstream LM symbol (links
# LM::Plugin via AgentCore). Its LM-free twin is
# LibreKDE/tests/agentclient/WireContractGuardTest.cpp.
add_executable(WireContractGuardTest WireContractGuardTest.cpp)
target_link_libraries(WireContractGuardTest PRIVATE
    LibreLinuxAgentCore
    GTest::gtest
    GTest::gtest_main)
add_test(NAME WireContractGuardTest COMMAND WireContractGuardTest)

# Machine gate for the errorCode taxonomy: pins the agent ErrorCode enum,
# value-for-value and count, against the enumeration documented in
# dbus/org.librescrs.Agent.Operation1.xml (the canonical wire contract — new
# codes land there first). -Werror=switch turns an upstream enum append into a
# compile failure here; the runtime half then forces the XML edit clients key
# off. Reads the XML from the source tree (TransportCaptureGuardTest pattern).
add_executable(Operation1ErrorCodeXmlGuardTest Operation1ErrorCodeXmlGuardTest.cpp)
target_compile_definitions(Operation1ErrorCodeXmlGuardTest PRIVATE
    LIBRELINUX_OPERATION1_XML="${CMAKE_CURRENT_SOURCE_DIR}/../dbus/org.librescrs.Agent.Operation1.xml")
target_compile_options(Operation1ErrorCodeXmlGuardTest PRIVATE -Werror=switch)
target_link_libraries(Operation1ErrorCodeXmlGuardTest PRIVATE
    LibreLinuxAgentCore
    GTest::gtest
    GTest::gtest_main)
add_test(NAME Operation1ErrorCodeXmlGuardTest COMMAND Operation1ErrorCodeXmlGuardTest)

# Machine gate for the sandbox's writable directories: while the unit confines
# the home directory read-only, it must declare a directory for each of the
# agent's write roots, or the writes fail with EROFS at runtime and nothing the
# user configures survives a restart. Reads the unit template from the source
# tree (same pattern as the guard above). Needs no agent library — it reads a
# file — so it links only gtest.
add_executable(SandboxWritableDirsGuardTest SandboxWritableDirsGuardTest.cpp)
target_compile_definitions(SandboxWritableDirsGuardTest PRIVATE
    LIBRELINUX_AGENT_UNIT_IN="${CMAKE_CURRENT_SOURCE_DIR}/../data/librescrs-agent.service.in")
target_link_libraries(SandboxWritableDirsGuardTest PRIVATE
    GTest::gtest
    GTest::gtest_main)
add_test(NAME SandboxWritableDirsGuardTest COMMAND SandboxWritableDirsGuardTest)

add_executable(Operation1XmlCodegenTest Operation1XmlCodegenTest.cpp)
target_link_libraries(Operation1XmlCodegenTest PRIVATE
    LibreLinuxAgentCore
    GTest::gtest
    GTest::gtest_main)
add_test(NAME Operation1XmlCodegenTest COMMAND Operation1XmlCodegenTest)

# ObjectId <-> object-path bijection (AgentObjectPath.h): round-trip + fail-closed
# parse of malformed / overflowing numeric tails. Pure header-only (no session bus).
add_executable(AgentObjectPathTest AgentObjectPathTest.cpp)
target_link_libraries(AgentObjectPathTest PRIVATE
    LibreLinuxAgentCore
    GTest::gtest
    GTest::gtest_main)
add_test(NAME AgentObjectPathTest COMMAND AgentObjectPathTest)

# Card1.CardType arbitration over the held-session candidate list
# (CardTypeArbitration.h): lowest probe priority wins, a tie at that value stays
# empty. Pure header-only (no session bus, no card).
add_executable(CardTypeArbitrationTest CardTypeArbitrationTest.cpp)
target_link_libraries(CardTypeArbitrationTest PRIVATE
    LibreLinuxAgentCore
    GTest::gtest
    GTest::gtest_main)
add_test(NAME CardTypeArbitrationTest COMMAND CardTypeArbitrationTest)

add_executable(Card1MethodsXmlCodegenTest Card1MethodsXmlCodegenTest.cpp)
target_link_libraries(Card1MethodsXmlCodegenTest PRIVATE
    LibreLinuxAgentCore
    GTest::gtest
    GTest::gtest_main)
add_test(NAME Card1MethodsXmlCodegenTest COMMAND Card1MethodsXmlCodegenTest)

# Manager1.Version + Manager1.Features (the agent feature-discovery property).
add_executable(Manager1XmlCodegenTest Manager1XmlCodegenTest.cpp)
target_link_libraries(Manager1XmlCodegenTest PRIVATE
    LibreLinuxAgentCore
    GTest::gtest
    GTest::gtest_main)
add_test(NAME Manager1XmlCodegenTest COMMAND Manager1XmlCodegenTest)

add_executable(Prompter1CancelXmlCodegenTest Prompter1CancelXmlCodegenTest.cpp)
target_link_libraries(Prompter1CancelXmlCodegenTest PRIVATE
    LibreLinuxAgentCore
    GTest::gtest
    GTest::gtest_main)
add_test(NAME Prompter1CancelXmlCodegenTest COMMAND Prompter1CancelXmlCodegenTest)

add_executable(Operation1AdaptorTest Operation1AdaptorTest.cpp)
target_link_libraries(Operation1AdaptorTest PRIVATE
    LibreLinuxAgentCore
    GTest::gtest
    GTest::gtest_main)
target_compile_definitions(Operation1AdaptorTest PRIVATE LIBRELINUX_TESTING)
add_test(NAME Operation1AdaptorTest
    COMMAND ${DBUS_RUN_SESSION} -- $<TARGET_FILE:Operation1AdaptorTest>)
set_tests_properties(Operation1AdaptorTest PROPERTIES TIMEOUT 120)

# Certificates1.Result wire-shape conformance (compile-only static_assert).
add_executable(Certificates1XmlCodegenTest Certificates1XmlCodegenTest.cpp)
target_link_libraries(Certificates1XmlCodegenTest PRIVATE
    LibreLinuxAgentCore
    GTest::gtest
    GTest::gtest_main)
add_test(NAME Certificates1XmlCodegenTest COMMAND Certificates1XmlCodegenTest)

# Identity1 / Photo1 Result + GetResult wire-shape conformance (compile-only).
add_executable(Identity1XmlCodegenTest Identity1XmlCodegenTest.cpp)
target_link_libraries(Identity1XmlCodegenTest PRIVATE
    LibreLinuxAgentCore
    GTest::gtest
    GTest::gtest_main)
add_test(NAME Identity1XmlCodegenTest COMMAND Identity1XmlCodegenTest)

add_executable(Photo1XmlCodegenTest Photo1XmlCodegenTest.cpp)
target_link_libraries(Photo1XmlCodegenTest PRIVATE
    LibreLinuxAgentCore
    GTest::gtest
    GTest::gtest_main)
add_test(NAME Photo1XmlCodegenTest COMMAND Photo1XmlCodegenTest)

add_executable(ReadIdentityOperationTest ReadIdentityOperationTest.cpp)
target_link_libraries(ReadIdentityOperationTest PRIVATE
    LibreLinuxAgentCore
    GTest::gtest
    GTest::gtest_main)
add_test(NAME ReadIdentityOperationTest COMMAND ReadIdentityOperationTest)

add_executable(GetPhotoOperationTest GetPhotoOperationTest.cpp)
target_link_libraries(GetPhotoOperationTest PRIVATE
    LibreLinuxAgentCore
    GTest::gtest
    GTest::gtest_main)
add_test(NAME GetPhotoOperationTest COMMAND GetPhotoOperationTest)

add_executable(ReadCertificatesOperationTest ReadCertificatesOperationTest.cpp)
target_link_libraries(ReadCertificatesOperationTest PRIVATE
    LibreLinuxAgentCore
    GTest::gtest
    GTest::gtest_main)
add_test(NAME ReadCertificatesOperationTest COMMAND ReadCertificatesOperationTest)

add_executable(OperationManagerNameOwnerChangedTest OperationManagerNameOwnerChangedTest.cpp)
target_link_libraries(OperationManagerNameOwnerChangedTest PRIVATE
    LibreLinuxAgentCore
    GTest::gtest
    GTest::gtest_main)
add_test(NAME OperationManagerNameOwnerChangedTest
    COMMAND ${DBUS_RUN_SESSION} -- $<TARGET_FILE:OperationManagerNameOwnerChangedTest>)
set_tests_properties(OperationManagerNameOwnerChangedTest PROPERTIES TIMEOUT 120)

# D-Bus integration test — needs a private session bus + dbus-run-session.
add_executable(ReaderRemoveDrainTest ReaderRemoveDrainTest.cpp)
target_link_libraries(ReaderRemoveDrainTest PRIVATE
    LibreLinuxAgentCore
    GTest::gtest
    GTest::gtest_main)
add_test(NAME ReaderRemoveDrainTest
    COMMAND ${DBUS_RUN_SESSION} -- $<TARGET_FILE:ReaderRemoveDrainTest>)
set_tests_properties(ReaderRemoveDrainTest PROPERTIES TIMEOUT 120)

# Reader map + ReaderObject-field concurrency guard: resolveReaderCard (loop
# thread) hammered against reader/card churn (monitor thread). Needs a private
# session bus; meaningful under a thread-sanitizer build.
add_executable(BusExporterReaderRaceTest BusExporterReaderRaceTest.cpp)
target_link_libraries(BusExporterReaderRaceTest PRIVATE
    LibreLinuxAgentCore
    GTest::gtest
    GTest::gtest_main)
add_test(NAME BusExporterReaderRaceTest
    COMMAND ${DBUS_RUN_SESSION} -- $<TARGET_FILE:BusExporterReaderRaceTest>)
set_tests_properties(BusExporterReaderRaceTest PROPERTIES TIMEOUT 120)

add_executable(DBusServiceTest DBusServiceTest.cpp)
target_link_libraries(DBusServiceTest PRIVATE
    LibreLinuxAgentCore
    GTest::gtest
    GTest::gtest_main)
add_test(NAME DBusServiceTest
    COMMAND ${DBUS_RUN_SESSION} -- $<TARGET_FILE:DBusServiceTest>)
set_tests_properties(DBusServiceTest PROPERTIES TIMEOUT 120)

# Config1 end-to-end (Get/SetValue/Reset/Changed + mutability + polkit gate).
add_executable(Config1Test Config1Test.cpp)
target_link_libraries(Config1Test PRIVATE
    LibreLinuxAgentCore
    GTest::gtest
    GTest::gtest_main)
add_test(NAME Config1Test
    COMMAND ${DBUS_RUN_SESSION} -- $<TARGET_FILE:Config1Test>)
set_tests_properties(Config1Test PROPERTIES TIMEOUT 120)

# Card1.ReadIdentity / GetPhoto end-to-end — capability gate + enqueue path.
add_executable(CardObjectOperationsTest CardObjectOperationsTest.cpp)
target_link_libraries(CardObjectOperationsTest PRIVATE
    LibreLinuxAgentCore
    GTest::gtest
    GTest::gtest_main)
add_test(NAME CardObjectOperationsTest
    COMMAND ${DBUS_RUN_SESSION} -- $<TARGET_FILE:CardObjectOperationsTest>)
set_tests_properties(CardObjectOperationsTest PROPERTIES TIMEOUT 120)

# PrompterClient end-to-end: drive the client against an in-process mock
# Prompter1 adaptor (hosted on a separate connection to avoid sd-bus self-call
# rejection). The mock side needs the generated _adaptor.h, which the parent
# agent target does not generate (it only consumes the proxy); we generate
# it locally here so the test is self-contained. add_custom_command OUTPUT
# must live in the same CMake scope as the target that consumes it, hence
# this duplication rather than re-using a parent-scope list.
set(_test_prompter_adaptor ${LL_DBUS_GEN_DIR}/org.librescrs.Prompter1_adaptor.h)
add_custom_command(
    OUTPUT ${_test_prompter_adaptor}
    COMMAND ${SDBUS_CPP_XML2CPP} ${LL_DBUS_XML_DIR}/org.librescrs.Prompter1.xml
            --adaptor=${_test_prompter_adaptor}
    DEPENDS ${LL_DBUS_XML_DIR}/org.librescrs.Prompter1.xml
    VERBATIM)

add_executable(PrompterIntegrationTest
    PrompterIntegrationTest.cpp
    ${_test_prompter_adaptor})
target_include_directories(PrompterIntegrationTest PRIVATE ${LL_DBUS_GEN_DIR})
# The production-read case drives the real IdentityReadFlow against a detached
# fake card session, which needs the middleware-internal session factory (same
# opt-in the other session-driving suites here use).
target_compile_definitions(PrompterIntegrationTest PRIVATE LIBRESCRS_INTERNAL_BUILD)
target_link_libraries(PrompterIntegrationTest PRIVATE
    LibreLinuxAgentCore
    GTest::gtest
    GTest::gtest_main)
add_test(NAME PrompterIntegrationTest
    COMMAND ${DBUS_RUN_SESSION} -- $<TARGET_FILE:PrompterIntegrationTest>)
set_tests_properties(PrompterIntegrationTest PROPERTIES TIMEOUT 120)

# SecretMemfdReader trust-root input-shape check: a correctly-sealed memfd is
# accepted, an unsealed memfd (or a non-memfd fd) is rejected. Bus-free — it
# constructs the fds directly and calls the reader.
add_executable(SecretMemfdReaderTest SecretMemfdReaderTest.cpp)
target_link_libraries(SecretMemfdReaderTest PRIVATE
    LibreLinuxAgentCore
    GTest::gtest
    GTest::gtest_main)
add_test(NAME SecretMemfdReaderTest COMMAND SecretMemfdReaderTest)

# Full-stack: agent (Card1 + Operation paths) + FakePrompterService on a
# private bus. Exercises the happy path (Identity1.Result before
# Operation1.Finished(Ok)) and the auto-cancel-on-disconnect path (client
# connection closes mid-read -> NameOwnerChanged -> cancel -> Phase
# becomes Done). Reuses the prompter adaptor codegen artefact so the fake
# host stays in lock-step with the production wire contract.
add_executable(CardOperationsIntegrationTest
    CardOperationsIntegrationTest.cpp
    ${_test_prompter_adaptor})
target_include_directories(CardOperationsIntegrationTest PRIVATE ${LL_DBUS_GEN_DIR})
target_link_libraries(CardOperationsIntegrationTest PRIVATE
    LibreLinuxAgentCore
    PkgConfig::Systemd # the pre-read-auth marshal test drives an sd-event loop directly
    GTest::gtest
    GTest::gtest_main)
add_test(NAME CardOperationsIntegrationTest
    COMMAND ${DBUS_RUN_SESSION} -- $<TARGET_FILE:CardOperationsIntegrationTest>)
set_tests_properties(CardOperationsIntegrationTest PROPERTIES TIMEOUT 120)

# --- A4 signing (card-free) ------------------------------------------------
add_executable(SignFlowTest SignFlowTest.cpp)
target_link_libraries(SignFlowTest PRIVATE
    LibreLinuxAgentCore
    GTest::gtest
    GTest::gtest_main)
add_test(NAME SignFlowTest COMMAND SignFlowTest)

# Late-subscriber recovery store for the inline typed results (the Sign1
# store's seal-specific suite stays in SignFlowTest).
add_executable(TypedResultStoreTest TypedResultStoreTest.cpp)
target_link_libraries(TypedResultStoreTest PRIVATE
    LibreLinuxAgentCore
    GTest::gtest
    GTest::gtest_main)
add_test(NAME TypedResultStoreTest COMMAND TypedResultStoreTest)

add_executable(Sign1XmlCodegenTest Sign1XmlCodegenTest.cpp)
target_include_directories(Sign1XmlCodegenTest PRIVATE ${LL_DBUS_GEN_DIR})
target_link_libraries(Sign1XmlCodegenTest PRIVATE
    LibreLinuxAgentCore
    GTest::gtest
    GTest::gtest_main)
add_test(NAME Sign1XmlCodegenTest COMMAND Sign1XmlCodegenTest)

# SignBatch1.Result/GetResult wire-shape conformance (compile-only).
add_executable(SignBatch1XmlCodegenTest SignBatch1XmlCodegenTest.cpp)
target_include_directories(SignBatch1XmlCodegenTest PRIVATE ${LL_DBUS_GEN_DIR})
target_link_libraries(SignBatch1XmlCodegenTest PRIVATE
    LibreLinuxAgentCore
    GTest::gtest
    GTest::gtest_main)
add_test(NAME SignBatch1XmlCodegenTest COMMAND SignBatch1XmlCodegenTest)

# Hermetic exercise of SignBatchOperation (Card1.SignBatch's worker-side
# Operation): every seam is a Fake, the flow runs synchronously on the test
# thread. Mirrors SignFlowTest.cpp's bus-less convention for Sign.
add_executable(SignBatchOperationTest SignBatchOperationTest.cpp)
target_link_libraries(SignBatchOperationTest PRIVATE
    LibreLinuxAgentCore
    GTest::gtest
    GTest::gtest_main)
add_test(NAME SignBatchOperationTest COMMAND SignBatchOperationTest)

add_executable(Pkcs11XmlCodegenTest Pkcs11XmlCodegenTest.cpp)
target_include_directories(Pkcs11XmlCodegenTest PRIVATE ${LL_DBUS_GEN_DIR})
target_link_libraries(Pkcs11XmlCodegenTest PRIVATE
    LibreLinuxAgentCore
    GTest::gtest
    GTest::gtest_main)
add_test(NAME Pkcs11XmlCodegenTest COMMAND Pkcs11XmlCodegenTest)

add_executable(Pkcs11OutcomeNamesTest Pkcs11OutcomeNamesTest.cpp)
target_link_libraries(Pkcs11OutcomeNamesTest PRIVATE
    LibreLinuxAgentCore
    GTest::gtest
    GTest::gtest_main)
add_test(NAME Pkcs11OutcomeNamesTest COMMAND Pkcs11OutcomeNamesTest)

# Hardware smoke (env-gated; skipped without LIBRESCRS_HW). Not committed yet —
# the start of the HW-validation increment.
add_executable(SignHwSmokeTest SignHwSmokeTest.cpp)
target_link_libraries(SignHwSmokeTest PRIVATE
    LibreLinuxAgentCore
    GTest::gtest
    GTest::gtest_main)
add_test(NAME SignHwSmokeTest COMMAND SignHwSmokeTest)

# These backend tests construct a stable per-session key via the LM-internal
# detached-session factory LibreSCRS::SmartCard::detail::makeDetachedCardSession.
# Its prototype in <LibreSCRS/SmartCard/CardSession.h> is guarded behind
# LIBRESCRS_INTERNAL_BUILD and the symbol is exported from libLibreSCRS_SmartCard
# (LM_4), so the TEST TUs that use it must enable the internal declaration — the
# same opt-in LibreMiddleware's own tests use. Production agent/module targets
# NEVER define this, so the internal surface stays out of the shipped binaries.
foreach(_internal_session_test IN ITEMS
        CardObjectOperationsTest
        CardOperationsIntegrationTest
        CredentialOperationContractTest
        SignFlowTest
        SignBatchOperationTest
        GetPhotoOperationTest
        ReadCertificatesOperationTest
        ReadIdentityOperationTest)
    if(TARGET ${_internal_session_test})
        target_compile_definitions(${_internal_session_test} PRIVATE LIBRESCRS_INTERNAL_BUILD)
    endif()
endforeach()

# RequestSecrets (multi-secret) wire-shape conformance: compile-only
# static_assert on the generated Prompter1 proxy + the shared PrompterWire
# change_pin vocabulary (sibling of Prompter1CancelXmlCodegenTest).
add_executable(RequestSecretsXmlCodegenTest RequestSecretsXmlCodegenTest.cpp)
target_link_libraries(RequestSecretsXmlCodegenTest PRIVATE
    LibreLinuxAgentCore
    GTest::gtest
    GTest::gtest_main)
add_test(NAME RequestSecretsXmlCodegenTest COMMAND RequestSecretsXmlCodegenTest)

# The ONE place the RequestSecret alternative-kind option key and its distinct
# success status are spelled absolutely (everything else goes through the
# PrompterWire constants). Keeps the cross-platform wire strings pinned; see the
# file header. Header-only vocabulary, so no bus and no link beyond gtest.
add_executable(PrompterVocabularyPinTest PrompterVocabularyPinTest.cpp)
target_link_libraries(PrompterVocabularyPinTest PRIVATE
    LibreLinuxAgentCore
    GTest::gtest
    GTest::gtest_main)
add_test(NAME PrompterVocabularyPinTest COMMAND PrompterVocabularyPinTest)

# PrompterClient multi-secret (change_pin) end-to-end: drive requestPinChange
# against an in-process mock Prompter1 adaptor scripting RequestSecrets (two
# sealed fds; primary = current PIN, secondary = new PIN). Reuses the locally
# generated adaptor artefact + a private session bus, mirroring
# PrompterIntegrationTest. Asserts the read-both-then-validate discipline: a
# seal failure on either fd leaks no partial secret.
add_executable(PrompterClientPinChangeTest
    PrompterClientPinChangeTest.cpp
    ${_test_prompter_adaptor})
target_include_directories(PrompterClientPinChangeTest PRIVATE ${LL_DBUS_GEN_DIR})
target_link_libraries(PrompterClientPinChangeTest PRIVATE
    LibreLinuxAgentCore
    GTest::gtest
    GTest::gtest_main)
add_test(NAME PrompterClientPinChangeTest
    COMMAND ${DBUS_RUN_SESSION} -- $<TARGET_FILE:PrompterClientPinChangeTest>)
set_tests_properties(PrompterClientPinChangeTest PROPERTIES TIMEOUT 120)

# Human-paced prompt budget: the mock prompter replies only AFTER the D-Bus
# default method timeout has elapsed; the client must still receive the
# answer (interactive requests carry an explicit generous budget). A slow
# test by design (~half a minute) — the only honest end-to-end proof of the
# regression it pins (real MRZ entry aborted mid-typing at ~25 s).
add_executable(PrompterClientInteractiveBudgetTest
    PrompterClientInteractiveBudgetTest.cpp
    ${_test_prompter_adaptor})
target_include_directories(PrompterClientInteractiveBudgetTest PRIVATE ${LL_DBUS_GEN_DIR})
target_link_libraries(PrompterClientInteractiveBudgetTest PRIVATE
    LibreLinuxAgentCore
    GTest::gtest
    GTest::gtest_main)
add_test(NAME PrompterClientInteractiveBudgetTest
    COMMAND ${DBUS_RUN_SESSION} -- $<TARGET_FILE:PrompterClientInteractiveBudgetTest>)
# Higher ceiling than the 120 s default used elsewhere in this file: the
# measured floor is ~32 s because the test deliberately rides past sd-bus's
# ~25 s default reply window (same class as the pkcs11 ModuleAbiTest sibling).
# The previous 90 s left under 3x headroom, which a loaded runner can eat
# without anything actually being wrong.
set_tests_properties(PrompterClientInteractiveBudgetTest PROPERTIES TIMEOUT 180)

# Credentials1 D-Bus surface end-to-end: CardObject (Card1 + Credentials1) + a fake
# CredentialManager seam + FakePrompterService on a private session bus. Reuses the
# locally-generated Prompter1 adaptor artefact; needs the LM-internal detached
# session factory (LIBRESCRS_INTERNAL_BUILD) for the fake CardSession.
add_executable(CredentialsDbusTest
    CredentialsDbusTest.cpp
    ${_test_prompter_adaptor})
target_include_directories(CredentialsDbusTest PRIVATE ${LL_DBUS_GEN_DIR})
target_link_libraries(CredentialsDbusTest PRIVATE
    LibreLinuxAgentCore
    GTest::gtest
    GTest::gtest_main)
target_compile_definitions(CredentialsDbusTest PRIVATE LIBRESCRS_INTERNAL_BUILD)
add_test(NAME CredentialsDbusTest
    COMMAND ${DBUS_RUN_SESSION} -- $<TARGET_FILE:CredentialsDbusTest>)
set_tests_properties(CredentialsDbusTest PROPERTIES TIMEOUT 120)

# --- country-signing anchor import ------------------------------------------
#
# The synthetic master-list fixture mints its certificates with the SYSTEM
# OpenSSL. That dependency is the test's alone: the agent consumes the published
# LibreMiddleware trust API and links no crypto library of its own, which is the
# property CscaAnchorImport.cpp exists to preserve.
find_package(OpenSSL REQUIRED COMPONENTS Crypto)
add_library(SyntheticMasterList STATIC SyntheticMasterList.cpp)
target_include_directories(SyntheticMasterList PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(SyntheticMasterList PUBLIC OpenSSL::Crypto)
target_compile_features(SyntheticMasterList PUBLIC cxx_std_23)
set_target_properties(SyntheticMasterList PROPERTIES POSITION_INDEPENDENT_CODE ON)

# Trust bootstrap away from D-Bus: first import, pin, rotation, and the
# refusals — including the link certificate that a self-signed-only filter
# would drop.
add_executable(CscaAnchorImportTest CscaAnchorImportTest.cpp)
target_link_libraries(CscaAnchorImportTest PRIVATE
    LibreLinuxAgentCore
    SyntheticMasterList
    GTest::gtest
    GTest::gtest_main)
add_test(NAME CscaAnchorImportTest COMMAND CscaAnchorImportTest)
set_tests_properties(CscaAnchorImportTest PROPERTIES TIMEOUT 120)

# Config1.ImportCscaMasterList over a private session bus: the authorise ->
# rate-limit -> read ORDER (proved by the descriptor's own file offset, not by
# the error name, which an implementation with the checks reversed also
# returns), the descriptor discipline, and the accepted path.
add_executable(CscaImportDbusTest CscaImportDbusTest.cpp)
target_link_libraries(CscaImportDbusTest PRIVATE
    LibreLinuxAgentCore
    SyntheticMasterList
    GTest::gtest
    GTest::gtest_main)
add_test(NAME CscaImportDbusTest
    COMMAND ${DBUS_RUN_SESSION} -- $<TARGET_FILE:CscaImportDbusTest>)
set_tests_properties(CscaImportDbusTest PROPERTIES TIMEOUT 120)
