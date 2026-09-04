# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 hirashix0
#
# Hybrid LibreAgent core consumption (mirrors
# LibreCelik/cmake/FindOrUseLibreMiddleware.cmake): prefer
# find_package(CONFIG) when LIBRELINUX_USE_INSTALLED_AGENT_CORE=ON, otherwise
# build the neutral core from source via FetchContent. Either path provides the
# namespaced LibreAgent::Core imported/alias target the Linux backend links.
#
# The FetchContent path takes a fixed 40-hex revision from cmake/libreagent.pin,
# never a branch. This is the DEFAULT path here (the installed-package option
# below is opt-in), so a branch would make every build of a given LibreLinux
# revision depend on whatever the agent's trunk happened to be that day: two
# builds of the same tag would compile different code, and an unrelated agent
# push could turn this repo's CI red with no change here. Raising the pin is a
# deliberate act that rides with the change that needs it.
#
# Dev builds re-point FetchContent at a local sibling checkout with
#   -DFETCHCONTENT_SOURCE_DIR_LIBREAGENT=/path/to/LibreAgent
# (the source tree is consumed in place; its tests + install/export stay behind
# PROJECT_IS_TOP_LEVEL, so only the library builds here). A green build against
# a source override proves the SOURCES, not the pin -- only a fetch of the
# pinned revision proves the pin. Do not read one as the other.

option(LIBRELINUX_USE_INSTALLED_AGENT_CORE
       "Consume LibreAgent via find_package(CONFIG) instead of FetchContent" OFF)

file(READ "${CMAKE_CURRENT_SOURCE_DIR}/cmake/libreagent.pin" LIBREAGENT_PIN)
string(STRIP "${LIBREAGENT_PIN}" LIBREAGENT_PIN)
# Exactly 40 lowercase hex characters. Spelled as a length test plus a
# character-class test because CMake's regex engine has no {n} repetition
# operator -- "^[0-9a-f]{40}$" would silently never match.
string(LENGTH "${LIBREAGENT_PIN}" LIBREAGENT_PIN_LENGTH)
if(NOT LIBREAGENT_PIN_LENGTH EQUAL 40 OR NOT LIBREAGENT_PIN MATCHES "^[0-9a-f]+$")
    message(FATAL_ERROR "cmake/libreagent.pin must hold one 40-hex commit SHA")
endif()

# This backend always builds its own test tree (enable_testing() in the root
# CMakeLists.txt is unconditional), and one of those tests drives the CSCA
# anchor import against a synthetic master list. That fixture is the agent's,
# and used to be carried here as a byte-identical copy; it is now asked for by
# name. Set BEFORE the FetchContent branch below, which reads it.
#
# Deliberately not gated on BUILD_TESTING: this repository never defines that
# variable, so the condition would simply be false, the component would never
# be requested, and the fixture would go missing at link time. A gate that is
# always closed is worse than no gate.
set(LIBREAGENT_BUILD_TEST_SUPPORT ON CACHE BOOL "" FORCE)

if(LIBRELINUX_USE_INSTALLED_AGENT_CORE)
    # The floor is a PACKAGING compatibility statement, not an API-accuracy one:
    # it says only "an agent this old cannot possibly satisfy this backend", and
    # the exported package's own SameMajorVersion rule additionally rejects
    # anything from a different major. It is NOT what keeps this backend in step
    # with the core's API — that is the revision the source path below consumes,
    # and a mismatch there fails at compile time, where it belongs. Raising the
    # floor above the agent's actual released version buys no accuracy: it just
    # makes this branch unsatisfiable by every agent package that exists, which
    # is a build break for packagers rather than a guard.
    #
    # Name the components. Without them the lookup probes EVERY known
    # component, which on a machine that also has the Qt client installed runs
    # that component's find_dependency(Qt6) and fails hard for a dependency
    # this backend never asked for: a clean chroot passes, a developer machine
    # does not. Naming them also makes an agent package built without one of
    # them fail configuration BY NAME here, instead of the module discovering a
    # missing component at link time -- or the fixture test quietly
    # disappearing. Four are needed: the neutral core this backend has always
    # linked, the PKCS#11 facade the module is now built from, the master-list
    # fixture the anchor-import test links, and the wire vocabulary the
    # error-name parity test links. The last one is why this list is checked
    # by configuring against a real install and not by reading: the source
    # path defines every target, so a name missing here is invisible until
    # someone takes the installed path.
    find_package(LibreAgent 5.0 REQUIRED CONFIG COMPONENTS Core Wire Pkcs11Facade TestSupport)
    message(STATUS "LibreAgent: using installed package (CONFIG)")
else()
    message(STATUS "LibreAgent: building from source (FetchContent, pin ${LIBREAGENT_PIN})")
    include(FetchContent)
    # Both component switches default OFF in the agent, and option() does not
    # overwrite a cache variable that already exists -- so the switch has to be
    # seeded BEFORE the subproject is configured. Without this the module links
    # a target that was never defined, on the DEFAULT consumption path. The
    # other platform backend already seeds Core and Wire the same way.
    set(LIBREAGENT_BUILD_PKCS11_FACADE ON CACHE BOOL "" FORCE)
    FetchContent_Declare(LibreAgent
        GIT_REPOSITORY https://github.com/LibreSCRS/LibreAgent.git
        GIT_TAG ${LIBREAGENT_PIN})
    FetchContent_MakeAvailable(LibreAgent) # provides LibreAgent::Core + ::Pkcs11Facade
endif()
