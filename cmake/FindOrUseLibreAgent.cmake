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
    find_package(LibreAgent 4.2 REQUIRED CONFIG)
    message(STATUS "LibreAgent: using installed package (CONFIG)")
else()
    message(STATUS "LibreAgent: building from source (FetchContent, pin ${LIBREAGENT_PIN})")
    include(FetchContent)
    FetchContent_Declare(LibreAgent
        GIT_REPOSITORY https://github.com/LibreSCRS/LibreAgent.git
        GIT_TAG ${LIBREAGENT_PIN})
    FetchContent_MakeAvailable(LibreAgent) # provides LibreAgent::Core
endif()
