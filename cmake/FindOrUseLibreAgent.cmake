# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 hirashix0
#
# Hybrid LibreAgent core consumption (mirrors
# LibreCelik/cmake/FindOrUseLibreMiddleware.cmake): prefer
# find_package(CONFIG) when LIBRELINUX_USE_INSTALLED_AGENT_CORE=ON, otherwise
# build the neutral core from source via FetchContent. Either path provides the
# namespaced LibreAgent::Core imported/alias target the Linux backend links.
#
# Dev builds re-point FetchContent at a local sibling checkout with
#   -DFETCHCONTENT_SOURCE_DIR_LIBREAGENT=/path/to/LibreAgent
# (the source tree is consumed in place; its tests + install/export stay behind
# PROJECT_IS_TOP_LEVEL, so only the library builds here).

option(LIBRELINUX_USE_INSTALLED_AGENT_CORE
       "Consume LibreAgent via find_package(CONFIG) instead of FetchContent" OFF)

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
    message(STATUS "LibreAgent: building from source (FetchContent)")
    include(FetchContent)
    FetchContent_Declare(LibreAgent
        GIT_REPOSITORY https://github.com/LibreSCRS/LibreAgent.git
        GIT_TAG main)
    FetchContent_MakeAvailable(LibreAgent) # provides LibreAgent::Core
endif()
