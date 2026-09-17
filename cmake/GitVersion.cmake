# SPDX-License-Identifier: LGPL-2.1-or-later
# GitVersion
#
# Version from git tag according to https://semver.org/
#
# GIT_VERSION_MAJOR         - Major version
# GIT_VERSION_MINOR         - Minor version
# GIT_VERSION_PATCH         - Patch version
# GIT_VERSION_PRERELEASE    - Pre-release label (e.g. rc1, beta2)
# GIT_VERSION_COMMIT_NUM    - Commit number
# GIT_VERSION_COMMIT_SHA    - Hash

if(NOT DEFINED GIT_EXECUTABLE)
    find_package(Git QUIET REQUIRED)
endif()

# CMAKE_CURRENT_LIST_DIR is the cmake/ subdir hosting this module, so
# `${CMAKE_CURRENT_LIST_DIR}/..` is the repository root regardless of how this
# repository is consumed. PROJECT_SOURCE_DIR is not yet set at the time this
# module is include()d (project() has not been called yet -- it needs the
# version this file derives). It is set OUTSIDE the GIT_EXECUTABLE branch
# because the VERSION fallback below needs it in exactly the case where git is
# not what answers.
set(SRC_DIR "${CMAKE_CURRENT_LIST_DIR}/..")

if(GIT_EXECUTABLE)
  # Only consider release-style semver tags (e.g. 5.0.0, v5.0.0-rc1); never
  # local rollback tags (backup/*, pre-*, ...), which are not version strings
  # and would otherwise yield an empty ".." version on reconfigure.
  execute_process(
    COMMAND ${GIT_EXECUTABLE} describe --tags --abbrev=0 --match "[0-9]*" --match "v[0-9]*"
    WORKING_DIRECTORY ${SRC_DIR}
    OUTPUT_VARIABLE GIT_DESCRIBE_VERSION
    RESULT_VARIABLE GIT_DESCRIBE_ERROR_CODE
    OUTPUT_STRIP_TRAILING_WHITESPACE
    ERROR_QUIET # silence git "fatal: No names found" on fresh/untagged repos
    )
  if(NOT GIT_DESCRIBE_ERROR_CODE)
    # Strip leading 'v' if present (e.g. v3.0.0-rc1 → 3.0.0-rc1)
    string(REGEX REPLACE "^v" "" GIT_DESCRIBE_VERSION "${GIT_DESCRIBE_VERSION}")
    set(PROJECT_VERSION ${GIT_DESCRIBE_VERSION})
  endif()
endif()

# The VERSION file is read UNCONDITIONALLY, and the NEWER of the two wins.
#
# Two different callers used to be conflated here. Release tarballs (makepkg,
# GitHub source archives) ship WITHOUT a .git tree, so `git describe` above
# cannot run and the committed VERSION file is the only version there is;
# without it a tarball build silently stamps PROJECT_VERSION 0.0.1, which every
# downstream `find_package(... CONFIG)` against an installed package then
# rejects. A DEVELOPMENT checkout has the opposite problem: `git describe`
# answers with the PREVIOUS release for the whole cycle, so between code freeze
# (VERSION bumped) and the tag the build stamps the OLD major while VERSION,
# the CHANGELOG and the packaging all state the new one. This repository
# carries no release tag today -- `git describe` has nothing to answer with --
# so that half is dormant here rather than absent: the first tag arms it, and
# the code freeze after it is when it would bite.
#
# So VERSION is not a fallback, it is a floor: it carries the version this tree
# is heading for and is bumped at code freeze. The tag still wins on the release
# commit (equal) and on any checkout whose tag is ahead of VERSION.
set(GITVERSION_FILE_VERSION "")
if(EXISTS "${SRC_DIR}/VERSION")
  file(STRINGS "${SRC_DIR}/VERSION" GITVERSION_FILE_VERSION LIMIT_COUNT 1)
  string(STRIP "${GITVERSION_FILE_VERSION}" GITVERSION_FILE_VERSION)
  string(REGEX REPLACE "^v" "" GITVERSION_FILE_VERSION "${GITVERSION_FILE_VERSION}")
endif()

if(NOT DEFINED PROJECT_VERSION)
  set(PROJECT_VERSION "${GITVERSION_FILE_VERSION}")
elseif(NOT GITVERSION_FILE_VERSION STREQUAL "")
  # Compare numeric triples only: a pre-release suffix on the tag (5.0.0-rc2)
  # must not decide the comparison against a plain VERSION.
  string(REGEX MATCH "^[0-9]+(\\.[0-9]+)*" GITVERSION_TAG_NUM  "${PROJECT_VERSION}")
  string(REGEX MATCH "^[0-9]+(\\.[0-9]+)*" GITVERSION_FILE_NUM "${GITVERSION_FILE_VERSION}")
  if(GITVERSION_FILE_NUM AND GITVERSION_TAG_NUM
     AND GITVERSION_FILE_NUM VERSION_GREATER GITVERSION_TAG_NUM)
    set(PROJECT_VERSION "${GITVERSION_FILE_VERSION}")
  endif()
endif()

if(NOT PROJECT_VERSION)
  set(PROJECT_VERSION 0.0.1)
  message(WARNING "Failed to determine PROJECT_VERSION from Git tags or the VERSION file. Using default version \"${PROJECT_VERSION}\".")
endif()

# Extract semantic version components; strip pre-release for CMake project(VERSION ...)
string(REGEX MATCH "^([0-9]+)\\.([0-9]+)\\.([0-9]+)(-([a-zA-Z0-9.]+))?(-([0-9]+)-([a-z0-9]+))?" GITVERSIONDETECT_VERSION_MATCH ${PROJECT_VERSION})
set(GIT_VERSION_MAJOR ${CMAKE_MATCH_1})
set(GIT_VERSION_MINOR ${CMAKE_MATCH_2})
set(GIT_VERSION_PATCH ${CMAKE_MATCH_3})
set(GIT_VERSION_PRERELEASE ${CMAKE_MATCH_5})
set(GIT_VERSION_COMMIT_NUM ${CMAKE_MATCH_7})
set(GIT_VERSION_COMMIT_SHA ${CMAKE_MATCH_8})
