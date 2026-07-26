// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Unit test for SecretMemfdReader::read — in particular its trust-root
// input-shape check: the received fd MUST be a sealed memfd carrying the exact
// seal set the producer (SealedMemfdCreator::makeSealedMemfd) applies
// (F_SEAL_WRITE | F_SEAL_SHRINK | F_SEAL_GROW). A correctly-sealed memfd is
// accepted; an UNSEALED memfd — or any non-memfd fd whose sealing query fails —
// is rejected onto the read-failure path. The reject cases are RED-proven: drop
// the seal check in SecretMemfdReader.cpp and Unsealed*/PipeFd* below start
// accepting the payload, failing the has_value() assertions.

#include "SecretMemfdReader.h"

#include "SealedMemfdCreator.h" // shared sealed-memfd creator (matches the producer)

#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>

#include <sdbus-c++/Types.h>
#include <gtest/gtest.h>

#include <cstdint>
#include <span>
#include <string>
#include <string_view>

using LibreSCRS::Agent::SecretMemfdReader;

namespace {

// A correctly-sealed memfd, produced exactly as the prompter/agent do.
int makeSealedFd(std::string_view bytes)
{
    return LibreLinux::Common::makeSealedMemfd(
        "librescrs-test-secret",
        std::span<const std::uint8_t>{reinterpret_cast<const std::uint8_t*>(bytes.data()), bytes.size()});
}

// An UNSEALED memfd: same MFD_ALLOW_SEALING creation and content write as the
// producer, but F_ADD_SEALS is deliberately never called, so F_GET_SEALS
// returns 0. This is the shape a rogue prompter could hand back to keep the fd
// writable/growable under the agent.
int makeUnsealedFd(std::string_view bytes)
{
    const int fd = ::memfd_create("librescrs-test-unsealed", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    if (fd < 0) {
        return -1;
    }
    std::size_t off = 0;
    while (off < bytes.size()) {
        const ssize_t n = ::write(fd, bytes.data() + off, bytes.size() - off);
        if (n <= 0) {
            ::close(fd);
            return -1;
        }
        off += static_cast<std::size_t>(n);
    }
    return fd;
}

} // namespace

TEST(SecretMemfdReaderTest, SealedMemfdIsAccepted)
{
    const int fd = makeSealedFd("1234");
    ASSERT_GE(fd, 0);

    std::string error;
    const auto secret = SecretMemfdReader::read(sdbus::UnixFd{fd, sdbus::adopt_fd}, &error);

    ASSERT_TRUE(secret.has_value()) << "sealed memfd must be accepted: " << error;
    EXPECT_EQ(secret->view(), "1234");
    EXPECT_TRUE(error.empty());
}

TEST(SecretMemfdReaderTest, SealedEmptyMemfdIsAcceptedAsEmptySecret)
{
    // The producer seals even zero-byte secrets (makeEmptySealedFd), so an empty
    // *sealed* fd is a legitimate "ok with no bytes" — engaged but empty.
    const int fd = makeSealedFd("");
    ASSERT_GE(fd, 0);

    std::string error;
    const auto secret = SecretMemfdReader::read(sdbus::UnixFd{fd, sdbus::adopt_fd}, &error);

    ASSERT_TRUE(secret.has_value()) << "sealed empty memfd must be accepted: " << error;
    EXPECT_TRUE(secret->empty());
    EXPECT_TRUE(error.empty());
}

TEST(SecretMemfdReaderTest, UnsealedMemfdIsRejected)
{
    // RED-proof: without the seal check this content would be read back and the
    // optional would be engaged, failing the assertion below.
    const int fd = makeUnsealedFd("1234");
    ASSERT_GE(fd, 0);

    std::string error;
    const auto secret = SecretMemfdReader::read(sdbus::UnixFd{fd, sdbus::adopt_fd}, &error);

    EXPECT_FALSE(secret.has_value()) << "unsealed memfd must be rejected";
    EXPECT_FALSE(error.empty());
}

TEST(SecretMemfdReaderTest, UnsealedEmptyMemfdIsRejected)
{
    // Even a zero-byte payload must be rejected when unsealed: the seal check
    // runs before the zero-length fast path.
    const int fd = makeUnsealedFd("");
    ASSERT_GE(fd, 0);

    std::string error;
    const auto secret = SecretMemfdReader::read(sdbus::UnixFd{fd, sdbus::adopt_fd}, &error);

    EXPECT_FALSE(secret.has_value()) << "unsealed empty memfd must be rejected";
    EXPECT_FALSE(error.empty());
}

TEST(SecretMemfdReaderTest, PipeFdIsRejected)
{
    // A non-memfd fd (here a pipe read end) cannot answer F_GET_SEALS at all
    // (EINVAL). It must be rejected, not read.
    int fds[2] = {-1, -1};
    ASSERT_EQ(::pipe2(fds, O_CLOEXEC), 0);
    ::close(fds[1]); // writer end unused

    std::string error;
    const auto secret = SecretMemfdReader::read(sdbus::UnixFd{fds[0], sdbus::adopt_fd}, &error);

    EXPECT_FALSE(secret.has_value()) << "a pipe fd must be rejected";
    EXPECT_FALSE(error.empty());
}
