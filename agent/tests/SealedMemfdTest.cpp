// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// The sealed descriptor round trip. This is a passenger that could not follow
// the photo operation into the agent core: memfd creation and the F_SEAL_*
// family are Linux-only, so the case belongs to the backend that seals, not to
// the platform-neutral operation that hands it plain bytes.

#include "SealedMemfd.h"

#include <gtest/gtest.h>
#include <sys/mman.h>
#include <unistd.h>
#include <cstring>
#include <span>
#include <vector>

using namespace LibreSCRS::Agent;

TEST(SealedMemfd, RoundTripsBytes)
{
    const std::vector<std::uint8_t> payload{0xFF, 0xD8, 0xFF, 0xE0};
    const int fd = SealedMemfd::create(std::span<const std::uint8_t>{payload});
    ASSERT_GE(fd, 0);

    const auto size = ::lseek(fd, 0, SEEK_END);
    ASSERT_EQ(size, static_cast<off_t>(payload.size()));
    void* p = ::mmap(nullptr, payload.size(), PROT_READ, MAP_PRIVATE, fd, 0);
    ASSERT_NE(p, MAP_FAILED);
    EXPECT_EQ(0, std::memcmp(p, payload.data(), payload.size()));
    ::munmap(p, payload.size());
    ::close(fd);
}
