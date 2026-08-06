// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Proves the auto-prompter's memfd/seal contract end-to-end
// WITHOUT any smart card, sign, login or real PIN. It is a pure Prompter1 CLIENT
// (mirrors the agent's PrompterClient) that:
//
//   Test A (gate absent)  -> RequestSecret("pin") must return status="cancelled"
//                            with a 0-byte memfd (fail-safe, no secret leaked).
//   Test B (gate present) -> RequestSecret("pin") must return status="ok", a
//                            memfd whose bytes == the DUMMY secret (argv[1],
//                            e.g. "contract-probe-not-a-pin") and whose size
//                            <= kMaxSecretBytes (8 KiB),
//                            sealed EXACTLY F_SEAL_SHRINK|GROW|WRITE with
//                            F_SEAL_SEAL NOT set — the contract the agent's
//                            SecretMemfdReader + shared creator define.
//
// Usage: validate-prompter <expected-dummy-pin>
//   env LIBRESCRS_PROMPTER_GATE selects the gate file the validator toggles
//   (must match the auto-prompter's gate; default /tmp/librescrs-e2e/prompt.gate).

#include "org.librescrs.Prompter1_proxy.h" // generated (build/agent/generated)

#include <sdbus-c++/IConnection.h>
#include <sdbus-c++/ProxyInterfaces.h>
#include <sdbus-c++/Types.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <string>
#include <tuple>

namespace {

constexpr const char* kServiceName = "org.librescrs.Prompter1";
constexpr const char* kObjectPath = "/org/librescrs/Prompter1";
constexpr const char* kDefaultGate = "/tmp/librescrs-e2e/prompt.gate";

// Mirrors SecretMemfdReader::kMaxSecretBytes (agent/src/SecretMemfdReader.h).
constexpr std::size_t kMaxSecretBytes = 8 * 1024;
// Contract seal set (common/SealedMemfdCreator.h): SHRINK|GROW|WRITE, no SEAL.
constexpr unsigned kExpectedSeals = F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE;

std::string gatePath()
{
    const char* g = std::getenv("LIBRESCRS_PROMPTER_GATE");
    return (g && *g) ? std::string{g} : std::string{kDefaultGate};
}

class PrompterProxy final : public sdbus::ProxyInterfaces<org::librescrs::Prompter1_proxy>
{
public:
    PrompterProxy(sdbus::IConnection& connection)
        : ProxyInterfaces(connection, sdbus::ServiceName{kServiceName}, sdbus::ObjectPath{kObjectPath})
    {
        registerProxy();
    }
    ~PrompterProxy()
    {
        unregisterProxy();
    }
};

bool g_pass = true;
void check(bool cond, const char* what)
{
    std::fprintf(stderr, "  [%s] %s\n", cond ? "PASS" : "FAIL", what);
    if (!cond) {
        g_pass = false;
    }
}

// Read the whole (small) memfd via pread, exactly as SecretMemfdReader does.
std::string readAll(int fd, std::size_t size)
{
    std::string out;
    out.resize(size);
    std::size_t total = 0;
    while (total < size) {
        const ssize_t n = ::pread(fd, out.data() + total, size - total, static_cast<off_t>(total));
        if (n <= 0) {
            break;
        }
        total += static_cast<std::size_t>(n);
    }
    out.resize(total);
    return out;
}

} // namespace

int main(int argc, char** argv)
{
    const std::string expectedPin = (argc > 1) ? argv[1] : "contract-probe-not-a-pin";
    const std::string gate = gatePath();

    auto conn = sdbus::createSessionBusConnection();
    if (conn == nullptr) {
        std::fprintf(stderr, "[validate] FATAL: no session bus (run under dbus-run-session)\n");
        return 2;
    }
    conn->enterEventLoopAsync();
    PrompterProxy proxy(*conn);

    // ---- Test A: gate ABSENT -> cancelled, empty memfd -------------------
    std::fprintf(stderr, "[validate] Test A: gate absent -> expect cancelled\n");
    ::unlink(gate.c_str());
    {
        auto [status, fd, msg] = proxy.RequestSecret("pin", {});
        check(status == "cancelled", "status == \"cancelled\" when gate absent");
        struct ::stat st{};
        const bool ok = fd.isValid() && ::fstat(fd.get(), &st) == 0;
        check(ok && st.st_size == 0, "cancelled reply carries a 0-byte memfd (no secret leaked)");
    }

    // ---- Test B: gate PRESENT -> ok, bytes == dummy pin, seals correct ---
    std::fprintf(stderr, "[validate] Test B: gate present -> expect ok + sealed \"%s\"\n", expectedPin.c_str());
    {
        const int gfd = ::open(gate.c_str(), O_CREAT | O_WRONLY | O_CLOEXEC, 0600);
        if (gfd >= 0) {
            ::close(gfd);
        }
    }
    {
        auto [status, fd, msg] = proxy.RequestSecret("pin", {});
        check(status == "ok", "status == \"ok\" when gate present + pin env set");
        check(msg.empty(), "user_message is empty on ok");

        if (fd.isValid()) {
            const int rawFd = fd.get();
            struct ::stat st{};
            const bool statOk = ::fstat(rawFd, &st) == 0;
            check(statOk, "fstat(secret_fd) succeeds");
            const std::size_t size = statOk && st.st_size >= 0 ? static_cast<std::size_t>(st.st_size) : SIZE_MAX;

            check(size <= kMaxSecretBytes, "size <= kMaxSecretBytes (8 KiB)");
            check(size == expectedPin.size(), "size == strlen(dummy pin) (no trailing newline)");

            const std::string bytes = readAll(rawFd, size == SIZE_MAX ? 0 : size);
            check(bytes == expectedPin, "memfd bytes == dummy pin");

            const int seals = ::fcntl(rawFd, F_GET_SEALS);
            check(seals >= 0, "fcntl(F_GET_SEALS) succeeds (memfd is sealable)");
            check(static_cast<unsigned>(seals) == kExpectedSeals, "seals == F_SEAL_SHRINK|GROW|WRITE exactly");
            check((static_cast<unsigned>(seals) & F_SEAL_SEAL) == 0,
                  "F_SEAL_SEAL is NOT set (receiver may add its own seals)");
        } else {
            check(false, "secret_fd is a valid fd on ok");
        }
    }

    // Cleanup: never leave the gate open.
    ::unlink(gate.c_str());

    std::fprintf(stderr, "[validate] RESULT: %s\n", g_pass ? "ALL PASS" : "FAILURES PRESENT");
    return g_pass ? 0 : 1;
}
