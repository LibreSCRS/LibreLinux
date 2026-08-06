// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Hardware acceptance client — NOT part of the shipped product and not built by
// CMake. A lean through-the-agent sign proof, driven by the runner scripts here.
//
// Drives Card1.Sign on the live librescrs-agent daemon against a real card on a
// real reader, retrieves the CAdES AdES artifact via the Sign1 sub-interface,
// writes it to disk, and reports the Operation1 outcome. Cryptographic
// verification (openssl cms -verify) is done by the wrapper script.
//
// The signature level is taken from LIBRESCRS_PROOF_LEVEL. Left unset, the Sign
// request carries NO level at all — the shape a desktop client sends — so the
// run proves which level the agent resolves on its own. Setting it pins one,
// which is the control case.
//
// SAFETY: performs EXACTLY ONE Sign call (one PIN use). Never retries a sign on
// failure. Secrets are never touched by this client — they live only in the
// auto-prompter's env and are released across the SCM_RIGHTS memfd wire. The
// only card credential this client observes is the CAN (unlimited) via the
// PACE-gated certificate read; the counter-limited PIN is requested once, by the
// single Sign, and served by the auto-prompter while the gate file exists.

#include <sdbus-c++/sdbus-c++.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <map>
#include <mutex>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>
#include <vector>

namespace {

constexpr const char* kAgentSvc = "org.librescrs.Agent";
constexpr const char* kRootPath = "/org/librescrs/Agent";
constexpr const char* kObjMgr = "org.freedesktop.DBus.ObjectManager";
constexpr const char* kReaderIf = "org.librescrs.Agent.Reader1";
constexpr const char* kCardIf = "org.librescrs.Agent.Card1";
constexpr const char* kOpIf = "org.librescrs.Agent.Operation1";
constexpr const char* kCertsIf = "org.librescrs.Agent.Operation.Certificates1";
constexpr const char* kSignIf = "org.librescrs.Agent.Operation.Sign1";

// GetManagedObjects reply shape: a{oa{sa{sv}}}.
using PropMap = std::map<std::string, sdbus::Variant>;
using IfaceMap = std::map<std::string, PropMap>;
using ManagedObjects = std::map<sdbus::ObjectPath, IfaceMap>;

// Certificates1.Result payload element: (s b a{sa{s(ssv)}} u as as u).
using FieldVal = sdbus::Struct<std::string, std::string, sdbus::Variant>;
using FieldGroup = std::map<std::string, FieldVal>;
using Fields = std::map<std::string, FieldGroup>;
using CertEntry = sdbus::Struct<std::string, bool, Fields, std::uint32_t, std::vector<std::string>,
                                std::vector<std::string>, std::uint32_t>;
using CertList = std::vector<CertEntry>;

std::string envOr(const char* key, const char* fallback)
{
    const char* v = std::getenv(key);
    return (v != nullptr && *v != '\0') ? std::string{v} : std::string{fallback};
}

// Read the whole content of an fd from offset 0. Never logs bytes.
std::string readAll(int fd)
{
    std::string out;
    if (::lseek(fd, 0, SEEK_SET) == static_cast<off_t>(-1) && errno != ESPIPE) {
        // memfd/regular files are seekable; a pipe would be ESPIPE (read as-is).
    }
    char buf[65536];
    for (;;) {
        const ssize_t n = ::read(fd, buf, sizeof(buf));
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        if (n == 0) {
            break;
        }
        out.append(buf, static_cast<std::size_t>(n));
    }
    return out;
}

bool writeFile(const std::string& path, const std::string& bytes)
{
    const int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        return false;
    }
    std::size_t off = 0;
    bool ok = true;
    while (off < bytes.size()) {
        const ssize_t n = ::write(fd, bytes.data() + off, bytes.size() - off);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            ok = false;
            break;
        }
        off += static_cast<std::size_t>(n);
    }
    ::close(fd);
    return ok;
}

std::string variantStr(const sdbus::Variant& v)
{
    try {
        return v.get<std::string>();
    } catch (...) {
        return {};
    }
}

// Format an a{sv} meta map compactly (strings and bools only, which is all Sign meta uses).
std::string fmtMeta(const std::map<std::string, sdbus::Variant>& meta)
{
    std::string s = "{";
    bool first = true;
    for (const auto& [k, v] : meta) {
        if (!first) {
            s += ", ";
        }
        first = false;
        s += k;
        s += '=';
        try {
            s += v.get<std::string>();
        } catch (...) {
            try {
                s += v.get<bool>() ? "true" : "false";
            } catch (...) {
                s += "?";
            }
        }
    }
    s += "}";
    return s;
}

} // namespace

int main(int argc, char** argv)
{
    const std::string readerSubstr = envOr("LIBRESCRS_READER_SUBSTR", "");
    const std::string outDir = envOr("LIBRESCRS_OUT_DIR", "/tmp/librescrs-e2e");
    // No certificate is baked in: a default would pin one operator's own card.
    // Unset means "take the first signing certificate the card offers".
    const std::string prefCertPrefix = envOr("LIBRESCRS_CERT_PREFIX", "");
    std::string forcedCertId = envOr("LIBRESCRS_CERT_ID", "");
    if (argc > 1 && argv[1] != nullptr && argv[1][0] != '\0') {
        forcedCertId = argv[1]; // optional runtime override (non-secret)
    }
    ::mkdir(outDir.c_str(), 0700);
    const std::string docPath = outDir + "/sign-doc.txt";
    const std::string artPath = outDir + "/sign-cades.p7s";
    const std::string docBody = "librescrs through-agent sign proof\n";

    auto conn = sdbus::createSessionBusConnection();
    if (conn == nullptr) {
        std::fprintf(stderr, "[proof] FATAL: no session bus (need DBUS_SESSION_BUS_ADDRESS)\n");
        return 10;
    }
    conn->enterEventLoopAsync();

    // ---- 1. Discover the card via the ObjectManager --------------------------
    // The contactless card object can lag the first (contact) card export, so
    // poll GetManagedObjects until a Card1-exporting card sits on a reader whose
    // name matches the substring (bounded). This is read-only, no card auth.
    auto root = sdbus::createProxy(*conn, sdbus::ServiceName{kAgentSvc}, sdbus::ObjectPath{kRootPath});
    std::string cardPath;
    std::string cardReaderName;
    const auto discoverDeadline = std::chrono::steady_clock::now() + std::chrono::seconds(30);
    for (int attempt = 0;; ++attempt) {
        ManagedObjects managed;
        try {
            root->callMethod("GetManagedObjects").onInterface(kObjMgr).storeResultsTo(managed);
        } catch (const sdbus::Error& e) {
            std::fprintf(stderr, "[proof] FATAL: GetManagedObjects failed: %s: %s\n", e.getName().c_str(),
                         e.getMessage().c_str());
            return 11;
        }
        std::string matchReader;
        std::string matchCardObj; // Card path advertised by a matching reader (may not be exported yet)
        for (const auto& [path, ifaces] : managed) {
            auto rit = ifaces.find(kReaderIf);
            if (rit == ifaces.end()) {
                continue;
            }
            const auto& props = rit->second;
            std::string name;
            bool hasCard = false;
            std::string cardObj;
            if (auto p = props.find("Name"); p != props.end()) {
                name = variantStr(p->second);
            }
            if (auto p = props.find("HasCard"); p != props.end()) {
                try {
                    hasCard = p->second.get<bool>();
                } catch (...) {
                }
            }
            if (auto p = props.find("Card"); p != props.end()) {
                try {
                    cardObj = p->second.get<sdbus::ObjectPath>();
                } catch (...) {
                }
            }
            if (attempt == 0) {
                std::fprintf(stderr, "[proof]   reader %s  name=\"%s\"  hasCard=%s  card=%s\n", path.c_str(),
                             name.c_str(), hasCard ? "yes" : "no", cardObj.empty() ? "(none)" : cardObj.c_str());
            }
            if (name.find(readerSubstr) != std::string::npos && hasCard && !cardObj.empty() && cardObj != "/") {
                matchReader = name;
                matchCardObj = cardObj;
                // Only accept once the card object actually exports Card1.
                if (auto cit = managed.find(sdbus::ObjectPath{cardObj});
                    cit != managed.end() && cit->second.find(kCardIf) != cit->second.end()) {
                    cardPath = cardObj;
                    cardReaderName = name;
                }
            }
        }
        if (!cardPath.empty()) {
            break;
        }
        if (std::chrono::steady_clock::now() >= discoverDeadline) {
            if (!matchCardObj.empty()) {
                std::fprintf(stderr,
                             "[proof] FATAL: reader \"%s\" advertises card %s but it never exported %s "
                             "(no plugin matched the card)\n",
                             matchReader.c_str(), matchCardObj.c_str(), kCardIf);
                return 17;
            }
            std::fprintf(stderr, "[proof] FATAL: no card on a reader matching \"%s\"\n", readerSubstr.c_str());
            return 12;
        }
        if (attempt == 0) {
            std::fprintf(stderr, "[proof] waiting for a Card1 object on \"%s\" ...\n", readerSubstr.c_str());
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
    std::fprintf(stderr, "[proof] card = %s  (reader \"%s\")\n", cardPath.c_str(), cardReaderName.c_str());

    auto card = sdbus::createProxy(*conn, sdbus::ServiceName{kAgentSvc}, sdbus::ObjectPath{cardPath});

    // ---- 2. Resolve the signing certId ---------------------------------------
    std::string certId = forcedCertId;
    if (certId.empty()) {
        // ReadCertificates -> op path; subscribe to Certificates1.Result + Finished.
        // CAN-only (PACE), no PIN: this read is safe to run (and, if needed, retry).
        std::mutex m;
        std::condition_variable cv;
        bool finished = false;
        bool gotCerts = false;
        std::uint32_t cStatus = 99, cErr = 0;
        std::string cMsg;
        CertList certs;

        sdbus::ObjectPath opPath;
        try {
            card->callMethod("ReadCertificates").onInterface(kCardIf).storeResultsTo(opPath);
        } catch (const sdbus::Error& e) {
            std::fprintf(stderr, "[proof] FATAL: ReadCertificates failed: %s: %s\n", e.getName().c_str(),
                         e.getMessage().c_str());
            return 13;
        }
        std::fprintf(stderr, "[proof] ReadCertificates op = %s\n", opPath.c_str());
        auto op = sdbus::createProxy(*conn, sdbus::ServiceName{kAgentSvc}, opPath);
        op->uponSignal("Result").onInterface(kCertsIf).call([&](const CertList& c) {
            std::lock_guard<std::mutex> lk(m);
            certs = c;
            gotCerts = true;
        });
        op->uponSignal("Finished")
            .onInterface(kOpIf)
            .call([&](std::uint32_t status, std::uint32_t errorCode, const std::string& /*msgKey*/,
                      const std::string& msgFallback) {
                std::lock_guard<std::mutex> lk(m);
                cStatus = status;
                cErr = errorCode;
                cMsg = msgFallback;
                finished = true;
                cv.notify_all();
            });

        {
            std::unique_lock<std::mutex> lk(m);
            if (!cv.wait_for(lk, std::chrono::seconds(90), [&] { return finished; })) {
                std::fprintf(stderr, "[proof] FATAL: certificate read timed out (90s)\n");
                return 14;
            }
        }
        if (cStatus != 0) {
            std::fprintf(stderr, "[proof] FATAL: certificate read failed status=%u errorCode=%u msg=\"%s\"\n", cStatus,
                         cErr, cMsg.c_str());
            return 14;
        }
        if (!gotCerts) {
            std::fprintf(stderr, "[proof] FATAL: cert read finished Ok but Result signal was missed\n");
            return 14;
        }
        std::fprintf(stderr, "[proof] certificates: %zu\n", certs.size());
        std::string firstSigning;
        std::string prefMatch;
        for (const auto& e : certs) {
            const std::string& id = e.get<0>();
            const bool signing = e.get<1>();
            const std::uint32_t ku = e.get<3>();
            const auto& chainCns = e.get<5>();
            const std::string leaf = chainCns.empty() ? std::string{} : chainCns.front();
            std::fprintf(stderr, "[proof]   cert id=%s  signingCapable=%s  keyUsageBits=0x%x  leafCN=\"%s\"\n",
                         id.c_str(), signing ? "yes" : "no", ku, leaf.c_str());
            if (signing) {
                if (firstSigning.empty()) {
                    firstSigning = id;
                }
                // Guarded on non-empty: rfind("", 0) matches everything, which
                // would report the first certificate as a "prefix-match".
                if (!prefCertPrefix.empty() && prefMatch.empty() && id.rfind(prefCertPrefix, 0) == 0) {
                    prefMatch = id;
                }
            }
        }
        certId = !prefMatch.empty() ? prefMatch : firstSigning;
        if (certId.empty()) {
            std::fprintf(stderr, "[proof] FATAL: no signingCapable certificate found\n");
            return 15;
        }
        std::fprintf(stderr, "[proof] chosen signing certId = %s  (%s)\n", certId.c_str(),
                     !prefMatch.empty() ? "prefix-match" : "first-signing");
    } else {
        std::fprintf(stderr, "[proof] using forced certId = %s\n", certId.c_str());
    }

    // Discover-only mode: validate all D-Bus plumbing (session connect, managed
    // objects, cert read/deserialize) WITHOUT the counter-limited PIN sign. Used
    // to de-risk before the one real sign attempt.
    if (!envOr("LIBRESCRS_DISCOVER_ONLY", "").empty()) {
        std::fprintf(stderr, "[proof] DISCOVER_ONLY set — stopping before Sign (no PIN used)\n");
        std::printf("DISCOVER_OK certId=%s reader=%s\n", certId.c_str(), cardReaderName.c_str());
        return 0;
    }

    // ---- 3. Prepare the document -------------------------------------------
    if (!writeFile(docPath, docBody)) {
        std::fprintf(stderr, "[proof] FATAL: cannot write doc %s\n", docPath.c_str());
        return 16;
    }
    const int docFd = ::open(docPath.c_str(), O_RDONLY | O_CLOEXEC);
    if (docFd < 0) {
        std::fprintf(stderr, "[proof] FATAL: cannot open doc for read %s\n", docPath.c_str());
        return 16;
    }

    // ---- 4. The ONE Sign call ------------------------------------------------
    std::map<std::string, sdbus::Variant> options;
    options["format"] = sdbus::Variant{std::string{"cades"}};
    // The level is DELIBERATELY ABSENT: this is the request shape a desktop
    // client now sends, and the whole point of this run is which level the
    // agent resolves for it. LIBRESCRS_PROOF_LEVEL pins one instead, for the
    // control case.
    {
        const std::string forcedLevel = envOr("LIBRESCRS_PROOF_LEVEL", "");
        if (!forcedLevel.empty()) {
            options["level"] = sdbus::Variant{forcedLevel};
            std::fprintf(stderr, "[proof] level PINNED to \"%s\" (control case)\n", forcedLevel.c_str());
        } else {
            std::fprintf(stderr, "[proof] level OMITTED -- the agent's configuration decides\n");
        }
    }
    options["packaging"] = sdbus::Variant{std::string{"detached"}};
    options["displayName"] = sdbus::Variant{std::string{"librescrs level deferral proof"}};

    std::mutex m;
    std::condition_variable cv;
    bool finished = false;
    std::uint32_t sStatus = 99, sErr = 0;
    std::string sMsgKey, sMsgFallback;
    bool gotResult = false;
    std::string artifact;
    std::map<std::string, sdbus::Variant> resultMeta;

    sdbus::ObjectPath signOp;
    std::fprintf(stderr, "[proof] === issuing THE ONE Sign call (certId=%s) ===\n", certId.c_str());
    try {
        card->callMethod("Sign")
            .onInterface(kCardIf)
            .withArguments(certId, sdbus::UnixFd{docFd}, options)
            .storeResultsTo(signOp);
    } catch (const sdbus::Error& e) {
        ::close(docFd);
        std::fprintf(stderr, "[proof] FATAL: Sign method-entry error: %s: %s\n", e.getName().c_str(),
                     e.getMessage().c_str());
        return 20;
    }
    ::close(docFd);
    std::fprintf(stderr, "[proof] Sign op = %s\n", signOp.c_str());

    auto op = sdbus::createProxy(*conn, sdbus::ServiceName{kAgentSvc}, signOp);
    op->uponSignal("Result").onInterface(kSignIf).call(
        [&](const sdbus::UnixFd& fd, const std::map<std::string, sdbus::Variant>& meta) {
            std::string bytes = readAll(fd.get());
            std::lock_guard<std::mutex> lk(m);
            artifact = std::move(bytes);
            resultMeta = meta;
            gotResult = true;
        });
    op->uponSignal("Finished")
        .onInterface(kOpIf)
        .call([&](std::uint32_t status, std::uint32_t errorCode, const std::string& msgKey,
                  const std::string& msgFallback) {
            std::lock_guard<std::mutex> lk(m);
            sStatus = status;
            sErr = errorCode;
            sMsgKey = msgKey;
            sMsgFallback = msgFallback;
            finished = true;
            cv.notify_all();
        });

    {
        std::unique_lock<std::mutex> lk(m);
        if (!cv.wait_for(lk, std::chrono::seconds(120), [&] { return finished; })) {
            std::fprintf(stderr, "[proof] FATAL: sign timed out after 120s (NO retry)\n");
            return 21;
        }
    }

    std::fprintf(stderr, "[proof] Sign Finished: status=%u errorCode=%u msgKey=\"%s\" msgFallback=\"%s\"\n", sStatus,
                 sErr, sMsgKey.c_str(), sMsgFallback.c_str());

    if (sStatus != 0) {
        std::fprintf(stderr, "[proof] === SIGN FAILED (status=%u errorCode=%u) — NOT retrying ===\n", sStatus, sErr);
        std::printf("SIGN_RESULT=FAIL status=%u errorCode=%u msgKey=%s msgFallback=%s\n", sStatus, sErr,
                    sMsgKey.c_str(), sMsgFallback.c_str());
        return 22;
    }

    // ---- 5. Retrieve the artifact -------------------------------------------
    if (!gotResult) {
        std::fprintf(stderr, "[proof] Result signal missed; recovering via Sign1.GetResult()\n");
        try {
            sdbus::UnixFd fd;
            std::map<std::string, sdbus::Variant> meta;
            op->callMethod("GetResult").onInterface(kSignIf).storeResultsTo(fd, meta);
            artifact = readAll(fd.get());
            resultMeta = meta;
        } catch (const sdbus::Error& e) {
            std::fprintf(stderr, "[proof] FATAL: GetResult failed: %s: %s\n", e.getName().c_str(),
                         e.getMessage().c_str());
            return 23;
        }
    }

    if (artifact.empty()) {
        std::fprintf(stderr, "[proof] FATAL: sign Ok but artifact is empty\n");
        return 24;
    }
    if (!writeFile(artPath, artifact)) {
        std::fprintf(stderr, "[proof] FATAL: cannot write artifact %s\n", artPath.c_str());
        return 24;
    }

    std::fprintf(stderr, "[proof] === SIGN OK ===\n");
    std::fprintf(stderr, "[proof] artifact bytes = %zu -> %s\n", artifact.size(), artPath.c_str());
    std::fprintf(stderr, "[proof] meta = %s\n", fmtMeta(resultMeta).c_str());
    std::fprintf(stderr, "[proof] document = %zu bytes -> %s\n", docBody.size(), docPath.c_str());

    // stdout: machine-readable summary the wrapper greps.
    std::printf("SIGN_RESULT=OK status=0 artifactBytes=%zu artifact=%s document=%s meta=%s\n", artifact.size(),
                artPath.c_str(), docPath.c_str(), fmtMeta(resultMeta).c_str());
    return 0;
}
