#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# check-signal-state-lifetime.selftest.sh — prove the lifetime check can fail.
#
# The gate is green the moment it lands, because the reordering lands with it.
# Its whole value is the next handler somebody writes, so without this
# selftest nothing here demonstrates that it discriminates -- and one of its
# two halves, the allowlist that must stop being true, cannot be observed at
# all from the repository's own sources.
#
# Every case runs against a throwaway source tree under /var/tmp (never /tmp,
# which is a RAM filesystem here). The allowlist is pushed in through
# ALLOW_FILE so no case depends on the one the repository ships.
#
# Cases:
#   1  state declared before the proxy                     -> 0
#   2  the same file with the two swapped                  -> 1, line named
#   3  case 2 plus an allowlist entry for that site        -> 0
#   4  case 1 plus that same entry (it no longer applies)  -> 1
#   5  no uponSignal anywhere                              -> 1 (vacuum)
#   6  an alias-typed container declared after the proxy   -> 1
#   7  state declared deeper, inside a nested block        -> 0 (not the scope)
#   8  state whose types are on no list at all              -> 1
#   9  an array declarator and a structured binding          -> 1, both named
#  10  an owner declared in a header, no allowlist entry     -> 1, reported
#  11  the same owner with the entry                         -> 0, counted apart
#  12  a declaration wrapped over two lines, which is what
#      clang-format produces at 120 columns                  -> 1, joined
#  13  case 3 with a line inserted above the site: the
#      amnesty is keyed on the owner, so it survives         -> 0
#  14  a SECOND local, in another function, spelled with the
#      allowlisted owner's name, on another signal           -> 1: a name is
#      not an identity, and the entry covers one signal
#  15  a second handler on the genuinely amnestied owner,
#      with an entry for that signal too                     -> 0
#  16  an entry that is missing a field                      -> 1, named
#  17  the amnestied registration DELETED and a same-named
#      stranger put in its place                             -> 1: the count
#      alone matched, because it only sees sites being ADDED
#  18  the disarm the entry is granted for, deleted from the
#      destructor it names                                   -> 1: the amnesty
#      states a behaviour, so the behaviour is read
#  19  an entry naming a destructor the file does not define  -> 1, named
#  20  the OWNER's own declaration wrapped by the formatter   -> 1, and the
#      owner resolves to its own line, not to an earlier stranger's
#  21  ONE entry, and a second registration of the SAME signal
#      on the SAME member in another function of the type      -> 1: "covers
#      1 site(s), 2 found" -- the branch that says so had no
#      case at all, so deleting it changed nothing here
#  22  the amnestied registration REPLACED by a same-name,
#      same-signal local in a free function of the same file,
#      whose ~T still performs the disarm                      -> 1: the disarm
#      is a statement about a MEMBER of T, and a local is
#      nobody's member
#  23  the same substitution one scope deeper: the stranger is
#      a local in a MEMBER FUNCTION of the amnestied type       -> 1: being
#      inside T is not being a member of T
#  24  a digit separator on the line that OPENS a member
#      function, with the stranger inside it                    -> 1: an
#      apostrophe that closes nothing used to swallow the `{`
#      with it, and the local then read as a member of the type
#  25  the amnestied registration REPLACED by a member of a
#      SECOND type of the same name, whose own destructor does
#      nothing                                                  -> 1: the
#      disarm is read from the owner's OWN type, not from the
#      first ~T the file happens to spell
#  26  the same two types with both destructors defined out of
#      line, so neither belongs to the owner's block             -> 1: an
#      amnesty nobody can attribute is not a pass
set -uo pipefail

CHECK="$(cd "$(dirname "$0")" && pwd)/check-signal-state-lifetime.sh"
WORK="$(mktemp -d /var/tmp/siglifetime-selftest.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

pass=0
fail=0
cases=0
red=0

check() {
    local label="$1" expected="$2" actual="$3"
    cases=$((cases + 1))
    # red-proved: the case in which the gate returned non-zero on a perturbed input.
    if [ "$expected" != 0 ]; then red=$((red + 1)); fi
    if [ "$expected" = "$actual" ]; then
        echo "case $label: OK   — exit $actual"; pass=$((pass + 1))
    else
        echo "case $label: FAIL — expected exit $expected, got $actual"; fail=$((fail + 1))
    fi
}

# Message assertions count towards the total too: a printed number that only
# moves when a CASE is added or removed is not a denominator anyone can diff.
names() {
    local label="$1" needle="$2" out="$3"
    case "$out" in
        *"$needle"*) pass=$((pass + 1)) ;;
        *) echo "  case $label: FAIL — the output does not name '$needle'"; fail=$((fail + 1)) ;;
    esac
}

tree() {
    local root="$WORK/$1"
    mkdir -p "$root/agent/tests" "$root/ci"
    printf '%s' "$root"
}

# The correctly ordered shape: the state outlives the proxy that dispatches
# into it.
ordered() {
    cat > "$1" <<'EOF'
void t()
{
    std::mutex m;
    std::atomic<bool> got{false};
    auto proxy = sdbus::createProxy(*conn, svc, path);
    proxy->uponSignal(sdbus::SignalName{"Result"}).onInterface(iface).call([&](int) {
        std::lock_guard lk(m);
        got.store(true);
    });
}
EOF
}

# The inversion: the proxy is destroyed last, so a delivery in the window
# locks a destroyed mutex.
inverted() {
    cat > "$1" <<'EOF'
void t()
{
    auto proxy = sdbus::createProxy(*conn, svc, path);
    std::mutex m;
    std::atomic<bool> got{false};
    proxy->uponSignal(sdbus::SignalName{"Result"}).onInterface(iface).call([&](int) {
        std::lock_guard lk(m);
        got.store(true);
    });
}
EOF
}

# The disarm the allowlist entries are granted for. The gate reads the named
# destructor's body, so a fixture that is amnestied has to actually contain one.
disarmer() {
    cat >> "$1" <<'EOF'

struct Holder
{
    std::unique_ptr<sdbus::IProxy> proxy;
    ~Holder()
    {
        proxy.reset();
    }
};
EOF
}

# The shape an amnesty is actually written for, and the shape both amnestied
# owners in this repository have: the proxy is a MEMBER, the state it captures is
# a member declared after it, and the destructor BODY disarms it before either
# dies. Member order inverts the window; the disarm closes it.
member() {
    cat > "$1" <<'EOF'
struct Holder
{
    std::unique_ptr<sdbus::IProxy> proxy;
    std::mutex m;

    Holder()
    {
        proxy = sdbus::createProxy(*conn, svc, path);
        proxy->uponSignal(sdbus::SignalName{"Result"}).onInterface(iface).call([this](int) {
            std::lock_guard lk(m);
        });
    }

    ~Holder()
    {
        proxy.reset();
    }
};
EOF
}

# The same type with the two declarations in the safe order: the state outlives
# the proxy, so there is no window and nothing for an amnesty to cover.
memberOrdered() {
    cat > "$1" <<'EOF'
struct Holder
{
    std::mutex m;
    std::unique_ptr<sdbus::IProxy> proxy;

    Holder()
    {
        proxy = sdbus::createProxy(*conn, svc, path);
        proxy->uponSignal(sdbus::SignalName{"Result"}).onInterface(iface).call([this](int) {
            std::lock_guard lk(m);
        });
    }

    ~Holder()
    {
        proxy.reset();
    }
};
EOF
}

# A local in a free function, spelled with the amnestied owner's name and
# registering the amnestied signal. Everything the key can see matches; what does
# not match is that ~Holder's disarm is about a member, and this is not one.
stranger() {
    cat >> "$1" <<'EOF'

void strangerWatch()
{
    auto proxy = sdbus::createProxy(*conn, svc, path);
    std::string capturedState;
    proxy->uponSignal(sdbus::SignalName{"Result"}).onInterface(iface).call([&](int) {
        capturedState = "seen";
    });
}
EOF
}

ENTRY='agent/tests/T.cpp:proxy:Result:~Holder:proxy.reset()  # disarmed in the destructor body'

# --- case 1
r="$(tree c1)"; ordered "$r/agent/tests/T.cpp"
out="$(ALLOW_FILE=/dev/null bash "$CHECK" "$r" 2>&1)"; rc=$?
check 1 0 $rc
names 1 "none outlives its state" "$out"

# --- case 2: the same handler, the two declarations swapped
r="$(tree c2)"; inverted "$r/agent/tests/T.cpp"
out="$(ALLOW_FILE=/dev/null bash "$CHECK" "$r" 2>&1)"; rc=$?
check 2 1 $rc
names 2 "agent/tests/T.cpp:6" "$out"
names 2 "declared at :3" "$out"

# --- case 3: the inversion, allowlisted by its exact site
r="$(tree c3)"; member "$r/agent/tests/T.cpp"
printf '%s\n' "$ENTRY" > "$r/ci/allow.txt"
out="$(ALLOW_FILE="$r/ci/allow.txt" bash "$CHECK" "$r" 2>&1)"; rc=$?
check 3 0 $rc
names 3 "1 allowlisted" "$out"

# --- case 4: the same entry against a tree that no longer inverts anything.
# An allowlist that outlives its reason is the way this kind of gate rots.
r="$(tree c4)"; memberOrdered "$r/agent/tests/T.cpp"
printf '%s\n' "$ENTRY" > "$r/ci/allow.txt"
out="$(ALLOW_FILE="$r/ci/allow.txt" bash "$CHECK" "$r" 2>&1)"; rc=$?
check 4 1 $rc
names 4 "matches no inversion any more" "$out"

# --- case 5: nothing to measure is not a pass
r="$(tree c5)"; printf 'void t() {}\n' > "$r/agent/tests/T.cpp"
out="$(ALLOW_FILE=/dev/null bash "$CHECK" "$r" 2>&1)"; rc=$?
check 5 1 $rc
names 5 "would pass vacuously" "$out"

# --- case 6: the state is a project alias for a nested std::map, not a
# std:: name. A regex that only knows the std spellings certifies half a
# reordering as done.
r="$(tree c6)"
cat > "$r/agent/tests/T.cpp" <<'EOF'
void t()
{
    auto proxy = sdbus::createProxy(*conn, svc, path);
    using IdentityFieldsMap = std::map<std::string, std::string>;
    IdentityFieldsMap signalledFields;
    proxy->uponSignal(sdbus::SignalName{"Result"}).onInterface(iface).call([&](int) {
        signalledFields.clear();
    });
}
EOF
out="$(ALLOW_FILE=/dev/null bash "$CHECK" "$r" 2>&1)"; rc=$?
check 6 1 $rc
names 6 "IdentityFieldsMap signalledFields" "$out"

# --- case 7: a declaration nested DEEPER sits in an inner block and dies long
# before either the owner or the handler. Reporting it would be a false red,
# and a gate that cries wolf is a gate somebody switches off.
r="$(tree c7)"
cat > "$r/agent/tests/T.cpp" <<'EOF'
void t()
{
    auto proxy = sdbus::createProxy(*conn, svc, path);
    {
        std::vector<std::string> scratch;
        (void)scratch.size();
    }
    proxy->uponSignal(sdbus::SignalName{"Result"}).onInterface(iface).call([&](int) {});
}
EOF
out="$(ALLOW_FILE=/dev/null bash "$CHECK" "$r" 2>&1)"; rc=$?
check 7 0 $rc

# --- case 8: the same inversion as case 2, spelled with types that appear on
# no list anybody would have written. A vocabulary of type names is a hole the
# width of every name it does not contain, and promise/future is one of the
# most natural shapes for waiting on a signal.
r="$(tree c8)"
cat > "$r/agent/tests/T.cpp" <<'EOF'
void t()
{
    auto proxy = sdbus::createProxy(*conn, svc, path);
    std::promise<int> pending;
    std::deque<std::string> seen;
    proxy->uponSignal(sdbus::SignalName{"Result"}).onInterface(iface).call([&](int v) {
        seen.push_back("x");
        pending.set_value(v);
    });
}
EOF
out="$(ALLOW_FILE=/dev/null bash "$CHECK" "$r" 2>&1)"; rc=$?
check 8 1 $rc
names 8 "std::promise<int> pending" "$out"
names 8 "std::deque<std::string> seen" "$out"

# --- case 9: two ordinary declarations whose DECLARATOR is not a bare name --
# an array bound and a structured binding. A rule that reads "<type> <name>"
# and then demands `=`, `;`, `{` or `(` sees neither, and a shape rule with a
# hole in it is the type-name list again wearing a different hat.
r="$(tree c9)"
cat > "$r/agent/tests/T.cpp" <<'EOF'
void t()
{
    auto proxy = sdbus::createProxy(*conn, svc, path);
    char scratch[64];
    auto [ok, key] = std::pair<bool, std::string>{false, {}};
    proxy->uponSignal(sdbus::SignalName{"Result"}).onInterface(iface).call([&](int) {
        scratch[0] = key.empty() ? '"'"'0'"'"' : key[0];
        (void)ok;
    });
}
EOF
out="$(ALLOW_FILE=/dev/null bash "$CHECK" "$r" 2>&1)"; rc=$?
check 9 1 $rc
names 9 "char scratch[64];" "$out"
names 9 "auto [ok, key]" "$out"

# --- case 10: the owner is a class member declared in the HEADER. Nothing in
# the .cpp can say whether it outlives the state its handler touches, and the
# first version of this gate answered that by dropping the site without a
# word -- which is how the one such owner in this repository went unmeasured.
r="$(tree c10)"
mkdir -p "$r/agent/src"
cat > "$r/agent/src/E.h" <<'EOF'
class E
{
public:
    E();
    ~E();

private:
    std::vector<std::function<void(int)>> m_handlers;
    std::unique_ptr<sdbus::IProxy> m_proxy;
};
EOF
cat > "$r/agent/src/E.cpp" <<'EOF'
E::E()
{
    m_proxy = sdbus::createProxy(*conn, svc, path);
    m_proxy->uponSignal(sdbus::SignalName{"Result"}).onInterface(iface).call([this](int) {
        for (const auto& h : m_handlers)
            h(0);
    });
}

E::~E()
{
    m_proxy.reset();
}
EOF
out="$(ALLOW_FILE=/dev/null bash "$CHECK" "$r" 2>&1)"; rc=$?
check 10 1 $rc
names 10 "agent/src/E.cpp:4" "$out"
names 10 "is not declared in this file" "$out"

# --- case 11: the same tree with the site allowlisted. The amnesty is explicit
# and the green line says how many owners it could not read for itself.
printf '%s\n' "agent/src/E.cpp:m_proxy:Result:~E:m_proxy.reset()  # member in E.h" > "$r/ci/allow.txt"
out="$(ALLOW_FILE="$r/ci/allow.txt" bash "$CHECK" "$r" 2>&1)"; rc=$?
check 11 0 $rc
names 11 "1 declared outside its .cpp" "$out"
names 11 "1 allowlisted" "$out"

# --- case 12: the declaration whose type is long enough that clang-format puts
# the declarator on the next line. The formatter REQUIRES that split at this
# repository's column limit, so a rule that reads one line at a time is blind in
# a shape the house style produces on its own.
r="$(tree c12)"
cat > "$r/agent/tests/T.cpp" <<'EOF'
void t()
{
    auto proxy = sdbus::createProxy(*conn, svc, path);
    std::map<std::string, std::vector<std::pair<std::string, std::string>>>
        signalledFieldsByReader;
    proxy->uponSignal(sdbus::SignalName{"Result"}).onInterface(iface).call([&](int) {
        signalledFieldsByReader.clear();
    });
}
EOF
out="$(ALLOW_FILE=/dev/null bash "$CHECK" "$r" 2>&1)"; rc=$?
check 12 1 $rc
names 12 "signalledFieldsByReader;" "$out"

# --- case 13: the amnesty must not depend on the edits above it. This is the
# case-3 tree with one line inserted at the top; the site has moved, the owner
# has not, and an allowlist keyed on the line number failed here -- reporting an
# inversion nobody had introduced and blaming the entry for it.
r="$(tree c13)"; member "$r/agent/tests/T.cpp"
sed -i '1i #include <cstring>' "$r/agent/tests/T.cpp"
printf '%s\n' "$ENTRY" > "$r/ci/allow.txt"
out="$(ALLOW_FILE="$r/ci/allow.txt" bash "$CHECK" "$r" 2>&1)"; rc=$?
check 13 0 $rc
names 13 "1 allowlisted" "$out"

# --- case 14: the amnesty is written for ONE handler. A second local somewhere
# else in the same file, spelled the same way and listening for another signal,
# shares nothing with it but the spelling -- and inherited the amnesty when the
# entry was keyed on the name alone, so a brand-new inversion came out green.
r="$(tree c14)"; member "$r/agent/tests/T.cpp"
cat >> "$r/agent/tests/T.cpp" <<'EOF'

void u()
{
    auto proxy = sdbus::createProxy(*conn, svc, path);
    std::string capturedState;
    proxy->uponSignal(sdbus::SignalName{"Other"}).onInterface(iface).call([&](int) {
        capturedState = "seen";
    });
}
EOF
printf '%s\n' "$ENTRY" > "$r/ci/allow.txt"
out="$(ALLOW_FILE="$r/ci/allow.txt" bash "$CHECK" "$r" 2>&1)"; rc=$?
check 14 1 $rc
names 14 "std::string capturedState;" "$out"

# --- case 15: the other direction. One disarm really can cover two handlers on
# the same owner, and the allowlist says so per signal -- an amnesty spelled out
# handler by handler, not a licence to be vague.
r="$(tree c15)"; member "$r/agent/tests/T.cpp"
sed -i 's|^    ~Holder()$|    void rearm()\n    {\n        proxy->uponSignal(sdbus::SignalName{"Other"}).onInterface(iface).call([this](int) {\n            std::lock_guard lk(m);\n        });\n    }\n\n    ~Holder()|' "$r/agent/tests/T.cpp"
{
    printf '%s\n' "$ENTRY"
    printf '%s\n' 'agent/tests/T.cpp:proxy:Other:~Holder:proxy.reset()  # the same disarm'
} > "$r/ci/allow.txt"
out="$(ALLOW_FILE="$r/ci/allow.txt" bash "$CHECK" "$r" 2>&1)"; rc=$?
check 15 0 $rc
names 15 "2 allowlisted" "$out"

# --- case 16: an entry that does not say which handler it covers, or what
# closes the window, is not an entry this gate can hold to anything, and reading
# it as "one, probably" is how the widening got in.
r="$(tree c16)"; inverted "$r/agent/tests/T.cpp"
printf '%s\n' 'agent/tests/T.cpp:proxy  # a class member disarmed in the destructor body' > "$r/ci/allow.txt"
out="$(ALLOW_FILE="$r/ci/allow.txt" bash "$CHECK" "$r" 2>&1)"; rc=$?
check 16 1 $rc
names 16 "<path>:<owner>:<signal>:<destructor>:<disarm>" "$out"

# --- case 17: the swap. A site count only notices sites being ADDED: delete the
# registration the amnesty was written for, put a stranger of the same name in
# its place, and the count still balances while a fresh inversion runs under an
# old reason. The signal the handler registers is what tells the two apart, and
# unlike a line number it does not move when the text above it does.
r="$(tree c17)"
cat > "$r/agent/tests/T.cpp" <<'EOF'
void u()
{
    auto proxy = sdbus::createProxy(*conn, svc, path);
    std::string capturedState;
    proxy->uponSignal(sdbus::SignalName{"Other"}).onInterface(iface).call([&](int) {
        capturedState = "seen";
    });
}
EOF
disarmer "$r/agent/tests/T.cpp"
printf '%s\n' "$ENTRY" > "$r/ci/allow.txt"
out="$(ALLOW_FILE="$r/ci/allow.txt" bash "$CHECK" "$r" 2>&1)"; rc=$?
check 17 1 $rc
names 17 "std::string capturedState;" "$out"
names 17 "matches no inversion any more" "$out"

# --- case 18: the entry states a BEHAVIOUR -- a named disarm in a named
# destructor. An amnesty that certifies where the owner lives rather than what
# its destructor does stays green after somebody deletes the disarm, which is
# exactly the window it was granted for.
r="$(tree c18)"; member "$r/agent/tests/T.cpp"
sed -i 's|^        proxy.reset();$|        // proxy.reset() used to happen here|' "$r/agent/tests/T.cpp"
printf '%s\n' "$ENTRY" > "$r/ci/allow.txt"
out="$(ALLOW_FILE="$r/ci/allow.txt" bash "$CHECK" "$r" 2>&1)"; rc=$?
check 18 1 $rc
names 18 "no longer" "$out"

# --- case 19: an entry naming a destructor that is not in the file at all. The
# reason cannot be read, so it cannot be believed.
r="$(tree c19)"; member "$r/agent/tests/T.cpp"
printf '%s\n' 'agent/tests/T.cpp:proxy:Result:~Absent:proxy.reset()  # nothing defines this' > "$r/ci/allow.txt"
out="$(ALLOW_FILE="$r/ci/allow.txt" bash "$CHECK" "$r" 2>&1)"; rc=$?
check 19 1 $rc
names 19 "which agent/tests/T.cpp does not define" "$out"

# --- case 20: the OWNER's own declaration wrapped by the formatter. Resolving it
# one line at a time found no declaration here at all and bound the handler to an
# unrelated local of the same name in an earlier function -- a red pointing at
# the wrong place, with six declarations quoted that have nothing to do with it.
r="$(tree c20)"
cat > "$r/agent/tests/T.cpp" <<'EOF'
void t()
{
    auto proxy = sdbus::createProxy(*conn, svc, path);
    std::mutex m;
    proxy->uponSignal(sdbus::SignalName{"Result"}).onInterface(iface).call([&](int) {
        std::lock_guard lk(m);
    });
}

void u()
{
    std::unique_ptr<sdbus::IProxy>
        proxy = sdbus::createProxy(*conn, svc, path);
    std::string capturedState;
    proxy->uponSignal(sdbus::SignalName{"Other"}).onInterface(iface).call([&](int) {
        capturedState = "seen";
    });
}
EOF
out="$(ALLOW_FILE=/dev/null bash "$CHECK" "$r" 2>&1)"; rc=$?
check 20 1 $rc
names 20 "agent/tests/T.cpp:15 -- the handler's owner 'proxy' is declared at :12" "$out"
names 20 "std::string capturedState;" "$out"

# --- case 21: the site count. One entry was written for one handler; a second
# registration of the SAME signal on the SAME member, in another function of the
# type, is a second window under one reason. Until this case existed the branch
# that says so could be deleted without a single case noticing -- and with it
# gone the second window came out green.
r="$(tree c21)"; member "$r/agent/tests/T.cpp"
sed -i 's|^    ~Holder()$|    void rearm()\n    {\n        proxy->uponSignal(sdbus::SignalName{"Result"}).onInterface(iface).call([this](int) {\n            std::lock_guard lk(m);\n        });\n    }\n\n    ~Holder()|' "$r/agent/tests/T.cpp"
printf '%s\n' "$ENTRY" > "$r/ci/allow.txt"
out="$(ALLOW_FILE="$r/ci/allow.txt" bash "$CHECK" "$r" 2>&1)"; rc=$?
check 21 1 $rc
names 21 "covers 1 site(s), 2 found" "$out"

# --- case 22: the substitution the count cannot see. Delete the registration the
# amnesty was written for and put a local of the same name, on the same signal,
# in a free function of the same file: one site, one entry, and ~Holder still
# performs the disarm it names. Everything the key reads matches. What does not
# is the disarm's subject -- it is about a MEMBER of Holder, and a local in a
# free function is nobody's member, so it inherits nothing.
r="$(tree c22)"; member "$r/agent/tests/T.cpp"
python3 - "$r/agent/tests/T.cpp" <<'PYEOF'
import sys
p = sys.argv[1]
lines = open(p).read().splitlines(True)
out = [l for l in lines if 'uponSignal' not in l and 'std::lock_guard lk(m);' not in l
       and l.strip() not in ('});',)]
open(p, 'w').writelines(out)
PYEOF
stranger "$r/agent/tests/T.cpp"
printf '%s\n' "$ENTRY" > "$r/ci/allow.txt"
out="$(ALLOW_FILE="$r/ci/allow.txt" bash "$CHECK" "$r" 2>&1)"; rc=$?
check 22 1 $rc
names 22 "is not a member of Holder" "$out"
names 22 "std::string capturedState;" "$out"

# --- case 23: the substitution the scope check has to reach one level deeper
# than "inside T". The stranger is declared in a member function of Holder, so
# every enclosing-type answer still names Holder -- but it is a local, it dies
# with the call, and ~Holder's disarm is about the member of the same name.
r="$(tree c23)"
cat > "$r/agent/tests/T.cpp" <<'EOF'
struct Holder
{
    std::unique_ptr<sdbus::IProxy> proxy;
    std::mutex m;

    Holder()
    {
    }

    void watchAgain()
    {
        auto proxy = sdbus::createProxy(*conn, svc, path);
        std::string capturedState;
        proxy->uponSignal(sdbus::SignalName{"Result"}).onInterface(iface).call([&](int) {
            capturedState = "seen";
        });
    }

    ~Holder()
    {
        proxy.reset();
    }
};
EOF
printf '%s\n' "$ENTRY" > "$r/ci/allow.txt"
out="$(ALLOW_FILE="$r/ci/allow.txt" bash "$CHECK" "$r" 2>&1)"; rc=$?
check 23 1 $rc
names 23 "is not a member of Holder" "$out"
names 23 "a local inside Holder's own body" "$out"

# --- case 24: the scope check counts braces, so whatever blinds the reading of
# a line moves the scope of everything after it. `1'000` is a digit separator,
# not a character literal, and reading it as one discarded the rest of the line
# -- including the `{` that opens the member function below. With that brace
# uncounted the local inside it reads as a member of the type and inherits the
# amnesty. This repository writes separators like that.
r="$(tree c24)"
cat > "$r/agent/tests/T.cpp" <<'EOF'
struct Holder
{
    std::unique_ptr<sdbus::IProxy> proxy;
    std::mutex m;

    Holder()
    {
    }

    ~Holder()
    {
        proxy.reset();
    }

    int budget = 1'000; void watchAgain() {
        auto proxy = sdbus::createProxy(*conn, svc, path);
        std::string capturedState;
        proxy->uponSignal(sdbus::SignalName{"Result"}).onInterface(iface).call([&](int) {
            capturedState = "seen";
        });
    }
};
EOF
printf '%s\n' "$ENTRY" > "$r/ci/allow.txt"
out="$(ALLOW_FILE="$r/ci/allow.txt" bash "$CHECK" "$r" 2>&1)"; rc=$?
check 24 1 $rc
names 24 "is not a member of Holder" "$out"
names 24 "a local inside Holder's own body" "$out"

# --- case 25: the substitution the SCOPE check cannot see, because the stranger
# really is a member -- of a SECOND type spelled the same way. The amnestied
# registration is gone, the stranger sits in `detail::Holder`, and its own
# ~Holder does nothing. Reading "the destructor" as the first ~Holder in the
# file handed it the disarm that belongs to the other type's members.
r="$(tree c25)"
cat > "$r/agent/tests/T.cpp" <<'EOF'
struct Holder
{
    std::unique_ptr<sdbus::IProxy> proxy;
    std::mutex m;

    Holder()
    {
    }

    ~Holder()
    {
        proxy.reset();
    }
};

namespace detail {
struct Holder
{
    std::unique_ptr<sdbus::IProxy> proxy;
    std::string capturedState;

    Holder()
    {
        proxy = sdbus::createProxy(*conn, svc, path);
        proxy->uponSignal(sdbus::SignalName{"Result"}).onInterface(iface).call([this](int) {
            capturedState = "seen";
        });
    }

    ~Holder() {}
};
} // namespace detail
EOF
printf '%s\n' "$ENTRY" > "$r/ci/allow.txt"
out="$(ALLOW_FILE="$r/ci/allow.txt" bash "$CHECK" "$r" 2>&1)"; rc=$?
check 25 1 $rc
names 25 "no longer performs it" "$out"

# --- case 26: the same two types, both with their destructor defined out of
# line, so neither body sits inside the block that declares the owner. Which
# ~Holder the amnesty is about cannot be read at all, and picking the first is
# the borrowing case 25 closes. An unreadable amnesty is a red, not a pass.
r="$(tree c26)"
cat > "$r/agent/tests/T.cpp" <<'EOF'
struct Holder
{
    std::unique_ptr<sdbus::IProxy> proxy;
    std::string capturedState;

    Holder()
    {
        proxy = sdbus::createProxy(*conn, svc, path);
        proxy->uponSignal(sdbus::SignalName{"Result"}).onInterface(iface).call([this](int) {
            capturedState = "seen";
        });
    }

    ~Holder();
};

Holder::~Holder()
{
    proxy.reset();
}

namespace detail {
struct Holder
{
    std::unique_ptr<sdbus::IProxy> proxy;
    ~Holder();
};
} // namespace detail

detail::Holder::~Holder()
{
}
EOF
printf '%s\n' "$ENTRY" > "$r/ci/allow.txt"
out="$(ALLOW_FILE="$r/ci/allow.txt" bash "$CHECK" "$r" 2>&1)"; rc=$?
check 26 1 $rc
names 26 "defines ~Holder 2 times" "$out"

echo "selftest: $pass passed, $fail failed"
printf 'selftest: %s cases, %s red-proved\n' "$cases" "$red"
[ "$fail" = 0 ]
