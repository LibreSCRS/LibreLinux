#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# check-signal-state-lifetime.sh — a signal handler must not outlive the state
# it captures by reference.
#
# sdbus-c++ keeps a registered handler armed for as long as its proxy lives,
# and delivers it on the connection's event-loop thread. Locals die in reverse
# declaration order, so a proxy declared BEFORE the state its handler captures
# is destroyed AFTER that state: a signal delivered in the window between the
# two locks a destroyed std::mutex, notifies a destroyed condition_variable and
# writes into a dead frame. The correctly ordered example in this repository is
# e2e/sign-proof.cpp -- state at :266-272, proxy at :283.
#
# Rule: between the declaration of a proxy that gets uponSignal() and that
# uponSignal() call, NOTHING may be declared at the proxy's own scope.
#
# The test is the SHAPE of a declaration, not a list of type names. A list is a
# closed vocabulary: the first spelling nobody thought of -- a project alias for
# a nested map, a std::promise, a deque -- reads as clean, and a reordering that
# left exactly that one behind comes out certified as done. The shape has to
# cover every DECLARATOR too, not just every type: an array (`char buf[64];`)
# and a structured binding (`auto [ok, key] = ...;`) are ordinary declarations
# whose name is not followed by `=`, `;`, `{` or `(`. Statements that parse like
# a declaration but declare no object (return, delete, throw, an alias `using`)
# are excluded by keyword; a declaration nested DEEPER sits in an inner block
# and dies long before either the owner or the handler, so only the owner's own
# indentation counts.
#
# An owner whose declaration is not in the same translation unit -- a class
# member declared in a header -- cannot be judged here and is REPORTED, never
# skipped: silence would hide the whole class, and the one such owner in this
# repository was invisible to the first version of this gate.
#
# A declaration is a STATEMENT, not a line. clang-format wraps at 120 columns
# here, so a declaration whose type is long enough arrives with the type on one
# line and the declarator on the next -- and the formatter REQUIRES that, which
# means a line-at-a-time rule is blind in exactly the shape the repository's own
# style produces. Lines at the owner's indentation open a statement and every
# more-indented line that follows continues it; the joined text is what the
# shape is tested against, and what is printed when it fails.
#
# Exceptions live in ci/signal-state-lifetime-allow.txt, one
# "<path>:<owner>:<signal>:<destructor>:<disarm>  # reason" per line: an owner
# that is a CLASS MEMBER follows a different discipline (the destructor BODY
# runs before any member is destroyed, so an explicit disarm there closes the
# window that member order would otherwise open).
#
# The key is the file, the OWNER and the SIGNAL, never the line. What is being
# amnestied is a disarm in that owner's destructor, which is a property of the
# owner; keying it on a line number made the amnesty rot on any edit above it --
# one inserted #include moved every site and the gate then failed, blaming the
# allowlist for an inversion nobody had introduced.
#
# A name, though, is not an identity. Keying on the owner alone let a second
# local spelled the same way, in another function of the same file, inherit an
# amnesty written for something else; keying on the owner plus a SITE COUNT only
# caught that when a site was ADDED -- delete the amnestied registration and put
# the stranger in its place and the count still matched. The signal the handler
# registers is what distinguishes one site from another and, unlike a line
# number, it does not move when the text above it does. The count is kept on top
# of it, so two handlers on the same signal still need two entries: fewer sites
# than entries means the allowlist has rotted, more means an inversion arrived
# that nobody amnestied.
#
# A key of file + owner + signal still does not establish object IDENTITY on its
# own: a handler in another function, on an owner of the same name, registering
# the same signal, matched it -- and the destructor field did not save it while
# that destructor was read from the FILE, because it goes on performing its
# disarm whoever else in the file happens to reuse the name. A second TYPE of the
# same short name is the same fact one turn further: its members are members, its
# own destructor may do nothing at all, and reading "~T" as the first ~T in the
# file handed it a disarm written for somebody else's members. So the destructor
# is read from the OWNER'S OWN type: when the owner is declared directly in a T
# block, the ~T inside that block is the one that speaks for it, and when there
# is no such body, the file must define ~T exactly once -- two definitions are
# two types, and an amnesty nobody can attribute is a red, not a pass.
#
# What closes that is reading the last two fields as a statement about the OWNER,
# not about the file. The amnesty says: this owner is disarmed in ~T's body. So
# the gate requires two things of it. First, the disarm has to be there -- ~T is
# brace-matched and its body read with comments stripped, and an amnesty whose
# stated reason has been deleted from the code fails rather than certifying a
# window that is open again. Second, the amnestied site's owner has to BE a
# member of T, and what counts as evidence of that differs between the two
# shapes that land here:
#
#   * the owner is declared in this .cpp. Then the declaration is the evidence
#     and it must sit DIRECTLY in T's body -- the innermost scope around it is
#     T itself. A local declared inside one of T's own member functions is not
#     a member: it dies with the call and ~T never sees it, so an amnesty
#     written for the member of that name says nothing about it;
#   * the owner is declared in a header. Then this file has no declaration to
#     read, and the only evidence it carries is that the registration happens
#     from inside T -- an in-class or out-of-line member function of it. That
#     is weaker on purpose: it is everything the .cpp knows.
#
# The two halves are the same fact read from two ends, and both are needed: the
# disarm read alone certifies a behaviour that may belong to a different object,
# and the scope check alone certifies a member whose destructor may no longer
# disarm it.
#
# Both readings count braces, so anything that blinds the reading of a line
# moves the scope of every line after it. A digit separator is written with an
# apostrophe (`1'000`), and reading that as an opening character literal
# discarded the rest of the line -- braces included -- which is one line's worth
# of work to turn a local into a member. A quote opens a literal here only when
# one closes on the same line and the character before it is not part of an
# identifier or a number.
#
# Threat model. This gate catches an honest regression: a proxy declared above
# the state its handler captures, in the ordinary shapes this codebase
# declares things in today -- a local, an array, a structured binding, a member
# declared in a header. It reads source text with comments and literals
# stripped, so it cannot see identity and does not try to: two different
# things that happen to be spelled the same are one thing to it, and that is
# out of scope here and belongs to code review. Known door, measured on a
# git-archive copy: enclosing_types() names a class or struct block by its
# LAST identifier segment only, with no qualification and no notion of two
# distinct types sharing that segment. An owner declared directly inside a
# second, differently-scoped type of the same short name as the one an
# allowlist entry names -- a `namespace detail { struct Impl { ... }; }` beside
# the real `Impl`, with its own (possibly empty) `~Impl()` -- reads as a member
# of "Impl" either way, so it inherits an amnesty written for the other type's
# destructor. Telling the two apart needs the owner's enclosing NAMESPACE
# chain read as well as its class chain, which this gate does not do.
#
# Usage:   ci/scripts/check-signal-state-lifetime.sh [repo-root]
# Exit:    0 = no handler outlives its captured state
#          1 = an inversion, an allowlist entry that no longer applies, one that
#              covers more sites than it was written for, a named disarm that is
#              no longer in its destructor, or an amnestied site whose owner is
#              not a member of the type that destructor belongs to
set -uo pipefail
export LC_ALL=C

ROOT="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
ALLOW="${ALLOW_FILE:-$ROOT/ci/signal-state-lifetime-allow.txt}"
cd "$ROOT" || exit 1

# A declaration statement: <type-ish tokens> <name> followed by an
# initialiser, a brace, a paren, a semicolon or an array bound. Template
# arguments, references, pointers and qualified names all live inside the type
# part. The second alternative is a structured binding, whose declarator is a
# bracket list rather than a name.
DECL_RE='^[[:space:]]*[A-Za-z_][A-Za-z0-9_:<>,&*[:space:]]*[[:space:]&*][A-Za-z_][A-Za-z0-9_]*[[:space:]]*[;{(=[]|^[[:space:]]*(const[[:space:]]+)?auto[[:space:]]*&*[[:space:]]*\\['
# ...that is not one of the statements which merely parse that way.
SKIP_RE='^[[:space:]]*(return|delete|throw|using|namespace|typedef|else|do|goto|break|continue|case|default|template|friend|public|private|protected|static_assert|if|for|while|switch|catch|try|new|co_return|co_await|co_yield|operator)([[:space:]]|$)'

declare -A allowed=()
declare -A dtorOf=()
declare -A disarmOf=()
malformed=0
if [[ -f "$ALLOW" ]]; then
    while IFS= read -r line; do
        line="${line%%#*}"
        line="${line//[[:space:]]/}"
        [[ -z "$line" ]] && continue
        IFS=: read -r apath aowner asignal adtor adisarm <<< "$line"
        if [[ -z "$apath" || -z "$aowner" || -z "$asignal" || -z "$adtor" || -z "$adisarm" ]]; then
            echo "FAIL: allowlist entry '$line' is not" >&2
            echo "      <path>:<owner>:<signal>:<destructor>:<disarm>." >&2
            echo "      The signal says WHICH handler is covered; the destructor and the" >&2
            echo "      disarm say what closes the window, and both are read from the code." >&2
            malformed=1
            continue
        fi
        key="${apath}:${aowner}:${asignal}"
        if [[ -n "${dtorOf[$key]:-}" && ( "${dtorOf[$key]}" != "$adtor" || "${disarmOf[$key]}" != "$adisarm" ) ]]; then
            echo "FAIL: allowlist entries for '$key' disagree about the disarm." >&2
            malformed=1
            continue
        fi
        allowed["$key"]=$(( ${allowed[$key]:-0} + 1 ))
        dtorOf["$key"]="$adtor"
        disarmOf["$key"]="$adisarm"
    done < "$ALLOW"
fi
[[ $malformed -eq 1 ]] && exit 1

# Every DEFINITION of <destructor> in <file>, one "<line>:<body>" per line, the
# body brace-matched and read with string literals and comments removed --
# because a disarm named in a comment is a disarm nobody performs, and a brace
# inside a literal is not a scope. Whitespace is squeezed out of the body, so
# the allowlist may be written without spaces and clang-format may put them
# wherever it likes. A bare declaration (`~T();`, `= default;`) defines no body
# and is not one of these.
#
# There can be more than one, and that is the point: two unrelated types in one
# file can share a short name, and reading "the destructor" as "the first ~T in
# the file" let the second one borrow the first one's disarm.
dtor_bodies() {
    awk -v d="$2" '
    function identish(c) { return (c ~ /[A-Za-z0-9_]/) }
    function closes(s, i, q, n,   j, c) {
        j = i + 1
        while (j <= n) {
            c = substr(s, j, 1)
            if (c == "\\") { j += 2; continue }
            if (c == q) return j
            j++
        }
        return 0
    }
    function strip(s,   n, i, out, ch, two, prev, end) {
        n = length(s); out = ""; i = 1
        while (i <= n) {
            ch = substr(s, i, 1); two = substr(s, i, 2)
            if (inblock) { if (two == "*/") { inblock = 0; i += 2 } else { i++ }; continue }
            if (two == "/*") { inblock = 1; i += 2; continue }
            if (two == "//") break
            if (ch == dq || ch == sq) {
                prev = (i > 1) ? substr(s, i - 1, 1) : ""
                if (ch == sq && identish(prev)) { out = out ch; i++; continue }
                end = closes(s, i, ch, n)
                if (end == 0) { out = out ch; i++; continue }
                i = end + 1
                continue
            }
            out = out ch; i++
        }
        return out
    }
    BEGIN { dq = sprintf("%c", 34); sq = sprintf("%c", 39); inblock = 0; found = 0 }
    {
        clean = strip($0)
        if (!found) {
            if (clean !~ ("(^|[^A-Za-z0-9_~])" d "[ \t]*\\(")) next
            found = 1; start = NR; depth = 0; opened = 0; body = ""
        }
        n = length(clean)
        for (k = 1; k <= n; k++) {
            ch = substr(clean, k, 1)
            if (ch == "{") { depth++; opened = 1 }
            else if (ch == "}") { depth-- }
            else if (ch == ";" && !opened) { found = 0; break }  # a declaration
        }
        if (!found) next
        body = body clean
        if (opened && depth <= 0) {
            gsub(/[ \t]/, "", body)
            print start ":" body
            found = 0
        }
    }' "$1"
}

# The types whose bodies enclose <line> in <file>, outermost first: a `class X`
# or `struct X` block (qualified names count as their last component, so
# `struct A::B` is a B), and an out-of-line member definition `X::f(...)` or
# `X::~X()`, whose body is inside X as far as member lifetime is concerned.
# Namespaces, functions, lambdas and plain blocks contribute nothing, so a local
# in a free function comes back with an empty list.
#
# Braces are counted on the source with string literals and comments removed --
# a brace inside a string is not a scope, and a `{` in a comment used to be one.
enclosing_types() {
    awk -v target="$2" '
    function identish(c) { return (c ~ /[A-Za-z0-9_]/) }
    # Where the literal opened at i closes on this line, or 0 when it does not.
    # An apostrophe that closes nothing is not a literal -- a digit separator is
    # written that way, and reading it as an opener swallowed the rest of the
    # line, braces included, which made a free function look like a class body.
    function closes(s, i, q, n,   j, c) {
        j = i + 1
        while (j <= n) {
            c = substr(s, j, 1)
            if (c == "\\") { j += 2; continue }
            if (c == q) return j
            j++
        }
        return 0
    }
    function strip(s,   n, i, out, ch, two, prev, end) {
        n = length(s); out = ""; i = 1
        while (i <= n) {
            ch = substr(s, i, 1); two = substr(s, i, 2)
            if (inblock) { if (two == "*/") { inblock = 0; i += 2 } else { i++ }; continue }
            if (two == "/*") { inblock = 1; i += 2; continue }
            if (two == "//") break
            if (ch == dq || ch == sq) {
                prev = (i > 1) ? substr(s, i - 1, 1) : ""
                if (ch == sq && identish(prev)) { out = out ch; i++; continue }
                end = closes(s, i, ch, n)
                if (end == 0) { out = out ch; i++; continue }
                i = end + 1
                continue
            }
            out = out ch; i++
        }
        return out
    }
    function tagof(s,   t) {
        if (match(s, /(^|[^A-Za-z0-9_])(class|struct)[ \t]+[A-Za-z_][A-Za-z0-9_:]*/)) {
            t = substr(s, RSTART, RLENGTH)
            sub(/^.*(class|struct)[ \t]+/, "", t)
            sub(/^.*::/, "", t)
            return t
        }
        if (match(s, /[A-Za-z_][A-Za-z0-9_]*[ \t]*::[ \t]*~?[A-Za-z_][A-Za-z0-9_]*[ \t]*\(/)) {
            t = substr(s, RSTART, RLENGTH)
            sub(/[ \t]*::.*$/, "", t)
            return t
        }
        return ""
    }
    BEGIN { dq = sprintf("%c", 34); sq = sprintf("%c", 39); inblock = 0; depth = 0; buf = "" }
    {
        if (NR == target) {
            out = ""
            for (j = 1; j <= depth; j++) out = out ((tag[j] != "") ? tag[j] : "-") " "
            print out
            exit
        }
        clean = strip($0)
        n = length(clean)
        for (k = 1; k <= n; k++) {
            ch = substr(clean, k, 1)
            if (ch == "{") { depth++; tag[depth] = tagof(buf); buf = "" }
            else if (ch == "}") { if (depth > 0) depth--; buf = "" }
            else if (ch == ";") { buf = "" }
            else buf = buf ch
        }
        buf = buf " "
    }
    END { }' "$1"
}

# The line range of the innermost block around <line> in <file> whose tag is
# <type>: "<open-line> <close-line>", or nothing when no such block encloses it.
# This is what makes "~T's body" a statement about ONE T and not about whichever
# T in the file happens to be spelled first.
type_block() {
    awk -v target="$2" -v want="$3" '
    function identish(c) { return (c ~ /[A-Za-z0-9_]/) }
    function closes(s, i, q, n,   j, c) {
        j = i + 1
        while (j <= n) {
            c = substr(s, j, 1)
            if (c == "\\") { j += 2; continue }
            if (c == q) return j
            j++
        }
        return 0
    }
    function strip(s,   n, i, out, ch, two, prev, end) {
        n = length(s); out = ""; i = 1
        while (i <= n) {
            ch = substr(s, i, 1); two = substr(s, i, 2)
            if (inblock) { if (two == "*/") { inblock = 0; i += 2 } else { i++ }; continue }
            if (two == "/*") { inblock = 1; i += 2; continue }
            if (two == "//") break
            if (ch == dq || ch == sq) {
                prev = (i > 1) ? substr(s, i - 1, 1) : ""
                if (ch == sq && identish(prev)) { out = out ch; i++; continue }
                end = closes(s, i, ch, n)
                if (end == 0) { out = out ch; i++; continue }
                i = end + 1
                continue
            }
            out = out ch; i++
        }
        return out
    }
    function tagof(s,   t) {
        if (match(s, /(^|[^A-Za-z0-9_])(class|struct)[ \t]+[A-Za-z_][A-Za-z0-9_:]*/)) {
            t = substr(s, RSTART, RLENGTH)
            sub(/^.*(class|struct)[ \t]+/, "", t)
            sub(/^.*::/, "", t)
            return t
        }
        if (match(s, /[A-Za-z_][A-Za-z0-9_]*[ \t]*::[ \t]*~?[A-Za-z_][A-Za-z0-9_]*[ \t]*\(/)) {
            t = substr(s, RSTART, RLENGTH)
            sub(/[ \t]*::.*$/, "", t)
            return t
        }
        return ""
    }
    BEGIN { dq = sprintf("%c", 34); sq = sprintf("%c", 39); inblock = 0; depth = 0; buf = ""; resolved = 0 }
    {
        if (NR == target && !resolved) {
            for (d = depth; d >= 1; d--) {
                if (tag[d] == want) { resolved = 1; want_depth = d; open_line = opened[d]; break }
            }
            if (!resolved) exit
        }
        clean = strip($0)
        n = length(clean)
        for (k = 1; k <= n; k++) {
            ch = substr(clean, k, 1)
            if (ch == "{") { depth++; tag[depth] = tagof(buf); opened[depth] = NR; buf = "" }
            else if (ch == "}") {
                if (resolved && depth == want_depth) { print open_line " " NR; exit }
                if (depth > 0) depth--
                buf = ""
            }
            else if (ch == ";") { buf = "" }
            else buf = buf ch
        }
        buf = buf " "
    }
    END { }' "$1"
}

# Is the amnestied site really a member of the type whose destructor the entry
# names? What counts as evidence differs between the two shapes, and reading
# them the same way is how a stranger got in twice.
#
#   decl -- the owner is declared in this .cpp, so the declaration itself is the
#           evidence, and it has to sit DIRECTLY in T's body: a member is
#           declared in the class, and a local declared inside one of T's own
#           member functions is a different object with its own lifetime, which
#           ~T's disarm says nothing about. So the INNERMOST enclosing scope has
#           to be T, not merely one of them.
#   site -- the owner is declared in a header and this file cannot see it. The
#           only evidence here is that the registration happens from inside T --
#           a member function of it, in-class or out-of-line -- so T has to be
#           somewhere in the chain.
#
# The chain enclosing_types() returns carries a "-" for every scope that is not
# a type (a function, a lambda, a namespace, a bare block), which is what makes
# "inside T" and "IS a member of T" two different questions.
declare -A scopeChecked=()
check_scope() {
    local key="$1" f="$2" at="$3" owner="$4" mode="$5" type="${dtorOf[$1]#\~}"
    local memo="$key|$at"
    [[ -n "${scopeChecked[$memo]:-}" ]] && return "${scopeChecked[$memo]}"
    local types innermost named
    types="$(enclosing_types "$f" "$at")"
    innermost="${types% }"
    innermost="${innermost##* }"
    named="$(printf '%s' "$types" | tr ' ' '\n' | grep -v -E '^-?$' | tr '\n' ' ')"
    if [[ "$mode" == "decl" ]]; then
        if [[ "$innermost" == "$type" ]]; then
            scopeChecked["$memo"]=0
            return 0
        fi
    elif [[ " $types " == *" $type "* ]]; then
        scopeChecked["$memo"]=0
        return 0
    fi
    echo "FAIL: $f:$at -- the amnesty '$key' is granted for the disarm" >&2
    echo "      '${disarmOf[$key]}' in ${dtorOf[$key]}, but this '$owner' is not a member of $type:" >&2
    if [[ -z "${named// /}" ]]; then
        echo "      it is declared in no class or struct body at all." >&2
    elif [[ "$mode" == "decl" && " $types " == *" $type "* ]]; then
        echo "      it is a local inside $type's own body, not one of its members --" >&2
        echo "      it dies with the function that declares it, and ~$type never sees it." >&2
    else
        echo "      it is declared inside ${named% }." >&2
    fi
    echo "      A handler that merely shares an owner's name and signal is a new" >&2
    echo "      inversion, not a covered one." >&2
    scopeChecked["$memo"]=1
    return 1
}

declare -A disarmChecked=()
check_disarm() {
    local key="$1" f="$2" at="$3" mode="$4"
    local memo="$key|$at"
    [[ -n "${disarmChecked[$memo]:-}" ]] && return "${disarmChecked[$memo]}"
    local type="${dtorOf[$key]#\~}"
    local -a bodies=()
    mapfile -t bodies < <(dtor_bodies "$f" "${dtorOf[$key]}")
    if [[ ${#bodies[@]} -eq 0 ]]; then
        echo "FAIL: allowlist entry '$key' names the destructor ${dtorOf[$key]}," >&2
        echo "      which $f does not define -- the amnesty cannot be read." >&2
        disarmChecked["$memo"]=1
        return 1
    fi
    local picked="" range="" bstart bend b bl
    # The owner is declared directly in T's body, so T's body is where its
    # destructor is: read that one, not whichever ~T comes first in the file.
    if [[ "$mode" == "decl" ]]; then
        range="$(type_block "$f" "$at" "$type")"
        if [[ -n "$range" ]]; then
            bstart="${range% *}"; bend="${range#* }"
            for b in "${bodies[@]}"; do
                bl="${b%%:*}"
                if [[ "$bl" -ge "$bstart" && "$bl" -le "$bend" ]]; then
                    picked="${b#*:}"
                    break
                fi
            done
        fi
    fi
    # Otherwise the destructor is defined out of line (or the owner comes from a
    # header and this file has no body to bound the search with). Then it has to
    # be the only one: two definitions of ~T in one file are two types, and
    # picking either of them for the other is the borrowing this closes.
    if [[ -z "$picked" ]]; then
        if [[ ${#bodies[@]} -ne 1 ]]; then
            echo "FAIL: $f defines ${dtorOf[$key]} ${#bodies[@]} times, and none of them is inside the" >&2
            echo "      body that declares '$key'. Which one the amnesty is about cannot be read," >&2
            echo "      and reading it as the first one is how a second type of the same name" >&2
            echo "      borrowed a disarm written for another object." >&2
            disarmChecked["$memo"]=1
            return 1
        fi
        picked="${bodies[0]#*:}"
    fi
    if [[ "$picked" == *"${disarmOf[$key]}"* ]]; then
        disarmChecked["$memo"]=0
        return 0
    fi
    echo "FAIL: allowlist entry '$key' is granted for the disarm" >&2
    echo "      '${disarmOf[$key]}' in ${dtorOf[$key]}, and the ${dtorOf[$key]} that belongs to this" >&2
    echo "      owner no longer performs it -- the window the amnesty describes is open again." >&2
    disarmChecked["$memo"]=1
    return 1
}

fail=0
checked=0
external=0
declare -A hit=()
declare -A hitat=()

# Every tracked C/C++ source in the repository, not a list of the subsystems
# that happen to use sdbus-c++ today: a proxy added under prompter/ or common/
# must not be invisible because the agent's files keep the set non-empty.
mapfile -t files < <(grep -rl --include='*.cpp' --include='*.h' 'uponSignal' . \
    --exclude-dir='build*' --exclude-dir='.git' 2>/dev/null | sed 's|^\./||' | sort)
if [[ ${#files[@]} -eq 0 ]]; then
    echo "FAIL: no file uses uponSignal -- this gate would pass vacuously." >&2
    exit 1
fi

for f in "${files[@]}"; do
    while IFS=: read -r sigline rest; do
        # Owner = the FIRST identifier of the call expression: `h.proxy->uponSignal`
        # is owned by `h`, whose lifetime is the one that matters.
        owner="$(printf '%s' "$rest" | sed -n \
            's/.*[^A-Za-z0-9_>.]\([A-Za-z_][A-Za-z0-9_]*\)\([.][A-Za-z_][A-Za-z0-9_]*\)*->uponSignal.*/\1/p' | head -1)"
        [[ -z "$owner" ]] && owner="$(printf '%s' "$rest" | sed -n \
            's/^[[:space:]]*\([A-Za-z_][A-Za-z0-9_]*\)\([.][A-Za-z_][A-Za-z0-9_]*\)*->uponSignal.*/\1/p' | head -1)"
        [[ -z "$owner" ]] && continue
        # The signal this handler registers. It is what tells one site from
        # another under the same owner name, and it does not move when a line
        # above it does. A name the gate cannot read (a constant, a variable)
        # leaves the site unamnestiable rather than silently amnestied.
        signal="$(printf '%s' "$rest" | sed -n \
            's/.*uponSignal[[:space:]]*([^"]*"\([A-Za-z_][A-Za-z0-9_.]*\)".*/\1/p' | head -1)"
        # The owner's own declaration is a STATEMENT too: at 120 columns the
        # formatter puts a long proxy type on its own line, and reading one line
        # at a time then bound the owner to an unrelated earlier local of the
        # same name and reported that stranger's function.
        decl="$(awk -v n="$sigline" -v o="$owner" '
            function emit(ln, t) {
                if (t ~ ("(^|[^A-Za-z0-9_])(auto|[A-Za-z_][A-Za-z0-9_:<>,& *]*)[ &*]" o "[[:space:]]*(=|\\{|\\(|;)")) d = ln
            }
            NR >= n { exit }
            {
                if (buf == "") {
                    if ($0 ~ /^[ \t]*$/) next
                    start = NR; buf = $0
                } else { cont = $0; sub(/^[ \t]+/, "", cont); buf = buf " " cont }
                if ($0 ~ /[;{}]/) { emit(start, buf); buf = "" }
            }
            END { if (buf != "") emit(start, buf); print d + 0 }' "$f")"
        key="${f}:${owner}:${signal}"
        if [[ "$decl" -eq 0 ]]; then
            # Not a local: the owner is declared elsewhere, in practice a class
            # member in the matching header. Member order is not the deciding
            # fact there -- the destructor BODY runs before any member dies, so
            # an explicit disarm in it closes the window -- but that disarm has
            # to be NAMED by a human, which is what the allowlist is for.
            checked=$((checked + 1))
            external=$((external + 1))
            if [[ -n "${allowed[$key]:-}" ]]; then
                # Both halves of the entry have to hold: the destructor really
                # performs the disarm, and this owner really is one of that
                # type's members. A site the amnesty does not reach is not a
                # covered one, so it does not count towards the entry either --
                # which is why the entry then reports that it matches nothing.
                if check_disarm "$key" "$f" "$sigline" site && check_scope "$key" "$f" "$sigline" "$owner" site; then
                    hit["$key"]=$(( ${hit[$key]:-0} + 1 ))
                    hitat["$key"]="${hitat[$key]:-}${hitat[$key]:+, }:$sigline"
                    continue
                fi
                fail=1
                continue
            fi
            echo "FAIL: $f:$sigline -- the handler's owner '$owner' is not declared in this file," >&2
            echo "      so nothing here can say whether it outlives the state it captures." >&2
            echo "      Name the destructor-body disarm in ci/signal-state-lifetime-allow.txt." >&2
            fail=1
            continue
        fi
        checked=$((checked + 1))
        # Only state at the OWNER'S OWN indentation is in the same scope: a
        # declaration nested deeper sits in a lambda body or an inner block and
        # dies long before either the owner or the handler.
        bad="$(awk -v a="$decl" -v b="$sigline" -v re="$DECL_RE" -v skip="$SKIP_RE" '
            function flush() {
                if (start == 0) return
                if (text ~ re && text !~ skip) printf "%d:%s\n", start, text
                start = 0; text = ""
            }
            NR == a { match($0, /^[ \t]*/); own = RLENGTH }
            NR > a && NR < b {
                match($0, /^[ \t]*/); ind = RLENGTH
                if (ind == own) {
                    flush()
                    start = NR; text = $0
                } else if (ind > own && start != 0) {
                    cont = $0; sub(/^[ \t]+/, "", cont)
                    text = text " " cont
                } else {
                    flush()
                }
            }
            END { flush() }' "$f")"
        [[ -z "$bad" ]] && continue
        if [[ -n "${allowed[$key]:-}" ]]; then
            if check_disarm "$key" "$f" "$decl" decl && check_scope "$key" "$f" "$decl" "$owner" decl; then
                hit["$key"]=$(( ${hit[$key]:-0} + 1 ))
                hitat["$key"]="${hitat[$key]:-}${hitat[$key]:+, }:$sigline"
                continue
            fi
            fail=1
            # An amnesty that does not reach this site leaves the inversion
            # itself unexplained, so it is reported below as what it is.
        fi
        echo "FAIL: $f:$sigline -- the handler's owner '$owner' is declared at :$decl," >&2
        echo "      BEFORE the state it captures, so the state is destroyed FIRST:" >&2
        printf '%s\n' "$bad" | sed 's/^/        /' >&2
        fail=1
    done < <(grep -n 'uponSignal' "$f")
done

for key in "${!allowed[@]}"; do
    seen="${hit[$key]:-0}"
    want="${allowed[$key]}"
    if [[ "$seen" -eq 0 ]]; then
        echo "FAIL: allowlist entry '$key' matches no inversion any more -- delete it." >&2
        fail=1
    elif [[ "$seen" -ne "$want" ]]; then
        echo "FAIL: allowlist entry '$key' covers $want site(s), $seen found (${hitat[$key]})." >&2
        echo "      What is amnestied is the disarm in that owner's destructor; a handler" >&2
        echo "      that merely shares the owner's name and signal is a new inversion, not" >&2
        echo "      a covered one." >&2
        fail=1
    fi
done

if [[ $checked -eq 0 ]]; then
    echo "FAIL: uponSignal call sites found but no owner declaration resolved." >&2
    exit 1
fi
if [[ $fail -eq 0 ]]; then
    echo "OK: $checked handler owner(s) checked ($external declared outside its .cpp), ${#allowed[@]} allowlisted, none outlives its state"
fi
exit $fail
