// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Drift guard: the <property> elements published in
// dbus/org.librescrs.Agent.Config1.xml against the key set ConfigStore owns.
//
// The agent's configuration lives in two artefacts that have to agree, and
// nothing checked that they do. ConfigStore decides which keys exist and how
// each may be changed; the Config1 XML decides what a client can read over the
// bus. A key added to one and not the other compiles, links, and passes every
// other test in this tree -- Config1Test drives keys it names itself, so it
// cannot notice a key nobody named.
//
// Checked in BOTH directions on purpose. "every key the store publishes has a
// property" alone misses a SURPLUS -- a property naming a key the store does
// not have -- and a surplus is what nothing else would notice: the adaptor
// getter behind such a property is hand-written, and a hand-written getter
// returning a hand-written value reads exactly like a working one.
//
// FILE-ONLY KEYS. Some keys are settable only by editing the config file: the
// cache directories, the PKCS#11 login-lease knobs, and -- emphatically -- the
// plugin directory, whose D-Bus mutability would be a dlopen code-execution
// vector. Those are exempt from the "must be a property" direction; publishing
// one read-only is a free choice this guard does not make for the interface.
// The exemption is taken from ConfigStore::mutability() itself, never from a
// list of key spellings kept here: a hand-written list would be a third
// artefact to keep in step with the two this file was written to compare,
// which is the very defect it exists to catch.
//
// Note the asymmetry that follows. A file-only key MAY be a property, so the
// surplus direction is measured against the FULL key set, not the reduced one.
// Today some file-only keys are published read-only and some are not, and this
// guard deliberately says nothing about which -- it guards the wire-settable
// surface and the dead-property case, not that editorial choice.
//
// NO EXEMPTIONS. This file once carried one: CscaAnchorState was a property
// the agent DERIVED and no key the store owned, so the surplus direction had
// to be told to ignore it. The store owns it now -- read-only, recorded by an
// accepted import so a client that has just started can be told what is
// installed -- and the exemption went with it rather than staying behind to
// mask the next real surplus. Both directions therefore measure the whole
// interface against the whole key set, with nothing hand-listed here at all,
// which is what the header above wants of this file.

#include <LibreSCRS/Agent/config/ConfigStore.h>

#include <gtest/gtest.h>

#include <algorithm>
#include <fstream>
#include <iterator>
#include <optional>
#include <regex>
#include <set>
#include <sstream>
#include <string>
#include <vector>

namespace {

using LibreSCRS::Agent::Config::ConfigStore;
using LibreSCRS::Agent::Config::Mutability;

std::string slurp(const char* path)
{
    std::ifstream in(path);
    std::stringstream buffer;
    buffer << in.rdbuf();
    return buffer.str();
}

// The property names declared by the interface. Introspection XML spells a
// property in exactly one form -- <property name="Something" type=... /> --
// and <arg name=...> deliberately does not match, so a method argument is
// never mistaken for a property. A form that stops matching empties the
// result, which the tests assert against, so this fails loudly rather than
// passing vacuously.
std::set<std::string> propertiesDeclaredInXml(const std::string& xml)
{
    // A raw string literal here confuses clang-format, which breaks it
    // mid-token, so the pattern is spelled with escapes instead.
    static const std::regex propertyRe("<property\\s+name\\s*=\\s*\"([^\"]+)\"");
    std::set<std::string> names;
    for (std::sregex_iterator it(xml.begin(), xml.end(), propertyRe), end; it != end; ++it) {
        names.insert((*it)[1].str());
    }
    return names;
}

std::set<std::string> everyKeyTheStoreOwns()
{
    const std::vector<std::string>& keys = ConfigStore::keys();
    return {keys.begin(), keys.end()};
}

// The keys whose absence from the interface would be a defect: everything the
// store owns except the file-only ones, asked key by key rather than listed.
std::set<std::string> keysThatMustBeProperties()
{
    std::set<std::string> out;
    for (const std::string& key : ConfigStore::keys()) {
        const std::optional<Mutability> how = ConfigStore::mutability(key);
        if (how.has_value() && *how != Mutability::FileOnly) {
            out.insert(key);
        }
    }
    return out;
}

// Keys the store owns that mutability() cannot classify. Such a key would drop
// silently out of keysThatMustBeProperties() above -- exempted by an omission
// rather than by a decision -- so the guard test asserts this stays empty.
std::set<std::string> keysWithNoMutability()
{
    std::set<std::string> out;
    for (const std::string& key : ConfigStore::keys()) {
        if (!ConfigStore::mutability(key).has_value()) {
            out.insert(key);
        }
    }
    return out;
}

std::set<std::string> difference(const std::set<std::string>& lhs, const std::set<std::string>& rhs)
{
    std::set<std::string> out;
    std::set_difference(lhs.begin(), lhs.end(), rhs.begin(), rhs.end(), std::inserter(out, out.end()));
    return out;
}

std::string joinSorted(const std::set<std::string>& names)
{
    std::string out;
    for (const std::string& name : names) {
        if (!out.empty()) {
            out += ", ";
        }
        out += name;
    }
    return out;
}

} // namespace

TEST(Config1PropertyKeyMirror, EveryKeyTheStoreOwnsIsClassified)
{
    // Guards the guard. The bidirectional test below leans on mutability()
    // having an answer for every key it filters on: a key it cannot classify
    // would drop out of the must-be-published set silently, exempted by an
    // omission rather than by a decision. That is a smaller copy of the drift
    // this file was written for.
    const std::set<std::string> unclassified = keysWithNoMutability();
    EXPECT_TRUE(unclassified.empty()) << "ConfigStore owns a key mutability() cannot classify, so the file-only "
                                         "filter below would drop it by omission rather than by decision: "
                                      << joinSorted(unclassified);
}

TEST(Config1PropertyKeyMirror, XmlPropertiesAndStoreKeysAgreeInBothDirections)
{
    const std::string xml = slurp(LIBRELINUX_CONFIG1_XML);
    ASSERT_FALSE(xml.empty()) << "could not read the interface at " << LIBRELINUX_CONFIG1_XML;

    const std::set<std::string> declared = propertiesDeclaredInXml(xml);
    ASSERT_FALSE(declared.empty()) << "the interface parsed to no properties at all, so the pattern no longer "
                                      "matches how Config1.xml declares them";

    const std::set<std::string> mustBePublished = keysThatMustBeProperties();
    ASSERT_FALSE(mustBePublished.empty()) << "ConfigStore reports no publishable key at all -- either keys() is "
                                             "empty or mutability() now calls every key file-only";

    const std::set<std::string> missingFromXml = difference(mustBePublished, declared);
    EXPECT_TRUE(missingFromXml.empty()) << "ConfigStore owns a key the Config1 interface does not publish as a "
                                           "property, so a client cannot read what it may be asked to set: "
                                        << joinSorted(missingFromXml);

    // Measured against every key, file-only included: a file-only key that IS
    // published read-only is a choice, not a surplus. Nothing is subtracted
    // from this beyond the store's own key set -- see the header.
    const std::set<std::string> surplusInXml = difference(declared, everyKeyTheStoreOwns());
    EXPECT_TRUE(surplusInXml.empty()) << "the Config1 interface declares a property ConfigStore knows no key for, "
                                         "so the wire carries a name nothing behind it stores: "
                                      << joinSorted(surplusInXml);
}
