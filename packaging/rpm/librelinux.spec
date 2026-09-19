# Link-time optimisation off, explicitly. Fedora's default %%optflags carry
# -flto=auto -ffat-lto-objects, and that conflicts with the vendored static
# LibreAgent::Core archive (the librescrs-agent-core package) exactly as this
# project's own Arch recipe has recorded (options=('!lto')). Debian does not
# enable LTO by default, which is why this line has no counterpart there and
# why one recipe mechanically translated into the other would have been
# wrong.
%global _lto_cflags %{nil}

Name:           librelinux
Version:        5.0.0
Release:        1%{?dist}
Summary:        Linux platform-native integration for LibreSCRS (D-Bus session agent)

License:        LGPL-2.1-or-later
URL:            https://github.com/LibreSCRS/LibreLinux
Source0:        %{name}-%{version}.tar.gz

ExclusiveArch:  x86_64

BuildRequires:  cmake >= 3.24
BuildRequires:  ninja-build
BuildRequires:  gcc-c++
BuildRequires:  make
BuildRequires:  pkgconf-pkg-config
# cmake/GitVersion.cmake calls find_package(Git REQUIRED) before project().
BuildRequires:  git
BuildRequires:  sdbus-cpp-devel >= 2.0
# The XML-to-C++ generator is a separate package on Debian and Ubuntu
# (libsdbus-c++-bin); on Fedora it comes with the development package. The
# build calls find_program(sdbus-c++-xml2cpp REQUIRED) before anything else,
# so a missing generator stops configuration outright.
BuildRequires:  sdbus-cpp-tools
# systemd, not systemd-devel: systemd.pc ships in the base package, and a build
# image with only the development package gets an empty pkg_get_variable and a
# unit installed where the manager never looks.
BuildRequires:  systemd
BuildRequires:  systemd-devel
BuildRequires:  openssl-devel
BuildRequires:  pcsc-lite-devel
BuildRequires:  p11-kit-devel
BuildRequires:  qt6-qtbase-devel
BuildRequires:  kf6-kcoreaddons-devel
BuildRequires:  kf6-ki18n-devel
# Configure-time, not check-time: the agent test tree is added unconditionally
# and calls find_package(GTest REQUIRED) and find_program(dbus-run-session).
BuildRequires:  gtest-devel
BuildRequires:  dbus-daemon
BuildRequires:  librescrs-middleware-devel >= 5.0
BuildRequires:  librescrs-agent-core-devel >= 5.0
%{?systemd_requires}

# This source package produces no package of its own name. The binary packages
# are named for what they are on every distribution -- librescrs-agent and
# librescrs-pinentry-kde -- rather than for the repository they are built from,
# so an instruction that works on Debian works here verbatim.
%description
A per-user, headless, Qt-free D-Bus session service that is the sole owner of
smart-card access for the LibreSCRS stack. It works on any desktop.

Five of its files land in root-owned system directories -- a systemd user unit,
two D-Bus drop-ins, a polkit action and a p11-kit registration -- which is why
no bundle format can deliver it and a distribution package is the only shape it
can take.

The dependency on the prompter is hard rather than suggested: an agent with no
prompter enumerates a card and then fails on the first PIN, because the
interface it calls has no implementation.

%package -n librescrs-agent
Summary:        LibreSCRS smart-card session agent (D-Bus)
Requires:       librescrs-middleware%{?_isa} >= 5.0
Requires:       librescrs-card-plugins%{?_isa} >= 5.0
Requires:       librescrs-pinentry-kde%{?_isa} = %{version}-%{release}
Requires:       p11-kit
Recommends:     pcsc-lite
Recommends:     polkit
Conflicts:      librescrs-pkcs11-direct

%description -n librescrs-agent
A per-user, headless, Qt-free D-Bus session service that is the sole owner of
smart-card access for the LibreSCRS stack. It works on any desktop.

Five of its files land in root-owned system directories, which is why no bundle
format can deliver it. The prompter is a hard dependency: an agent without one
enumerates a card and then fails on the first PIN.

%package -n librescrs-pinentry-kde
Summary:        Secure PIN and CAN entry prompter for the LibreSCRS agent

%description -n librescrs-pinentry-kde
The prompter the agent calls to collect a PIN or a card access number. It is
styled for KDE and built on KF6, and it is currently the only implementation of
the prompter interface, so a GNOME or XFCE machine installs KF6::I18n and
KF6::CoreAddons with it.

%prep
%autosetup -n %{name}-%{version}

%build
%cmake -GNinja \
    -DBUILD_TESTING=OFF \
    -DINSTALL_GTEST=OFF \
    -DLIBRELINUX_USE_INSTALLED_AGENT_CORE=ON
%cmake_build

%install
%cmake_install

# No %%check: the build host has no reader and no session bus.

# Presets rather than an enable of ours. Fedora's last preset is
# 99-default-disable, so a unit no preset names stays disabled -- and the unit
# is D-Bus activated anyway, so the first call starts it either way.
%post -n librescrs-agent
%systemd_user_post librescrs-agent.service

%preun -n librescrs-agent
%systemd_user_preun librescrs-agent.service

%postun -n librescrs-agent
%systemd_user_postun_with_reload librescrs-agent.service

%files -n librescrs-agent
%license LICENSE
%{_libexecdir}/librescrs-agent
%{_userunitdir}/librescrs-agent.service
%{_userunitdir}/librescrs-p11-server.service
%{_libdir}/pkcs11/librescrs-pkcs11-agent.so
%{_datadir}/p11-kit/modules/librescrs-agent.module
%{_datadir}/dbus-1/services/org.librescrs.Agent.service
%{_datadir}/dbus-1/session.d/org.librescrs.Agent.conf
%{_datadir}/dbus-1/interfaces/*.xml
%{_datadir}/polkit-1/actions/org.librescrs.agent.configure.policy

%files -n librescrs-pinentry-kde
%license LICENSE
%{_libexecdir}/librescrs-pinentry-kde
%{_userunitdir}/librescrs-pinentry-kde.service
%{_datadir}/dbus-1/services/org.librescrs.Prompter1.service
%{_datadir}/dbus-1/session.d/org.librescrs.Prompter1.conf
%{_datadir}/locale/*/LC_MESSAGES/librescrs-pinentry-kde.mo

%changelog
* Fri Sep 04 2026 LibreSCRS <packages@librescrs.org> - 5.0.0-1
- Real packaging for the agent and the prompter, replacing the initial stub.
