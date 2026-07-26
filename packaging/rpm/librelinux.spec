# Initial stub.
Name:           librelinux
Version:        0.0.1
Release:        1%{?dist}
Summary:        Linux platform-native integration for LibreSCRS (D-Bus session agent)
License:        LGPL-2.1-or-later
URL:            https://librescrs.github.io
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  cmake >= 3.24
BuildRequires:  ninja-build
BuildRequires:  sdbus-cpp-devel >= 2.0
BuildRequires:  systemd-devel
BuildRequires:  pkgconfig
BuildRequires:  librescrs-middleware-devel >= 4.2

Requires:       librescrs-middleware >= 4.2
Requires:       sdbus-cpp >= 2.0

%description
Per-user, headless, Qt-free D-Bus session service that is the sole owner of
smart-card access for the LibreSCRS ecosystem. Desktop-agnostic — works on
KDE, GNOME, or any other Linux desktop.

%prep
%autosetup

%build
%cmake -GNinja
%cmake_build

%install
%cmake_install

%check
%ctest

%files
%license LICENSE
%{_libexecdir}/librescrs-agent
%{_userunitdir}/librescrs-agent.service
%{_datadir}/dbus-1/services/org.librescrs.Agent.service
%{_datadir}/dbus-1/interfaces/org.librescrs.Agent.*.xml
