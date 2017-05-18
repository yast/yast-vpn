#
# spec file for package yast2-vpn
#
# Copyright (c) 2016 SUSE LINUX GmbH, Nuernberg, Germany.
#
# All modifications and additions to the file contributed by third parties
# remain the property of their copyright owners, unless otherwise agreed
# upon. The license for this file, and modifications and additions to the
# file, is the same license as for the pristine package itself (unless the
# license for the pristine package is not an Open Source License, in which
# case the license is the MIT License). An "Open Source License" is a
# license that conforms to the Open Source Definition (Version 1.9)
# published by the Open Source Initiative.

# Please submit bugfixes or comments via http://bugs.opensuse.org/
#


Name:           yast2-vpn
Version:        3.1.6
Release:        0
Url:            https://github.com/yast/yast-vpn
Source0:        %{name}-%{version}.tar.bz2
Summary:        A YaST module for configuring VPN gateway and clients
License:        GPL-2.0
Group:          System/YaST
BuildArch:      noarch
Requires:       yast2
Requires:       yast2-ruby-bindings
BuildRequires:  yast2
BuildRequires:  yast2-devtools
BuildRequires:  yast2-ruby-bindings
BuildRequires:  rubygem(rspec)
BuildRequires:  rubygem(yast-rake)

PreReq:         %fillup_prereq

%description
A YaST module for managing VPN gateway and client connections to secure site-to-site communication via IPSec VPN.

%prep
%setup -q

%check
rake test:unit

%build

%install
rake install DESTDIR="%{buildroot}"

%files
%defattr(-,root,root)
%doc %yast_docdir
%yast_desktopdir
%yast_moduledir
%yast_clientdir
%yast_schemadir
%yast_libdir
%yast_scrconfdir

%changelog
