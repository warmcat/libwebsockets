Name: libwebsockets
Version: 1.2
Release: 46.gmaster_f59d56cbd8305ed%{?dist}
Summary: Websocket Server Library

Group: System
License: GPL
URL: http://warmcat.com
Source0: %{name}-%{version}.tar.gz
BuildRoot:	%(mktemp -ud %{_tmppath}/%{name}-%{version}-%{release}-XXXXXX)

BuildRequires: openssl-devel
Requires: openssl-devel

%description
Webserver server library

%package devel
Summary: Development files for libwebsockets
Group: Development/Libraries
Requires: %{name} = %{version}-%{release}
Requires: openssl-devel

%description devel
Development files for libwebsockets

%prep
%setup -q

%build
./configure --prefix=/usr --libdir=%{_libdir} --enable-openssl
make


%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT


%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root,-)
%attr(755,root,root) /usr/bin/libwebsockets-test-server
%attr(755,root,root) /usr/bin/libwebsockets-test-server-extpoll
%attr(755,root,root) /usr/bin/libwebsockets-test-client
%attr(755,root,root) /usr/bin/libwebsockets-test-ping
%attr(755,root,root) /usr/bin/libwebsockets-test-echo
%attr(755,root,root) /usr/bin/libwebsockets-test-fraggle
%attr(755,root,root) 
/%{_libdir}/libwebsockets.so.3.0.0
/%{_libdir}/libwebsockets.so.3
/%{_libdir}/libwebsockets.so
/%{_libdir}/libwebsockets.la
%attr(755,root,root) /usr/share/libwebsockets-test-server
%doc
%files devel
%defattr(-,root,root,-)
/usr/include/*
%attr(755,root,root)
/%{_libdir}/libwebsockets.a
/%{_libdir}/pkgconfig/libwebsockets.pc

%changelog

