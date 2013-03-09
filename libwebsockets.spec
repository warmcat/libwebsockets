Name: libwebsockets
Version: 1.3
Release: 47.gmaster_b89f21c%{?dist}
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
mkdir -p build
cd build
%cmake ..
make

%install
rm -rf $RPM_BUILD_ROOT
cd build
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
/%{_libdir}/libwebsockets.so.4.0.0
/%{_libdir}/libwebsockets.so
%attr(755,root,root) /usr/share/libwebsockets-test-server
%doc
%files devel
%defattr(-,root,root,-)
/usr/include/*
%attr(755,root,root)
/%{_libdir}/libwebsockets.a
/%{_libdir}/pkgconfig/libwebsockets.pc

%changelog

