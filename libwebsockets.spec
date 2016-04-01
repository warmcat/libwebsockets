Name: libwebsockets
Version: 1.7.5
Release: 1%{?dist}
Summary: Websocket Server and Client Library

Group: System Environment/Libraries
License: LGPLv2 with exceptions
URL: https://libwebsockets.org
Source0: %{name}-%{version}.tar.gz
BuildRoot:	%(mktemp -ud %{_tmppath}/%{name}-%{version}-%{release}-XXXXXX)

BuildRequires: openssl-devel cmake
Requires: openssl

%description
Webserver server and client library

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

%post -p /sbin/ldconfig
%postun -p /sbin/ldconfig

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root,-)
%attr(755,root,root)
/usr/bin/libwebsockets-test-server
/usr/bin/libwebsockets-test-server-extpoll
/usr/bin/libwebsockets-test-server-pthreads
/usr/bin/libwebsockets-test-client
/usr/bin/libwebsockets-test-ping
/usr/bin/libwebsockets-test-echo
/usr/bin/libwebsockets-test-fraggle
/usr/bin/libwebsockets-test-fuzxy
/%{_libdir}/libwebsockets.so.7
/%{_libdir}/libwebsockets.so
/%{_libdir}/cmake/libwebsockets/LibwebsocketsConfig.cmake
/%{_libdir}/cmake/libwebsockets/LibwebsocketsConfigVersion.cmake
/%{_libdir}/cmake/libwebsockets/LibwebsocketsTargets.cmake
/usr/share/libwebsockets-test-server
%doc
%files devel
%defattr(-,root,root,-)
/usr/include/*
%attr(755,root,root)
/%{_libdir}/libwebsockets.a
/%{_libdir}/pkgconfig/libwebsockets.pc

%changelog

* Fri Apr 1 2016 Andy Green <andy@warmcat.com> 1.7.5-1
- MAJOR fixes Upstream 1.7.5 release (see changelog)

* Tue Mar 29 2016 Andy Green <andy@warmcat.com> 1.7.4-2
- MINOR added LibwebsocketsTargets.cmake

* Mon Mar 22 2016 Andy Green <andy@warmcat.com> 1.7.4-1
- MINOR fixes Upstream 1.7.4 release (see changelog)

* Mon Feb 29 2016 Andy Green <andy@warmcat.com> 1.7.3-1
- MAJOR fixes Upstream 1.7.3 release (see changelog)

* Thu Feb 25 2016 Andy Green <andy@warmcat.com> 1.7.2-1
- MINOR Upstream 1.7.2 release (see changelog)

* Sat Feb 20 2016 Andy Green <andy@warmcat.com> 1.7.1-1
- MINOR Upstream 1.7.1 release (see changelog)

* Tue Feb 16 2016 Andy Green <andy@warmcat.com> 1.7.0-1
- MAJOR SONAMEBUMP APICHANGES Upstream 1.7.0 release

* Sun Jan 17 2016 Andrew Cooks <acooks@linux.com> 1.6.0-1
- Bump version to 1.6.0
