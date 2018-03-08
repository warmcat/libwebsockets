Name: libwebsockets
Version: 2.4.2
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
/usr/bin/libwebsockets-test-client
/usr/bin/libwebsockets-test-ping
/usr/bin/libwebsockets-test-echo
/usr/bin/libwebsockets-test-fraggle
/usr/bin/libwebsockets-test-fuzxy
/%{_libdir}/libwebsockets.so.12
/%{_libdir}/libwebsockets.so
/%{_libdir}/cmake/libwebsockets/LibwebsocketsConfig.cmake
/%{_libdir}/cmake/libwebsockets/LibwebsocketsConfigVersion.cmake
/%{_libdir}/cmake/libwebsockets/LibwebsocketsTargets.cmake
/%{_libdir}/cmake/libwebsockets/LibwebsocketsTargets-release.cmake

/usr/share/libwebsockets-test-server
%doc
%files devel
%defattr(-,root,root,-)
/usr/include/*
%attr(755,root,root)
/%{_libdir}/libwebsockets.a
/%{_libdir}/pkgconfig/libwebsockets.pc
/%{_libdir}/pkgconfig/libwebsockets_static.pc

%changelog
* Sun Nov 05 2017 Andy Green <andy@warmcat.com> 2.4.1-1
- MINOR Upstream 2.4.1 release

* Mon Oct 16 2017 Andy Green <andy@warmcat.com> 2.4.0-1
- MAJOR SONAMEBUMP APICHANGES Upstream 2.4.0 release

* Fri Jul 28 2017 Andy Green <andy@warmcat.com> 2.3.0-1
- MAJOR SONAMEBUMP APICHANGES Upstream 2.3.0 release

* Mon Mar 06 2017 Andy Green <andy@warmcat.com> 2.2.0-1
- MAJOR SONAMEBUMP APICHANGES Upstream 2.2.0 release

* Thu Oct 06 2016 Andy Green <andy@warmcat.com> 2.1.0-1
- MAJOR SONAMEBUMP APICHANGES Upstream 2.1.0 release

* Thu May 05 2016 Andy Green <andy@warmcat.com> 2.0.0-1
- MAJOR SONAMEBUMP APICHANGES Upstream 2.0.0 release

* Tue Feb 16 2016 Andy Green <andy@warmcat.com> 1.7.0-1
- MAJOR SONAMEBUMP APICHANGES Upstream 1.7.0 release

* Sun Jan 17 2016 Andrew Cooks <acooks@linux.com> 1.6.0-1
- Bump version to 1.6.0
