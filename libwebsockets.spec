%global commit0 1587c5537d4c9a70b2d7f8238464037d2b5bfe22
%global gitbranch0 v1.6-stable
%global shortcommit0 %(c=%{commit0}; echo ${c:0:7})

Name:		libwebsockets
Version:	1.6.0
Release:	3%{?dist}
Summary:	A lightweight C library for Websockets

Group:		System Environment/Libraries
# base64-decode.c and ssl-http2.c is under MIT license with FPC exception.
# https://fedorahosted.org/fpc/ticket/546
# sha-1.c is BSD 3 clause, but we link to openssl instead.
# getifaddrs is BSD 3 clause, but we use system-provided instead.
# source tarball contains BSD and zlib licensed code in win32port.
License:	LGPLv2 with exceptions and MIT and BSD and zlib
URL:		http://libwebsockets.org
Source0:	https://github.com/warmcat/%{name}/archive/%{commit0}.tar.gz#/%{name}-%{shortcommit0}.tar.gz

BuildRequires:	cmake
BuildRequires:	openssl-devel
Requires:	openssl
Provides:	bundled(base64-decode)
Provides:	bundled(ssl-http2)

%description
This is the libwebsockets C library for lightweight websocket clients and
servers.

%package devel
Summary:	Headers for developing programs that will use %{name}
Group:		Development/Libraries
Requires:	%{name}%{?_isa} = %{version}-%{release}
Requires:	openssl-devel

%description devel
This package contains the header files needed for developing
%{name} applications.

%prep
%setup -qn %{name}-%{commit0}

%build
mkdir -p build
cd build
%cmake \
    -D LWS_LINK_TESTAPPS_DYNAMIC=ON \
    -D LWS_USE_LIBEV=OFF \
    -D LWS_USE_BUNDLED_ZLIB=OFF \
    -D LWS_WITHOUT_BUILTIN_GETIFADDRS=ON \
    -D LWS_WITHOUT_BUILTIN_SHA1=ON \
    -D LWS_WITH_STATIC=OFF \
    ..
make %{?_smp_mflags}

%install
rm -rf $RPM_BUILD_ROOT
cd build
make install DESTDIR=$RPM_BUILD_ROOT

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig

%files
%license LICENSE
%doc README.md
%{_libdir}/%{name}.so.*
%{_libdir}/cmake/%{name}*

%files devel
%license LICENSE
%doc README.coding.md README.test-apps.md changelog libwebsockets-api-doc.html
%{_bindir}/%{name}*
%{_includedir}/%{name}.h
%{_includedir}/lws_config.h
%{_libdir}/%{name}.so
%{_libdir}/pkgconfig/%{name}.pc
%{_datadir}/libwebsockets-test-server

%changelog
* Wed Jan 20 2016 Andrew Cooks <acooks@linux.com> 1.6.0-3
- Get source from the 1.6-stable branch
- Bump release to pick up bug fixes.

* Tue Jan 19 2016 Andrew Cooks <acooks@linux.com> 1.6.0-2
- Merge improvements from previously reviewed spec on RH bug #1198498
- Fetch tagged release from GH

* Sun Jan 17 2016 Andrew Cooks <acooks@linux.com> 1.6.0-1
- First attempt at a repeatable packaging process
