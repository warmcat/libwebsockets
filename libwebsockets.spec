Name:		libwebsockets
Version:	1.6.3
Release:	1%{?dist}
Summary:	A lightweight C library for Websockets

Group:		System Environment/Libraries
# base64-decode.c and ssl-http2.c is under MIT license with FPC exception.
# https://fedorahosted.org/fpc/ticket/546
# sha-1.c is BSD 3 clause, but we link to openssl instead.
# getifaddrs is BSD 3 clause, but we use system-provided instead.
# source tarball contains BSD and zlib licensed code in win32port.
License:	LGPLv2 with exceptions and MIT and BSD and zlib
URL:		http://libwebsockets.org
Source0:	https://github.com/warmcat/libwebsockets/archive/v%{version}.tar.gz#/%{name}-%{version}.tar.gz

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
%setup -qn %{name}-%{version}

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
* Tue Feb 9 2016 Andrew Cooks <acooks@linux.com> 1.6.3-1
- Update to version 1.6.3


* Sun Jan 17 2016 Andrew Cooks <acooks@linux.com> 1.6.0-1
- First attempt at a repeatable packaging process
