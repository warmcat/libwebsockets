Name:		libwebsockets
Version:	1.6.0
Release:	2%{?dist}
Summary:	A lightweight C library for Websockets

Group:		System Environment/Libraries
License:	LGPLv2 with exceptions and MIT
URL:		http://libwebsockets.org
Source0:	https://github.com/warmcat/libwebsockets/archive/v%{version}.tar.gz#/%{name}-%{version}.tar.gz

BuildRequires:	cmake
BuildRequires:	openssl-devel
Requires:	openssl
Provides:	bundled(base64-decode)

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
%setup -q

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
%doc README.md changelog
%{_libdir}/%{name}.so.*
%{_libdir}/cmake/%{name}/*

%files devel
%license LICENSE
%doc README.coding.md README.test-apps.md libwebsockets-api-doc.html
%{_bindir}/%{name}*
%{_includedir}/%{name}.h
%{_includedir}/lws_config.h
%{_libdir}/%{name}.so
%{_libdir}/pkgconfig/%{name}.pc
%{_datadir}/libwebsockets-test-server

%changelog
* Tue Jan 19 2016 Andrew Cooks <acooks@linux.com> 1.6.0-2
- Merge improvements from previously reviewed spec on RH bug #1198498
- Fetch tagged release from GH

* Sun Jan 17 2016 Andrew Cooks <acooks@linux.com> 1.6.0-1
- First attempt at a repeatable packaging process
