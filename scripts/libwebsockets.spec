Name: libwebsockets
Version: 3.2.0
Release: 1%{?dist}
Summary: Websocket Server and Client Library

Group: System Environment/Libraries
License: MIT
URL: https://libwebsockets.org
Source0: %{name}-%{version}.tar.gz
BuildRoot: %(mktemp -ud %{_tmppath}/%{name}-%{version}-%{release}-XXXXXX)

BuildRequires: openssl-devel libuv-devel libev-devel cmake
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
%cmake .. -DLWS_WITH_DISTRO_RECOMMENDED=1
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
"/usr/bin/libwebsockets-test-client"
"/usr/bin/libwebsockets-test-lejp"
"/usr/bin/libwebsockets-test-server"
"/usr/bin/libwebsockets-test-server-extpoll"
"/usr/bin/libwebsockets-test-sshd"
"/usr/bin/lwsws"
"/%{_libdir}/libwebsockets.so"
"/%{_libdir}/libwebsockets.so.15"
%dir "/usr/share/libwebsockets-test-server"
"/usr/share/libwebsockets-test-server/candide.zip"
"/usr/share/libwebsockets-test-server/favicon.ico"
%dir "/usr/share/libwebsockets-test-server/generic-table"
"/usr/share/libwebsockets-test-server/generic-table/index.html"
"/usr/share/libwebsockets-test-server/generic-table/lwsgt.js"
"/usr/share/libwebsockets-test-server/http2.png"
"/usr/share/libwebsockets-test-server/leaf.jpg"
"/usr/share/libwebsockets-test-server/libwebsockets-test-server.key.pem"
"/usr/share/libwebsockets-test-server/libwebsockets-test-server.pem"
"/usr/share/libwebsockets-test-server/libwebsockets.org-logo.svg"
"/usr/share/libwebsockets-test-server/lws-cgi-test.sh"
"/usr/share/libwebsockets-test-server/lws-common.js"
"/usr/share/libwebsockets-test-server/lws-ssh-test-keys"
"/usr/share/libwebsockets-test-server/lws-ssh-test-keys.pub"
%dir "/usr/share/libwebsockets-test-server/plugins"
"/usr/share/libwebsockets-test-server/plugins/libprotocol_client_loopback_test.so"
"/usr/share/libwebsockets-test-server/plugins/libprotocol_dumb_increment.so"
"/usr/share/libwebsockets-test-server/plugins/libprotocol_fulltext_demo.so"
"/usr/share/libwebsockets-test-server/plugins/libprotocol_lws_acme_client.so"
"/usr/share/libwebsockets-test-server/plugins/libprotocol_lws_mirror.so"
"/usr/share/libwebsockets-test-server/plugins/libprotocol_lws_raw_test.so"
"/usr/share/libwebsockets-test-server/plugins/libprotocol_lws_server_status.so"
"/usr/share/libwebsockets-test-server/plugins/libprotocol_lws_ssh_base.so"
"/usr/share/libwebsockets-test-server/plugins/libprotocol_lws_sshd_demo.so"
"/usr/share/libwebsockets-test-server/plugins/libprotocol_lws_status.so"
"/usr/share/libwebsockets-test-server/plugins/libprotocol_lws_table_dirlisting.so"
"/usr/share/libwebsockets-test-server/plugins/libprotocol_post_demo.so"
%dir "/usr/share/libwebsockets-test-server/private"
"/usr/share/libwebsockets-test-server/private/index.html"
%dir "/usr/share/libwebsockets-test-server/server-status"
"/usr/share/libwebsockets-test-server/server-status/lwsws-logo.png"
"/usr/share/libwebsockets-test-server/server-status/server-status.css"
"/usr/share/libwebsockets-test-server/server-status/server-status.html"
"/usr/share/libwebsockets-test-server/server-status/server-status.js"
"/usr/share/libwebsockets-test-server/test.css"
"/usr/share/libwebsockets-test-server/test.html"
"/usr/share/libwebsockets-test-server/test.js"
"/usr/share/libwebsockets-test-server/wss-over-h2.png"
%files devel
%defattr(-,root,root,-)
%dir "/usr/include/libwebsockets"
"/usr/include/libwebsockets.h"
"/usr/include/libwebsockets/lws-adopt.h"
"/usr/include/libwebsockets/lws-callbacks.h"
"/usr/include/libwebsockets/lws-cgi.h"
"/usr/include/libwebsockets/lws-client.h"
"/usr/include/libwebsockets/lws-context-vhost.h"
"/usr/include/libwebsockets/lws-dbus.h"
"/usr/include/libwebsockets/lws-diskcache.h"
"/usr/include/libwebsockets/lws-esp32.h"
"/usr/include/libwebsockets/lws-fts.h"
"/usr/include/libwebsockets/lws-genhash.h"
"/usr/include/libwebsockets/lws-genrsa.h"
"/usr/include/libwebsockets/lws-http.h"
"/usr/include/libwebsockets/lws-jose.h"
"/usr/include/libwebsockets/lws-jwk.h"
"/usr/include/libwebsockets/lws-jws.h"
"/usr/include/libwebsockets/lws-lejp.h"
"/usr/include/libwebsockets/lws-logs.h"
"/usr/include/libwebsockets/lws-lwsac.h"
"/usr/include/libwebsockets/lws-misc.h"
"/usr/include/libwebsockets/lws-network-helper.h"
"/usr/include/libwebsockets/lws-plugin-generic-sessions.h"
"/usr/include/libwebsockets/lws-protocols-plugins.h"
"/usr/include/libwebsockets/lws-purify.h"
"/usr/include/libwebsockets/lws-ring.h"
"/usr/include/libwebsockets/lws-service.h"
"/usr/include/libwebsockets/lws-sha1-base64.h"
"/usr/include/libwebsockets/lws-spa.h"
"/usr/include/libwebsockets/lws-stats.h"
"/usr/include/libwebsockets/lws-threadpool.h"
"/usr/include/libwebsockets/lws-timeout-timer.h"
"/usr/include/libwebsockets/lws-tokenize.h"
"/usr/include/libwebsockets/lws-vfs.h"
"/usr/include/libwebsockets/lws-write.h"
"/usr/include/libwebsockets/lws-writeable.h"
"/usr/include/libwebsockets/lws-ws-close.h"
"/usr/include/libwebsockets/lws-ws-ext.h"
"/usr/include/libwebsockets/lws-ws-state.h"
"/usr/include/libwebsockets/lws-x509.h"
"/usr/include/lws-plugin-ssh.h"
"/usr/include/lws_config.h"
%dir "/usr/lib/pkgconfig"
"/%{_libdir}/pkgconfig/libwebsockets.pc"
"/usr/lib/pkgconfig/libwebsockets_static.pc"
%dir "/usr/lib/cmake"
%dir "/usr/lib/cmake/libwebsockets"
"/%{_libdir}/cmake/libwebsockets/LibwebsocketsConfig.cmake"
"/%{_libdir}/cmake/libwebsockets/LibwebsocketsConfigVersion.cmake"
"/%{_libdir}/cmake/libwebsockets/LibwebsocketsTargets-debug.cmake"
"/%{_libdir}/cmake/libwebsockets/LibwebsocketsTargets.cmake"

%changelog
* Fri Aug 14 2019 Andy Green <andy@warmcat.com> 3.2.0-1
- MAJOR SONAMEBUMP APICHANGES Upstream 3.2.0 release (last LGPLv2.1+SLE)

* Fri Nov 23 2018 Andy Green <andy@warmcat.com> 3.1.0-1
- MAJOR SONAMEBUMP APICHANGES Upstream 3.1.0 release

* Fri May 4 2018 Andy Green <andy@warmcat.com> 3.0.0-1
- MAJOR SONAMEBUMP APICHANGES Upstream 3.0.0 release

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
