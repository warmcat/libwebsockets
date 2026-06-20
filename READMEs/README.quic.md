# Overiew of quic / h3 considerations

## Quic is the UDP-based transport underlying h3

`LWS_WITH_HTTP3` is enabled by default in lws, whenever that's enabled it auto-enabled `LWS_WITH_QUIC`.  So you can just think of it as QUIC / HTTP3 / UDP / WebTransport or not.

## There are many situations in the world, client h3 is blocked and has to fall back to h2

Unless you control the client network environment, you can bet on quic/h3 UDP :443 being blocked eg, by corporate firewalls.  It means for general use, you can only choose to combine h3 **in addition** to h1 / h2 as a fallback.

## That's unfortunate because h3 is much cheaper on memory

"TCP TLS" as used on h1 / h2 requires about 40KB per tcp connection.  quic tls is much cheaper, a few KB + ~4KB for qpack / h3 dynamic headers.

## h3 does not have to be provided on h2 addresses or ports

There are two ways that clients can hear about h3... first is a DNS record called "HTTP3" which if it exists, points to the addresses and ports you should be able to connect to it on.  Note these addresses don't have to be the main domain or :443.  Second, if you defaulted or fell back to h2, then the h2 server can serve a header called "alt-svc" which may, again, tell you where to go to get h3 service.

## lws has sophisticated parallel try and fallback mechanisms

Lws has combined support for "happy eyeballs" client connection optimization.  I

## Only some TLS libraries support Quic compatibly with lws

 - TLS libraries compatible with h3 + lws: Gnutls, Boringssl, Libressl, AWS-LC, WolfSSL, schannel
 - On Windows, the default is now schannel, the built-in tls library.
 - OpenSSL is not compatible with lws quic/h3.  This was the default for lws, it still is for LWS_WITH_HTTP3=0
 - With LWS_WITH_HTTP3=1 on non-windows, then the new default is gnutls.  This is very mature and supported everywhere.
 - Mbedtls is not compatible with quic/h3 as of 2026-06.  However, we provide a small OOT patch on mbedtls that makes it compatible (https://libwebsockets.org/git/mbedtls/log?h=development ).  lws detects if the patch is applied and enables quic/h3 build with mbedtls.

# libwebsockets QUIC and TLS Backends

clone, build, and link each supported TLS backend for use with lws QUIC, specifically targeting the `lws-minimal-quic-client-server` tests.

## General Considerations

When building static libraries for your TLS backend, you **must** build them with Position Independent Code (`-fPIC`) if you intend to link them into the `libwebsockets.so` shared library. If you forget to do this, your linker will throw (eg, for x86_64) an `R_X86_64_32 against .rodata can not be used when making a shared object` error.

Alternatively, if you only want to build the static `libwebsockets.a` and its executable tests, you can append `-DLWS_WITH_SHARED=OFF` to your lws `cmake` command.

---

## 1. BoringSSL

BoringSSL provides a robust QUIC API that lws fully integrates with.

*   **Source:** `git clone https://boringssl.googlesource.com/boringssl`
*   **Building BoringSSL:**
    ```bash
    cd boringssl && mkdir build && cd build
    cmake .. -DCMAKE_POSITION_INDEPENDENT_CODE=ON
    make -j
    ```
*   **Building lws:**
    BoringSSL doesn't export standard CMake packages, so you must explicitly specify the library paths.
    ```bash
    cmake .. \
        -DLWS_WITH_BORINGSSL=ON \
        -DOPENSSL_INCLUDE_DIRS="/path/to/boringssl/include" \
        -DOPENSSL_LIBRARIES="/path/to/boringssl/build/libssl.a;/path/to/boringssl/build/libcrypto.a" \
        -DLWS_ROLE_QUIC=ON
    make -j
    ```

## 2. AWS-LC

AWS-LC is a fork of BoringSSL with identical QUIC capabilities but different build targets.

*   **Source:** `git clone https://github.com/aws/aws-lc.git`
*   **Building AWS-LC:**
    ```bash
    cd aws-lc && mkdir build && cd build
    cmake .. -DCMAKE_POSITION_INDEPENDENT_CODE=ON -DBUILD_SHARED_LIBS=OFF
    make -j
    ```
*   **Building lws:**
    ```bash
    cmake .. \
        -DLWS_WITH_AWSLC=ON \
        -DOPENSSL_INCLUDE_DIRS="/path/to/aws-lc/include" \
        -DOPENSSL_LIBRARIES="/path/to/aws-lc/build/ssl/libssl.a;/path/to/aws-lc/build/crypto/libcrypto.a" \
        -DLWS_ROLE_QUIC=ON
    make -j
    ```

## 3. OpenSSL

OpenSSL 3.2 and later provides native QUIC support.

*   **Source:** `git clone https://github.com/openssl/openssl.git`
*   **Building OpenSSL:**
    ```bash
    cd openssl
    ./config -fPIC no-shared
    make -j
    ```
*   **Building lws:**
    ```bash
    cmake .. \
        -DLWS_WITH_SSL=ON \
        -DOPENSSL_ROOT_DIR="/path/to/openssl" \
        -DLWS_ROLE_QUIC=ON
    make -j
    ```

## 4. wolfSSL

wolfSSL supports QUIC, but it must be explicitly enabled during configuration.

*   **Source:** `git clone https://github.com/wolfSSL/wolfssl.git`
*   **Building wolfSSL:**
    ```bash
    cd wolfssl
    ./autogen.sh
    ./configure --enable-libwebsockets --enable-quic --enable-session-ticket --enable-earlydata --enable-all CFLAGS="-fPIC"
    make -j
    ```
*   **Building lws:**
    ```bash
    cmake .. \
        -DLWS_WITH_WOLFSSL=ON \
        -DWOLFSSL_INCLUDE_DIRS="/path/to/wolfssl" \
        -DWOLFSSL_LIBRARIES="/path/to/wolfssl/src/.libs/libwolfssl.a" \
        -DLWS_ROLE_QUIC=ON
    make -j
    ```

## 5. mbedTLS

mbedTLS version 3.x + an OOT patch is required for QUIC support in lws.
mbedTLS itself doesn't support quic (at least until 4.1.0) and needs some
extra apis grafting in (+434 LOC and another 300 docs and selftests).

Mbedtls with the patch rebased on top is available here:
https://libwebsockets.org/git/mbedtls/log?h=development

If the mbedts lib lws was built against was suitably patched, the lws_context
config string will append the mbedtls version with +LWSQUIC.

*   **Source:** `git clone https://github.com/Mbed-TLS/mbedtls.git`
*   **Building mbedTLS:**
    ```bash
    cd mbedtls
    cmake . -DCMAKE_POSITION_INDEPENDENT_CODE=ON
    make -j
    ```
*   **Building lws:**
    ```bash
    cmake .. \
        -DLWS_WITH_MBEDTLS=ON \
        -DMBEDTLS_INCLUDE_DIRS="/path/to/mbedtls/include" \
        -DMBEDTLS_LIBRARIES="/path/to/mbedtls/library/libmbedcrypto.a;/path/to/mbedtls/library/libmbedx509.a;/path/to/mbedtls/library/libmbedtls.a" \
        -DLWS_ROLE_QUIC=ON
    make -j
    ```

## 6. GnuTLS

GnuTLS supports QUIC natively in modern versions. It can typically be installed via your system's package manager, saving you the trouble of building it from source.

*   **Ubuntu/Debian:** `sudo apt install libgnutls28-dev`
*   **Building lws (with system GnuTLS):**
    ```bash
    cmake .. \
        -DLWS_WITH_GNUTLS=ON \
        -DLWS_ROLE_QUIC=ON
    make -j
    ```

### Building GnuTLS from source

If you want to build GnuTLS from scratch (for example, to get the absolute latest QUIC fixes without conflicting with your system's `libgnutls`), you can compile it locally and point lws to the build directory.

*   **Source:** `git clone https://gitlab.com/gnutls/gnutls.git`
*   **Building GnuTLS:**
    GnuTLS requires `nettle` and `gmp` installed on your system (e.g., `sudo apt install nettle-dev libgmp-dev`).
    In addition running bootstrap requires a lot of dependencies installed:
      gnulib-devel gtk-doc bison gettext gperf
    You can't go on with the build until bootstrap says it's happy with "./bootstrap: done.  Now you can run './configure'."
    ```bash
    cd gnutls
    ./bootstrap
    autoconf
    ./configure --with-included-libtasn1 --with-included-unistring --without-p11-kit --disable-doc
    make -j
    ```
*   **Building lws:**
    You can point lws directly to your uninstalled GnuTLS build directory using the `LWS_GNUTLS_` CMake variables.
    ```bash
    cmake .. \
        -DLWS_WITH_GNUTLS=ON \
        -DLWS_GNUTLS_INCLUDE_DIRS="/path/to/gnutls/lib/includes" \
        -DLWS_GNUTLS_LIBRARIES="/path/to/gnutls/lib/.libs/libgnutls.so" \
        -DLWS_ROLE_QUIC=ON
    make -j
    ```

    *Alternatively, you can use `pkg-config` by pointing it to the uninstalled GnuTLS `.pc` file:*
    ```bash
    PKG_CONFIG_PATH="/path/to/gnutls/lib" cmake .. \
        -DLWS_WITH_GNUTLS=ON \
        -DLWS_ROLE_QUIC=ON
    make -j
    ```

## 7. LibreSSL

LibreSSL provides standard OpenSSL API compatibility for QUIC.

*   **Source:** `git clone https://github.com/libressl/libressl.git`
*   **Building LibreSSL:**
    ```bash
    cd libressl
    cmake . -DCMAKE_POSITION_INDEPENDENT_CODE=ON
    make -j
    ```
*   **Building lws:**
    ```bash
    cmake .. \
        -DLWS_WITH_LIBRESSL=ON \
        -DOPENSSL_ROOT_DIR="/path/to/libressl" \
        -DLWS_ROLE_QUIC=ON
    make -j
    ```

## 8. SChannel (Windows)

SChannel is native to Windows, so no third-party TLS library compilation is required. SChannel uses Windows MSQuic APIs under the hood.

*   **Building lws (from a Visual Studio Command Prompt):**
    ```cmd
    cmake .. -DLWS_WITH_SCHANNEL=ON -DLWS_ROLE_QUIC=ON
    cmake --build . --config Release
    ```

---

## Testing QUIC and HTTP/3 Compliance

lws uses `h3spec` to validate its QUIC and HTTP/3 implementation against the RFCs. The `ctest` infrastructure automatically discovers and runs the `h3spec` test suite against the `lws-minimal-quic-client-server` test application if the `h3spec` executable is found in your system's `PATH`.

### Enabling `h3spec` tests in CI or locally

To enable `h3spec` testing, simply download the pre-compiled static binary for your platform from the [h3spec GitHub releases](https://github.com/kazu-yamamoto/h3spec/releases) and place it somewhere in your `PATH` (e.g., `/usr/local/bin`).

**Example for Linux x86_64:**
```bash
wget https://github.com/kazu-yamamoto/h3spec/releases/download/v0.1.13/h3spec-linux-x86_64
chmod +x h3spec-linux-x86_64
sudo cp h3spec-linux-x86_64 /usr/local/bin/h3spec
```

Once installed, re-run `cmake` on your lws build directory so it can discover the `h3spec` executable. Then, simply run `ctest` (or `make test`) as usual. The `h3spec` test will spawn a temporary test server in the background, run the compliance suite, and tear down the server automatically.

---

## Congestion Control

Libwebsockets features a pluggable QUIC Congestion Control architecture. By default, it uses a New Reno algorithm, but we also provide an implementation of CUBIC.

### Selecting a Congestion Control Algorithm

You can select the congestion control algorithm used for the context by configuring `quic_cc_ops` in `struct lws_context_creation_info`. We export two built-in implementations natively in `lws-quic.h`:

- `lws_cc_ops_newreno`
- `lws_cc_ops_cubic`

Example of selecting CUBIC:
```c
struct lws_context_creation_info info;
memset(&info, 0, sizeof(info));
/* ... other config ... */
info.quic_cc_ops = &lws_cc_ops_cubic;

struct lws_context *context = lws_create_context(&info);
```

### Writing Your Own Congestion Control Algorithm

If you need a specialized algorithm (like BBR), you can easily plug it in by implementing the `struct lws_cc_ops` interface defined in `lws-quic.h`:

```c
struct lws_cc_ops {
	void (*init)(struct lws *nwsi);
	void (*on_sent)(struct lws *nwsi, size_t bytes);
	void (*on_ack)(struct lws *nwsi, size_t bytes_acked, lws_usec_t rtt);
	void (*on_loss)(struct lws *nwsi, size_t bytes_lost);
	int  (*can_send)(struct lws *nwsi, size_t bytes);
	lws_usec_t (*get_pacing_delay)(struct lws *nwsi, size_t bytes_to_send);
};
```

1. **State Management**: Inside `init()`, allocate your custom state structure and assign it to `nwsi->quic.qn->cc_state`. 
2. **Implement Hooks**: Fill out the remaining hooks to track `bytes_in_flight`, adjust `cwnd`, manage `ssthresh`, and handle loss/ack events.
3. **Pacing**: `get_pacing_delay()` should return `0` if it's safe to send immediately, or the number of microseconds to delay the send.
4. **Use It**: Assign a pointer to your custom `lws_cc_ops` struct to `info.quic_cc_ops` during context creation.
