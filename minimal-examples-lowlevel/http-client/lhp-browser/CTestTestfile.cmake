# CMake generated Testfile for 
# Source directory: /home/user/libwebsockets/minimal-examples-lowlevel/http-client/lhp-browser
# Build directory: /home/user/libwebsockets/minimal-examples-lowlevel/http-client/lhp-browser
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test(lhp-browser-window-shot "/usr/bin/cmake" "-DTOOL=/home/user/libwebsockets/bin/lws-lhp-browser" "-DHTML=/home/user/libwebsockets/minimal-examples-lowlevel/http-client/lhp-browser/test.html" "-DOUT=/home/user/libwebsockets/minimal-examples-lowlevel/http-client/lhp-browser/window-shot.bmp" "-P" "/home/user/libwebsockets/minimal-examples-lowlevel/http-client/lhp-browser/shot-test.cmake")
set_tests_properties(lhp-browser-window-shot PROPERTIES  _BACKTRACE_TRIPLES "/home/user/libwebsockets/minimal-examples-lowlevel/http-client/lhp-browser/CMakeLists.txt;62;add_test;/home/user/libwebsockets/minimal-examples-lowlevel/http-client/lhp-browser/CMakeLists.txt;0;")
subdirs("plat/unix")
