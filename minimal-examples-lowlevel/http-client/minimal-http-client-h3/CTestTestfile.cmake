# CMake generated Testfile for 
# Source directory: /home/user/libwebsockets/minimal-examples-lowlevel/http-client/minimal-http-client-h3
# Build directory: /home/user/libwebsockets/minimal-examples-lowlevel/http-client/minimal-http-client-h3
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test(st_hc_h3_srv "/home/user/libwebsockets/scripts/ctest-background.sh" "hc_h3_srv" "/home/user/libwebsockets/bin/libwebsockets-test-server" "-r" "/home/user/libwebsockets/share/libwebsockets-test-server/" "-s" "--port" "19772")
set_tests_properties(st_hc_h3_srv PROPERTIES  FIXTURES_SETUP "hc_h3_srv" TIMEOUT "800" WORKING_DIRECTORY "." _BACKTRACE_TRIPLES "/home/user/libwebsockets/minimal-examples-lowlevel/http-client/minimal-http-client-h3/CMakeLists.txt;30;add_test;/home/user/libwebsockets/minimal-examples-lowlevel/http-client/minimal-http-client-h3/CMakeLists.txt;0;")
add_test(ki_hc_h3_srv "/home/user/libwebsockets/scripts/ctest-background-kill.sh" "hc_h3_srv" "libwebsockets-test-server" "--port" "19772")
set_tests_properties(ki_hc_h3_srv PROPERTIES  FIXTURES_CLEANUP "hc_h3_srv" _BACKTRACE_TRIPLES "/home/user/libwebsockets/minimal-examples-lowlevel/http-client/minimal-http-client-h3/CMakeLists.txt;36;add_test;/home/user/libwebsockets/minimal-examples-lowlevel/http-client/minimal-http-client-h3/CMakeLists.txt;0;")
add_test(minimal-http-client-h3 "/home/user/libwebsockets/bin/lws-minimal-http-client-h3" "-l" "--server" "localhost" "-p" "19772")
set_tests_properties(minimal-http-client-h3 PROPERTIES  FIXTURES_REQUIRED "hc_h3_srv" TIMEOUT "30" WORKING_DIRECTORY "/home/user/libwebsockets/minimal-examples-lowlevel/http-client/minimal-http-client-h3" _BACKTRACE_TRIPLES "/home/user/libwebsockets/minimal-examples-lowlevel/http-client/minimal-http-client-h3/CMakeLists.txt;47;add_test;/home/user/libwebsockets/minimal-examples-lowlevel/http-client/minimal-http-client-h3/CMakeLists.txt;0;")
