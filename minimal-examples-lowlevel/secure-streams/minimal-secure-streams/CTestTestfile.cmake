# CMake generated Testfile for 
# Source directory: /home/user/libwebsockets/minimal-examples-lowlevel/secure-streams/minimal-secure-streams
# Build directory: /home/user/libwebsockets/minimal-examples-lowlevel/secure-streams/minimal-secure-streams
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test(st_ms_hbin "/home/user/libwebsockets/scripts/ctest-background.sh" "ms_hbin" "/home/user/libwebsockets/bin/lws-minimal-http-server-httpbin" "-s" "-p" "19781")
set_tests_properties(st_ms_hbin PROPERTIES  ENVIRONMENT "SAI_LIST_PORT=19781" FIXTURES_SETUP "ms_hbin" TIMEOUT "800" WORKING_DIRECTORY "/home/user/libwebsockets/minimal-examples-lowlevel/http-server/minimal-http-server-tls" _BACKTRACE_TRIPLES "/home/user/libwebsockets/minimal-examples-lowlevel/secure-streams/minimal-secure-streams/CMakeLists.txt;99;add_test;/home/user/libwebsockets/minimal-examples-lowlevel/secure-streams/minimal-secure-streams/CMakeLists.txt;0;")
add_test(ki_ms_hbin "/home/user/libwebsockets/scripts/ctest-background-kill.sh" "ms_hbin" "lws-minimal-http-server-httpbin" "-p" "19781")
set_tests_properties(ki_ms_hbin PROPERTIES  FIXTURES_CLEANUP "ms_hbin" _BACKTRACE_TRIPLES "/home/user/libwebsockets/minimal-examples-lowlevel/secure-streams/minimal-secure-streams/CMakeLists.txt;103;add_test;/home/user/libwebsockets/minimal-examples-lowlevel/secure-streams/minimal-secure-streams/CMakeLists.txt;0;")
add_test(ss-warmcat-local "/home/user/libwebsockets/bin/lws-minimal-secure-streams" "-c" "/home/user/libwebsockets/minimal-examples-lowlevel/secure-streams/minimal-secure-streams/policy-local.json")
set_tests_properties(ss-warmcat-local PROPERTIES  FIXTURES_REQUIRED "ms_hbin" TIMEOUT "40" _BACKTRACE_TRIPLES "/home/user/libwebsockets/minimal-examples-lowlevel/secure-streams/minimal-secure-streams/CMakeLists.txt;114;add_test;/home/user/libwebsockets/minimal-examples-lowlevel/secure-streams/minimal-secure-streams/CMakeLists.txt;0;")
