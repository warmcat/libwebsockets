add_executable(lws-api-test-dir main.c)
target_link_libraries(lws-api-test-dir PRIVATE websockets)
set_target_properties(lws-api-test-dir PROPERTIES COMPILE_FLAGS "-I../../../lib")
