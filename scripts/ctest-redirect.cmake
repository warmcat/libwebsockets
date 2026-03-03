set(args COMMAND ${CMD} RESULT_VARIABLE res)

if (DEFINED INPUT)
    list(APPEND args INPUT_FILE ${INPUT})
endif()

if (DEFINED OUTPUT)
    list(APPEND args OUTPUT_FILE ${OUTPUT})
endif()

execute_process(${args})

if(NOT res EQUAL 0)
    message(FATAL_ERROR "Command failed with exit code: ${res}")
endif()
