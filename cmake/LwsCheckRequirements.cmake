# If we are being built as part of lws, eg, a plugin, or a minimal example
# with LWS_WITH_MINIMAL_EXAMPLES, confirm current build config supports
# reqconfig, else skip building ourselves.
#
# If we are being built externally, confirm installed lws was configured to
# support reqconfig, else error out with a helpful message about the problem.
#

include(CheckIncludeFile)

MACRO(require_lws_config reqconfig _val result)

	if (DEFINED ${reqconfig})
	if (${reqconfig})
		set (rq 1)
	else()
		set (rq 0)
	endif()
	else()
		set(rq 0)
	endif()

	if (${_val} EQUAL ${rq})
		set(SAME 1)
	else()
		set(SAME 0)
	endif()

	string(COMPARE EQUAL "${result}" requirements _cmp)

	if (DEFINED SAMP)
		set(_rq_name ${SAMP})
	else()
		get_filename_component(_rq_name ${CMAKE_CURRENT_SOURCE_DIR} NAME)
	endif()

	# we go in the first clause if in-tree
	if (LWS_BUILDING_IN_TREE AND NOT ${SAME})
		# just the first unmet requirement, the rest are moot
		if (_cmp AND ${result})
			if (${_val})
				message("${_rq_name}: skipping as lws being built without ${reqconfig} (${_val} / ${rq})")
			else()
				message("${_rq_name}: skipping as lws built with ${reqconfig} (${_val} / ${rq})")
			endif()
		endif()
		set(${result} 0)
		set(MET 0)
	else()
		if (LWS_BUILDING_IN_TREE)
			set(MET ${SAME})
		else()
			CHECK_C_SOURCE_COMPILES("#include <libwebsockets.h>\nint main(void) {\n#if defined(${reqconfig})\n return 0;\n#else\n fail;\n#endif\n return 0;\n}\n" HAS_${reqconfig})
			if (NOT DEFINED HAS_${reqconfig} OR NOT HAS_${reqconfig})
				set(HAS_${reqconfig} 0)
			else()
				set(HAS_${reqconfig} 1)
			endif()
			if ((HAS_${reqconfig} AND ${_val}) OR (NOT HAS_${reqconfig} AND NOT ${_val}))
				set(MET 1)
			else()
				set(MET 0)
			endif()
		endif()
		if (NOT MET AND _cmp)
			if (${_val})
				message(FATAL_ERROR "This project requires lws must have been configured with ${reqconfig}")
			else()
				message(FATAL_ERROR "Lws configuration of ${reqconfig} is incompatible with this project")
			endif()
		endif()

		# for non-requirements result vars, export whether the requirement
		# was met, so callers can gate optional features on it (eg, proxy
		# api ctests).  "requirements" keeps its earlier-failed sticky 0.

		if (NOT _cmp)
			set(${result} ${MET})
		endif()

	endif()
ENDMACRO()

MACRO(require_pthreads result)
	CHECK_INCLUDE_FILE(pthread.h LWS_HAVE_PTHREAD_H)
	if (NOT LWS_HAVE_PTHREAD_H)
		if (LWS_BUILDING_IN_TREE)
			set(${result} 0)
			message("${SAMP}: skipping as no pthreads")
		else()
			message(FATAL_ERROR "threading support requires pthreads")
		endif()
	else()
		if (WIN32)
			set(PTHREAD_LIB ${LWS_EXT_PTHREAD_LIBRARIES})
		else()
			if (NOT ${CMAKE_SYSTEM_NAME} MATCHES "QNX")
				set(PTHREAD_LIB pthread)
			endif()
		endif()
	endif()
ENDMACRO()

function(lws_get_free_port VAR_NAME)
    if (WIN32)
        set(COUNTER_FILE "$ENV{TEMP}/lws_port_counter_$ENV{USERNAME}")
    else()
        set(COUNTER_FILE "/tmp/lws_port_counter_$ENV{USER}")
    endif()

    file(LOCK "${COUNTER_FILE}.lock" GUARD PROCESS TIMEOUT 10)

    if (EXISTS "${COUNTER_FILE}")
        file(READ "${COUNTER_FILE}" port)
        string(STRIP "${port}" port)
    else()
        set(port 15000)
    endif()

    if (port GREATER 30000)
        set(port 15000)
    endif()

    math(EXPR next_port "${port} + 1")
    file(WRITE "${COUNTER_FILE}" "${next_port}")

    file(LOCK "${COUNTER_FILE}.lock" RELEASE)

    set(${VAR_NAME} ${port} PARENT_SCOPE)
endfunction()

#
# lws_get_free_ports(VAR_NAME COUNT)
#
# Like lws_get_free_port(), but reserves a contiguous block of COUNT adjacent
# ports under the same counter lock, returning the base (lowest) port in
# VAR_NAME.  Use this when a single test process listens on several ports at
# once (eg, multi-stage tests that create a fresh vhost per stage), so the
# block cannot be punched full of holes by sibling tests grabbing individual
# ports between separate lws_get_free_port() calls in parallel CI.
#
function(lws_get_free_ports VAR_NAME COUNT)
    if (WIN32)
        set(COUNTER_FILE "$ENV{TEMP}/lws_port_counter_$ENV{USERNAME}")
    else()
        set(COUNTER_FILE "/tmp/lws_port_counter_$ENV{USER}")
    endif()

    file(LOCK "${COUNTER_FILE}.lock" GUARD PROCESS TIMEOUT 10)

    if (EXISTS "${COUNTER_FILE}")
        file(READ "${COUNTER_FILE}" port)
        string(STRIP "${port}" port)
    else()
        set(port 15000)
    endif()

    if (port GREATER 30000)
        set(port 15000)
    endif()

    set(${VAR_NAME} ${port} PARENT_SCOPE)

    math(EXPR next_port "${port} + ${COUNT}")
    if (next_port GREATER 30000)
        set(next_port 15000)
    endif()
    file(WRITE "${COUNTER_FILE}" "${next_port}")

    file(LOCK "${COUNTER_FILE}.lock" RELEASE)
endfunction()
