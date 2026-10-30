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

#
# Test ports are leased at configure time from a counter shared by every lws
# build tree configured by the same user on the machine, so trees whose tests
# run at the same time, eg, parallel CI builds, don't share any ports.  The
# counter runs from LWS_PORT_LEASE_FIRST to LWS_PORT_LEASE_LAST and wraps.
#
set(LWS_PORT_LEASE_FIRST 15000)
set(LWS_PORT_LEASE_LAST 30000)

#
# The counter is per user: one user can't write another's file in /tmp.  A
# process started by a service manager, eg, launchd for a CI builder, may not
# have USER set, which would give it a counter of its own and leases the
# user's other trees also get.  So find the user some other way then.
#
function(_lws_port_counter_file VAR_NAME)
	if (WIN32)
		set(_dir "$ENV{TEMP}")
		set(_who "$ENV{USERNAME}")
	else()
		set(_dir "/tmp")
		set(_who "$ENV{USER}")
		if ("${_who}" STREQUAL "")
			set(_who "$ENV{LOGNAME}")
		endif()
		if ("${_who}" STREQUAL "")
			execute_process(COMMAND id -un
					OUTPUT_VARIABLE _who
					OUTPUT_STRIP_TRAILING_WHITESPACE
					ERROR_QUIET)
		endif()
	endif()

	if ("${_who}" STREQUAL "")
		set(_who "default")
	endif()

	set(${VAR_NAME} "${_dir}/lws_port_counter_${_who}" PARENT_SCOPE)
endfunction()

# four hex digits, as /proc/net shows a port, to decimal

function(_lws_hex4_to_dec HEX VAR_NAME)
	string(TOUPPER "${HEX}" _hex)
	set(_v 0)
	foreach(_i RANGE 3)
		string(SUBSTRING "${_hex}" ${_i} 1 _c)
		string(FIND "0123456789ABCDEF" "${_c}" _d)
		math(EXPR _v "${_v} * 16 + ${_d}")
	endforeach()
	set(${VAR_NAME} ${_v} PARENT_SCOPE)
endfunction()

#
# The ports in the lease range something on this machine already has a socket
# on, eg, a test server a killed CI job left running.  A lease of one of
# those would have its test die of EADDRINUSE.  It's looked at once per
# configure, before any of the configure's leases.
#
# It's only what was in use at configure time: a port taken between then and
# the test running can't be seen here.  Where the platform's tools aren't
# there to ask, the list is empty and leases are as they were.
#
function(_lws_ports_in_use VAR_NAME)
	get_property(_have GLOBAL PROPERTY LWS_PORTS_IN_USE_DONE)
	if (_have)
		get_property(_ports GLOBAL PROPERTY LWS_PORTS_IN_USE)
		set(${VAR_NAME} "${_ports}" PARENT_SCOPE)
		return()
	endif()

	set(_found)

	if (CMAKE_HOST_SYSTEM_NAME STREQUAL "Linux")
		# eg, "   0: 0100007F:7487 00000000:0000 0A ...", local first
		foreach(_f tcp tcp6 udp udp6)
			if (EXISTS "/proc/net/${_f}")
				file(STRINGS "/proc/net/${_f}" _lines
				     REGEX "^ *[0-9]+: [0-9A-Fa-f]+:[0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f] ")
				foreach(_l ${_lines})
					string(REGEX REPLACE
					       "^ *[0-9]+: [0-9A-Fa-f]+:([0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f]) .*"
					       "\\1" _hex "${_l}")
					_lws_hex4_to_dec(${_hex} _p)
					list(APPEND _found ${_p})
				endforeach()
			endif()
		endforeach()
	else()
		#
		# The BSDs and macOS show an address as "*.29854" or
		# "127.0.0.1.29854", Windows as "0.0.0.0:29854".  Every number after
		# a . or : is taken as a port: one that is something else, or a
		# peer's port, only costs a lease being skipped.
		#
		find_program(LWS_NETSTAT netstat)
		mark_as_advanced(LWS_NETSTAT)
		if (LWS_NETSTAT)
			execute_process(COMMAND ${LWS_NETSTAT} -an
					OUTPUT_VARIABLE _out
					ERROR_QUIET
					RESULT_VARIABLE _r)
			if (_r EQUAL 0)
				string(REGEX MATCHALL "[.:][0-9][0-9][0-9][0-9][0-9]"
				       _nums "${_out}")
				foreach(_n ${_nums})
					string(SUBSTRING "${_n}" 1 -1 _p)
					list(APPEND _found ${_p})
				endforeach()
			endif()
		endif()
	endif()

	set(_ports)
	foreach(_p ${_found})
		if (NOT _p LESS LWS_PORT_LEASE_FIRST AND
		    NOT _p GREATER LWS_PORT_LEASE_LAST)
			list(APPEND _ports ${_p})
		endif()
	endforeach()
	if (_ports)
		list(REMOVE_DUPLICATES _ports)
	endif()

	set_property(GLOBAL PROPERTY LWS_PORTS_IN_USE "${_ports}")
	set_property(GLOBAL PROPERTY LWS_PORTS_IN_USE_DONE 1)
	set(${VAR_NAME} "${_ports}" PARENT_SCOPE)
endfunction()

#
# lws_get_free_ports(VAR_NAME COUNT)
#
# Lease a contiguous block of COUNT adjacent ports under the counter lock,
# returning the base (lowest) port in VAR_NAME.  Use this when a single test
# process listens on several ports at once (eg, multi-stage tests that create
# a fresh vhost per stage), so the block cannot be punched full of holes by
# sibling tests grabbing individual ports between separate lws_get_free_port()
# calls in parallel CI.
#
# A block with a port in it something already has a socket on is passed over
# for the next one after that port.
#
function(lws_get_free_ports VAR_NAME COUNT)
	_lws_port_counter_file(COUNTER_FILE)
	_lws_ports_in_use(_in_use)

	file(LOCK "${COUNTER_FILE}.lock" GUARD PROCESS TIMEOUT 10)

	# not one the caller's scope has
	set(port "")
	if (EXISTS "${COUNTER_FILE}")
		file(READ "${COUNTER_FILE}" port)
		string(STRIP "${port}" port)
	endif()
	if (NOT port MATCHES "^[0-9]+$")
		set(port ${LWS_PORT_LEASE_FIRST})
	endif()

	#
	# Each pass either takes the block or moves past a port in it that is
	# in use, so it's done within one trip around the range.  If the whole
	# range somehow looks in use, take the block anyway, as before.
	#
	math(EXPR _tries "${LWS_PORT_LEASE_LAST} - ${LWS_PORT_LEASE_FIRST} + 1")
	while (1)
		math(EXPR _last "${port} + ${COUNT} - 1")
		if (port LESS LWS_PORT_LEASE_FIRST OR
		    _last GREATER LWS_PORT_LEASE_LAST)
			set(port ${LWS_PORT_LEASE_FIRST})
			math(EXPR _last "${port} + ${COUNT} - 1")
		endif()

		set(_busy)
		if (_in_use AND _tries GREATER 0)
			foreach(_p RANGE ${port} ${_last})
				list(FIND _in_use ${_p} _idx)
				if (NOT _idx EQUAL -1)
					set(_busy ${_p})
				endif()
			endforeach()
		endif()

		if (NOT _busy)
			break()
		endif()

		message(STATUS "lws_get_free_ports: port ${_busy} is in use, not leasing it")
		math(EXPR port "${_busy} + 1")
		math(EXPR _tries "${_tries} - 1")
	endwhile()

	math(EXPR next_port "${port} + ${COUNT}")
	file(WRITE "${COUNTER_FILE}" "${next_port}")

	file(LOCK "${COUNTER_FILE}.lock" RELEASE)

	set(${VAR_NAME} ${port} PARENT_SCOPE)
endfunction()

# lws_get_free_port(VAR_NAME): lease one port, as above

function(lws_get_free_port VAR_NAME)
	lws_get_free_ports(_port 1)
	set(${VAR_NAME} ${_port} PARENT_SCOPE)
endfunction()
