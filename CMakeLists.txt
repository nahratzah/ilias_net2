cmake_minimum_required (VERSION 2.6)
project (IliasNet2)
include (CTest)

list (APPEND headers
	include/ilias/net2/ilias_net2_export.h
	include/ilias/net2/acceptor.h
	include/ilias/net2/bitset.h
	include/ilias/net2/buffer.h
	include/ilias/net2/carver.h
	include/ilias/net2/conn_negotiator.h
	include/ilias/net2/connection.h
	include/ilias/net2/connstats.h
	include/ilias/net2/connwindow.h
	include/ilias/net2/udp_connection.h
	include/ilias/net2/context.h
	include/ilias/net2/context_xchange.h
	include/ilias/net2/cp.h
	include/ilias/net2/encdec_ctx.h
	include/ilias/net2/evbase.h
	include/ilias/net2/enc.h
	include/ilias/net2/hash.h
	include/ilias/net2/init.h
	include/ilias/net2/memory.h
	include/ilias/net2/mutex.h
	include/ilias/net2/obj_manager.h
	include/ilias/net2/obj_window.h
	include/ilias/net2/promise.h
	include/ilias/net2/protocol.h
	include/ilias/net2/sign.h
	include/ilias/net2/signset.h
	include/ilias/net2/sockdgram.h
	include/ilias/net2/stream_acceptor.h
	include/ilias/net2/tx_callback.h
	include/ilias/net2/xchange.h
	)
list (APPEND cluster_headers
	include/ilias/net2/cluster/cfg.h
	include/ilias/net2/cluster/cluster.h
	include/ilias/net2/cluster/socket.h
	)
list (APPEND srcs
	src/acceptor.c
	src/bitset.c
	src/buffer.c
	src/carver.c
	src/conn_negotiator.c
	src/connection.c
	src/connstats.c
	src/connwindow.c
	src/udp_connection.c
	src/context.c
	src/context_xchange.c
	src/cp.c
	src/encdec_ctx.c
	src/evbase.c
	src/enc.c
	src/hash.c
	src/init.c
	src/memory.c
	src/obj_manager.c
	src/obj_window.c
	src/promise.c
	src/protocol.c
	src/sign.c
	src/signset.c
	src/sockdgram.c
	src/stream_acceptor.c
	src/types.c
	src/tx_callback.c
	src/xchange.c
	src/cluster_cfg.c
	src/cluster_cluster.c
	src/cluster_socket.c
	)

#
# Enable BSD compatibility.
#
include (CheckFunctionExists)
include (CheckIncludeFiles)
check_function_exists (SHA256Init HAS_SHA2)
check_function_exists (arc4random HAS_ARC4RANDOM)
check_function_exists (vasprintf HAS_VASPRINTF)
check_function_exists (asprintf HAS_ASPRINTF)
check_function_exists (snprintf HAS_SNPRINTF)
check_function_exists (vsnprintf HAS_VSNPRINTF)
check_function_exists (strlcpy HAS_STRLCPY)
check_function_exists (strlcat HAS_STRLCAT)
check_include_files (sys/param.h HAVE_SYS_PARAM_H)
check_include_files (sysexits.h HAVE_SYSEXITS_H)
check_include_files (sys/time.h HAVE_SYS_TIME_H)
check_include_files (time.h HAVE_TIME_H)
check_include_files (sys/ioctl.h HAVE_SYS_IOCTL_H)
check_include_files (sys/queue.h HAVE_SYS_QUEUE_H)
check_include_files (sys/tree.h HAVE_SYS_TREE_H)
check_include_files (getopt.h HAVE_GETOPT_H)

list (APPEND headers
	include/ilias/net2/bsd_compat/error.h
	include/ilias/net2/bsd_compat/clock.h
	include/ilias/net2/bsd_compat/secure_random.h
	include/ilias/net2/bsd_compat/minmax.h
	include/ilias/net2/bsd_compat/endian.h
	)
list (APPEND srcs
	src/error.c
	src/clock.c
	)
if (NOT HAS_SHA2)
	list (APPEND headers include/ilias/net2/bsd_compat/sha2.h)
	list (APPEND srcs src/sha2.c)
endif (NOT HAS_SHA2)
if (NOT HAS_ARC4RANDOM)
	list (APPEND srcs src/secure_random.c)
endif (NOT HAS_ARC4RANDOM)
if (NOT HAVE_GETOPT_H)
	list (APPEND headers include/ilias/net2/bsd_compat/getopt.h)
	list (APPEND srcs src/getopt_long.c)
endif (NOT HAVE_GETOPT_H)
if (NOT HAVE_SYS_QUEUE_H)
	list (APPEND headers include/ilias/net2/bsd_compat/queue.h)
endif (NOT HAVE_SYS_QUEUE_H)
if (NOT HAVE_SYS_TREE_H)
	list (APPEND headers include/ilias/net2/bsd_compat/queue.h)
endif (NOT HAVE_SYS_TREE_H)

#
# Use locally defined cmake package rules.
#
# Include necessary submodules
set (CMAKE_MODULE_PATH
    "${IliasNet2_SOURCE_DIR}/CMake"
    "${IliasNet2_SOURCE_DIR}/CMake/Packages"
)


#
# Find exude allocation debugger.
#
find_library (exude_LIBS "exude" PATHS "${LOCALBASE}/lib")
if (NOT exude_LIBS-NOTFOUND)
	find_library (clog_LIBS "clog" PATHS "${LOCALBASE}/lib")
endif (NOT exude_LIBS-NOTFOUND)

option (WITH_EXUDE "Build with exude memory checker." NOT ${exude_LIBS-NOTFOUND})
if (WITH_EXUDE AND exude_LIBS-NOTFOUND)
	message (SEND_ERROR "Exude requested but not found.")
endif (WITH_EXUDE AND exude_LIBS-NOTFOUND)

if (${WITH_EXUDE})
	message (STATUS "exude build: enabled")
else (${WITH_EXUDE})
	message (STATUS "exude build: disabled")
endif (${WITH_EXUDE})

#
# Lex and yacc implementation required.
#
add_subdirectory (tools)

find_package (OpenSSL REQUIRED)
find_package (Threads)
find_package (Libevent REQUIRED)


if (CMAKE_COMPILER_IS_GNUCXX)
	set (CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -O0 -g")
	set (CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -O0 -g")
	set (CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -Wall -Wno-missing-noreturn -Wno-unused -Wsign-compare -Wuninitialized -Werror")
	set (CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -Wextra -Wall -Werror-implicit-function-declaration -Wno-missing-noreturn -Wno-unused -Werror")
endif (CMAKE_COMPILER_IS_GNUCXX)
if (WIN32)
	set (CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /Zi")
	set (CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} /Zi")
	set (CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} /DEBUG")
	set (CMAKE_SHARED_LINKER_FLAGS_DEBUG "${CMAKE_SHARED_LINKER_FLAGS} /DEBUG")
	set (CMAKE_MODULE_LINKER_FLAGS_DEBUG "${CMAKE_MODULE_LINKER_FLAGS_DEBUG} /DEBUG")
	# C++ throws exception, C never throws exceptions: /EHsc
	# Use multiple CPUs during compilation
	set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /EHsc /MP")
	# Disable incremental linking
	set (CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /LARGEADDRESSAWARE /NXCOMPAT /INCREMENTAL:NO")
	set (CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} /LARGEADDRESSAWARE /NXCOMPAT /INCREMENTAL:NO")
	set (CMAKE_MODULE_LINKER_FLAGS "${CMAKE_MODULE_LINKER_FLAGS} /LARGEADDRESSAWARE /NXCOMPAT /INCREMENTAL:NO")
endif (WIN32)


add_custom_command (OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/type_lex.c"
	COMMAND "${LEX}" -o${CMAKE_CURRENT_BINARY_DIR}/type_lex.c ${PROJECT_SOURCE_DIR}/tools/type/type.l
	MAIN_DEPENDENCY "tools/type/type.l"
	COMMENT "[LEX][type.l] Building scanner with lex"
	)
add_custom_command (OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/type_yacc.c" "${CMAKE_CURRENT_BINARY_DIR}/type_yacc.h"
	COMMAND "${YACC}" -d -o${CMAKE_CURRENT_BINARY_DIR}/type_yacc.c ${PROJECT_SOURCE_DIR}/tools/type/type.y
	MAIN_DEPENDENCY tools/type/type.y
	DEPENDS type_lex.c
	COMMENT "[YACC][type.y] Building parser with yacc"
	)


macro(net2type srclist n2tfile cfile hfile localprefix exportprefix hguard)
	get_filename_component (cfile_path "${cfile}" PATH)
	get_filename_component (hfile_path "${hfile}" PATH)
	file (MAKE_DIRECTORY "${cfile_path}" "${hfile_path}")
	unset (cfile_path)
	unset (hfile_path)
	add_custom_command (OUTPUT "${cfile}" "${hfile}"
	    COMMAND net2type "-H${hfile}" "-G${hguard}" "-o${cfile}"
	      "-L${localprefix}" "-E${exportprefix}" "${n2tfile}"
	    MAIN_DEPENDENCY "${n2tfile}"
	    DEPENDS net2type
	    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}"
	    )
	list (APPEND ${srclist} "${cfile}" "${hfile}")
endmacro(net2type)

net2type(srcs "types/ctypes.n2t"
    "${CMAKE_CURRENT_BINARY_DIR}/src/ctypes.c"
    "${CMAKE_CURRENT_BINARY_DIR}/include/ilias/net2/ctypes.h"
    "ILIAS_NET2_LOCAL"
    "ILIAS_NET2_EXPORT"
    "ILIAS_NET2_CTYPES_H")
net2type(srcs "types/packet.n2t"
    "${CMAKE_CURRENT_BINARY_DIR}/src/packet.c"
    "${CMAKE_CURRENT_BINARY_DIR}/include/ilias/net2/packet.h"
    "static"
    "ILIAS_NET2_LOCAL"
    "ILIAS_NET2_PACKET_H")
net2type(srcs "types/handshake.n2t"
    "${CMAKE_CURRENT_BINARY_DIR}/handshake.c"
    "${CMAKE_CURRENT_BINARY_DIR}/handshake.h"
    "static"
    "ILIAS_NET2_LOCAL"
    "ILIAS_NET2_HANDSHAKE_H")
net2type(srcs "types/exchange.n2t"
    "${CMAKE_CURRENT_BINARY_DIR}/exchange.c"
    "${CMAKE_CURRENT_BINARY_DIR}/exchange.h"
    "static"
    "ILIAS_NET2_LOCAL"
    "ILIAS_NET2_EXCHANGE_H")
net2type(srcs "types/carver_msg.n2t"
    "${CMAKE_CURRENT_BINARY_DIR}/carver_msg.c"
    "${CMAKE_CURRENT_BINARY_DIR}/carver_msg.h"
    "static"
    "ILIAS_NET2_LOCAL"
    "ILIAS_NET2_CARVER_MSG_H")
net2type(srcs "types/connwindow_cp.n2t"
    "${CMAKE_CURRENT_BINARY_DIR}/connwindow_cp.c"
    "${CMAKE_CURRENT_BINARY_DIR}/connwindow_cp.h"
    "static"
    "ILIAS_NET2_LOCAL"
    "ILIAS_NET2_CONNWINDOW_CP_H")
net2type(srcs "types/stream_packet.n2t"
    "${CMAKE_CURRENT_BINARY_DIR}/stream_packet.c"
    "${CMAKE_CURRENT_BINARY_DIR}/stream_packet.h"
    "static"
    "ILIAS_NET2_LOCAL"
    "ILIAS_NET2_STREAM_PACKET_H")
net2type(srcs "types/obj_manager_proto.n2t"
    "${CMAKE_CURRENT_BINARY_DIR}/obj_manager_proto.c"
    "${CMAKE_CURRENT_BINARY_DIR}/obj_manager_proto.h"
    "static"
    "ILIAS_NET2_LOCAL"
    "ILIAS_NET2_OBJ_MANAGER_PROTO_H")
net2type(srcs "types/signature.n2t"
    "${CMAKE_CURRENT_BINARY_DIR}/signature.c"
    "${CMAKE_CURRENT_BINARY_DIR}/signature.h"
    "static"
    "ILIAS_NET2_LOCAL"
    "ILIAS_NET2_SIGNATURE_H")
# Add headers generated above, that are to be published.
list (APPEND headers
	"${CMAKE_CURRENT_BINARY_DIR}/include/ilias/net2/ctypes.h"
	"${CMAKE_CURRENT_BINARY_DIR}/include/ilias/net2/packet.h"
	)


include_directories (${CMAKE_CURRENT_BINARY_DIR})
include_directories (${LIBEVENT_INCLUDE_DIRS})
include_directories ("${PROJECT_SOURCE_DIR}/include")
include_directories ("${CMAKE_CURRENT_BINARY_DIR}/include")
include_directories (${OPENSSL_INCLUDE_DIR})

add_definitions(-DQUEUE_MACRO_DEBUG)

if (Threads_FOUND AND CMAKE_USE_PTHREADS_INIT)
	list (APPEND srcs src/mutex-pthreads.c)
	list (APPEND srcs src/thread-pthreads.c)

	include (CMakePushCheckState)
	include (CheckIncludeFiles)
	include (CheckFunctionExists)
	cmake_push_check_state()
		set (CMAKE_EXTRA_INCLUDE_FILES "pthread.h")
		set (CMAKE_REQUIRED_LIBRARIES ${CMAKE_THREAD_LIBS_INIT})
		check_include_files("pthread.h;pthread_np.h" HAVE_PTHREAD_NP_H)
		check_function_exists (pthread_set_name_np HAS_PTHREAD_SET_NAME_NP)
		mark_as_advanced (HAS_PTHREAD_SET_NAME_NP)
	cmake_pop_check_state()
endif (Threads_FOUND AND CMAKE_USE_PTHREADS_INIT)
if (Threads_FOUND AND CMAKE_USE_WIN32_THREADS_INIT)
	list (APPEND srcs src/mutex-win32.c)
	list (APPEND srcs src/thread-win32.c)
endif (Threads_FOUND AND CMAKE_USE_WIN32_THREADS_INIT)

add_executable (net2type
	${CMAKE_CURRENT_BINARY_DIR}/type_yacc.c
	${CMAKE_CURRENT_BINARY_DIR}/type_yacc.h
	${CMAKE_CURRENT_BINARY_DIR}/type_lex.c
	)
target_link_libraries (net2type l y)


#
# Test if we can use sendmsg.
#
list (APPEND CMAKE_EXTRA_INCLUDE_FILES "sys/types.h")
if (WIN32)
	list (APPEND CMAKE_EXTRA_INCLUDE_FILES "winsock2.h" "ws2tcpip.h")
else (WIN32)
	list (APPEND CMAKE_EXTRA_INCLUDE_FILES "sys/socket.h")
	list (APPEND CMAKE_EXTRA_INCLUDE_FILES "netinet/in.h")
	list (APPEND CMAKE_EXTRA_INCLUDE_FILES "netinet/in6.h")
	list (APPEND CMAKE_EXTRA_INCLUDE_FILES "netdb.h")
endif (WIN32)

include (CheckFunctionExists)
if (WIN32)
	find_library (WS2_32 ws2_32)
	list (APPEND CHECK_FUNCTION_EXISTS_ADD_LIBRARIES ${WS2_32})
	list (APPEND CMAKE_EXTRA_INCLUDE_FILES "winsock2.h" "windows.h")
endif(WIN32)
check_function_exists (sendmsg HAVE_SENDMSG)

include (CheckStructHasMember)
check_struct_has_member ("struct sockaddr_in6" "sin6_len"
    "${CMAKE_EXTRA_INCLUDE_FILES}" HAVE_STRUCT_SOCKADDR_IN6_SIN6_LEN)
check_struct_has_member ("struct sockaddr_in" "sin_len"
    "${CMAKE_EXTRA_INCLUDE_FILES}" HAVE_STRUCT_SOCKADDR_IN_SIN_LEN)


configure_file (${PROJECT_SOURCE_DIR}/config.h.in ${CMAKE_CURRENT_BINARY_DIR}/include/ilias/net2/config.h)
list (APPEND headers ${CMAKE_CURRENT_BINARY_DIR}/include/ilias/net2/config.h)

add_definitions(-DBUILDING_ILIAS_NET2)
add_library (ilias_net2 SHARED
	${srcs}
	${headers}
	${cluster_headers}
	)
add_library (ilias_net2_static STATIC
	${srcs}
	${headers}
	${cluster_headers}
	)
target_link_libraries (ilias_net2 ${LIBEVENT_LIBRARIES} ${OPENSSL_LIBRARIES})
if (Threads_FOUND)
	target_link_libraries (ilias_net2 ${CMAKE_THREAD_LIBS_INIT})
endif (Threads_FOUND)
if (WIN32)
	target_link_libraries (ilias_net2 Ws2_32 Iphlpapi)
endif (WIN32)
set_property (TARGET ilias_net2 PROPERTY VERSION "0.0")
set_property (TARGET ilias_net2 PROPERTY SOVERSION "0.0")
if (NOT WIN32)
	set_property (TARGET ilias_net2_static PROPERTY OUTPUT_NAME ilias_net2)
endif (NOT WIN32)

if (${WITH_EXUDE})
	set_property (TARGET ilias_net2 PROPERTY COMPILE_DEFINITIONS_DEBUG "NET2_USE_EXUDE_DEBUG")
	set_property (TARGET ilias_net2_static PROPERTY COMPILE_DEFINITIONS_DEBUG "NET2_USE_EXUDE_DEBUG")
	target_link_libraries (ilias_net2 debug ${exude_LIBS} debug ${clog_LIBS})
endif (${WITH_EXUDE})

install (TARGETS ilias_net2 ilias_net2_static
	LIBRARY DESTINATION lib
	ARCHIVE DESTINATION lib)
install (FILES ${headers} DESTINATION include/ilias/net2)
install (FILES ${cluster_headers} DESTINATION include/ilias/net2/cluster)


if (BUILD_TESTING)
	enable_testing()

	# Buffer tests.
	add_executable (test_buffer
		test/buffer.c
		)
	target_link_libraries (test_buffer ilias_net2
	    ${LIBEVENT_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT})
	add_test(NAME test_buffer COMMAND test_buffer)

	# Carver tests.
	add_executable (test_carver
		test/carver.c
		)
	target_link_libraries (test_carver ilias_net2
	    ${LIBEVENT_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT})
	add_test(NAME test_carver COMMAND test_carver)

	# Encoding/decoding tests.
	add_executable (test_encdec_ctypes
		test/encdec_ctypes.c
		)
	target_link_libraries (test_encdec_ctypes ilias_net2
	    ${LIBEVENT_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT})
	add_test(NAME test_encdec_ctypes COMMAND test_encdec_ctypes)

	# Hash tests.
	add_executable (test_hash
		test/hash.c
		)
	target_link_libraries (test_hash ilias_net2
	    ${LIBEVENT_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT})
	add_test(NAME test_hash COMMAND test_hash)

	# Signature tests.
	add_executable (test_sign
		test/sign.c
		)
	target_link_libraries (test_sign ilias_net2
	    ${LIBEVENT_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT})
	add_test(NAME test_sign COMMAND test_sign)

	# Encryption/decryption tests.
	add_executable (test_enc
		test/enc.c
		)
	target_link_libraries (test_enc ilias_net2
	    ${LIBEVENT_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT})
	add_test(NAME test_enc COMMAND test_enc)

	# Key exchange tests.
	add_executable (test_xchange
		test/xchange.c
		)
	target_link_libraries (test_xchange ilias_net2
	    ${LIBEVENT_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT})
	add_test(NAME test_xchange COMMAND test_xchange)

	# Net2 eventbase tests.
	add_executable (test_evbase
		test/evbase.c
		)
	target_link_libraries (test_evbase ilias_net2
	    ${LIBEVENT_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT})
	add_test(NAME test_evbase COMMAND test_evbase)

	# Connection management tests.
	add_executable (test_conn
		test/conn.c
		test/testprotocol.h
		test/testprotocol.c
		test/testconn.h
		test/testconn.c
		)
	target_link_libraries (test_conn ilias_net2
	    ${LIBEVENT_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT})
	add_test(NAME test_conn COMMAND test_conn)

	# UDP connection tests.
	add_executable (test_udp_conn
		test/udp_conn.c
		test/testprotocol.h
		test/testprotocol.c
		)
	target_link_libraries (test_udp_conn ilias_net2
	    ${LIBEVENT_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT})
	add_test(NAME test_udp_conn COMMAND test_udp_conn)

	if (${WITH_EXUDE})
		target_link_libraries (test_buffer debug ${exude_LIBS} debug ${clog_LIBS})
		target_link_libraries (test_carver debug ${exude_LIBS} debug ${clog_LIBS})
		target_link_libraries (test_encdec_ctypes debug ${exude_LIBS} debug ${clog_LIBS})
		target_link_libraries (test_hash debug ${exude_LIBS} debug ${clog_LIBS})
		target_link_libraries (test_sign debug ${exude_LIBS} debug ${clog_LIBS})
		target_link_libraries (test_enc debug ${exude_LIBS} debug ${clog_LIBS})
		target_link_libraries (test_xchange debug ${exude_LIBS} debug ${clog_LIBS})
		target_link_libraries (test_evbase debug ${exude_LIBS} debug ${clog_LIBS})
		target_link_libraries (test_conn debug ${exude_LIBS} debug ${clog_LIBS})
		target_link_libraries (test_udp_conn debug ${exude_LIBS} debug ${clog_LIBS})

		set_property (TARGET test_buffer PROPERTY COMPILE_DEFINITIONS_DEBUG "NET2_USE_EXUDE_DEBUG")
		set_property (TARGET test_carver PROPERTY COMPILE_DEFINITIONS_DEBUG "NET2_USE_EXUDE_DEBUG")
		set_property (TARGET test_encdec_ctypes PROPERTY COMPILE_DEFINITIONS_DEBUG "NET2_USE_EXUDE_DEBUG")
		set_property (TARGET test_hash PROPERTY COMPILE_DEFINITIONS_DEBUG "NET2_USE_EXUDE_DEBUG")
		set_property (TARGET test_sign PROPERTY COMPILE_DEFINITIONS_DEBUG "NET2_USE_EXUDE_DEBUG")
		set_property (TARGET test_enc PROPERTY COMPILE_DEFINITIONS_DEBUG "NET2_USE_EXUDE_DEBUG")
		set_property (TARGET test_xchange PROPERTY COMPILE_DEFINITIONS_DEBUG "NET2_USE_EXUDE_DEBUG")
		set_property (TARGET test_evbase PROPERTY COMPILE_DEFINITIONS_DEBUG "NET2_USE_EXUDE_DEBUG")
		set_property (TARGET test_conn PROPERTY COMPILE_DEFINITIONS_DEBUG "NET2_USE_EXUDE_DEBUG")
		set_property (TARGET test_udp_conn PROPERTY COMPILE_DEFINITIONS_DEBUG "NET2_USE_EXUDE_DEBUG")
	endif (${WITH_EXUDE})
endif (BUILD_TESTING)
