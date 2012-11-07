cmake_minimum_required (VERSION 2.6)
project (IliasNet2)
include (CTest)


#
# Linux requires all kinds of feature macros to be defined.
# Whatever happened to sane defaults?
#
add_definitions (-D_REENTRANT -D_GNU_SOURCE)


#
# Set xcode to use llvm with libc++, so we can actually compile all this c++11 code.
#
if (APPLE)
	set(CMAKE_XCODE_ATTRIBUTE_GCC_VERSION "com.apple.compilers.llvm.clang.1_0")
	set(CMAKE_XCODE_ATTRIBUTE_CLANG_CXX_LANGUAGE_STANDARD "c++0x")
	set(CMAKE_XCODE_ATTRIBUTE_CLANG_CXX_LIBRARY "libc++")
endif (APPLE)


#
# Special options.
#
option (USE_EMBEDDED_EV "Use embedded libev library instead of system library." ON)
option (MEMDEBUG "Enable memory debug code." OFF)
if (MEMDEBUG)
	add_definitions (-DMEMDEBUG)
endif (MEMDEBUG)


if ("${CMAKE_C_COMPILER}" MATCHES "clang$" OR "${CMAKE_C_COMPILER_ID}" STREQUAL "Clang")
	set(CMAKE_COMPILER_IS_CLANG 1)
	unset(CMAKE_COMPILER_IS_GNUCC)
endif ("${CMAKE_C_COMPILER}" MATCHES "clang$" OR "${CMAKE_C_COMPILER_ID}" STREQUAL "Clang")
if ("${CMAKE_CXX_COMPILER}" MATCHES "clang(\\+\\+)?$" OR "${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
	set(CMAKE_COMPILER_IS_CLANGXX 1)
	unset(CMAKE_COMPILER_IS_GNUCXX)
endif ("${CMAKE_CXX_COMPILER}" MATCHES "clang(\\+\\+)?$" OR "${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")

include (CheckCCompilerFlag)
include (CheckCXXCompilerFlag)
#check_c_compiler_flag("-std=c11" STD_C11)
check_cxx_compiler_flag("-std=c++11" STD_CXX11)
check_cxx_compiler_flag("-std=c++0x" STD_CXX0X)
if (STD_C11)
	set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c11")
endif (STD_C11)
if (STD_CXX11)
	set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
elseif (STD_CXX0X)
	set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++0x")
endif ()
if (APPLE)
	check_cxx_compiler_flag("${CMAKE_CXX_FLAGS} -stdlib=libc++" STDLIB_LIBCXX)
	if (STDLIB_LIBCXX)
		set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -stdlib=libc++")
	endif ()
endif (APPLE)


# Include necessary submodules
set (CMAKE_MODULE_PATH
    "${IliasNet2_SOURCE_DIR}/CMake"
    "${IliasNet2_SOURCE_DIR}/CMake/Packages"
)

list (APPEND headers
	include/ilias/net2/ilias_net2_export.h
	include/ilias/net2/ll.h
	include/ilias/net2/acceptor.h
	include/ilias/net2/bitset.h
	include/ilias/net2/booltest.h
	include/ilias/net2/buffer.h
	include/ilias/net2/carver.h
	include/ilias/net2/signed_carver.h
	include/ilias/net2/datapipe.h
	include/ilias/net2/cneg_stage1.h
	include/ilias/net2/cneg_key_xchange.h
	include/ilias/net2/conn_negotiator.h
	include/ilias/net2/conn_keys.h
	include/ilias/net2/connection.h
	include/ilias/net2/connstats.h
	include/ilias/net2/connwindow.h
	include/ilias/net2/udp_connection.h
	include/ilias/net2/context.h
	include/ilias/net2/context_xchange.h
	include/ilias/net2/cp.h
	include/ilias/net2/encdec_ctx.h
	include/ilias/net2/enc.h
	include/ilias/net2/hash.h
	include/ilias/net2/memory.h
	include/ilias/net2/mutex.h
	include/ilias/net2/obj_manager.h
	include/ilias/net2/obj_window.h
	include/ilias/net2/poetry.h
	include/ilias/net2/promise.h
	include/ilias/net2/protocol.h
	include/ilias/net2/pool.h
	include/ilias/net2/refcnt.h
	include/ilias/net2/semaphore.h
	include/ilias/net2/sign.h
	include/ilias/net2/signset.h
	include/ilias/net2/sockdgram.h
	include/ilias/net2/spinlock.h
	include/ilias/net2/stream_acceptor.h
	include/ilias/net2/thread.h
	include/ilias/net2/tx_callback.h
	include/ilias/net2/workq.h
	include/ilias/net2/workq_timer.h
	include/ilias/net2/workq_io.h
	include/ilias/net2/xchange.h
	)
list (APPEND cluster_headers
	)
list (APPEND srcs
	# src/acceptor.c
	# src/bitset.c
	# src/carver.c
	# src/signed_carver.c
	# src/datapipe.c
	# src/cneg_stage1.c
	# src/cneg_key_xchange.c
	# src/conn_negotiator.c
	# src/conn_keys.c
	# src/connection.c
	# src/connstats.c
	# src/connwindow.c
	# src/udp_connection.c
	# src/context.c
	# src/context_xchange.c
	# src/encdec_ctx.c
	# src/enc.c
	# src/init.c
	# src/memory.c
	# src/obj_manager.c
	# src/obj_window.c
	# src/protocol.c
	# src/semaphore.c
	# src/sign.c
	# src/signset.c
	# src/sockdgram.c
	# src/stream_acceptor.c
	# src/types.c
	# src/tx_callback.c
	# src/workq.c
	# src/xchange.c
	)
list (APPEND cluster_srcs
	)

list (APPEND cxx_srcs
	cxx_src/buffer.cc
	cxx_src/bufcopy.cc
	cxx_src/cp.cc
	cxx_src/ll.cc
	cxx_src/promise.cc
	cxx_src/poetry.cc
	cxx_src/pool.cc
	cxx_src/workq.cc
	)

#
# Select platform dependant crypto.
#
if (APPLE)
	# Common Crypto framework from apple.
	list (APPEND cxx_srcs
		cxx_src/hash-apple.cc
		)
elseif (WIN32)
	# Windows Crypto framework.
	list (APPEND cxx_srcs
		cxx_src/hash-win32.cc
		)
else ()
	# Assuming you'll have openssl.
	find_package (OpenSSL REQUIRED)
	list (APPEND cxx_srcs
		cxx_src/hash-openssl.cc
		)
	include_directories (${OPENSSL_INCLUDE_DIR})
	list (APPEND EXTRA_LIBS ${OPENSSL_LIBRARIES})
endif ()

#
# Enable BSD compatibility.
#
include (CheckFunctionExists)
include (CheckIncludeFiles)
include (CheckIncludeFileCXX)
include (CheckTypeSize)
include (TestBigEndian)
include (CheckCXXSourceCompiles)
check_function_exists (arc4random HAS_ARC4RANDOM)
check_function_exists (vasprintf HAS_VASPRINTF)
check_function_exists (asprintf HAS_ASPRINTF)
check_function_exists (snprintf HAS_SNPRINTF)
check_function_exists (vsnprintf HAS_VSNPRINTF)
check_function_exists (strlcpy HAS_STRLCPY)
check_function_exists (strlcat HAS_STRLCAT)
check_function_exists (nanosleep HAS_NANOSLEEP)
check_include_files (sys/param.h HAVE_SYS_PARAM_H)
check_include_files (sysexits.h HAVE_SYSEXITS_H)
check_include_files (sys/time.h HAVE_SYS_TIME_H)
check_include_files (time.h HAVE_TIME_H)
check_include_files (sys/ioctl.h HAVE_SYS_IOCTL_H)
check_include_files (sys/queue.h HAVE_SYS_QUEUE_H)
check_include_files (sys/tree.h HAVE_SYS_TREE_H)
check_include_files (getopt.h HAVE_GETOPT_H)
check_include_files (stdatomic.h HAVE_STDATOMIC_H)
check_include_files (semaphore.h HAVE_SEMAPHORE_H)
check_include_file_cxx (type_traits HAVE_TYPE_TRAITS)

# Test if std::move exists.
file (READ "CMake/source/std_move.cc" STD_MOVE_CC)
mark_as_advanced (STD_MOVE_CC)
check_cxx_source_compiles ("${STD_MOVE_CC}" HAS_STD_MOVE)

# Test if std::move_if_noexcept exists.
file (READ "CMake/source/std_move_if_noexcept.cc" STD_MOVE_IF_NOEXCEPT_CC)
mark_as_advanced (STD_MOVE_IF_NOEXCEPT_CC)
check_cxx_source_compiles ("${STD_MOVE_IF_NOEXCEPT_CC}" HAS_STD_MOVE_IF_NOEXCEPT)

# Test if constructor traits (is_nothrow_destructable, is_nothrow_copy_constructable, is_nothrow_move_constructable) exist.
file (READ "CMake/source/std_constructor_traits.cc" STD_CONSTRUCTOR_TRAITS_CC)
mark_as_advanced (STD_CONSTRUCTOR_TRAITS_CC)
check_cxx_source_compiles ("${STD_CONSTRUCTOR_TRAITS_CC}" HAS_CONSTRUCTOR_TRAITS)

# Test if hardware is big endian.
test_big_endian (IS_BIG_ENDIAN)

#list (APPEND headers
#	include/ilias/net2/bsd_compat/error.h
#	include/ilias/net2/bsd_compat/clock.h
#	include/ilias/net2/bsd_compat/secure_random.h
#	include/ilias/net2/bsd_compat/minmax.h
#	include/ilias/net2/bsd_compat/endian.h
#	include/ilias/net2/bsd_compat/atomic.h
#	include/ilias/net2/bsd_compat/win32_atomic.h
#	include/ilias/net2/bsd_compat/spl_atomic.h
#	)
#list (APPEND srcs
#	src/error.c
#	src/clock.c
#	src/spl_atomic.c
#	)
#if (NOT HAS_ARC4RANDOM)
#	list (APPEND srcs src/secure_random.c)
#endif (NOT HAS_ARC4RANDOM)
#if (NOT HAVE_GETOPT_H)
#	list (APPEND headers include/ilias/net2/bsd_compat/getopt.h)
#	list (APPEND srcs src/getopt_long.c)
#endif (NOT HAVE_GETOPT_H)
#if (NOT HAVE_SYS_QUEUE_H)
#	list (APPEND headers include/ilias/net2/bsd_compat/queue.h)
#endif (NOT HAVE_SYS_QUEUE_H)
#if (NOT HAVE_SYS_TREE_H)
#	list (APPEND headers include/ilias/net2/bsd_compat/queue.h)
#endif (NOT HAVE_SYS_TREE_H)

#
# Workq-io and workq-timer code is different for windows.
#
if (WIN32)
	list (APPEND srcs
	    # src/workq_io-win32.c
	    # src/workq_timer-win32.c
	    )
else (WIN32)
	list (APPEND srcs
	    # src/workq_io-ev.c
	    # src/workq_timer-ev.c
	    )
endif (WIN32)

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

find_package (Threads)
if (NOT USE_EMBEDDED_EV)
	find_package (Ev REQUIRED)
endif (NOT USE_EMBEDDED_EV)


if (CMAKE_COMPILER_IS_GNUCC OR CMAKE_COMPILER_IS_CLANG)
	set (CMAKE_CXX_FLAGS_RELWITHDEBINFO "${CMAKE_CXX_FLAGS_RELWITHDEBINFO} -O3")
	set (CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O3")
	set (CMAKE_C_FLAGS_RELWITHDEBINFO "${CMAKE_C_FLAGS_RELWITHDEBINFO} -O3")
	set (CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -O3")

	set (CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -O0 -g -fno-omit-frame-pointer")
	set (CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -O0 -g -fno-omit-frame-pointer")
	set (CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -Wall -Wno-missing-noreturn -Wno-unused -Wsign-compare -Wuninitialized -Wno-unused-value")
	set (CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -Wextra -Wall -Werror-implicit-function-declaration -Wno-missing-noreturn -Wno-unused-value -Wno-unused-label")
	if (NOT USE_EMBEDDED_EV)
		set (CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -Werror")
		set (CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -Werror")
	endif (NOT USE_EMBEDDED_EV)
endif (CMAKE_COMPILER_IS_GNUCC OR CMAKE_COMPILER_IS_CLANG)
if (CMAKE_COMPILER_IS_CLANG)
	set (CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -Wno-tautological-compare")
	set (CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -Wno-tautological-compare")
endif (CMAKE_COMPILER_IS_CLANG)
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

# net2type(srcs "types/packet.n2t"
#     "${CMAKE_CURRENT_BINARY_DIR}/packet.c"
#     "${CMAKE_CURRENT_BINARY_DIR}/packet.h"
#     "static"
#     "ILIAS_NET2_LOCAL"
#     "ILIAS_NET2_PACKET_H")
# net2type(srcs "types/handshake.n2t"
#     "${CMAKE_CURRENT_BINARY_DIR}/handshake.c"
#     "${CMAKE_CURRENT_BINARY_DIR}/handshake.h"
#     "static"
#     "ILIAS_NET2_LOCAL"
#     "ILIAS_NET2_HANDSHAKE_H")
# net2type(srcs "types/exchange.n2t"
#     "${CMAKE_CURRENT_BINARY_DIR}/exchange.c"
#     "${CMAKE_CURRENT_BINARY_DIR}/exchange.h"
#     "static"
#     "ILIAS_NET2_LOCAL"
#     "ILIAS_NET2_EXCHANGE_H")
# net2type(srcs "types/carver_msg.n2t"
#     "${CMAKE_CURRENT_BINARY_DIR}/carver_msg.c"
#     "${CMAKE_CURRENT_BINARY_DIR}/carver_msg.h"
#     "static"
#     "ILIAS_NET2_LOCAL"
#     "ILIAS_NET2_CARVER_MSG_H")
# net2type(srcs "types/signed_carver_header.n2t"
#     "${CMAKE_CURRENT_BINARY_DIR}/signed_carver_header.c"
#     "${CMAKE_CURRENT_BINARY_DIR}/signed_carver_header.h"
#     "static"
#     "ILIAS_NET2_LOCAL"
#     "ILIAS_NET2_SIGNED_CARVER_HEADER_H")
# net2type(srcs "types/connwindow_cp.n2t"
#     "${CMAKE_CURRENT_BINARY_DIR}/connwindow_cp.c"
#     "${CMAKE_CURRENT_BINARY_DIR}/connwindow_cp.h"
#     "static"
#     "ILIAS_NET2_LOCAL"
#     "ILIAS_NET2_CONNWINDOW_CP_H")
# net2type(srcs "types/stream_packet.n2t"
#     "${CMAKE_CURRENT_BINARY_DIR}/stream_packet.c"
#     "${CMAKE_CURRENT_BINARY_DIR}/stream_packet.h"
#     "static"
#     "ILIAS_NET2_LOCAL"
#     "ILIAS_NET2_STREAM_PACKET_H")
# net2type(srcs "types/signature.n2t"
#     "${CMAKE_CURRENT_BINARY_DIR}/signature.c"
#     "${CMAKE_CURRENT_BINARY_DIR}/signature.h"
#     "static"
#     "ILIAS_NET2_LOCAL"
#     "ILIAS_NET2_SIGNATURE_H")


if (USE_EMBEDDED_EV)
	include_directories (${PROJECT_SOURCE_DIR}/contrib/libev-4.11)
	add_definitions (-DEV_C=\"ev.c\")
	list (APPEND EV_LIBRARIES)
	list (APPEND EV_INCLUDE_DIR)
	add_definitions (-DEV_STANDALONE -DEV_API_STATIC -DEV_MULTIPLICITY)
else (USE_EMBEDDED_EV)
	include_directories (${EV_INCLUDE_DIR})
endif (USE_EMBEDDED_EV)


include_directories (${CMAKE_CURRENT_BINARY_DIR})
include_directories ("${PROJECT_SOURCE_DIR}/include")
include_directories ("${CMAKE_CURRENT_BINARY_DIR}/include")

add_definitions(-DQUEUE_MACRO_DEBUG)

#if (Threads_FOUND AND CMAKE_USE_PTHREADS_INIT)
#	list (APPEND srcs src/mutex-pthreads.c)
#	list (APPEND srcs src/thread-pthreads.c)
#	list (APPEND srcs src/event-pthreads.c)
#
#	add_definitions(-pthread)
#	include (CheckIncludeFiles)
#	include (CheckFunctionExists)
#	set (CMAKE_EXTRA_INCLUDE_FILES "pthread.h")
#	set (CMAKE_REQUIRED_LIBRARIES ${CMAKE_THREAD_LIBS_INIT})
#	check_include_files("pthread.h;pthread_np.h" HAVE_PTHREAD_NP_H)
#	check_function_exists (pthread_set_name_np HAS_PTHREAD_SET_NAME_NP)
#	check_type_size (pthread_spinlock_t PTHREAD_SPINLOCK)
#	mark_as_advanced (HAS_PTHREAD_SET_NAME_NP)
#endif (Threads_FOUND AND CMAKE_USE_PTHREADS_INIT)
#if (Threads_FOUND AND CMAKE_USE_WIN32_THREADS_INIT)
#	list (APPEND srcs src/mutex-win32.c)
#	list (APPEND srcs src/thread-win32.c)
#	list (APPEND srcs src/event-win32.c)
#endif (Threads_FOUND AND CMAKE_USE_WIN32_THREADS_INIT)


list (APPEND EXTRA_LIBS)
find_library (RT_LIB rt)
if (RT_LIB)
	# Linux needs this for clock_gettime.
	list (APPEND EXTRA_LIBS ${RT_LIB})
endif (RT_LIB)


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
	list (APPEND CHECK_FUNCTION_EXISTS_ADD_LIBRARIES ws2_32 advapi32)
	list (APPEND CMAKE_EXTRA_INCLUDE_FILES "winsock2.h" "windows.h")
endif(WIN32)
check_function_exists (sendmsg HAVE_SENDMSG)

include (CheckStructHasMember)
check_struct_has_member ("struct sockaddr_in6" "sin6_len"
    "${CMAKE_EXTRA_INCLUDE_FILES}" HAVE_STRUCT_SOCKADDR_IN6_SIN6_LEN)
check_struct_has_member ("struct sockaddr_in" "sin_len"
    "${CMAKE_EXTRA_INCLUDE_FILES}" HAVE_STRUCT_SOCKADDR_IN_SIN_LEN)


#
# Configure libev.
#
if (USE_EMBEDDED_EV)
	check_include_files (poll.h HAVE_POLL_H)
	check_include_files (port.h HAVE_PORT_H)
	check_include_files ("sys/types.h;sys/epoll.h" HAVE_SYS_EPOLL_H)
	check_include_files ("sys/types.h;sys/event.h" HAVE_SYS_EVENT_H)
	check_include_files ("sys/types.h;sys/inotify.h" HAVE_SYS_INOTIFY_H)
	check_include_files ("sys/types.h;sys/select.h" HAVE_SYS_SELECT_H)
	check_include_files ("sys/types.h;sys/signalfd.h" HAVE_SYS_SIGNALFD_H)
	check_function_exists (clock_gettime HAVE_CLOCK_GETTIME)
	# XXX HAVE_CLOCK_SYSCALL
	check_function_exists (epoll_ctl HAVE_EPOLL_CTL)
	check_function_exists (eventfd HAVE_EVENTFD)
	# HAVE_FLOOR
	check_function_exists (inotify_init HAVE_INOTIFY_INIT)
	check_function_exists (kqueue HAVE_KQUEUE)
	check_function_exists (nanosleep HAVE_NANOSLEEP)
	check_function_exists (poll HAVE_POLL)
	check_function_exists (port_create HAVE_PORT_CREATE)
	check_function_exists (select HAVE_SELECT)
	check_function_exists (signalfd HAVE_SIGNALFD)

	# Wrap our configuration around ev.h, so libev will configure well.
	add_definitions (-DEV_H=\"config_ev.h\")
endif (USE_EMBEDDED_EV)


configure_file (${PROJECT_SOURCE_DIR}/config.h.in ${CMAKE_CURRENT_BINARY_DIR}/include/ilias/net2/config.h)
configure_file (${PROJECT_SOURCE_DIR}/config_ev.h.in ${CMAKE_CURRENT_BINARY_DIR}/config_ev.h)
list (APPEND headers
	${CMAKE_CURRENT_BINARY_DIR}/include/ilias/net2/config.h
	${CMAKE_CURRENT_BINARY_DIR}/config_ev.h
	)

add_definitions(-DBUILDING_ILIAS_NET2)
add_library (ilias_net2 SHARED
	${srcs}
	${cluster_srcs}
	${headers}
	${cluster_headers}
	${cxx_srcs}
	)
target_link_libraries (ilias_net2 ${EV_LIBRARIES} ${EXTRA_LIBS})
if (Threads_FOUND)
	target_link_libraries (ilias_net2 ${CMAKE_THREAD_LIBS_INIT})
endif (Threads_FOUND)
if (WIN32)
	target_link_libraries (ilias_net2 ws2_32 advapi32 Iphlpapi)
endif (WIN32)
set_property (TARGET ilias_net2 PROPERTY VERSION "0.0")
set_property (TARGET ilias_net2 PROPERTY SOVERSION "0.0")

if (${WITH_EXUDE})
	set_property (TARGET ilias_net2 PROPERTY COMPILE_DEFINITIONS_DEBUG "NET2_USE_EXUDE_DEBUG")
	target_link_libraries (ilias_net2 debug ${exude_LIBS} debug ${clog_LIBS})
endif (${WITH_EXUDE})

install (TARGETS ilias_net2
	LIBRARY DESTINATION lib
	ARCHIVE DESTINATION lib)
install (FILES ${headers} DESTINATION include/ilias/net2)
install (FILES ${cluster_headers} DESTINATION include/ilias/net2/cluster)


if (BUILD_TESTING)
	string (REPLACE ";" "\\;" TESTS_PATH "${TESTS_PATH}")
	enable_testing()

	# Buffer tests.
	add_executable (test_buffer
		test/buffer.cc
		)
	target_link_libraries (test_buffer ilias_net2
	    ${EV_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT})
	add_test(NAME test_buffer COMMAND test_buffer)
	set_tests_properties (test_buffer PROPERTIES ENVIRONMENT "PATH=${TESTS_PATH}")

	# Carver tests.
	add_executable (test_carver
		test/carver.c
		)
	target_link_libraries (test_carver ilias_net2
	    ${EV_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT})
	add_test(NAME test_carver COMMAND test_carver)
	set_tests_properties (test_carver PROPERTIES ENVIRONMENT "PATH=${TESTS_PATH}")

	# Encoding/decoding tests.
	add_executable (test_encdec_ctypes
		test/encdec_ctypes.c
		)
	target_link_libraries (test_encdec_ctypes ilias_net2
	    ${EV_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT})
	add_test(NAME test_encdec_ctypes COMMAND test_encdec_ctypes)
	set_tests_properties (test_encdec_ctypes PROPERTIES ENVIRONMENT "PATH=${TESTS_PATH}")

	# Hash tests.
	add_executable (test_hash
		test/hash.c
		)
	target_link_libraries (test_hash ilias_net2
	    ${EV_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT})
	add_test(NAME test_hash COMMAND test_hash)
	set_tests_properties (test_hash PROPERTIES ENVIRONMENT "PATH=${TESTS_PATH}")

	# Signature tests.
	add_executable (test_sign
		test/sign.c
		)
	target_link_libraries (test_sign ilias_net2
	    ${EV_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT})
	add_test(NAME test_sign COMMAND test_sign)
	set_tests_properties (test_sign PROPERTIES ENVIRONMENT "PATH=${TESTS_PATH}")

	# Encryption/decryption tests.
	add_executable (test_enc
		test/enc.c
		)
	target_link_libraries (test_enc ilias_net2
	    ${EV_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT})
	add_test(NAME test_enc COMMAND test_enc)
	set_tests_properties (test_enc PROPERTIES ENVIRONMENT "PATH=${TESTS_PATH}")

	# Key exchange tests.
	add_executable (test_xchange
		test/xchange.c
		)
	target_link_libraries (test_xchange ilias_net2
	    ${EV_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT})
	add_test(NAME test_xchange COMMAND test_xchange)
	set_tests_properties (test_xchange PROPERTIES ENVIRONMENT "PATH=${TESTS_PATH}")

	# Workq tests.
	add_executable (test_workq
		test/workq.c
		)
	target_link_libraries (test_workq ilias_net2
	    ${EV_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT})
	add_test(NAME test_workq COMMAND test_workq)
	set_tests_properties (test_workq PROPERTIES ENVIRONMENT "PATH=${TESTS_PATH}")

	# Connection management tests.
	add_executable (test_conn
		test/conn.c
		test/testprotocol.h
		test/testprotocol.c
		test/testconn.h
		test/testconn.c
		)
	target_link_libraries (test_conn ilias_net2
	    ${EV_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT})
	add_test(NAME test_conn COMMAND test_conn)
	set_tests_properties (test_conn PROPERTIES ENVIRONMENT "PATH=${TESTS_PATH}")

	# UDP connection tests.
	add_executable (test_udp_conn
		test/udp_conn.c
		test/testprotocol.h
		test/testprotocol.c
		)
	target_link_libraries (test_udp_conn ilias_net2
	    ${EV_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT})
	add_test(NAME test_udp_conn COMMAND test_udp_conn)
	set_tests_properties (test_udp_conn PROPERTIES ENVIRONMENT "PATH=${TESTS_PATH}")

	if (${WITH_EXUDE})
		target_link_libraries (test_buffer debug ${exude_LIBS} debug ${clog_LIBS})
		target_link_libraries (test_carver debug ${exude_LIBS} debug ${clog_LIBS})
		target_link_libraries (test_encdec_ctypes debug ${exude_LIBS} debug ${clog_LIBS})
		target_link_libraries (test_hash debug ${exude_LIBS} debug ${clog_LIBS})
		target_link_libraries (test_sign debug ${exude_LIBS} debug ${clog_LIBS})
		target_link_libraries (test_enc debug ${exude_LIBS} debug ${clog_LIBS})
		target_link_libraries (test_xchange debug ${exude_LIBS} debug ${clog_LIBS})
		target_link_libraries (test_conn debug ${exude_LIBS} debug ${clog_LIBS})
		target_link_libraries (test_udp_conn debug ${exude_LIBS} debug ${clog_LIBS})

		set_property (TARGET test_buffer PROPERTY COMPILE_DEFINITIONS_DEBUG "NET2_USE_EXUDE_DEBUG")
		set_property (TARGET test_carver PROPERTY COMPILE_DEFINITIONS_DEBUG "NET2_USE_EXUDE_DEBUG")
		set_property (TARGET test_encdec_ctypes PROPERTY COMPILE_DEFINITIONS_DEBUG "NET2_USE_EXUDE_DEBUG")
		set_property (TARGET test_hash PROPERTY COMPILE_DEFINITIONS_DEBUG "NET2_USE_EXUDE_DEBUG")
		set_property (TARGET test_sign PROPERTY COMPILE_DEFINITIONS_DEBUG "NET2_USE_EXUDE_DEBUG")
		set_property (TARGET test_enc PROPERTY COMPILE_DEFINITIONS_DEBUG "NET2_USE_EXUDE_DEBUG")
		set_property (TARGET test_xchange PROPERTY COMPILE_DEFINITIONS_DEBUG "NET2_USE_EXUDE_DEBUG")
		set_property (TARGET test_conn PROPERTY COMPILE_DEFINITIONS_DEBUG "NET2_USE_EXUDE_DEBUG")
		set_property (TARGET test_udp_conn PROPERTY COMPILE_DEFINITIONS_DEBUG "NET2_USE_EXUDE_DEBUG")
	endif (${WITH_EXUDE})
endif (BUILD_TESTING)
