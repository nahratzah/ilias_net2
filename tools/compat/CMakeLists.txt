cmake_minimum_required (VERSION 2.6)
project (compat)

include_directories ("${CMAKE_CURRENT_BINARY_DIR}/include" "${CMAKE_CURRENT_BINARY_DIR}")

include (CheckFunctionExists)
include (CheckIncludeFiles)
check_function_exists (vasprintf	HAS_VASPRINTF)
check_function_exists (asprintf		HAS_ASPRINTF)
check_function_exists (vsnprintf	HAS_VSNPRINTF)
check_function_exists (snprintf		HAS_SNPRINTF)
check_function_exists (strlcat		HAS_STRLCAT)
check_function_exists (strlcpy		HAS_STRLCPY)
check_include_files (getopt.h		HAVE_GETOPT_H)
check_include_files (err.h		HAVE_ERR_H)

list (APPEND compat_hdrs "${CMAKE_CURRENT_BINARY_DIR}/include/compat.h")
list (APPEND compat_srcs "compat.c")
if (NOT HAVE_GETOPT_H)
	file (COPY getopt.h DESTINATION "${CMAKE_CURRENT_BINARY_DIR}/include")
	list (APPEND compat_hdrs "${CMAKE_CURRENT_BINARY_DIR}/include/getopt.h")
	list (APPEND compat_srcs "getopt_long.c")
endif (NOT HAVE_GETOPT_H)
if (NOT HAVE_ERR_H)
	file (COPY err.h DESTINATION "${CMAKE_CURRENT_BINARY_DIR}/include")
	list (APPEND compat_hdrs "${CMAKE_CURRENT_BINARY_DIR}/include/err.h")
	list (APPEND compat_srcs "err.c")
endif (NOT HAVE_ERR_H)

configure_file (${PROJECT_SOURCE_DIR}/compat.h.in ${CMAKE_CURRENT_BINARY_DIR}/include/compat.h)

mark_as_advanced (
	HAS_VASPRINTF
	HAS_ASPRINTF
	HAS_VSNPRINTF
	HAS_SNPRINTF
	HAS_STRLCAT
	HAS_STRLCPY
	HAVE_GETOPT_H
	HAVE_ERR_H
	compat_hdrs
	compat_srcs)

add_library (compat STATIC
	${compat_srcs}
	${compat_hdrs}
	)
