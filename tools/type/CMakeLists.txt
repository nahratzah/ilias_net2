cmake_minimum_required (VERSION 2.6)
project (net2type C)

include_directories ("${CMAKE_CURRENT_BINARY_DIR}")
include_directories ("${compat_BINARY_DIR}/include")

add_custom_command (OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/type_lex.c"
	COMMAND lex -o${CMAKE_CURRENT_BINARY_DIR}/type_lex.c ${PROJECT_SOURCE_DIR}/type.l
	MAIN_DEPENDENCY type.l
	COMMENT "[LEX][type.l] Building scanner with lex"
	)
add_custom_command (OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/type_yacc.c" "${CMAKE_CURRENT_BINARY_DIR}/type_yacc.h"
	COMMAND yacc -d -o${CMAKE_CURRENT_BINARY_DIR}/type_yacc.c ${PROJECT_SOURCE_DIR}/type.y
	MAIN_DEPENDENCY type.y
	DEPENDS type_lex.c
	COMMENT "[YACC][type.y] Building parser with yacc"
	)

add_executable (net2type
	${CMAKE_CURRENT_BINARY_DIR}/type_yacc.c
	${CMAKE_CURRENT_BINARY_DIR}/type_yacc.h
	${CMAKE_CURRENT_BINARY_DIR}/type_lex.c
	)
target_link_libraries (net2type l y compat)
add_dependencies (net2type lex yacc compat)
