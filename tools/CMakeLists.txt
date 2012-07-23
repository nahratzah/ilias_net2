cmake_minimum_required (VERSION 2.6)
project (tools)

include_directories ("${PROJECT_SOURCE_DIR}/lex" "${PROJECT_SOURCE_DIR}/yacc")
include_directories ("${PROJECT_SOURCE_DIR}" "${CMAKE_CURRENT_BINARY_DIR}")

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

if (NOT HAVE_GETOPT_H)
	set (compat_srcs "${PROJECT_SOURCE_DIR}/getopt.h;${PROJECT_SOURCE_DIR}/getopt_long.c")
endif (NOT HAVE_GETOPT_H)
if (NOT HAVE_ERR_H)
	set (compat_srcs "${PROJECT_SOURCE_DIR}/err.h;${PROJECT_SOURCE_DIR}/err.c")
endif (NOT HAVE_ERR_H)

configure_file (${PROJECT_SOURCE_DIR}/compat.h.in ${CMAKE_CURRENT_BINARY_DIR}/compat.h)

find_program (YACC_BIN yacc)
find_program (LEX_BIN lex)
if (NOT LEX_BIN)
	unset (LEX_BIN)
	find_program (LEX_BIN flex)
endif (NOT LEX_BIN)
if (NOT YACC_BIN)
	find_program (YACC_BIN bison)
endif (NOT YACC_BIN)

if (LEX_BIN)
	set (LEX "${LEX_BIN}" CACHE PATH "lexer")
else (LEX_BIN)
	set (LEX "lex" CACHE PATH "lexer")
	add_executable (lex
		lex/FlexLexer.h
		lex/ccl.c
		lex/config.h
		lex/dfa.c
		lex/ecs.c
		lex/flexdef.h
		lex/gen.c
		lex/main.c
		lex/misc.c
		lex/nfa.c
		lex/sym.c
		lex/tblcmp.c
		lex/version.h
		lex/yylex.c

		# generated files
		lex/scan.c
		lex/parse.c
		lex/parse.h
		lex/skel.c

		# porting compatibility
		${CMAKE_CURRENT_BINARY_DIR}/compat.h
		compat.c
		${compat_srcs}
		)
	add_library (l
		lex/libmain.c
		lex/libyywrap.c
		)
	target_link_libraries (lex bsd_compat)
endif (LEX_BIN)

if (YACC_BIN)
	set (YACC "${YACC_BIN}" CACHE PATH "yacc")
else (YACC_BIN)
	set (YACC "yacc" CACHE PATH "yacc")
	add_executable (yacc
		yacc/closure.c
		yacc/defs.h
		yacc/error.c
		yacc/lalr.c
		yacc/lr0.c
		yacc/mkpar.c
		yacc/output.c
		yacc/reader.c
		yacc/skeleton.c
		yacc/symtab.c
		yacc/verbose.c
		yacc/warshall.c

		# porting compatibility
		${CMAKE_CURRENT_BINARY_DIR}/compat.h
		compat.c
		${compat_srcs}
		)
	add_library (y
		yacc/main.c
		yacc/yyerror.c
		)
	target_link_libraries (yacc y)
	target_link_libraries (yacc bsd_compat)
	target_link_libraries (y bsd_compat)
endif (YACC_BIN)
