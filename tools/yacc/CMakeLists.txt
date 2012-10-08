cmake_minimum_required (VERSION 2.6)
project (yacc C)

find_program (YACC_BIN yacc)
if (NOT YACC_BIN)
	find_program (YACC_BIN bison)
endif (NOT YACC_BIN)
find_library (YACC_LIB y)
mark_as_advanced (YACC_BIN)

if (YACC_BIN AND YACC_LIB)
	add_executable (yacc IMPORTED)
	add_library (y UNKNOWN IMPORTED)
	set_property (TARGET yacc PROPERTY IMPORTED_LOCATION "${YACC_BIN}")
	set_property (TARGET y PROPERTY IMPORTED_LOCATION "${YACC_LIB}")
else (YACC_BIN AND YACC_LIB)
	include_directories ("${PROJECT_SOURCE_DIR}")
	include_directories ("${compat_BINARY_DIR}/include")
	add_executable (yacc
		closure.c
		defs.h
		error.c
		lalr.c
		lr0.c
		mkpar.c
		output.c
		reader.c
		skeleton.c
		symtab.c
		verbose.c
		warshall.c
		)
	add_library (y STATIC
		main.c
		yyerror.c
		)
	target_link_libraries (yacc y compat)
	add_dependencies (yacc compat)
	add_dependencies (y compat)
endif (YACC_BIN AND YACC_LIB)
