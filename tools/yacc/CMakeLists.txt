cmake_minimum_required (VERSION 2.6)
project (yacc)

find_program (YACC_BIN yacc)
if (NOT YACC_BIN)
	find_program (YACC_BIN bison)
endif (NOT YACC_BIN)
mark_as_advanced (YACC_BIN)

if (YACC_BIN)
	add_executable (yacc IMPORTED)
	set_property (TARGET yacc PROPERTY IMPORTED_LOCATION "${YACC_BIN}")
else (YACC_BIN)
	set (YACC "yacc" CACHE PATH "yacc")
	include_directories ("${PROJECT_SOURCE_DIR}")
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
		)
	add_library (y STATIC
		yacc/main.c
		yacc/yyerror.c
		)
	target_link_libraries (yacc y compat)
endif (YACC_BIN)
