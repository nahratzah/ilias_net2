cmake_minimum_required (VERSION 2.6)
project (lex C)

find_program (LEX_BIN lex)
if (NOT LEX_BIN)
	unset (LEX_BIN)
	find_program (LEX_BIN flex)
endif (NOT LEX_BIN)
find_library (LEX_LIB l)
mark_as_advanced (LEX_BIN LEX_LIB)

if (LEX_BIN AND LEX_LIB)
	add_executable (lex IMPORTED)
	add_library (l UNKNOWN IMPORTED)
	set_property (TARGET lex PROPERTY IMPORTED_LOCATION "${LEX_BIN}")
	set_property (TARGET l PROPERTY IMPORTED_LOCATION "${LEX_LIB}")
else (LEX_BIN AND LEX_LIB)
	include_directories ("${PROJECT_SOURCE_DIR}")
	include_directories ("${compat_BINARY_DIR}/include")
	add_executable (lex
		FlexLexer.h
		ccl.c
		config.h
		dfa.c
		ecs.c
		flexdef.h
		gen.c
		main.c
		misc.c
		nfa.c
		sym.c
		tblcmp.c
		version.h
		yylex.c

		# generated files
		scan.c
		parse.c
		parse.h
		skel.c
		)
	add_library (l STATIC
		libmain.c
		libyywrap.c
		)
	target_link_libraries (lex compat)
	add_dependencies (lex compat)
	add_dependencies (l compat)
endif (LEX_BIN AND LEX_LIB)
