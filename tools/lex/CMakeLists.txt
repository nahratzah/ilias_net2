cmake_minimum_required (VERSION 2.6)
project (lex C)

find_program (LEX_BIN lex)
if (NOT LEX_BIN)
	unset (LEX_BIN)
	find_program (LEX_BIN flex)
endif (NOT LEX_BIN)
mark_as_advanced (LEX_BIN)

if (LEX_BIN)
	add_executable (lex IMPORTED)
	set_property (TARGET lex PROPERTY IMPORTED_LOCATION "${LEX_BIN}")
else (LEX_BIN)
	set (LEX "lex" CACHE PATH "lexer")
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
	add_dependancies (lex compat)
	add_dependancies (l compat)
endif (LEX_BIN)
