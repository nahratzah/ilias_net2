cmake_minimum_required (VERSION 2.6)
project (lex)

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
		)
	add_library (l STATIC
		lex/libmain.c
		lex/libyywrap.c
		)
	target_link_libraries (lex compat)
endif (LEX_BIN)
