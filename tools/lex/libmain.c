/*	$OpenBSD: libmain.c,v 1.6 2003/07/28 20:38:31 deraadt Exp $	*/

/* libmain - flex run-time support library "main" function */

/* $Header: /home/ariane/programming/cvs/ilias/tools/lex/libmain.c,v 1.2 2011/08/23 02:11:23 ariane Exp $ */

int yylex(void);
int main(int, char **);

/* ARGSUSED */
int
main(int argc, char *argv[])
{
	while (yylex() != 0)
		;

	return 0;
}
