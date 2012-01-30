/*	$OpenBSD: libyywrap.c,v 1.6 2003/07/28 20:38:31 deraadt Exp $	*/

/* libyywrap - flex run-time support library "yywrap" function */

/* $Header: /home/ariane/programming/cvs/ilias/tools/lex/libyywrap.c,v 1.2 2011/08/23 02:11:23 ariane Exp $ */

int yywrap(void);

int
yywrap(void)
{
	return 1;
}
