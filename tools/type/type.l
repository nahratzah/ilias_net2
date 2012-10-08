/*
 * Copyright (c) 2012 Ariane van der Steldt <ariane@stack.nl>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
%{
#include <limits.h>
#include <stdlib.h>
#include "type_yacc.h"

int yyline = 1;
long yynumber;
int yyliteral;
%}

%%
^"%%"				{ return SECTION_BOUNDARY; }
[^\n]+				{
					if (yyleng >= 2 && yytext[0] == '%' && yytext[1] == '%') {
						REJECT;
					} else if (yyliteral) {
						return OPAQUE_LINE;
					} else {
						REJECT;
					}
				};

[ \t\r\f]			;
\n				{
					yyline++;
					if (yyliteral)
						return OPAQUE_LINE;
				};
"type"				{ return KW_TYPE; };
"struct"			{ return KW_STRUCT; };
"ctype"				{ return KW_CNAME; };
"c++type"			{ return KW_CXXNAME; };

"encode"			{ return KW_ENCODE; };
"decode"			{ return KW_DECODE; };
"init"				{ return KW_INIT; };
"destroy"			{ return KW_DESTROY; };
"argument"			{ return KW_ARGUMENT; };

"protocol"			{ return KW_PROTOCOL; };
"NULL"				{ return KW_NULL; };

[a-zA-Z_][a-zA-Z0-9_]*		{ return ID; };
(0x[0-9a-fA-F]+)|([0-9]+)	{
					yynumber = strtol(yytext, NULL, 0);
					return NUMBER;
				};
.				{ return yytext[0]; };
