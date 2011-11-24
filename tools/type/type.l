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
