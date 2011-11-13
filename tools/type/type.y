%token <y_empty> KW_CNAME KW_CXXNAME KW_TYPE KW_STRUCT
%token <y_empty> KW_ENCODE KW_DECODE KW_INIT KW_DESTROY
%token <y_empty> KW_NULL NUMBER KW_PROTOCOL KW_ARGUMENT
%token <y_empty> ID
%token <y_empty> OPAQUE_LINE SECTION_BOUNDARY
%start program

%{
#include <bsd_compat.h>

#ifdef HAVE_SYS_QUEUE_H
#include <sys/queue.h>
#else /* HAVE_SYS_QUEUE_H */
#include <bsd_compat/queue.h>
#endif /* HAVE_SYS_QUEUE_H */

#ifdef HAVE_GETOPT_H
#include <getopt.h>
#else /* HAVE_GETOPT_H */
#include <bsd_compat/getopt.h>
#endif /* HAVE_GETOPT_H */

#include <stdint.h>
#include <stdio.h>
#ifndef WIN32
#include <unistd.h>
#endif /* WIN32 */
#include <fcntl.h>
#include <errno.h>
#include <bsd_compat/error.h>
#include <bsd_compat/sysexits.h>
#include <bsd_compat/printf.h>
#include <assert.h>

#ifdef WIN32
#include <io.h>
#endif

extern int	 yyline;
extern char	*yytext;
extern long	 yynumber;
extern int	 yyliteral;
extern char	*yyfilename;

extern int	 yyparse(void);
extern int	 yylex(void);
%}

%type <y_definitions>	definitions program
%type <y_type>		d_type
%type <y_struct>	d_struct
%type <y_string>	identifier
%type <y_bool>		opt_struct
%type <y_tsline>	d_ts_stmt d_ss_stmt
%type <y_type_spec>	d_ts_list d_typespecs
%type <y_struct_spec>	d_ss_list d_structspecs
%type <y_smembers>	d_smemberlist d_smembers
%type <y_structmember>	d_smember
%type <y_string>	opaque opaque_line opt_post_opaque
%type <y_number>	opt_number opt_end_number number pointer opt_pointer
%type <y_string>	opt_argument
%type <y_smopt>		sm_opt_default sm_default
%type <y_smoptspec>	d_smember_opts

%union {
	struct s_definitions	*y_definitions;
	struct np_type		*y_type;
	struct np_struct	*y_struct;
	struct np_structmember	*y_structmember;
	struct np_type_spec	*y_type_spec;
	struct np_struct_spec	*y_struct_spec;
	char			*y_string;
	int			 y_bool;
	long			 y_number;

	struct y_tsline_t {
		/* A kind of typespec. */
		enum np_ts_kind {
			NPTS_CTYPE,
			NPTS_CSTRUCT,
			NPTS_ENCODE,
			NPTS_DECODE,
			NPTS_INIT,
			NPTS_DESTROY,
			NPTS_NOINIT,
			NPTS_NODESTROY,
			NPTS_ARG,
			NPTS_ARGSTRUCT,
		}		 kind;
		char		*text;
		int		 ptr;
	}			 y_tsline;

	struct y_smopt_t {
		enum np_sm_kind {
			SMDFL_NONE,
			SMDFL_NULL,
			SMDFL_NUMBER,
			SMDFL_FUNCTION,
			SMDFL_VALUE,
		}		 kind;
		long		 number;
		char		*function;
		char		*value;
	}			 y_smopt;

	struct y_smoptspec_t {
		long		 firstprot;
		long		 lastprot;
		struct y_smopt_t dfl;
	}			 y_smoptspec;

	struct np_structmemberq	*y_smembers;

	struct { char dummy; }	 y_empty; /* For rules without result. */
}

%{
struct s_definitions;
struct np_type;
struct np_struct;
struct np_structmember;
struct np_type_spec;
struct np_struct_spec;

TAILQ_HEAD(s_typeq, np_type);
TAILQ_HEAD(s_structq, np_struct);
TAILQ_HEAD(np_structmemberq, np_structmember);

/* Full definition of types. */
struct s_definitions {
	char			*sd_header;
	char			*sd_pre;
	char			*sd_post;
	struct s_typeq		 sd_types;
	struct s_structq	 sd_structs;
};

/* Type specification. */
struct np_type_spec {
	char			*cname;		/* C name. */
	char			*encode;	/* Encoding function. */
	char			*decode;	/* Decoding function. */
	char			*init;		/* Initialization function. */
	char			*destroy;	/* Destructor. */
	int			 is_struct;	/* C type is a struct. */
	int			 is_ptr;	/* C type is a pointer. */
	char			*argtype;	/* Argument type. */
};

/* Describes a builtin or opaque handled type. */
struct np_type {
	TAILQ_ENTRY(np_type)	 npt_q;		/* Link to definitions. */

	char			*npt_name;	/* Name of this type. */
	struct np_type_spec	 npt_spec;
	int			 npt_line;	/* Line number of defn. */
};

/* Struct specification. */
struct np_struct_spec {
	char			*cname;		/* C name. */
	char			*init;		/* Initialization function. */
	char			*destroy;	/* Destructor. */
	int			 is_struct;	/* C type is a struct. */
	int			 is_ptr;	/* C type is a pointer. */
	int			 no_init;	/* No init needed. */
	int			 no_destroy;	/* No destroy needed. */
	char			*argtype;	/* Argument type. */
};

/* Describes a struct. */
struct np_struct {
	TAILQ_ENTRY(np_struct)	 nps_q;		/* Link to definitions. */

	char			*nps_name;	/* Name of this type. */
	struct np_struct_spec	 nps_spec;	/* Struct specification. */

	struct np_structmemberq	 nps_members;	/* Members to encode/decode. */
	int			 nps_line;	/* Line number of defn. */
};

/* Describes a member of a struct. */
struct np_structmember {
	TAILQ_ENTRY(np_structmember)
				 npsm_q;	/* Link to struct. */

	char			*npsm_name;	/* Member name. */
	char			*npsm_type;	/* Member type. */
	int			 npsm_is_ptr;	/* Will need dereferencing. */
	int			 npsm_firstprot;/* Appeared in protocol. */
	int			 npsm_lastprot;	/* Went away in protocol. */
	struct y_smopt_t	 npsm_dfl;	/* Default value. */
	char			*npsm_arg;	/* Cp_arg argument. */
};


extern int ts_apply(struct np_type_spec*, struct y_tsline_t*);
extern int ss_apply(struct np_struct_spec*, struct y_tsline_t*);
extern int ss_present(struct np_structmemberq*, const char*);

extern struct s_definitions	*definitions;

/* Move all items from src to dst. */
void
smq_move(struct np_structmemberq *dst, struct np_structmemberq *src)
{
	struct np_structmember *m;

	while ((m = TAILQ_FIRST(src)) != NULL) {
		TAILQ_REMOVE(src, m, npsm_q);
		TAILQ_INSERT_TAIL(dst, m, npsm_q);
	}
}


%}

%%


program		:	{ yyliteral = 1; }
		  opaque SECTION_BOUNDARY
		  opaque SECTION_BOUNDARY
			{ yyliteral = 0; }
		  definitions
			{ yyliteral = 1; }
		  opt_post_opaque
			{
				$$ = $7;
				$$->sd_header = $2;
				$$->sd_pre = $4;
				$$->sd_post = $9;
			}
opt_post_opaque	: /* empty */
			{
				$$ = NULL;
			}
		| SECTION_BOUNDARY opaque
			{
				$$ = $2;
			}
		;
opaque		: /* empty */
			{
				if (asprintf(&$$, "#line %d \"%s\"\n",
				    yyline, yyfilename) == -1)
					err(EX_OSERR, "asprintf");
			}
		| opaque opaque_line
			{
				if ($1 == NULL) {
					$$ = $2;
				} else {
					if (asprintf(&$$, "%s%s", $1, $2) ==
					    -1)
						err(EX_OSERR, "asprintf");
					free($1);
					free($2);
				}
			}
		;
opaque_line	: OPAQUE_LINE
			{
				$$ = strdup(yytext);
			}
		;

definitions	: /* empty */
			{
				definitions = $$ = malloc(sizeof(*$$));
				if ($$ == NULL)
					err(EX_OSERR, "malloc");
				TAILQ_INIT(&$$->sd_types);
				TAILQ_INIT(&$$->sd_structs);
			}
		| definitions d_type
			{
				TAILQ_INSERT_TAIL(&$1->sd_types, $2, npt_q);
				$$ = $1;
			}
		| definitions d_struct
			{
				TAILQ_INSERT_TAIL(&$1->sd_structs, $2, nps_q);
				$$ = $1;
			}
		| definitions error ';'
			{
				$$ = $1;
			}
		;

identifier	: ID
			{
				$$ = strdup(yytext);
				if ($$ == NULL)
					err(EX_OSERR, "strdup");
			}
		;
number		: NUMBER
			{
				$$ = yynumber;
			}
		;

opt_struct	: /* empty */
			{	$$ = 0; }
		| KW_STRUCT
			{	$$ = 1; }
		;

pointer		: '*'
			{	$$ = 1; }
		| pointer '*'
			{	$$ = $1 + 1; }
		;
opt_pointer	: /* empty */
			{	$$ = 0; }
		| pointer
			{	$$ = $1; }
		;

d_type		: KW_TYPE identifier d_typespecs ';'
			{
				$$ = malloc(sizeof(*$$));
				if ($$ == NULL)
					err(EX_OSERR, "malloc");
				memset($$, 0, sizeof(*$$));
				$$->npt_name = $2;
				$$->npt_spec = *$3;
				free($3);
				$$->npt_line = yyline;
			}
		;

d_struct	: KW_STRUCT identifier d_structspecs d_smembers ';'
			{
				$$ = malloc(sizeof(*$$));
				if ($$ == NULL)
					err(EX_OSERR, "malloc");
				memset($$, 0, sizeof(*$$));
				$$->nps_name = $2;
				$$->nps_spec = *$3;
				free($3);
				$$->nps_line = yyline;
				TAILQ_INIT(&$$->nps_members);
				smq_move(&$$->nps_members, $4);
				free($4);
			}
		;

d_typespecs	: '(' d_ts_list ')'
			{
				if ($2->cname == NULL) {
					warnx("%d: missing C type", yyline);
					YYERROR;
				}
				if ($2->encode == NULL) {
					warnx("%s: missing encoder", yyline);
					YYERROR;
				}
				if ($2->decode == NULL) {
					warnx("%s: missing decoder", yyline);
					YYERROR;
				}
				$$ = $2;
			}
		;
d_structspecs	: '(' d_ss_list ')'
			{
				$$ = $2;
				if ($2->cname == NULL) {
					warnx("%s: missing C type", yyline);
					YYERROR;
				}
			}
		;

d_ts_list	: d_ts_stmt
			{
				$$ = malloc(sizeof(*$$));
				if ($$ == NULL)
					err(EX_OSERR, "malloc");
				memset($$, 0, sizeof(*$$));

				if (ts_apply($$, &$1))
					YYERROR;
			}
		| d_ts_list ',' d_ts_stmt
			{
				if (ts_apply($1, &$3))
					YYERROR;
				$$ = $1;
			}
		;
d_ts_stmt	: KW_CNAME opt_struct identifier opt_pointer
			{
				$$.kind = ( $2 ? NPTS_CSTRUCT : NPTS_CTYPE );
				$$.text = $3;
				$$.ptr = $4;
			}
		| KW_ENCODE identifier
			{
				$$.kind = NPTS_ENCODE;
				$$.text = $2;
			}
		| KW_DECODE identifier
			{
				$$.kind = NPTS_DECODE;
				$$.text = $2;
			}
		| KW_INIT identifier
			{
				$$.kind = NPTS_INIT;
				$$.text = $2;
			}
		| KW_DESTROY identifier
			{
				$$.kind = NPTS_DESTROY;
				$$.text = $2;
			}
		| KW_ARGUMENT opt_struct identifier
			{
				$$.kind = ($2 ? NPTS_ARGSTRUCT : NPTS_ARG);
				$$.text = $3;
				$$.ptr = 0;
			}
		;

d_ss_list	: d_ss_stmt
			{
				$$ = malloc(sizeof(*$$));
				if ($$ == NULL)
					err(EX_OSERR, "malloc");
				memset($$, 0, sizeof(*$$));

				if (ss_apply($$, &$1))
					YYERROR;
			}
		| d_ss_list ',' d_ss_stmt
			{
				if (ss_apply($1, &$3))
					YYERROR;
				$$ = $1;
			}
		;
d_ss_stmt	: KW_CNAME opt_struct identifier opt_pointer
			{
				$$.kind = ( $2 ? NPTS_CSTRUCT : NPTS_CTYPE );
				$$.text = $3;
				$$.ptr = $4;
			}
		| KW_INIT identifier
			{
				$$.kind = NPTS_INIT;
				$$.text = $2;
			}
		| KW_INIT KW_NULL
			{
				$$.kind = NPTS_NOINIT;
			}
		| KW_DESTROY identifier
			{
				$$.kind = NPTS_DESTROY;
				$$.text = $2;
			}
		| KW_DESTROY KW_NULL
			{
				$$.kind = NPTS_NODESTROY;
			}
		| KW_ARGUMENT opt_struct identifier
			{
				$$.kind = ($2 ? NPTS_ARGSTRUCT : NPTS_ARG);
				$$.text = $3;
				$$.ptr = 0;
			}
		;

d_smembers	: '{' d_smemberlist '}'
			{
				$$ = $2;
			}
		;
d_smemberlist	: /* empty */
			{
				$$ = malloc(sizeof(*$$));
				if ($$ == NULL)
					err(EX_OSERR, "malloc");
				TAILQ_INIT($$);
			}
		| d_smemberlist d_smember
			{
				$$ = $1;

				if (ss_present($$, $2->npsm_name)) {
					warnx("%d: duplicate member %s",
					    yyline, $2->npsm_name);
					YYERROR;
				}
				TAILQ_INSERT_TAIL($$, $2, npsm_q);
			}
		;
d_smember	: identifier opt_pointer opt_argument identifier d_smember_opts ';'
			{
				$$ = malloc(sizeof(*$$));
				$$->npsm_name = $4;
				$$->npsm_type = $1;
				$$->npsm_is_ptr = $2;
				$$->npsm_firstprot = $5.firstprot;
				$$->npsm_lastprot = $5.lastprot;
				$$->npsm_dfl = $5.dfl;
				$$->npsm_arg = $3;
			}
		;
d_smember_opts	: /* empty */
			{
				memset(&$$, 0, sizeof($$));
				$$.dfl.kind = SMDFL_NONE;
			}
		| KW_PROTOCOL opt_number opt_end_number sm_opt_default
			{
				if ($3 < $2 && $3 != 0) {
					warnx("%d: protocol range invalid",
					    yyline);
					YYERROR;
				}

				$$.firstprot = $2;
				$$.lastprot = $3;
				$$.dfl = $4;
			}
		;
opt_argument	: /* empty */
			{
				$$ = NULL;
			}
		| '(' identifier ')'
			{
				$$ = $2;
			}
		;
opt_number	: /* empty */
			{
				$$ = 0;
			}
		| number
			{
				$$ = $1;
			}
		;
opt_end_number	: /* empty */
			{
				$$ = 0;
			}
		| '-' number
			{
				$$ = $2;
			}
		;
sm_opt_default	: /* empty */
			{
				$$.kind = SMDFL_NONE;
			}
		| '=' sm_default
			{
				$$ = $2;
			}
		;
sm_default	: KW_NULL
			{
				$$.kind = SMDFL_NULL;
			}
		| number
			{
				$$.kind = SMDFL_NUMBER;
				$$.number = $1;
			}
		| identifier '(' ')'
			{
				$$.kind = SMDFL_FUNCTION;
				$$.function = $1;
			}
		| identifier
			{
				$$.kind = SMDFL_VALUE;
				$$.value = $1;
			}
		;


%%

struct s_definitions		*definitions;
char				*yyfilename;

char*
make_pointer(int count, char *prefix)
{
	char			*result;

	if (count == 0)
		return "";

	if ((result = malloc(strlen(prefix) + count + 1)) == NULL)
		err(EX_OSERR, "malloc");
	strcpy(result, prefix);
	memset(result + strlen(prefix), '*', count);
	*(result + strlen(prefix) + count) = '\0';
	return result;
}


int
ss_present(struct np_structmemberq *queue, const char *name)
{
	struct np_structmember *m;

	TAILQ_FOREACH(m, queue, npsm_q) {
		if (strcmp(m->npsm_name, name) == 0)
			return 1;
	}
	return 0;
}

int
ts_apply(struct np_type_spec *spec, struct y_tsline_t *line)
{
	switch (line->kind) {
	case NPTS_CSTRUCT:
		spec->is_struct = 1;
		/* FALLTHROUGH */
	case NPTS_CTYPE:
		if (spec->cname != NULL) {
			warnx("%d: C name already defined", yyline);
			return -1;
		}
		spec->cname = line->text;
		spec->is_ptr = line->ptr;
		break;
	case NPTS_ENCODE:
		if (spec->encode != NULL) {
			warnx("%d: encoding function already defined", yyline);
			return -1;
		}
		spec->encode = line->text;
		break;
	case NPTS_DECODE:
		if (spec->decode != NULL) {
			warnx("%d: decoding function already defined", yyline);
			return -1;
		}
		spec->decode = line->text;
		break;
	case NPTS_INIT:
		if (spec->init != NULL) {
			warnx("%d: initialization function already defined",
			    yyline);
			return -1;
		}
		spec->init = line->text;
		break;
	case NPTS_DESTROY:
		if (spec->destroy != NULL) {
			warnx("%d: destruction function already defined",
			    yyline);
			return -1;
		}
		spec->destroy = line->text;
		break;
	case NPTS_NOINIT:
		if (spec->init != NULL) {
			warnx("%d: initialization function already defined",
			    yyline);
		} else
			warnx("%d: incorrect initialization token", yyline);
		return -1;
		break;
	case NPTS_NODESTROY:
		if (spec->destroy != NULL) {
			warnx("%d: destruction function already defined",
			    yyline);
		} else
			warnx("%d: incorrect destruction token", yyline);
		return -1;
	case NPTS_ARG:
		if (spec->argtype != NULL) {
			warnx("%d: argument type already defined",
			    yyline);
			return -1;
		}
		spec->argtype = line->text;
		break;
	case NPTS_ARGSTRUCT:
		if (spec->argtype != NULL) {
			warnx("%d: argument type already defined",
			    yyline);
			return -1;
		}
		if (asprintf(&spec->argtype, "struct %s", line->text) < 0)
			err(EX_OSERR, "asprintf");
		free(line->text);
		break;
	}
	return 0;
}

int
ss_apply(struct np_struct_spec *spec, struct y_tsline_t *line)
{
	switch (line->kind) {
	case NPTS_CSTRUCT:
		spec->is_struct = 1;
		/* FALLTHROUGH */
	case NPTS_CTYPE:
		if (spec->cname != NULL) {
			warnx("%d: C name already defined", yyline);
			return -1;
		}
		spec->cname = line->text;
		spec->is_ptr = line->ptr;
		break;
	case NPTS_ENCODE:
		errx(EX_SOFTWARE, "programmer error: %s"
		    "encode function in struct");
		break;
	case NPTS_DECODE:
		errx(EX_SOFTWARE, "programmer error: %s",
		    "decode function in struct");
		break;
	case NPTS_INIT:
		if (spec->init != NULL || spec->no_init) {
			warnx("%d: initialization function already defined",
			    yyline);
			return -1;
		}
		spec->init = line->text;
		break;
	case NPTS_NOINIT:
		if (spec->init != NULL || spec->no_init) {
			warnx("%d: initialization function already defined",
			    yyline);
			return -1;
		}
		spec->no_init = 1;
		break;
	case NPTS_DESTROY:
		if (spec->destroy != NULL || spec->no_destroy) {
			warnx("%d: destruction function already defined",
			    yyline);
			return -1;
		}
		spec->destroy = line->text;
		break;
	case NPTS_NODESTROY:
		if (spec->destroy != NULL || spec->no_destroy) {
			warnx("%d: destruction function already defined",
			    yyline);
			return -1;
		}
		spec->no_destroy = 1;
		break;
	case NPTS_ARG:
		if (spec->argtype != NULL) {
			warnx("%d: argument type already defined",
			    yyline);
			return -1;
		}
		spec->argtype = line->text;
		break;
	case NPTS_ARGSTRUCT:
		if (spec->argtype != NULL) {
			warnx("%d: argument type already defined",
			    yyline);
			return -1;
		}
		if (asprintf(&spec->argtype, "struct %s", line->text) < 0)
			err(EX_OSERR, "asprintf");
		free(line->text);
		break;
	}
	return 0;
}

void
yyerror(const char *errortext)
{
	warnx("%s at line %d", errortext, yyline);
}

extern void parse();
extern void create_type_code(struct np_type*);
extern void create_compound_encoder(struct np_struct*);
extern void create_compound_decoder(struct np_struct*);
extern void create_compound_initfun(struct np_struct*);
extern void create_compound_destroyfun(struct np_struct*);
extern void create_compound_encode_sm(const char*, struct np_structmember*);
extern void create_compound_decode_sm(const char*, struct np_structmember*);
extern void create_compound_init_sm(const char*, struct np_structmember*, int);
extern void create_compound_destroy_sm(const char*, struct np_structmember*);
extern void create_compound_default_sm(const char*, struct np_structmember*);
extern void create_compound_typedescr(struct np_struct*);

char *visibility_local = NULL;
char *visibility_export = NULL;

static int
usage(const char *program)
{
	if (printf(
	    "%s [-H header] [-G guard] [-o outfile] \\\n"
	    "    [-L localspec] [-E exportspec] files...\n"
	    "\n"
	    "\t-h:\t\tprint this help\n"
	    "\t-H header:\tgenerate header file\n"
	    "\t\t\tIf no header is given, no header file will\n"
	    "\t\t\tbe generated.\n"
	    "\t-G guard:\theader file inclusion guard\n"
	    "\t\t\tThe header file will be preceded by\n"
	    "\t\t\t  #ifndef guard\n"
	    "\t\t\t  #define guard\n"
	    "\t\t\tand end with\n"
	    "\t\t\t  #endif /* guard */\n"
	    "\t-o outfile:\twrite C code to specified output\n"
	    "\t\t\tIf no outfile is given, C code will be written\n"
	    "\t\t\tto stdout.\n"
	    "\t-L localspec:\tplaces local spec before non-exported symbols\n"
	    "\t-E exportspec:\tplaces export spec before exported symbols\n"
	    "\t\t\tExported symbols are cp_TYPE specifications\n"
	    "\t\t\tfor each type.\n"
	    "\tfiles...\tparse the given files\n"
	    "\t\t\tIf omitted, stdin will be parsed.\n",
	    program) < 0)
		err(EX_OSERR, "printf");

	return EX_USAGE;
}

static const char *const optstring = "hH:G:o:L:E:";
FILE			*hfile = NULL;
FILE			*cfile = NULL;
const char		*hguard = NULL;

int
main(int argc, char*const* argv)
{
	int			 ch;
	const char		*program;
	int			 fd;

	program = (argv == 0 ? "net2type" : argv[0]);

	/*
	 * Parse options.
	 */
	while ((ch = getopt(argc, argv, optstring)) != -1) {
		switch (ch) {
		case 'h':
			usage(program);
			return 0;
		case 'H':
			if (hfile) {
				err(EX_USAGE, "duplicate -%c option",
				    (char)ch);
			}
			hfile = fopen(optarg, "w");
			if (!hfile)
				err(EX_OSERR, "fopen(%s, \"w\")", optarg);
			break;
		case 'G':
			if (hguard) {
				err(EX_USAGE, "duplicate -%c option",
				    (char)ch);
			}
			hguard = optarg;
			break;
		case 'o':
			if (cfile) {
				err(EX_USAGE, "duplicate -%c option",
				    (char)ch);
			}
			cfile = fopen(optarg, "w");
			if (!cfile)
				err(EX_OSERR, "fopen(%s, \"w\")", optarg);
			break;
		case 'L':
			if (visibility_local) {
				err(EX_USAGE, "duplicate -%c option",
				    (char)ch);
			}
			visibility_local = optarg;
			break;
		case 'E':
			if (visibility_export) {
				err(EX_USAGE, "duplicate -%c option",
				    (char)ch);
			}
			visibility_export = optarg;
			break;
		default:
			warn("unrecognized option -%c", (char)ch);
			return usage(program);
		}
	}
	argc -= optind;
	argv += optind;

	/*
	 * Fill in default values.
	 */
	if (visibility_local == NULL)
		visibility_local = "";
	if (visibility_export == NULL)
		visibility_export = "";
	if (cfile == NULL)
		cfile = stdout;
	if (hfile == NULL) {
		hguard = NULL;
		hfile = cfile;
	}

	/*
	 * Write the header file guard.
	 */
	if (hguard) {
		if (fprintf(hfile,
		    "#ifndef %s\n"
		    "#define %s\n"
		    "\n",
		    hguard,
		    hguard) < 0)
			err(EX_OSERR, "fprintf");
	}

	/*
	 * If no files are given, parse stdin.
	 */
	if (argc == 0) {
		yyfilename = "stdin";
		parse();
	} else {
		/* Move standard input out of the way. */
		while (close(0) == -1) {
			if (errno == EBADF)
				break;
			if (errno == EINTR)
				continue;
			err(EX_OSERR, "close(stdin)");
		}

		/* Parse each input file. */
		while (argc > 0) {
			/* Open the next input file. */
			yyfilename = argv[0];
			fd = open(argv[0], O_RDONLY, 0);
			if (fd == -1) {
				err(EX_OSERR, "failed to read input %s",
				    argv[0]);
			}
			/* Move its descriptor to position 0 (stdin). */
			if (fd != 0) {
				if (dup2(fd, 0) == -1)
					err(EX_OSERR, "dup2 %d -> %d", fd, 0);
				while (close(fd) == -1) {
					if (errno == EINTR)
						continue; /* Try again. */
					err(EX_OSERR, "close(%s)", argv[0]);
				}
				fd = 0;
			}

			parse();

			/* Close the file. */
			while (close(fd) == -1) {
				if (errno == EINTR)
					continue; /* Try again. */
				err(EX_OSERR, "close(%s)", argv[0]);
			}

			/* Move to next. */
			argc--;
			argv++;
		}
	}

	/* Close the header file guard. */
	if (hguard) {
		if (fprintf(hfile,
		    "#endif /* %s */\n",
		    hguard) < 0)
			err(EX_OSERR, "fprintf");
	}

	/*
	 * Close outputs.
	 */
	if (hfile == cfile)
		hfile = NULL;
	else {
		while (fclose(hfile) == EOF) {
			if (errno == EINTR)
				continue;
			err(EX_OSERR, "failed to close header file");
		}
	}

	if (cfile == stdin) {
		while (fflush(cfile) == EOF) {
			if (errno == EINTR)
				continue;
			err(EX_OSERR, "failed to flush output");
		}
	} else {
		while (fclose(cfile) == EOF) {
			if (errno == EINTR)
				continue;
			err(EX_OSERR, "failed to close output file");
		}
	}

	return 0;
}

/*
 * Parse stdin and write result to hfile and cfile.
 */
void
parse()
{
	struct np_type		*type;
	struct np_struct	*struc;

	/*
	 * Parse input file.
	 */
	if (yyparse() != 0)
		errx(EX_DATAERR, "parse error");

	/*
	 * Print all opaque bits prior to rules to header file.
	 */
	if (definitions->sd_header) {
		if (fprintf(hfile, "%s\n", definitions->sd_header) < 0)
			err(EX_OSERR, "fprintf");
	}

	/*
	 * Write prologue for C code.
	 */
	if (definitions->sd_pre) {
		if (fprintf(cfile, "%s\n", definitions->sd_pre) < 0)
			err(EX_OSERR, "fprintf");
	}
	if (fprintf(cfile, "%s\n%s\n%s\n%s\n\n",
	    "#include <ilias/net2/cp.h>",
	    "#include <ilias/net2/encdec_ctx.h>",
	    "#include <ilias/net2/connection.h>",
	    "#include <ilias/net2/buffer.h>") < 0)
		err(EX_OSERR, "fprintf");

	/*
	 * Forward declare all types.
	 */
	TAILQ_FOREACH(type, &definitions->sd_types, npt_q) {
		if (fprintf(hfile,
		    "extern %s const struct command_param cp_%s;\n",
		    visibility_export, type->npt_name) < 0)
			err(EX_OSERR, "fprintf");
	}
	TAILQ_FOREACH(struc, &definitions->sd_structs, nps_q) {
		if (fprintf(hfile,
		    "extern %s const struct command_param cp_%s;\n",
		    visibility_export, struc->nps_name) < 0)
			err(EX_OSERR, "fprintf");
	}
	if (fprintf(hfile, "\n\n") < 0)
		err(EX_OSERR, "fprintf");

	/*
	 * Print all builtin or specially handled types.
	 */
	TAILQ_FOREACH(type, &definitions->sd_types, npt_q)
		create_type_code(type);

	/*
	 * Print code to handle compound (struct) types.
	 */
	TAILQ_FOREACH(struc, &definitions->sd_structs, nps_q) {
		/* Small documentation. */
		if (fprintf(cfile, "/*\n"
		    " * Compound command param type: %s\n"
		    " * C type: %s%s%s\n"
		    " * Argument type: %s\n"
		    " */\n",
		    struc->nps_name,
		    (struc->nps_spec.is_struct ? "struct " : ""),
		    struc->nps_spec.cname,
		    make_pointer(struc->nps_spec.is_ptr, " "),
		    (struc->nps_spec.argtype ? struc->nps_spec.argtype :
		     "unspecified")
		    ) < 0)
			err(EX_OSERR, "fprintf");
		/* Line number information. */
		if (fprintf(cfile, "#line %d \"%s\"\n", struc->nps_line,
		    yyfilename) == -1)
			err(EX_OSERR, "fprintf");

		/* Ensure argtype is a valid type. */
		if (struc->nps_spec.argtype == NULL)
			struc->nps_spec.argtype = "void";

		/* Encoding function. */
		create_compound_encoder(struc);
		/* Decoding function. */
		create_compound_decoder(struc);

		/* Initialization function. */
		if (struc->nps_spec.no_init) {
			/* nothing */
		} else if (struc->nps_spec.init) {
			if (fprintf(cfile, "%s int %s("
			    "struct net2_encdec_ctx*,\n"
			    "    %s%s%s*,\n"
			    "    const %s*);\n",
			    visibility_local, struc->nps_spec.init,
			    (struc->nps_spec.is_struct ? "struct " : ""),
			    struc->nps_spec.cname,
			    make_pointer(struc->nps_spec.is_ptr, ""),
			    struc->nps_spec.argtype
			    ) < 0)
				err(EX_OSERR, "fprintf");
		} else {
			if (asprintf(&struc->nps_spec.init,
			    "npcompound_%s_init", struc->nps_name) < 0)
				err(EX_OSERR, "asprintf");
			create_compound_initfun(struc);
		}

		/* Destructor function. */
		if (struc->nps_spec.no_destroy) {
			/* nothing */
		} else if (struc->nps_spec.destroy) {
			if (fprintf(cfile, "%s int %s("
			    "struct net2_encdec_ctx*,\n"
			    "    %s%s%s*,\n"
			    "    const %s*);\n",
			    visibility_local, struc->nps_spec.destroy,
			    (struc->nps_spec.is_struct ? "struct " : ""),
			    struc->nps_spec.cname,
			    make_pointer(struc->nps_spec.is_ptr, ""),
			    struc->nps_spec.argtype
			    ) < 0)
				err(EX_OSERR, "fprintf");
		} else {
			if (asprintf(&struc->nps_spec.destroy,
			    "npcompound_%s_destroy", struc->nps_name) < 0)
				err(EX_OSERR, "asprintf");
			create_compound_destroyfun(struc);
		}

		/* Write out the type. */
		create_compound_typedescr(struc);

		/* Seperator between this definition and the next. */
		if (fprintf(cfile, "\n\n") < 0)
			err(EX_OSERR, "fprintf");
	}

	/*
	 * Write out additional code.
	 */
	if (definitions->sd_post) {
		if (fprintf(cfile, "%s\n", definitions->sd_post) < 0)
			err(EX_OSERR, "fprintf");
	}
}

/*
 * Write the code that describes this specific type.
 */
void
create_type_code(struct np_type *type)
{
	/* Documentation. */
	if (fprintf(cfile, "/*\n"
	    " * Command param type: %s\n"
	    " * C type: %s%s%s\n"
	    " * Argument type: %s\n"
	    " */\n",
	    type->npt_name,
	    (type->npt_spec.is_struct ? "struct " : ""),
	    type->npt_spec.cname,
	    make_pointer(type->npt_spec.is_ptr, " "),
	    (type->npt_spec.argtype ? type->npt_spec.argtype : "unspecified")
	    ) < 0)
		err(EX_OSERR, "fprintf");
	/* Line number information. */
	if (fprintf(cfile, "#line %d \"%s\"\n", type->npt_line,
	    yyfilename) == -1)
		err(EX_OSERR, "fprintf");

	if (type->npt_spec.argtype == NULL)
		type->npt_spec.argtype = "void";

	/* Declare encoder function. */
	if (fprintf(cfile, "%s int %s(struct net2_encdec_ctx*,\n"
	    "    struct net2_buffer*, %s%s%s%s%s*, const %s*);\n",
	    visibility_local, type->npt_spec.encode,
	    (type->npt_spec.is_ptr ? "" : "const "),
	    (type->npt_spec.is_struct ? "struct " : ""),
	    type->npt_spec.cname,
	    make_pointer(type->npt_spec.is_ptr, ""),
	    (type->npt_spec.is_ptr ? "const" : ""),
	    type->npt_spec.argtype
	    ) < 0)
		err(EX_OSERR, "fprintf");
	/* Declare decoder function. */
	if (fprintf(cfile, "%s int %s(struct net2_encdec_ctx*,\n"
	    "    %s%s%s*, struct net2_buffer*, const %s*);\n",
	    visibility_local, type->npt_spec.decode,
	    (type->npt_spec.is_struct ? "struct " : ""),
	    type->npt_spec.cname,
	    make_pointer(type->npt_spec.is_ptr, ""),
	    type->npt_spec.argtype
	    ) < 0)
		err(EX_OSERR, "fprintf");
	/* Initialization function. */
	if (type->npt_spec.init &&
	    fprintf(cfile, "%s int %s(struct net2_encdec_ctx*,\n"
	    "    %s%s%s*, const %s*);\n",
	    visibility_local, type->npt_spec.init,
	    (type->npt_spec.is_struct ? "struct " : ""),
	    type->npt_spec.cname,
	    make_pointer(type->npt_spec.is_ptr, ""),
	    type->npt_spec.argtype
	    ) < 0)
		err(EX_OSERR, "fprintf");
	/* Destructor function. */
	if (type->npt_spec.destroy &&
	    fprintf(cfile, "%s int %s(struct net2_encdec_ctx*,\n"
	    "    %s%s%s*, const %s*);\n",
	    visibility_local, type->npt_spec.destroy,
	    (type->npt_spec.is_struct ? "struct " : ""),
	    type->npt_spec.cname,
	    make_pointer(type->npt_spec.is_ptr, ""),
	    type->npt_spec.argtype
	    ) < 0)
		err(EX_OSERR, "fprintf");
	/* Little vertical space for readability. */
	if (fprintf(cfile, "\n") < 0)
		err(EX_OSERR, "fprintf");

	/* Define type. */
	if (fprintf(cfile, "%s const struct command_param cp_%s = {\n"
	    "\tCPT_NONE,\n"
	    "\tsizeof(%s%s%s),\n"
	    "\t\"%s\",\n"
	    "\t(net2_cp_encfun) &%s,\n"
	    "\t(net2_cp_decfun) &%s,\n"
	    "\t(net2_cp_initfun)%s%s,\n"
	    "\t(net2_cp_delfun) %s%s,\n"
	    "};\n",
	    visibility_export, type->npt_name,
	    (type->npt_spec.is_struct ? "struct " : ""),
	    type->npt_spec.cname,
	    make_pointer(type->npt_spec.is_ptr, ""),
	    type->npt_name,
	    type->npt_spec.encode,
	    type->npt_spec.decode,
	    (type->npt_spec.init ? "&" : ""),
	    (type->npt_spec.init ? type->npt_spec.init : "NULL"),
	    (type->npt_spec.destroy ? "&" : ""),
	    (type->npt_spec.destroy ? type->npt_spec.destroy : "NULL")
	    ) < 0)
		err(EX_OSERR, "fprintf");
	/* Large vertical space for readability. */
	if (fprintf(cfile, "\n\n") < 0)
		err(EX_OSERR, "fprintf");
}

/*
 * Generate encode statements for compound type.
 */
void
create_compound_encoder(struct np_struct *s)
{
	struct np_structmember	*sm;
	const char		*indent;
	int			 do_if;
	char			 cond[128];

	/* Function declaration. */
	if (fprintf(cfile, "static int\n"
	    "npcompound_%s_encode(struct net2_encdec_ctx *c,\n"
	    "    struct net2_buffer *out, const %s%s%s%s*val,\n"
	    "    const %s *cp_arg)\n",
	    s->nps_name,
	    (s->nps_spec.is_struct ? "struct " : ""),
	    s->nps_spec.cname,
	    make_pointer(s->nps_spec.is_ptr, ""),
	    (s->nps_spec.is_ptr ? "const" : ""),
	    s->nps_spec.argtype
	    ) < 0)
		err(EX_OSERR, "fprintf");

	/* Begin function body. */
	if (fprintf(cfile, "{\n") < 0)
		err(EX_OSERR, "fprintf");
	/* Extract version. */
	if (fprintf(cfile, "\tnet2_protocol_t version = "
	    "c->ed_conn->n2c_version;\n") < 0)
		err(EX_OSERR, "fprintf");

	/* Handle each member. */
	TAILQ_FOREACH(sm, &s->nps_members, npsm_q) {
		if (sm->npsm_firstprot != 0 && sm->npsm_lastprot != 0) {
			indent = "\t\t";
			if (snprintf(cond, sizeof(cond),
			    "version >= %d && version < %d",
			    sm->npsm_firstprot, sm->npsm_lastprot) < 0)
				err(EX_OSERR, "snprintf");
			do_if = 1;
		} else if (sm->npsm_lastprot != 0) {
			indent = "\t\t";
			if (snprintf(cond, sizeof(cond),
			    "version < %d",
			    sm->npsm_lastprot) < 0)
				err(EX_OSERR, "snprintf");
			do_if = 1;
		} else if (sm->npsm_firstprot != 0) {
			indent = "\t\t";
			if (snprintf(cond, sizeof(cond),
			    "verion >= %d",
			    sm->npsm_firstprot) < 0)
				err(EX_OSERR, "snprintf");
			do_if = 1;
		} else {
			indent = "\t";
			do_if = 0;
		}

		if (fprintf(cfile, "\t/* Encode %s. */\n",
		    sm->npsm_name) < 0)
			err(EX_OSERR, "fprintf");

		/* Open if block. */
		if (do_if) {
			if (fprintf(cfile, "\tif (%s) {\n", cond) < 0)
				err(EX_OSERR, "fprintf");
		}

		/* Write encoding statement. */
		create_compound_encode_sm(indent, sm);

		if (do_if) {
			if (fprintf(cfile, "\t}\n") < 0)
				err(EX_OSERR, "fprintf");
		}
		if (fprintf(cfile, "\n") < 0)
			err(EX_OSERR, "fprintf");
	}

	/* End function body. */
	if (fprintf(cfile, "\treturn 0;\n}\n\n") < 0)
		err(EX_OSERR, "fprintf");
}

/*
 * Generate decode statements for compound type.
 */
void
create_compound_decoder(struct np_struct *s)
{
	struct np_structmember	*sm;
	const char		*indent;
	int			 do_if;
	char			 cond[128];

	/* Function declaration. */
	if (fprintf(cfile, "static int\n"
	    "npcompound_%s_decode(struct net2_encdec_ctx *c,\n"
	    "    %s%s%s*val, struct net2_buffer *in,\n"
	    "    const %s *cp_arg)\n",
	    s->nps_name,
	    (s->nps_spec.is_struct ? "struct " : ""),
	    s->nps_spec.cname,
	    make_pointer(s->nps_spec.is_ptr, ""),
	    s->nps_spec.argtype
	    ) < 0)
		err(EX_OSERR, "fprintf");

	/* Begin function body. */
	if (fprintf(cfile, "{\n") < 0)
		err(EX_OSERR, "fprintf");
	/* Extract version. */
	if (fprintf(cfile, "\tnet2_protocol_t version = "
	    "c->ed_conn->n2c_version;\n") < 0)
		err(EX_OSERR, "fprintf");

	/* Handle each member. */
	TAILQ_FOREACH(sm, &s->nps_members, npsm_q) {
		if (sm->npsm_firstprot != 0 && sm->npsm_lastprot != 0) {
			indent = "\t\t";
			if (snprintf(cond, sizeof(cond),
			    "version >= %d && version < %d",
			    sm->npsm_firstprot, sm->npsm_lastprot) < 0)
				err(EX_OSERR, "snprintf");
			do_if = 1;
		} else if (sm->npsm_lastprot != 0) {
			indent = "\t\t";
			if (snprintf(cond, sizeof(cond),
			    "version < %d",
			    sm->npsm_lastprot) < 0)
				err(EX_OSERR, "snprintf");
			do_if = 1;
		} else if (sm->npsm_firstprot != 0) {
			indent = "\t\t";
			if (snprintf(cond, sizeof(cond),
			    "verion >= %d",
			    sm->npsm_firstprot) < 0)
				err(EX_OSERR, "snprintf");
			do_if = 1;
		} else {
			indent = "\t";
			do_if = 0;
		}

		if (fprintf(cfile, "\t/* Decode %s. */\n",
		    sm->npsm_name) < 0)
			err(EX_OSERR, "fprintf");

		/* Open if block. */
		if (do_if) {
			if (fprintf(cfile, "\tif (%s) {\n", cond) < 0)
				err(EX_OSERR, "fprintf");
		}

		/* Write encoding statement. */
		create_compound_decode_sm(indent, sm);

		if (do_if) {
			if (fprintf(cfile, "\t} else {\n") < 0)
				err(EX_OSERR, "fprintf");
			create_compound_default_sm(indent, sm);
			if (fprintf(cfile, "\t}\n") < 0)
				err(EX_OSERR, "fprintf");
		}
		if (fprintf(cfile, "\n") < 0)
			err(EX_OSERR, "fprintf");
	}

	/* End function body. */
	if (fprintf(cfile, "\treturn 0;\n}\n\n") < 0)
		err(EX_OSERR, "fprintf");
}

/*
 * Generate initialization statements for compound type.
 */
void
create_compound_initfun(struct np_struct *s)
{
	struct np_structmember	*sm;
	int			 idx, top_idx;

	/* Function declaration. */
	if (fprintf(cfile, "static int\n"
	    "%s(struct net2_encdec_ctx *c,\n"
	    "    %s%s%s%s*val,\n"
	    "    const %s *cp_arg)\n",
	    s->nps_spec.init,
	    (s->nps_spec.is_struct ? "struct " : ""),
	    s->nps_spec.cname,
	    make_pointer(s->nps_spec.is_ptr, ""),
	    (s->nps_spec.is_ptr ? "const" : ""),
	    s->nps_spec.argtype
	    ) < 0)
		err(EX_OSERR, "fprintf");

	/* Begin function body. */
	if (fprintf(cfile, "{\n\tint err = -1;\n") < 0)
		err(EX_OSERR, "fprintf");
	/* Extract version. */
	if (fprintf(cfile, "\tnet2_protocol_t version = "
	    "c->ed_conn->n2c_version;\n") < 0)
		err(EX_OSERR, "fprintf");

	/* Handle each member. */
	idx = 0;
	TAILQ_FOREACH(sm, &s->nps_members, npsm_q) {
		if (fprintf(cfile, "\t/* %2d: Init %s. */\n",
		    idx, sm->npsm_name) < 0)
			err(EX_OSERR, "fprintf");

		/* Invoke init code. */
		create_compound_init_sm("\t", sm, idx);
		if (fprintf(cfile, "\n") < 0)
			err(EX_OSERR, "fprintf");

		idx++;
	}
	top_idx = idx;

	/* Return without failure. */
	if (fprintf(cfile, "\treturn 0;\n\n") < 0)
		err(EX_OSERR, "fprintf");

	TAILQ_FOREACH_REVERSE(sm, &s->nps_members, np_structmemberq, npsm_q) {
		/* Last failure only needs label, no destruction code. */
		if (idx-- == top_idx)
			goto write_label;

		if (fprintf(cfile, "\t/* Unwind for %2d: %s. */\n",
		    idx, sm->npsm_name) < 0)
			err(EX_OSERR, "fprintf");

		/* Invoke destroy code. */
		create_compound_destroy_sm("\t", sm);
		if (fprintf(cfile, "\n") < 0)
			err(EX_OSERR, "fprintf");

write_label:
		if (fprintf(cfile, "fail_%d:\n", idx) < 0)
			err(EX_OSERR, "fprintf");
	}
	if (idx != 0)
		errx(EX_SOFTWARE, "Init unwind code failure: idx = %d.", idx);

	/* End function body. */
	if (fprintf(cfile, "\treturn err;\n}\n\n") < 0)
		err(EX_OSERR, "fprintf");
}

/*
 * Generate destruction statements for compound type.
 */
void
create_compound_destroyfun(struct np_struct *s)
{
	struct np_structmember	*sm;

	/* Function declaration. */
	if (fprintf(cfile, "static int\n"
	    "%s(struct net2_encdec_ctx *c,\n"
	    "    %s%s%s%s*val,\n"
	    "    const %s *cp_arg)\n",
	    s->nps_spec.destroy,
	    (s->nps_spec.is_struct ? "struct " : ""),
	    s->nps_spec.cname,
	    make_pointer(s->nps_spec.is_ptr, ""),
	    (s->nps_spec.is_ptr ? "const" : ""),
	    s->nps_spec.argtype
	    ) < 0)
		err(EX_OSERR, "fprintf");

	/* Begin function body. */
	if (fprintf(cfile, "{\n") < 0)
		err(EX_OSERR, "fprintf");
	/* Define error result. */
	if (fprintf(cfile, "\tint err = 0;\n") < 0)
		err(EX_OSERR, "fprintf");
	/* Extract version. */
	if (fprintf(cfile, "\tnet2_protocol_t version = "
	    "c->ed_conn->n2c_version;\n") < 0)
		err(EX_OSERR, "fprintf");

	/* Handle each member. */
	TAILQ_FOREACH(sm, &s->nps_members, npsm_q) {
		if (fprintf(cfile, "\t/* Destroy %s. */\n",
		    sm->npsm_name) < 0)
			err(EX_OSERR, "fprintf");

		/* Invoke destroy code. */
		create_compound_destroy_sm("\t", sm);
		if (fprintf(cfile, "\n") < 0)
			err(EX_OSERR, "fprintf");
	}

	/* End function body. */
	if (fprintf(cfile, "\treturn err;\n}\n\n") < 0)
		err(EX_OSERR, "fprintf");
}

/*
 * Encode a struct member.
 */
void
create_compound_encode_sm(const char *indent, struct np_structmember *sm)
{
	const char	*arg_prefix, *arg;

	if (sm->npsm_arg) {
		arg = sm->npsm_arg;
		arg_prefix = "&";
	} else {
		arg = "NULL";
		arg_prefix = "";
	}

	if (fprintf(cfile, "%sif (net2_cp_encode(c, &cp_%s,\n"
	    "%s    out, &val->%s, %s%s))\n"
	    "%s\treturn -1;\n",
	    indent, sm->npsm_type,
	    indent, sm->npsm_name, arg_prefix, arg,
	    indent
	    ) < 0)
		err(EX_OSERR, "fprintf");
}

/*
 * Decode a struct member.
 */
void
create_compound_decode_sm(const char *indent, struct np_structmember *sm)
{
	const char	*arg_prefix, *arg;

	if (sm->npsm_arg) {
		arg = sm->npsm_arg;
		arg_prefix = "&";
	} else {
		arg = "NULL";
		arg_prefix = "";
	}

	if (fprintf(cfile, "%sif (net2_cp_decode(c, &cp_%s,\n"
	    "%s    &val->%s, in, %s%s))\n"
	    "%s\treturn -1;\n",
	    indent, sm->npsm_type,
	    indent, sm->npsm_name, arg_prefix, arg,
	    indent
	    ) < 0)
		err(EX_OSERR, "fprintf");
}

/*
 * Initialize a struct member.
 */
void
create_compound_init_sm(const char *indent, struct np_structmember *sm, int idx)
{
	const char	*arg_prefix, *arg;

	if (sm->npsm_arg) {
		arg = sm->npsm_arg;
		arg_prefix = "&";
	} else {
		arg = "NULL";
		arg_prefix = "";
	}

	if (fprintf(cfile, "%sif (net2_cp_init(c, &cp_%s, &val->%s, %s%s))\n"
	    "%s\tgoto fail_%d;\n",
	    indent, sm->npsm_type, sm->npsm_name, arg_prefix, arg,
	    indent, idx
	    ) < 0)
		err(EX_OSERR, "fprintf");
}

/*
 * Destroy a struct member.
 */
void
create_compound_destroy_sm(const char *indent, struct np_structmember *sm)
{
	const char	*arg_prefix, *arg;

	if (sm->npsm_arg) {
		arg = sm->npsm_arg;
		arg_prefix = "&";
	} else {
		arg = "NULL";
		arg_prefix = "";
	}

	if (fprintf(cfile,
	    "%sif (net2_cp_destroy(c, &cp_%s, &val->%s, %s%s))\n"
	    "%s\terr = -1;\n",
	    indent, sm->npsm_type, sm->npsm_name, arg_prefix, arg,
	    indent
	    ) < 0)
		err(EX_OSERR, "fprintf");
}

/*
 * Generate a default value for decoded member variable.
 */
void
create_compound_default_sm(const char *indent, struct np_structmember *sm)
{
	switch (sm->npsm_dfl.kind) {
	case SMDFL_NONE:
		if (fprintf(cfile, "%s/* %s: no default */\n",
		    indent, sm->npsm_name) < 0)
			err(EX_OSERR, "fprintf");
		break;
	case SMDFL_NULL:
		if (fprintf(cfile, "%sval->%s = NULL;\n",
		    indent, sm->npsm_name) < 0)
			err(EX_OSERR, "fprintf");
		break;
	case SMDFL_NUMBER:
		if (fprintf(cfile, "%sval->%s = %ld;\n",
		    indent, sm->npsm_name, sm->npsm_dfl.number) < 0)
			err(EX_OSERR, "fprintf");
		break;
	case SMDFL_FUNCTION:
		if (fprintf(cfile, "%sif (%s(&val->%s))\n"
		    "%s\treturn -1;\n",
		    indent, sm->npsm_dfl.function, sm->npsm_name,
		    indent) < 0)
			err(EX_OSERR, "fprintf");
		break;
	case SMDFL_VALUE:
		if (fprintf(cfile, "%sval->%s = %s;\n",
		    indent, sm->npsm_name, sm->npsm_dfl.value) < 0)
			err(EX_OSERR, "fprintf");
		break;
	}
}

/* Define compound type. */
void
create_compound_typedescr(struct np_struct *struc)
{
	if (fprintf(cfile, "%s const struct command_param cp_%s = {\n"
	    "\tCPT_NONE,\n"
	    "\tsizeof(struct %s%s),\n"
	    "\t\"%s\",\n"
	    "\t(net2_cp_encfun)&npcompound_%s_encode,\n"
	    "\t(net2_cp_decfun)&npcompound_%s_decode,\n"
	    "\t(net2_cp_initfun)%s%s,\n"
	    "\t(net2_cp_delfun)%s%s,\n"
	    "};\n",
	    visibility_export, struc->nps_name,
	    struc->nps_spec.cname,
	    make_pointer(struc->nps_spec.is_ptr, ""),
	    struc->nps_name,
	    struc->nps_name,
	    struc->nps_name,
	    (struc->nps_spec.init ? "&" : ""),
	    (struc->nps_spec.init ? struc->nps_spec.init : "NULL"),
	    (struc->nps_spec.destroy ? "&" : ""),
	    (struc->nps_spec.destroy ? struc->nps_spec.destroy : "NULL")
	    ) < 0)
		err(EX_OSERR, "fprintf");
}
