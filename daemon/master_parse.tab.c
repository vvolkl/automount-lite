/* A Bison parser, made by GNU Bison 3.8.2.  */

/* Bison implementation for Yacc-like parsers in C

   Copyright (C) 1984, 1989-1990, 2000-2015, 2018-2021 Free Software Foundation,
   Inc.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <https://www.gnu.org/licenses/>.  */

/* As a special exception, you may create a larger work that contains
   part or all of the Bison parser skeleton and distribute that work
   under terms of your choice, so long as that work isn't itself a
   parser generator using the skeleton or a modified version thereof
   as a parser skeleton.  Alternatively, if you modify or redistribute
   the parser skeleton itself, you may (at your option) remove this
   special exception, which will cause the skeleton and the resulting
   Bison output files to be licensed under the GNU General Public
   License without this special exception.

   This special exception was added by the Free Software Foundation in
   version 2.2 of Bison.  */

/* C LALR(1) parser skeleton written by Richard Stallman, by
   simplifying the original so-called "semantic" parser.  */

/* DO NOT RELY ON FEATURES THAT ARE NOT DOCUMENTED in the manual,
   especially those whose name start with YY_ or yy_.  They are
   private implementation details that can be changed or removed.  */

/* All symbols defined below should begin with yy or YY, to avoid
   infringing on user name space.  This should be done even for local
   variables, as they might otherwise be expanded by user macros.
   There are some unavoidable exceptions within include files to
   define necessary library symbols; they are noted "INFRINGES ON
   USER NAME SPACE" below.  */

/* Identify Bison output, and Bison version.  */
#define YYBISON 30802

/* Bison version string.  */
#define YYBISON_VERSION "3.8.2"

/* Skeleton name.  */
#define YYSKELETON_NAME "yacc.c"

/* Pure parsers.  */
#define YYPURE 0

/* Push parsers.  */
#define YYPUSH 0

/* Pull parsers.  */
#define YYPULL 1


/* Substitute the variable and function names.  */
#define yyparse         master_parse
#define yylex           master_lex
#define yyerror         master_error
#define yydebug         master_debug
#define yynerrs         master_nerrs
#define yylval          master_lval
#define yychar          master_char

/* First part of user prologue.  */
#line 1 "master_parse.y"

/* ----------------------------------------------------------------------- *
 *   
 *  master_parser.y - master map buffer parser.
 *
 *   Copyright 2006 Ian Kent <raven@themaw.net>
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, Inc., 675 Mass Ave, Cambridge MA 02139,
 *   USA; either version 2 of the License, or (at your option) any later
 *   version.
 *   
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 * ----------------------------------------------------------------------- */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <ctype.h>
#include <sys/ioctl.h>

#include "automount.h"
#include "master.h"

#define MAX_ERR_LEN	512
#define STRTYPE_LEN	2048

extern struct master *master_list;

char **add_argv(int, char **, char *);
const char **copy_argv(int, const char **);
int free_argv(int, const char **);

extern FILE *master_in;
extern char *master_text;
extern int master_lex(void);
extern int master_lineno;
extern void master_set_scan_buffer(const char *);

static char *master_strdup(char *);
static void local_init_vars(void);
static void local_free_vars(void);
static void trim_maptype(char *);
static int add_multi_mapstr(void);

static int master_error(const char *s);
static int master_notify(const char *s);
static int master_msg(const char *s);
 
static char *path;
static char *type;
static char *format;
static long timeout;
static long negative_timeout;
static long positive_timeout;
static unsigned symlnk;
static unsigned strictexpire;
static unsigned nobind;
static unsigned ghost;
extern unsigned global_selection_options;
static unsigned random_selection;
static unsigned use_weight;
static unsigned long mode;
static char **tmp_argv;
static int tmp_argc;
static char **local_argv;
static int local_argc;

#define PROPAGATION_SHARED	MOUNT_FLAG_SHARED
#define PROPAGATION_SLAVE	MOUNT_FLAG_SLAVE
#define PROPAGATION_PRIVATE	MOUNT_FLAG_PRIVATE
#define PROPAGATION_MASK	(MOUNT_FLAG_SHARED | \
				 MOUNT_FLAG_SLAVE  | \
				 MOUNT_FLAG_PRIVATE)
static unsigned int propagation;

static char errstr[MAX_ERR_LEN];
static int errlen;

static unsigned int verbose;
static unsigned int debug;

static int lineno;

#define YYDEBUG 0

#ifndef YYENABLE_NLS
#define YYENABLE_NLS 0
#endif
#ifndef YYLTYPE_IS_TRIVIAL
#define YYLTYPE_IS_TRIVIAL 0
#endif

#if YYDEBUG
static int master_fprintf(FILE *, char *, ...);
#undef YYFPRINTF
#define YYFPRINTF master_fprintf
#endif


#line 185 "master_parse.tab.c"

# ifndef YY_CAST
#  ifdef __cplusplus
#   define YY_CAST(Type, Val) static_cast<Type> (Val)
#   define YY_REINTERPRET_CAST(Type, Val) reinterpret_cast<Type> (Val)
#  else
#   define YY_CAST(Type, Val) ((Type) (Val))
#   define YY_REINTERPRET_CAST(Type, Val) ((Type) (Val))
#  endif
# endif
# ifndef YY_NULLPTR
#  if defined __cplusplus
#   if 201103L <= __cplusplus
#    define YY_NULLPTR nullptr
#   else
#    define YY_NULLPTR 0
#   endif
#  else
#   define YY_NULLPTR ((void*)0)
#  endif
# endif

#include "master_parse.tab.h"
/* Symbol kind.  */
enum yysymbol_kind_t
{
  YYSYMBOL_YYEMPTY = -2,
  YYSYMBOL_YYEOF = 0,                      /* "end of file"  */
  YYSYMBOL_YYerror = 1,                    /* error  */
  YYSYMBOL_YYUNDEF = 2,                    /* "invalid token"  */
  YYSYMBOL_COMMENT = 3,                    /* COMMENT  */
  YYSYMBOL_MAP = 4,                        /* MAP  */
  YYSYMBOL_OPT_TIMEOUT = 5,                /* OPT_TIMEOUT  */
  YYSYMBOL_OPT_NTIMEOUT = 6,               /* OPT_NTIMEOUT  */
  YYSYMBOL_OPT_PTIMEOUT = 7,               /* OPT_PTIMEOUT  */
  YYSYMBOL_OPT_NOBIND = 8,                 /* OPT_NOBIND  */
  YYSYMBOL_OPT_NOGHOST = 9,                /* OPT_NOGHOST  */
  YYSYMBOL_OPT_GHOST = 10,                 /* OPT_GHOST  */
  YYSYMBOL_OPT_VERBOSE = 11,               /* OPT_VERBOSE  */
  YYSYMBOL_OPT_DEBUG = 12,                 /* OPT_DEBUG  */
  YYSYMBOL_OPT_RANDOM = 13,                /* OPT_RANDOM  */
  YYSYMBOL_OPT_USE_WEIGHT = 14,            /* OPT_USE_WEIGHT  */
  YYSYMBOL_OPT_SYMLINK = 15,               /* OPT_SYMLINK  */
  YYSYMBOL_OPT_MODE = 16,                  /* OPT_MODE  */
  YYSYMBOL_OPT_STRICTEXPIRE = 17,          /* OPT_STRICTEXPIRE  */
  YYSYMBOL_OPT_SHARED = 18,                /* OPT_SHARED  */
  YYSYMBOL_OPT_SLAVE = 19,                 /* OPT_SLAVE  */
  YYSYMBOL_OPT_PRIVATE = 20,               /* OPT_PRIVATE  */
  YYSYMBOL_COLON = 21,                     /* COLON  */
  YYSYMBOL_COMMA = 22,                     /* COMMA  */
  YYSYMBOL_NL = 23,                        /* NL  */
  YYSYMBOL_DDASH = 24,                     /* DDASH  */
  YYSYMBOL_PATH = 25,                      /* PATH  */
  YYSYMBOL_QUOTE = 26,                     /* QUOTE  */
  YYSYMBOL_NILL = 27,                      /* NILL  */
  YYSYMBOL_SPACE = 28,                     /* SPACE  */
  YYSYMBOL_EQUAL = 29,                     /* EQUAL  */
  YYSYMBOL_MULTITYPE = 30,                 /* MULTITYPE  */
  YYSYMBOL_MAPTYPE = 31,                   /* MAPTYPE  */
  YYSYMBOL_DNSERVER = 32,                  /* DNSERVER  */
  YYSYMBOL_DNATTR = 33,                    /* DNATTR  */
  YYSYMBOL_DNNAME = 34,                    /* DNNAME  */
  YYSYMBOL_MAPHOSTS = 35,                  /* MAPHOSTS  */
  YYSYMBOL_MAPNULL = 36,                   /* MAPNULL  */
  YYSYMBOL_MAPXFN = 37,                    /* MAPXFN  */
  YYSYMBOL_MAPNAME = 38,                   /* MAPNAME  */
  YYSYMBOL_NUMBER = 39,                    /* NUMBER  */
  YYSYMBOL_OCTALNUMBER = 40,               /* OCTALNUMBER  */
  YYSYMBOL_OPTION = 41,                    /* OPTION  */
  YYSYMBOL_YYACCEPT = 42,                  /* $accept  */
  YYSYMBOL_file = 43,                      /* file  */
  YYSYMBOL_44_1 = 44,                      /* $@1  */
  YYSYMBOL_line = 45,                      /* line  */
  YYSYMBOL_mapspec = 46,                   /* mapspec  */
  YYSYMBOL_maplist = 47,                   /* maplist  */
  YYSYMBOL_map = 48,                       /* map  */
  YYSYMBOL_dn = 49,                        /* dn  */
  YYSYMBOL_dnattrs = 50,                   /* dnattrs  */
  YYSYMBOL_dnattr = 51,                    /* dnattr  */
  YYSYMBOL_options = 52,                   /* options  */
  YYSYMBOL_option = 53,                    /* option  */
  YYSYMBOL_daemon_option = 54,             /* daemon_option  */
  YYSYMBOL_mount_option = 55               /* mount_option  */
};
typedef enum yysymbol_kind_t yysymbol_kind_t;




#ifdef short
# undef short
#endif

/* On compilers that do not define __PTRDIFF_MAX__ etc., make sure
   <limits.h> and (if available) <stdint.h> are included
   so that the code can choose integer types of a good width.  */

#ifndef __PTRDIFF_MAX__
# include <limits.h> /* INFRINGES ON USER NAME SPACE */
# if defined __STDC_VERSION__ && 199901 <= __STDC_VERSION__
#  include <stdint.h> /* INFRINGES ON USER NAME SPACE */
#  define YY_STDINT_H
# endif
#endif

/* Narrow types that promote to a signed type and that can represent a
   signed or unsigned integer of at least N bits.  In tables they can
   save space and decrease cache pressure.  Promoting to a signed type
   helps avoid bugs in integer arithmetic.  */

#ifdef __INT_LEAST8_MAX__
typedef __INT_LEAST8_TYPE__ yytype_int8;
#elif defined YY_STDINT_H
typedef int_least8_t yytype_int8;
#else
typedef signed char yytype_int8;
#endif

#ifdef __INT_LEAST16_MAX__
typedef __INT_LEAST16_TYPE__ yytype_int16;
#elif defined YY_STDINT_H
typedef int_least16_t yytype_int16;
#else
typedef short yytype_int16;
#endif

/* Work around bug in HP-UX 11.23, which defines these macros
   incorrectly for preprocessor constants.  This workaround can likely
   be removed in 2023, as HPE has promised support for HP-UX 11.23
   (aka HP-UX 11i v2) only through the end of 2022; see Table 2 of
   <https://h20195.www2.hpe.com/V2/getpdf.aspx/4AA4-7673ENW.pdf>.  */
#ifdef __hpux
# undef UINT_LEAST8_MAX
# undef UINT_LEAST16_MAX
# define UINT_LEAST8_MAX 255
# define UINT_LEAST16_MAX 65535
#endif

#if defined __UINT_LEAST8_MAX__ && __UINT_LEAST8_MAX__ <= __INT_MAX__
typedef __UINT_LEAST8_TYPE__ yytype_uint8;
#elif (!defined __UINT_LEAST8_MAX__ && defined YY_STDINT_H \
       && UINT_LEAST8_MAX <= INT_MAX)
typedef uint_least8_t yytype_uint8;
#elif !defined __UINT_LEAST8_MAX__ && UCHAR_MAX <= INT_MAX
typedef unsigned char yytype_uint8;
#else
typedef short yytype_uint8;
#endif

#if defined __UINT_LEAST16_MAX__ && __UINT_LEAST16_MAX__ <= __INT_MAX__
typedef __UINT_LEAST16_TYPE__ yytype_uint16;
#elif (!defined __UINT_LEAST16_MAX__ && defined YY_STDINT_H \
       && UINT_LEAST16_MAX <= INT_MAX)
typedef uint_least16_t yytype_uint16;
#elif !defined __UINT_LEAST16_MAX__ && USHRT_MAX <= INT_MAX
typedef unsigned short yytype_uint16;
#else
typedef int yytype_uint16;
#endif

#ifndef YYPTRDIFF_T
# if defined __PTRDIFF_TYPE__ && defined __PTRDIFF_MAX__
#  define YYPTRDIFF_T __PTRDIFF_TYPE__
#  define YYPTRDIFF_MAXIMUM __PTRDIFF_MAX__
# elif defined PTRDIFF_MAX
#  ifndef ptrdiff_t
#   include <stddef.h> /* INFRINGES ON USER NAME SPACE */
#  endif
#  define YYPTRDIFF_T ptrdiff_t
#  define YYPTRDIFF_MAXIMUM PTRDIFF_MAX
# else
#  define YYPTRDIFF_T long
#  define YYPTRDIFF_MAXIMUM LONG_MAX
# endif
#endif

#ifndef YYSIZE_T
# ifdef __SIZE_TYPE__
#  define YYSIZE_T __SIZE_TYPE__
# elif defined size_t
#  define YYSIZE_T size_t
# elif defined __STDC_VERSION__ && 199901 <= __STDC_VERSION__
#  include <stddef.h> /* INFRINGES ON USER NAME SPACE */
#  define YYSIZE_T size_t
# else
#  define YYSIZE_T unsigned
# endif
#endif

#define YYSIZE_MAXIMUM                                  \
  YY_CAST (YYPTRDIFF_T,                                 \
           (YYPTRDIFF_MAXIMUM < YY_CAST (YYSIZE_T, -1)  \
            ? YYPTRDIFF_MAXIMUM                         \
            : YY_CAST (YYSIZE_T, -1)))

#define YYSIZEOF(X) YY_CAST (YYPTRDIFF_T, sizeof (X))


/* Stored state numbers (used for stacks). */
typedef yytype_int8 yy_state_t;

/* State numbers in computations.  */
typedef int yy_state_fast_t;

#ifndef YY_
# if defined YYENABLE_NLS && YYENABLE_NLS
#  if ENABLE_NLS
#   include <libintl.h> /* INFRINGES ON USER NAME SPACE */
#   define YY_(Msgid) dgettext ("bison-runtime", Msgid)
#  endif
# endif
# ifndef YY_
#  define YY_(Msgid) Msgid
# endif
#endif


#ifndef YY_ATTRIBUTE_PURE
# if defined __GNUC__ && 2 < __GNUC__ + (96 <= __GNUC_MINOR__)
#  define YY_ATTRIBUTE_PURE __attribute__ ((__pure__))
# else
#  define YY_ATTRIBUTE_PURE
# endif
#endif

#ifndef YY_ATTRIBUTE_UNUSED
# if defined __GNUC__ && 2 < __GNUC__ + (7 <= __GNUC_MINOR__)
#  define YY_ATTRIBUTE_UNUSED __attribute__ ((__unused__))
# else
#  define YY_ATTRIBUTE_UNUSED
# endif
#endif

/* Suppress unused-variable warnings by "using" E.  */
#if ! defined lint || defined __GNUC__
# define YY_USE(E) ((void) (E))
#else
# define YY_USE(E) /* empty */
#endif

/* Suppress an incorrect diagnostic about yylval being uninitialized.  */
#if defined __GNUC__ && ! defined __ICC && 406 <= __GNUC__ * 100 + __GNUC_MINOR__
# if __GNUC__ * 100 + __GNUC_MINOR__ < 407
#  define YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN                           \
    _Pragma ("GCC diagnostic push")                                     \
    _Pragma ("GCC diagnostic ignored \"-Wuninitialized\"")
# else
#  define YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN                           \
    _Pragma ("GCC diagnostic push")                                     \
    _Pragma ("GCC diagnostic ignored \"-Wuninitialized\"")              \
    _Pragma ("GCC diagnostic ignored \"-Wmaybe-uninitialized\"")
# endif
# define YY_IGNORE_MAYBE_UNINITIALIZED_END      \
    _Pragma ("GCC diagnostic pop")
#else
# define YY_INITIAL_VALUE(Value) Value
#endif
#ifndef YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
# define YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
# define YY_IGNORE_MAYBE_UNINITIALIZED_END
#endif
#ifndef YY_INITIAL_VALUE
# define YY_INITIAL_VALUE(Value) /* Nothing. */
#endif

#if defined __cplusplus && defined __GNUC__ && ! defined __ICC && 6 <= __GNUC__
# define YY_IGNORE_USELESS_CAST_BEGIN                          \
    _Pragma ("GCC diagnostic push")                            \
    _Pragma ("GCC diagnostic ignored \"-Wuseless-cast\"")
# define YY_IGNORE_USELESS_CAST_END            \
    _Pragma ("GCC diagnostic pop")
#endif
#ifndef YY_IGNORE_USELESS_CAST_BEGIN
# define YY_IGNORE_USELESS_CAST_BEGIN
# define YY_IGNORE_USELESS_CAST_END
#endif


#define YY_ASSERT(E) ((void) (0 && (E)))

#if !defined yyoverflow

/* The parser invokes alloca or malloc; define the necessary symbols.  */

# ifdef YYSTACK_USE_ALLOCA
#  if YYSTACK_USE_ALLOCA
#   ifdef __GNUC__
#    define YYSTACK_ALLOC __builtin_alloca
#   elif defined __BUILTIN_VA_ARG_INCR
#    include <alloca.h> /* INFRINGES ON USER NAME SPACE */
#   elif defined _AIX
#    define YYSTACK_ALLOC __alloca
#   elif defined _MSC_VER
#    include <malloc.h> /* INFRINGES ON USER NAME SPACE */
#    define alloca _alloca
#   else
#    define YYSTACK_ALLOC alloca
#    if ! defined _ALLOCA_H && ! defined EXIT_SUCCESS
#     include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
      /* Use EXIT_SUCCESS as a witness for stdlib.h.  */
#     ifndef EXIT_SUCCESS
#      define EXIT_SUCCESS 0
#     endif
#    endif
#   endif
#  endif
# endif

# ifdef YYSTACK_ALLOC
   /* Pacify GCC's 'empty if-body' warning.  */
#  define YYSTACK_FREE(Ptr) do { /* empty */; } while (0)
#  ifndef YYSTACK_ALLOC_MAXIMUM
    /* The OS might guarantee only one guard page at the bottom of the stack,
       and a page size can be as small as 4096 bytes.  So we cannot safely
       invoke alloca (N) if N exceeds 4096.  Use a slightly smaller number
       to allow for a few compiler-allocated temporary stack slots.  */
#   define YYSTACK_ALLOC_MAXIMUM 4032 /* reasonable circa 2006 */
#  endif
# else
#  define YYSTACK_ALLOC YYMALLOC
#  define YYSTACK_FREE YYFREE
#  ifndef YYSTACK_ALLOC_MAXIMUM
#   define YYSTACK_ALLOC_MAXIMUM YYSIZE_MAXIMUM
#  endif
#  if (defined __cplusplus && ! defined EXIT_SUCCESS \
       && ! ((defined YYMALLOC || defined malloc) \
             && (defined YYFREE || defined free)))
#   include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
#   ifndef EXIT_SUCCESS
#    define EXIT_SUCCESS 0
#   endif
#  endif
#  ifndef YYMALLOC
#   define YYMALLOC malloc
#   if ! defined malloc && ! defined EXIT_SUCCESS
void *malloc (YYSIZE_T); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
#  ifndef YYFREE
#   define YYFREE free
#   if ! defined free && ! defined EXIT_SUCCESS
void free (void *); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
# endif
#endif /* !defined yyoverflow */

#if (! defined yyoverflow \
     && (! defined __cplusplus \
         || (defined YYSTYPE_IS_TRIVIAL && YYSTYPE_IS_TRIVIAL)))

/* A type that is properly aligned for any stack member.  */
union yyalloc
{
  yy_state_t yyss_alloc;
  YYSTYPE yyvs_alloc;
};

/* The size of the maximum gap between one aligned stack and the next.  */
# define YYSTACK_GAP_MAXIMUM (YYSIZEOF (union yyalloc) - 1)

/* The size of an array large to enough to hold all stacks, each with
   N elements.  */
# define YYSTACK_BYTES(N) \
     ((N) * (YYSIZEOF (yy_state_t) + YYSIZEOF (YYSTYPE)) \
      + YYSTACK_GAP_MAXIMUM)

# define YYCOPY_NEEDED 1

/* Relocate STACK from its old location to the new one.  The
   local variables YYSIZE and YYSTACKSIZE give the old and new number of
   elements in the stack, and YYPTR gives the new location of the
   stack.  Advance YYPTR to a properly aligned location for the next
   stack.  */
# define YYSTACK_RELOCATE(Stack_alloc, Stack)                           \
    do                                                                  \
      {                                                                 \
        YYPTRDIFF_T yynewbytes;                                         \
        YYCOPY (&yyptr->Stack_alloc, Stack, yysize);                    \
        Stack = &yyptr->Stack_alloc;                                    \
        yynewbytes = yystacksize * YYSIZEOF (*Stack) + YYSTACK_GAP_MAXIMUM; \
        yyptr += yynewbytes / YYSIZEOF (*yyptr);                        \
      }                                                                 \
    while (0)

#endif

#if defined YYCOPY_NEEDED && YYCOPY_NEEDED
/* Copy COUNT objects from SRC to DST.  The source and destination do
   not overlap.  */
# ifndef YYCOPY
#  if defined __GNUC__ && 1 < __GNUC__
#   define YYCOPY(Dst, Src, Count) \
      __builtin_memcpy (Dst, Src, YY_CAST (YYSIZE_T, (Count)) * sizeof (*(Src)))
#  else
#   define YYCOPY(Dst, Src, Count)              \
      do                                        \
        {                                       \
          YYPTRDIFF_T yyi;                      \
          for (yyi = 0; yyi < (Count); yyi++)   \
            (Dst)[yyi] = (Src)[yyi];            \
        }                                       \
      while (0)
#  endif
# endif
#endif /* !YYCOPY_NEEDED */

/* YYFINAL -- State number of the termination state.  */
#define YYFINAL  3
/* YYLAST -- Last index in YYTABLE.  */
#define YYLAST   319

/* YYNTOKENS -- Number of terminals.  */
#define YYNTOKENS  42
/* YYNNTS -- Number of nonterminals.  */
#define YYNNTS  14
/* YYNRULES -- Number of rules.  */
#define YYNRULES  79
/* YYNSTATES -- Number of states.  */
#define YYNSTATES  93

/* YYMAXUTOK -- Last valid token kind.  */
#define YYMAXUTOK   296


/* YYTRANSLATE(TOKEN-NUM) -- Symbol number corresponding to TOKEN-NUM
   as returned by yylex, with out-of-bounds checking.  */
#define YYTRANSLATE(YYX)                                \
  (0 <= (YYX) && (YYX) <= YYMAXUTOK                     \
   ? YY_CAST (yysymbol_kind_t, yytranslate[YYX])        \
   : YYSYMBOL_YYUNDEF)

/* YYTRANSLATE[TOKEN-NUM] -- Symbol number corresponding to TOKEN-NUM
   as returned by yylex.  */
static const yytype_int8 yytranslate[] =
{
       0,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     1,     2,     3,     4,
       5,     6,     7,     8,     9,    10,    11,    12,    13,    14,
      15,    16,    17,    18,    19,    20,    21,    22,    23,    24,
      25,    26,    27,    28,    29,    30,    31,    32,    33,    34,
      35,    36,    37,    38,    39,    40,    41
};

#if YYDEBUG
/* YYRLINE[YYN] -- Source line where rule number YYN was defined.  */
static const yytype_int16 yyrline[] =
{
       0,   150,   150,   150,   158,   159,   169,   213,   214,   215,
     216,   217,   218,   219,   220,   221,   222,   223,   224,   225,
     226,   227,   228,   229,   230,   231,   232,   233,   234,   237,
     246,   257,   265,   273,   288,   305,   315,   325,   335,   341,
     351,   368,   413,   451,   505,   510,   515,   521,   538,   557,
     562,   569,   584,   601,   606,   613,   614,   615,   616,   621,
     628,   629,   630,   637,   638,   639,   640,   641,   642,   643,
     644,   645,   646,   647,   648,   649,   650,   651,   652,   655
};
#endif

/** Accessing symbol of state STATE.  */
#define YY_ACCESSING_SYMBOL(State) YY_CAST (yysymbol_kind_t, yystos[State])

#if YYDEBUG || 0
/* The user-facing name of the symbol whose (internal) number is
   YYSYMBOL.  No bounds checking.  */
static const char *yysymbol_name (yysymbol_kind_t yysymbol) YY_ATTRIBUTE_UNUSED;

/* YYTNAME[SYMBOL-NUM] -- String name of the symbol SYMBOL-NUM.
   First, the terminals, then, starting at YYNTOKENS, nonterminals.  */
static const char *const yytname[] =
{
  "\"end of file\"", "error", "\"invalid token\"", "COMMENT", "MAP",
  "OPT_TIMEOUT", "OPT_NTIMEOUT", "OPT_PTIMEOUT", "OPT_NOBIND",
  "OPT_NOGHOST", "OPT_GHOST", "OPT_VERBOSE", "OPT_DEBUG", "OPT_RANDOM",
  "OPT_USE_WEIGHT", "OPT_SYMLINK", "OPT_MODE", "OPT_STRICTEXPIRE",
  "OPT_SHARED", "OPT_SLAVE", "OPT_PRIVATE", "COLON", "COMMA", "NL",
  "DDASH", "PATH", "QUOTE", "NILL", "SPACE", "EQUAL", "MULTITYPE",
  "MAPTYPE", "DNSERVER", "DNATTR", "DNNAME", "MAPHOSTS", "MAPNULL",
  "MAPXFN", "MAPNAME", "NUMBER", "OCTALNUMBER", "OPTION", "$accept",
  "file", "$@1", "line", "mapspec", "maplist", "map", "dn", "dnattrs",
  "dnattr", "options", "option", "daemon_option", "mount_option", YY_NULLPTR
};

static const char *
yysymbol_name (yysymbol_kind_t yysymbol)
{
  return yytname[yysymbol];
}
#endif

#define YYPACT_NINF (-40)

#define yypact_value_is_default(Yyn) \
  ((Yyn) == YYPACT_NINF)

#define YYTABLE_NINF (-35)

#define yytable_value_is_error(Yyn) \
  0

/* YYPACT[STATE-NUM] -- Index in YYTABLE of the portion describing
   STATE-NUM.  */
static const yytype_int16 yypact[] =
{
     -40,     6,    75,   -40,   -40,   261,   -40,   -40,   -40,   -40,
     -40,   -40,   -40,   -40,   -40,   -40,   -40,   -40,   -40,   -40,
     -40,   -40,   -40,   -40,   -40,   -40,   -40,   109,     0,     1,
     -40,   -40,   -40,   -40,   -40,   -40,   -40,   187,   -40,     5,
     113,   -40,   -29,   -40,   -40,   -40,    26,   -40,    -4,    -3,
      23,   -40,   -40,   -40,   -40,   -40,   -40,   -40,   -40,    24,
     -40,   -40,   -40,   -40,   -40,    76,   -40,   -40,   -40,   109,
       2,   -40,    43,   -40,   -40,   -40,   -40,   207,   -40,   -40,
     150,    -6,   244,   -40,    39,    37,   -40,   -40,   -40,    33,
      47,    -6,   -40
};

/* YYDEFACT[STATE-NUM] -- Default reduction number in state STATE-NUM.
   Performed when YYTABLE does not specify something else to do.  Zero
   means the default is an error.  */
static const yytype_int8 yydefact[] =
{
       2,     0,     4,     1,    28,    24,    25,    27,    26,     3,
      13,    19,    21,    20,    22,    12,    10,    11,    14,    23,
      15,    16,    17,    18,     7,    35,     9,     0,    46,    50,
      49,    37,    39,    38,    36,     8,     5,     0,    40,     6,
       0,    41,     0,    42,    43,    45,     0,    62,     0,     0,
       0,    71,    72,    73,    74,    75,    76,    77,    66,     0,
      67,    68,    69,    70,    79,     0,    55,    60,    61,     0,
       0,    44,    47,    63,    64,    65,    78,     0,    59,    57,
       0,     0,     0,    56,     0,    53,    54,    48,    58,     0,
      51,     0,    52
};

/* YYPGOTO[NTERM-NUM].  */
static const yytype_int16 yypgoto[] =
{
     -40,   -40,   -40,   -40,   -40,   -40,   -27,   -40,    -5,   -21,
     -39,   235,   -40,   -40
};

/* YYDEFGOTO[NTERM-NUM].  */
static const yytype_int8 yydefgoto[] =
{
       0,     1,     2,     9,    36,    39,    37,    44,    38,    87,
      65,    66,    67,    68
};

/* YYTABLE[YYPACT[STATE-NUM]] -- What to do in state STATE-NUM.  If
   positive, shift that token.  If negative, reduce the rule whose
   number is the opposite.  If YYTABLE_NINF, syntax error.  */
static const yytype_int8 yytable[] =
{
      40,    70,   -32,    47,    29,    30,     3,    48,    49,    50,
      51,    52,    53,    54,    55,    56,    57,    58,    59,    60,
      61,    62,    63,    45,    77,    41,   -32,    85,    86,    69,
      46,    78,    42,    29,    30,    73,    74,    71,    43,   -34,
      47,    84,    80,    64,    48,    49,    50,    51,    52,    53,
      54,    55,    56,    57,    58,    59,    60,    61,    62,    63,
      72,    77,    75,   -34,    76,    81,    89,    90,    78,    91,
      92,     0,     0,     0,     0,     0,   -30,    47,     4,     0,
      64,    48,    49,    50,    51,    52,    53,    54,    55,    56,
      57,    58,    59,    60,    61,    62,    63,     0,    77,     0,
       5,     6,     7,     0,     0,    78,     0,     0,     0,     0,
       0,     0,     0,   -31,    47,     0,     8,    64,    48,    49,
      50,    51,    52,    53,    54,    55,    56,    57,    58,    59,
      60,    61,    62,    63,    25,     0,     0,   -31,     0,     0,
      28,     0,    29,    30,    31,    32,    33,    34,     0,     0,
     -33,    47,     0,     0,    64,    48,    49,    50,    51,    52,
      53,    54,    55,    56,    57,    58,    59,    60,    61,    62,
      63,     0,     0,     0,   -33,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,   -29,    47,     0,
       0,    64,    48,    49,    50,    51,    52,    53,    54,    55,
      56,    57,    58,    59,    60,    61,    62,    63,    47,     0,
       0,     0,    48,    49,    50,    51,    52,    53,    54,    55,
      56,    57,    58,    59,    60,    61,    62,    63,    64,    82,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,    47,     0,     0,    64,    48,
      49,    50,    51,    52,    53,    54,    55,    56,    57,    58,
      59,    60,    61,    62,    63,     0,    10,     0,     0,    11,
      12,    13,    14,    15,    16,    17,    18,    19,    20,    21,
      22,    23,    24,     0,     0,    64,    25,     0,    26,     0,
       0,    27,    28,     0,    29,    30,    31,    32,    33,    34,
      79,     0,    35,     0,     0,    79,     0,     0,     0,     0,
       0,     0,    83,     0,     0,     0,     0,    88,     0,    79
};

static const yytype_int8 yycheck[] =
{
      27,    40,     0,     1,    33,    34,     0,     5,     6,     7,
       8,     9,    10,    11,    12,    13,    14,    15,    16,    17,
      18,    19,    20,    28,    22,    25,    24,    33,    34,    24,
      29,    29,    32,    33,    34,    39,    39,    42,    38,     0,
       1,    80,    69,    41,     5,     6,     7,     8,     9,    10,
      11,    12,    13,    14,    15,    16,    17,    18,    19,    20,
      34,    22,    39,    24,    40,    22,    29,    34,    29,    22,
      91,    -1,    -1,    -1,    -1,    -1,     0,     1,     3,    -1,
      41,     5,     6,     7,     8,     9,    10,    11,    12,    13,
      14,    15,    16,    17,    18,    19,    20,    -1,    22,    -1,
      25,    26,    27,    -1,    -1,    29,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,     0,     1,    -1,    41,    41,     5,     6,
       7,     8,     9,    10,    11,    12,    13,    14,    15,    16,
      17,    18,    19,    20,    25,    -1,    -1,    24,    -1,    -1,
      31,    -1,    33,    34,    35,    36,    37,    38,    -1,    -1,
       0,     1,    -1,    -1,    41,     5,     6,     7,     8,     9,
      10,    11,    12,    13,    14,    15,    16,    17,    18,    19,
      20,    -1,    -1,    -1,    24,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,     0,     1,    -1,
      -1,    41,     5,     6,     7,     8,     9,    10,    11,    12,
      13,    14,    15,    16,    17,    18,    19,    20,     1,    -1,
      -1,    -1,     5,     6,     7,     8,     9,    10,    11,    12,
      13,    14,    15,    16,    17,    18,    19,    20,    41,    22,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,     1,    -1,    -1,    41,     5,
       6,     7,     8,     9,    10,    11,    12,    13,    14,    15,
      16,    17,    18,    19,    20,    -1,     5,    -1,    -1,     8,
       9,    10,    11,    12,    13,    14,    15,    16,    17,    18,
      19,    20,    21,    -1,    -1,    41,    25,    -1,    27,    -1,
      -1,    30,    31,    -1,    33,    34,    35,    36,    37,    38,
      65,    -1,    41,    -1,    -1,    70,    -1,    -1,    -1,    -1,
      -1,    -1,    77,    -1,    -1,    -1,    -1,    82,    -1,    84
};

/* YYSTOS[STATE-NUM] -- The symbol kind of the accessing symbol of
   state STATE-NUM.  */
static const yytype_int8 yystos[] =
{
       0,    43,    44,     0,     3,    25,    26,    27,    41,    45,
       5,     8,     9,    10,    11,    12,    13,    14,    15,    16,
      17,    18,    19,    20,    21,    25,    27,    30,    31,    33,
      34,    35,    36,    37,    38,    41,    46,    48,    50,    47,
      48,    25,    32,    38,    49,    50,    29,     1,     5,     6,
       7,     8,     9,    10,    11,    12,    13,    14,    15,    16,
      17,    18,    19,    20,    41,    52,    53,    54,    55,    24,
      52,    50,    34,    39,    39,    39,    40,    22,    29,    53,
      48,    22,    22,    53,    52,    33,    34,    51,    53,    29,
      34,    22,    51
};

/* YYR1[RULE-NUM] -- Symbol kind of the left-hand side of rule RULE-NUM.  */
static const yytype_int8 yyr1[] =
{
       0,    42,    44,    43,    45,    45,    45,    45,    45,    45,
      45,    45,    45,    45,    45,    45,    45,    45,    45,    45,
      45,    45,    45,    45,    45,    45,    45,    45,    45,    46,
      46,    47,    47,    47,    47,    48,    48,    48,    48,    48,
      48,    48,    48,    48,    49,    49,    49,    50,    50,    50,
      50,    51,    51,    51,    51,    52,    52,    52,    52,    52,
      53,    53,    53,    54,    54,    54,    54,    54,    54,    54,
      54,    54,    54,    54,    54,    54,    54,    54,    54,    55
};

/* YYR2[RULE-NUM] -- Number of symbols on the right-hand side of rule RULE-NUM.  */
static const yytype_int8 yyr2[] =
{
       0,     2,     0,     2,     0,     2,     3,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     1,     1,     1,     1,     1,     1,
       2,     1,     2,     3,     4,     1,     1,     1,     1,     1,
       1,     2,     2,     2,     2,     1,     0,     3,     5,     1,
       1,     3,     5,     1,     1,     1,     3,     2,     4,     2,
       1,     1,     1,     2,     2,     2,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     2,     1
};


enum { YYENOMEM = -2 };

#define yyerrok         (yyerrstatus = 0)
#define yyclearin       (yychar = YYEMPTY)

#define YYACCEPT        goto yyacceptlab
#define YYABORT         goto yyabortlab
#define YYERROR         goto yyerrorlab
#define YYNOMEM         goto yyexhaustedlab


#define YYRECOVERING()  (!!yyerrstatus)

#define YYBACKUP(Token, Value)                                    \
  do                                                              \
    if (yychar == YYEMPTY)                                        \
      {                                                           \
        yychar = (Token);                                         \
        yylval = (Value);                                         \
        YYPOPSTACK (yylen);                                       \
        yystate = *yyssp;                                         \
        goto yybackup;                                            \
      }                                                           \
    else                                                          \
      {                                                           \
        yyerror (YY_("syntax error: cannot back up")); \
        YYERROR;                                                  \
      }                                                           \
  while (0)

/* Backward compatibility with an undocumented macro.
   Use YYerror or YYUNDEF. */
#define YYERRCODE YYUNDEF


/* Enable debugging if requested.  */
#if YYDEBUG

# ifndef YYFPRINTF
#  include <stdio.h> /* INFRINGES ON USER NAME SPACE */
#  define YYFPRINTF fprintf
# endif

# define YYDPRINTF(Args)                        \
do {                                            \
  if (yydebug)                                  \
    YYFPRINTF Args;                             \
} while (0)




# define YY_SYMBOL_PRINT(Title, Kind, Value, Location)                    \
do {                                                                      \
  if (yydebug)                                                            \
    {                                                                     \
      YYFPRINTF (stderr, "%s ", Title);                                   \
      yy_symbol_print (stderr,                                            \
                  Kind, Value); \
      YYFPRINTF (stderr, "\n");                                           \
    }                                                                     \
} while (0)


/*-----------------------------------.
| Print this symbol's value on YYO.  |
`-----------------------------------*/

static void
yy_symbol_value_print (FILE *yyo,
                       yysymbol_kind_t yykind, YYSTYPE const * const yyvaluep)
{
  FILE *yyoutput = yyo;
  YY_USE (yyoutput);
  if (!yyvaluep)
    return;
  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  YY_USE (yykind);
  YY_IGNORE_MAYBE_UNINITIALIZED_END
}


/*---------------------------.
| Print this symbol on YYO.  |
`---------------------------*/

static void
yy_symbol_print (FILE *yyo,
                 yysymbol_kind_t yykind, YYSTYPE const * const yyvaluep)
{
  YYFPRINTF (yyo, "%s %s (",
             yykind < YYNTOKENS ? "token" : "nterm", yysymbol_name (yykind));

  yy_symbol_value_print (yyo, yykind, yyvaluep);
  YYFPRINTF (yyo, ")");
}

/*------------------------------------------------------------------.
| yy_stack_print -- Print the state stack from its BOTTOM up to its |
| TOP (included).                                                   |
`------------------------------------------------------------------*/

static void
yy_stack_print (yy_state_t *yybottom, yy_state_t *yytop)
{
  YYFPRINTF (stderr, "Stack now");
  for (; yybottom <= yytop; yybottom++)
    {
      int yybot = *yybottom;
      YYFPRINTF (stderr, " %d", yybot);
    }
  YYFPRINTF (stderr, "\n");
}

# define YY_STACK_PRINT(Bottom, Top)                            \
do {                                                            \
  if (yydebug)                                                  \
    yy_stack_print ((Bottom), (Top));                           \
} while (0)


/*------------------------------------------------.
| Report that the YYRULE is going to be reduced.  |
`------------------------------------------------*/

static void
yy_reduce_print (yy_state_t *yyssp, YYSTYPE *yyvsp,
                 int yyrule)
{
  int yylno = yyrline[yyrule];
  int yynrhs = yyr2[yyrule];
  int yyi;
  YYFPRINTF (stderr, "Reducing stack by rule %d (line %d):\n",
             yyrule - 1, yylno);
  /* The symbols being reduced.  */
  for (yyi = 0; yyi < yynrhs; yyi++)
    {
      YYFPRINTF (stderr, "   $%d = ", yyi + 1);
      yy_symbol_print (stderr,
                       YY_ACCESSING_SYMBOL (+yyssp[yyi + 1 - yynrhs]),
                       &yyvsp[(yyi + 1) - (yynrhs)]);
      YYFPRINTF (stderr, "\n");
    }
}

# define YY_REDUCE_PRINT(Rule)          \
do {                                    \
  if (yydebug)                          \
    yy_reduce_print (yyssp, yyvsp, Rule); \
} while (0)

/* Nonzero means print parse trace.  It is left uninitialized so that
   multiple parsers can coexist.  */
int yydebug;
#else /* !YYDEBUG */
# define YYDPRINTF(Args) ((void) 0)
# define YY_SYMBOL_PRINT(Title, Kind, Value, Location)
# define YY_STACK_PRINT(Bottom, Top)
# define YY_REDUCE_PRINT(Rule)
#endif /* !YYDEBUG */


/* YYINITDEPTH -- initial size of the parser's stacks.  */
#ifndef YYINITDEPTH
# define YYINITDEPTH 200
#endif

/* YYMAXDEPTH -- maximum size the stacks can grow to (effective only
   if the built-in stack extension method is used).

   Do not make this value too large; the results are undefined if
   YYSTACK_ALLOC_MAXIMUM < YYSTACK_BYTES (YYMAXDEPTH)
   evaluated with infinite-precision integer arithmetic.  */

#ifndef YYMAXDEPTH
# define YYMAXDEPTH 10000
#endif






/*-----------------------------------------------.
| Release the memory associated to this symbol.  |
`-----------------------------------------------*/

static void
yydestruct (const char *yymsg,
            yysymbol_kind_t yykind, YYSTYPE *yyvaluep)
{
  YY_USE (yyvaluep);
  if (!yymsg)
    yymsg = "Deleting";
  YY_SYMBOL_PRINT (yymsg, yykind, yyvaluep, yylocationp);

  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  YY_USE (yykind);
  YY_IGNORE_MAYBE_UNINITIALIZED_END
}


/* Lookahead token kind.  */
int yychar;

/* The semantic value of the lookahead symbol.  */
YYSTYPE yylval;
/* Number of syntax errors so far.  */
int yynerrs;




/*----------.
| yyparse.  |
`----------*/

int
yyparse (void)
{
    yy_state_fast_t yystate = 0;
    /* Number of tokens to shift before error messages enabled.  */
    int yyerrstatus = 0;

    /* Refer to the stacks through separate pointers, to allow yyoverflow
       to reallocate them elsewhere.  */

    /* Their size.  */
    YYPTRDIFF_T yystacksize = YYINITDEPTH;

    /* The state stack: array, bottom, top.  */
    yy_state_t yyssa[YYINITDEPTH];
    yy_state_t *yyss = yyssa;
    yy_state_t *yyssp = yyss;

    /* The semantic value stack: array, bottom, top.  */
    YYSTYPE yyvsa[YYINITDEPTH];
    YYSTYPE *yyvs = yyvsa;
    YYSTYPE *yyvsp = yyvs;

  int yyn;
  /* The return value of yyparse.  */
  int yyresult;
  /* Lookahead symbol kind.  */
  yysymbol_kind_t yytoken = YYSYMBOL_YYEMPTY;
  /* The variables used to return semantic value and location from the
     action routines.  */
  YYSTYPE yyval;



#define YYPOPSTACK(N)   (yyvsp -= (N), yyssp -= (N))

  /* The number of symbols on the RHS of the reduced rule.
     Keep to zero when no symbol should be popped.  */
  int yylen = 0;

  YYDPRINTF ((stderr, "Starting parse\n"));

  yychar = YYEMPTY; /* Cause a token to be read.  */

  goto yysetstate;


/*------------------------------------------------------------.
| yynewstate -- push a new state, which is found in yystate.  |
`------------------------------------------------------------*/
yynewstate:
  /* In all cases, when you get here, the value and location stacks
     have just been pushed.  So pushing a state here evens the stacks.  */
  yyssp++;


/*--------------------------------------------------------------------.
| yysetstate -- set current state (the top of the stack) to yystate.  |
`--------------------------------------------------------------------*/
yysetstate:
  YYDPRINTF ((stderr, "Entering state %d\n", yystate));
  YY_ASSERT (0 <= yystate && yystate < YYNSTATES);
  YY_IGNORE_USELESS_CAST_BEGIN
  *yyssp = YY_CAST (yy_state_t, yystate);
  YY_IGNORE_USELESS_CAST_END
  YY_STACK_PRINT (yyss, yyssp);

  if (yyss + yystacksize - 1 <= yyssp)
#if !defined yyoverflow && !defined YYSTACK_RELOCATE
    YYNOMEM;
#else
    {
      /* Get the current used size of the three stacks, in elements.  */
      YYPTRDIFF_T yysize = yyssp - yyss + 1;

# if defined yyoverflow
      {
        /* Give user a chance to reallocate the stack.  Use copies of
           these so that the &'s don't force the real ones into
           memory.  */
        yy_state_t *yyss1 = yyss;
        YYSTYPE *yyvs1 = yyvs;

        /* Each stack pointer address is followed by the size of the
           data in use in that stack, in bytes.  This used to be a
           conditional around just the two extra args, but that might
           be undefined if yyoverflow is a macro.  */
        yyoverflow (YY_("memory exhausted"),
                    &yyss1, yysize * YYSIZEOF (*yyssp),
                    &yyvs1, yysize * YYSIZEOF (*yyvsp),
                    &yystacksize);
        yyss = yyss1;
        yyvs = yyvs1;
      }
# else /* defined YYSTACK_RELOCATE */
      /* Extend the stack our own way.  */
      if (YYMAXDEPTH <= yystacksize)
        YYNOMEM;
      yystacksize *= 2;
      if (YYMAXDEPTH < yystacksize)
        yystacksize = YYMAXDEPTH;

      {
        yy_state_t *yyss1 = yyss;
        union yyalloc *yyptr =
          YY_CAST (union yyalloc *,
                   YYSTACK_ALLOC (YY_CAST (YYSIZE_T, YYSTACK_BYTES (yystacksize))));
        if (! yyptr)
          YYNOMEM;
        YYSTACK_RELOCATE (yyss_alloc, yyss);
        YYSTACK_RELOCATE (yyvs_alloc, yyvs);
#  undef YYSTACK_RELOCATE
        if (yyss1 != yyssa)
          YYSTACK_FREE (yyss1);
      }
# endif

      yyssp = yyss + yysize - 1;
      yyvsp = yyvs + yysize - 1;

      YY_IGNORE_USELESS_CAST_BEGIN
      YYDPRINTF ((stderr, "Stack size increased to %ld\n",
                  YY_CAST (long, yystacksize)));
      YY_IGNORE_USELESS_CAST_END

      if (yyss + yystacksize - 1 <= yyssp)
        YYABORT;
    }
#endif /* !defined yyoverflow && !defined YYSTACK_RELOCATE */


  if (yystate == YYFINAL)
    YYACCEPT;

  goto yybackup;


/*-----------.
| yybackup.  |
`-----------*/
yybackup:
  /* Do appropriate processing given the current state.  Read a
     lookahead token if we need one and don't already have one.  */

  /* First try to decide what to do without reference to lookahead token.  */
  yyn = yypact[yystate];
  if (yypact_value_is_default (yyn))
    goto yydefault;

  /* Not known => get a lookahead token if don't already have one.  */

  /* YYCHAR is either empty, or end-of-input, or a valid lookahead.  */
  if (yychar == YYEMPTY)
    {
      YYDPRINTF ((stderr, "Reading a token\n"));
      yychar = yylex ();
    }

  if (yychar <= YYEOF)
    {
      yychar = YYEOF;
      yytoken = YYSYMBOL_YYEOF;
      YYDPRINTF ((stderr, "Now at end of input.\n"));
    }
  else if (yychar == YYerror)
    {
      /* The scanner already issued an error message, process directly
         to error recovery.  But do not keep the error token as
         lookahead, it is too special and may lead us to an endless
         loop in error recovery. */
      yychar = YYUNDEF;
      yytoken = YYSYMBOL_YYerror;
      goto yyerrlab1;
    }
  else
    {
      yytoken = YYTRANSLATE (yychar);
      YY_SYMBOL_PRINT ("Next token is", yytoken, &yylval, &yylloc);
    }

  /* If the proper action on seeing token YYTOKEN is to reduce or to
     detect an error, take that action.  */
  yyn += yytoken;
  if (yyn < 0 || YYLAST < yyn || yycheck[yyn] != yytoken)
    goto yydefault;
  yyn = yytable[yyn];
  if (yyn <= 0)
    {
      if (yytable_value_is_error (yyn))
        goto yyerrlab;
      yyn = -yyn;
      goto yyreduce;
    }

  /* Count tokens shifted since error; after three, turn off error
     status.  */
  if (yyerrstatus)
    yyerrstatus--;

  /* Shift the lookahead token.  */
  YY_SYMBOL_PRINT ("Shifting", yytoken, &yylval, &yylloc);
  yystate = yyn;
  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  *++yyvsp = yylval;
  YY_IGNORE_MAYBE_UNINITIALIZED_END

  /* Discard the shifted token.  */
  yychar = YYEMPTY;
  goto yynewstate;


/*-----------------------------------------------------------.
| yydefault -- do the default action for the current state.  |
`-----------------------------------------------------------*/
yydefault:
  yyn = yydefact[yystate];
  if (yyn == 0)
    goto yyerrlab;
  goto yyreduce;


/*-----------------------------.
| yyreduce -- do a reduction.  |
`-----------------------------*/
yyreduce:
  /* yyn is the number of a rule to reduce with.  */
  yylen = yyr2[yyn];

  /* If YYLEN is nonzero, implement the default value of the action:
     '$$ = $1'.

     Otherwise, the following line sets YYVAL to garbage.
     This behavior is undocumented and Bison
     users should not rely upon it.  Assigning to YYVAL
     unconditionally makes the parser a bit smaller, and it avoids a
     GCC warning that YYVAL may be used uninitialized.  */
  yyval = yyvsp[1-yylen];


  YY_REDUCE_PRINT (yyn);
  switch (yyn)
    {
  case 2: /* $@1: %empty  */
#line 150 "master_parse.y"
      {
		master_lineno = 0;
#if YYDEBUG != 0
		master_debug = YYDEBUG;
#endif
	}
#line 1342 "master_parse.tab.c"
    break;

  case 5: /* line: PATH mapspec  */
#line 160 "master_parse.y"
        {
		if (path)
			free(path);
		path = master_strdup((yyvsp[-1].strtype));
		if (!path) {
			local_free_vars();
			YYABORT;
		}
	}
#line 1356 "master_parse.tab.c"
    break;

  case 6: /* line: PATH MULTITYPE maplist  */
#line 170 "master_parse.y"
        {
		char *tmp = NULL;

		trim_maptype((yyvsp[-1].strtype));

		if (path)
			free(path);
		path = master_strdup((yyvsp[-2].strtype));
		if (!path) {
			master_error("memory allocation error");
			local_free_vars();
			YYABORT;
		}

		if ((tmp = strchr((yyvsp[-1].strtype), ',')))
			*tmp++ = '\0';
#ifndef WITH_HESIOD
		/* Map type or map type parser is hesiod */
		if (!strcmp((yyvsp[-1].strtype), "hesiod") || (tmp && !strcmp(tmp, "hesiod"))) {
			master_error("hesiod support not built in");
			local_free_vars();
			YYABORT;
		}
#endif
		if (type)
			free(type);
		type = master_strdup((yyvsp[-1].strtype));
		if (!type) {
			master_error("memory allocation error");
			local_free_vars();
			YYABORT;
		}
		if (tmp) {
			if (format)
				free(format);
			format = master_strdup(tmp);
			if (!format) {
				master_error("memory allocation error");
				local_free_vars();
				YYABORT;
			}
		}
	}
#line 1404 "master_parse.tab.c"
    break;

  case 7: /* line: PATH COLON  */
#line 213 "master_parse.y"
                     { master_notify((yyvsp[-1].strtype)); YYABORT; }
#line 1410 "master_parse.tab.c"
    break;

  case 8: /* line: PATH OPTION  */
#line 214 "master_parse.y"
                      { master_notify((yyvsp[0].strtype)); YYABORT; }
#line 1416 "master_parse.tab.c"
    break;

  case 9: /* line: PATH NILL  */
#line 215 "master_parse.y"
                    { master_notify((yyvsp[0].strtype)); YYABORT; }
#line 1422 "master_parse.tab.c"
    break;

  case 10: /* line: PATH OPT_RANDOM  */
#line 216 "master_parse.y"
                          { master_notify((yyvsp[-1].strtype)); YYABORT; }
#line 1428 "master_parse.tab.c"
    break;

  case 11: /* line: PATH OPT_USE_WEIGHT  */
#line 217 "master_parse.y"
                              { master_notify((yyvsp[-1].strtype)); YYABORT; }
#line 1434 "master_parse.tab.c"
    break;

  case 12: /* line: PATH OPT_DEBUG  */
#line 218 "master_parse.y"
                         { master_notify((yyvsp[-1].strtype)); YYABORT; }
#line 1440 "master_parse.tab.c"
    break;

  case 13: /* line: PATH OPT_TIMEOUT  */
#line 219 "master_parse.y"
                           { master_notify((yyvsp[-1].strtype)); YYABORT; }
#line 1446 "master_parse.tab.c"
    break;

  case 14: /* line: PATH OPT_SYMLINK  */
#line 220 "master_parse.y"
                           { master_notify((yyvsp[-1].strtype)); YYABORT; }
#line 1452 "master_parse.tab.c"
    break;

  case 15: /* line: PATH OPT_STRICTEXPIRE  */
#line 221 "master_parse.y"
                                { master_notify((yyvsp[-1].strtype)); YYABORT; }
#line 1458 "master_parse.tab.c"
    break;

  case 16: /* line: PATH OPT_SHARED  */
#line 222 "master_parse.y"
                          { master_notify((yyvsp[-1].strtype)); YYABORT; }
#line 1464 "master_parse.tab.c"
    break;

  case 17: /* line: PATH OPT_SLAVE  */
#line 223 "master_parse.y"
                         { master_notify((yyvsp[-1].strtype)); YYABORT; }
#line 1470 "master_parse.tab.c"
    break;

  case 18: /* line: PATH OPT_PRIVATE  */
#line 224 "master_parse.y"
                           { master_notify((yyvsp[-1].strtype)); YYABORT; }
#line 1476 "master_parse.tab.c"
    break;

  case 19: /* line: PATH OPT_NOBIND  */
#line 225 "master_parse.y"
                          { master_notify((yyvsp[-1].strtype)); YYABORT; }
#line 1482 "master_parse.tab.c"
    break;

  case 20: /* line: PATH OPT_GHOST  */
#line 226 "master_parse.y"
                         { master_notify((yyvsp[-1].strtype)); YYABORT; }
#line 1488 "master_parse.tab.c"
    break;

  case 21: /* line: PATH OPT_NOGHOST  */
#line 227 "master_parse.y"
                           { master_notify((yyvsp[-1].strtype)); YYABORT; }
#line 1494 "master_parse.tab.c"
    break;

  case 22: /* line: PATH OPT_VERBOSE  */
#line 228 "master_parse.y"
                           { master_notify((yyvsp[-1].strtype)); YYABORT; }
#line 1500 "master_parse.tab.c"
    break;

  case 23: /* line: PATH OPT_MODE  */
#line 229 "master_parse.y"
                        { master_notify((yyvsp[-1].strtype)); YYABORT; }
#line 1506 "master_parse.tab.c"
    break;

  case 24: /* line: PATH  */
#line 230 "master_parse.y"
               { master_notify((yyvsp[0].strtype)); YYABORT; }
#line 1512 "master_parse.tab.c"
    break;

  case 25: /* line: QUOTE  */
#line 231 "master_parse.y"
                { master_notify((yyvsp[0].strtype)); YYABORT; }
#line 1518 "master_parse.tab.c"
    break;

  case 26: /* line: OPTION  */
#line 232 "master_parse.y"
                 { master_notify((yyvsp[0].strtype)); YYABORT; }
#line 1524 "master_parse.tab.c"
    break;

  case 27: /* line: NILL  */
#line 233 "master_parse.y"
               { master_notify((yyvsp[0].strtype)); YYABORT; }
#line 1530 "master_parse.tab.c"
    break;

  case 28: /* line: COMMENT  */
#line 234 "master_parse.y"
                  { YYABORT; }
#line 1536 "master_parse.tab.c"
    break;

  case 29: /* mapspec: map  */
#line 238 "master_parse.y"
        {
		if (local_argv)
			free_argv(local_argc, (const char **) local_argv);
		local_argc = tmp_argc;
		local_argv = tmp_argv;
		tmp_argc = 0;
		tmp_argv = NULL;
	}
#line 1549 "master_parse.tab.c"
    break;

  case 30: /* mapspec: map options  */
#line 247 "master_parse.y"
        {
		if (local_argv)
			free_argv(local_argc, (const char **) local_argv);
		local_argc = tmp_argc;
		local_argv = tmp_argv;
		tmp_argc = 0;
		tmp_argv = NULL;
	}
#line 1562 "master_parse.tab.c"
    break;

  case 31: /* maplist: map  */
#line 258 "master_parse.y"
        {
		if (!add_multi_mapstr()) {
			master_error("memory allocation error");
			local_free_vars();
			YYABORT;
		}
	}
#line 1574 "master_parse.tab.c"
    break;

  case 32: /* maplist: map options  */
#line 266 "master_parse.y"
        {
		if (!add_multi_mapstr()) {
			master_error("memory allocation error");
			local_free_vars();
			YYABORT;
		}
	}
#line 1586 "master_parse.tab.c"
    break;

  case 33: /* maplist: maplist DDASH map  */
#line 274 "master_parse.y"
        {
		local_argc++;
		local_argv = add_argv(local_argc, local_argv, "--");
		if (!local_argv) {
			master_error("memory allocation error");
			local_free_vars();
			YYABORT;
		}
		if (!add_multi_mapstr()) {
			master_error("memory allocation error");
			local_free_vars();
			YYABORT;
		}
	}
#line 1605 "master_parse.tab.c"
    break;

  case 34: /* maplist: maplist DDASH map options  */
#line 289 "master_parse.y"
        {
		local_argc++;
		local_argv = add_argv(local_argc, local_argv, "--");
		if (!local_argv) {
			master_error("memory allocation error");
			local_free_vars();
			YYABORT;
		}
		if (!add_multi_mapstr()) {
			master_error("memory allocation error");
			local_free_vars();
			YYABORT;
		}
	}
#line 1624 "master_parse.tab.c"
    break;

  case 35: /* map: PATH  */
#line 306 "master_parse.y"
        {
		tmp_argc++;
		tmp_argv = add_argv(tmp_argc, tmp_argv, (yyvsp[0].strtype));
		if (!tmp_argv) {
			master_error("memory allocation error");
			local_free_vars();
			YYABORT;
		}
	}
#line 1638 "master_parse.tab.c"
    break;

  case 36: /* map: MAPNAME  */
#line 316 "master_parse.y"
        {
		tmp_argc++;
		tmp_argv = add_argv(tmp_argc, tmp_argv, (yyvsp[0].strtype));
		if (!tmp_argv) {
			master_error("memory allocation error");
			local_free_vars();
			YYABORT;
		}
	}
#line 1652 "master_parse.tab.c"
    break;

  case 37: /* map: MAPHOSTS  */
#line 326 "master_parse.y"
        {
		if (type)
			free(type);
		type = master_strdup((yyvsp[0].strtype) + 1);
		if (!type) {
			local_free_vars();
			YYABORT;
		}
	}
#line 1666 "master_parse.tab.c"
    break;

  case 38: /* map: MAPXFN  */
#line 336 "master_parse.y"
        {
		master_notify((yyvsp[0].strtype));
		master_msg("X/Open Federated Naming service not supported");
		YYABORT;
	}
#line 1676 "master_parse.tab.c"
    break;

  case 39: /* map: MAPNULL  */
#line 342 "master_parse.y"
        {
		if (type)
			free(type);
		type = master_strdup((yyvsp[0].strtype) + 1);
		if (!type) {
			local_free_vars();
			YYABORT;
		}
	}
#line 1690 "master_parse.tab.c"
    break;

  case 40: /* map: dnattrs  */
#line 352 "master_parse.y"
        {
		if (type)
			free(type);
		type = master_strdup("ldap");
		if (!type) {
			local_free_vars();
			YYABORT;
		}
		tmp_argc++;
		tmp_argv = add_argv(tmp_argc, tmp_argv, (yyvsp[0].strtype));
		if (!tmp_argv) {
			master_error("memory allocation error");
			local_free_vars();
			YYABORT;
		}
	}
#line 1711 "master_parse.tab.c"
    break;

  case 41: /* map: MAPTYPE PATH  */
#line 369 "master_parse.y"
        {
		char *tmp = NULL;

		trim_maptype((yyvsp[-1].strtype));

		if ((tmp = strchr((yyvsp[-1].strtype), ',')))
			*tmp++ = '\0';
#ifndef WITH_HESIOD
		/* Map type or map type parser is hesiod */
		if (!strcmp((yyvsp[-1].strtype), "hesiod") || (tmp && !strcmp(tmp, "hesiod"))) {
			master_error("hesiod support not built in");
			local_free_vars();
			YYABORT;
		}
#endif
		if (type)
			free(type);
		if (strcmp((yyvsp[-1].strtype), "exec"))
			type = master_strdup((yyvsp[-1].strtype));
		else
			type = master_strdup("program");
		if (!type) {
			master_error("memory allocation error");
			local_free_vars();
			YYABORT;
		}
		if (tmp) {
			if (format)
				free(format);
			format = master_strdup(tmp);
			if (!format) {
				master_error("memory allocation error");
				local_free_vars();
				YYABORT;
			}
		}
		tmp_argc++;
		tmp_argv = add_argv(tmp_argc, tmp_argv, (yyvsp[0].strtype));
		if (!tmp_argv) {
			master_error("memory allocation error");
			local_free_vars();
			YYABORT;
		}
	}
#line 1760 "master_parse.tab.c"
    break;

  case 42: /* map: MAPTYPE MAPNAME  */
#line 414 "master_parse.y"
        {
		char *tmp = NULL;

		trim_maptype((yyvsp[-1].strtype));

		if ((tmp = strchr((yyvsp[-1].strtype), ',')))
			*tmp++ = '\0';

		if (type)
			free(type);
		if (strcmp((yyvsp[-1].strtype), "exec"))
			type = master_strdup((yyvsp[-1].strtype));
		else
			type = master_strdup("program");
		if (!type) {
			master_error("memory allocation error");
			local_free_vars();
			YYABORT;
		}
		if (tmp) {
			if (format)
				free(format);
			format = master_strdup(tmp);
			if (!format) {
				master_error("memory allocation error");
				local_free_vars();
				YYABORT;
			}
		}
		tmp_argc++;
		tmp_argv = add_argv(tmp_argc, tmp_argv, (yyvsp[0].strtype));
		if (!tmp_argv) {
			master_error("memory allocation error");
			local_free_vars();
			YYABORT;
		}
	}
#line 1802 "master_parse.tab.c"
    break;

  case 43: /* map: MAPTYPE dn  */
#line 452 "master_parse.y"
        {
		char *tmp = NULL;

		trim_maptype((yyvsp[-1].strtype));

		if ((tmp = strchr((yyvsp[-1].strtype), ',')))
			*tmp++ = '\0';

		if (type)
			free(type);
		if (strcmp((yyvsp[-1].strtype), "exec"))
			type = master_strdup((yyvsp[-1].strtype));
		else
			type = master_strdup("program");
		if (!type) {
			master_error("memory allocation error");
			local_free_vars();
			YYABORT;
		}
		if (tmp) {
			if (format)
				free(format);
			format = master_strdup(tmp);
			if (!format) {
				master_error("memory allocation error");
				local_free_vars();
				YYABORT;
			}
		}
		tmp_argc++;
		tmp_argv = add_argv(tmp_argc, tmp_argv, (yyvsp[0].strtype));
		if (!tmp_argv) {
			master_error("memory allocation error");
			local_free_vars();
			YYABORT;
		}
		/* Add back the type for lookup_ldap.c to handle ldaps */
		if (*tmp_argv[0]) {
			tmp = malloc(strlen(type) + strlen(tmp_argv[0]) + 2);
			if (!tmp) {
				master_error("memory allocation error");
				local_free_vars();
				YYABORT;
			}
			strcpy(tmp, type);
			strcat(tmp, ":");
			strcat(tmp, tmp_argv[0]);
			free(tmp_argv[0]);
			tmp_argv[0] = tmp;
		}
	}
#line 1858 "master_parse.tab.c"
    break;

  case 44: /* dn: DNSERVER dnattrs  */
#line 506 "master_parse.y"
        {
		strcpy((yyval.strtype), (yyvsp[-1].strtype));
		strcat((yyval.strtype), (yyvsp[0].strtype));
	}
#line 1867 "master_parse.tab.c"
    break;

  case 45: /* dn: dnattrs  */
#line 511 "master_parse.y"
        {
		strcpy((yyval.strtype), (yyvsp[0].strtype));
	}
#line 1875 "master_parse.tab.c"
    break;

  case 46: /* dn: %empty  */
#line 515 "master_parse.y"
        {
		master_notify("syntax error in dn");
		YYABORT;
	}
#line 1884 "master_parse.tab.c"
    break;

  case 47: /* dnattrs: DNATTR EQUAL DNNAME  */
#line 522 "master_parse.y"
        {
		if (strcasecmp((yyvsp[-2].strtype), "cn") &&
		    strcasecmp((yyvsp[-2].strtype), "ou") &&
		    strcasecmp((yyvsp[-2].strtype), "automountMapName") &&
		    strcasecmp((yyvsp[-2].strtype), "nisMapName")) {
			errlen = snprintf(errstr, MAX_ERR_LEN, "%s=%s", (yyvsp[-2].strtype), (yyvsp[0].strtype));
			if (errlen < MAX_ERR_LEN)
				master_notify(errstr);
			else
				master_notify("error string too long");
			YYABORT;
		}
		strcpy((yyval.strtype), (yyvsp[-2].strtype));
		strcat((yyval.strtype), "=");
		strcat((yyval.strtype), (yyvsp[0].strtype));
	}
#line 1905 "master_parse.tab.c"
    break;

  case 48: /* dnattrs: DNATTR EQUAL DNNAME COMMA dnattr  */
#line 539 "master_parse.y"
        {
		if (strcasecmp((yyvsp[-4].strtype), "cn") &&
		    strcasecmp((yyvsp[-4].strtype), "ou") &&
		    strcasecmp((yyvsp[-4].strtype), "automountMapName") &&
		    strcasecmp((yyvsp[-4].strtype), "nisMapName")) {
			errlen = snprintf(errstr, MAX_ERR_LEN, "%s=%s", (yyvsp[-4].strtype), (yyvsp[-2].strtype));
			if (errlen < MAX_ERR_LEN)
				master_notify(errstr);
			else
				master_notify("error string too long");
			YYABORT;
		}
		strcpy((yyval.strtype), (yyvsp[-4].strtype));
		strcat((yyval.strtype), "=");
		strcat((yyval.strtype), (yyvsp[-2].strtype));
		strcat((yyval.strtype), ",");
		strcat((yyval.strtype), (yyvsp[0].strtype));
	}
#line 1928 "master_parse.tab.c"
    break;

  case 49: /* dnattrs: DNNAME  */
#line 558 "master_parse.y"
        {
		/* Matches map in old style syntax ldap:server:map */
		strcpy((yyval.strtype), (yyvsp[0].strtype));
	}
#line 1937 "master_parse.tab.c"
    break;

  case 50: /* dnattrs: DNATTR  */
#line 563 "master_parse.y"
        {
		master_notify((yyvsp[0].strtype));
		YYABORT;
	}
#line 1946 "master_parse.tab.c"
    break;

  case 51: /* dnattr: DNATTR EQUAL DNNAME  */
#line 570 "master_parse.y"
        {
		if (!strcasecmp((yyvsp[-2].strtype), "automountMapName") ||
		    !strcasecmp((yyvsp[-2].strtype), "nisMapName")) {
			errlen = snprintf(errstr, MAX_ERR_LEN, "%s=%s", (yyvsp[-2].strtype), (yyvsp[0].strtype));
			if (errlen < MAX_ERR_LEN)
				master_notify(errstr);
			else
				master_notify("error string too long");
			YYABORT;
		}
		strcpy((yyval.strtype), (yyvsp[-2].strtype));
		strcat((yyval.strtype), "=");
		strcat((yyval.strtype), (yyvsp[0].strtype));
	}
#line 1965 "master_parse.tab.c"
    break;

  case 52: /* dnattr: DNATTR EQUAL DNNAME COMMA dnattr  */
#line 585 "master_parse.y"
        {
		if (!strcasecmp((yyvsp[-4].strtype), "automountMapName") ||
		    !strcasecmp((yyvsp[-4].strtype), "nisMapName")) {
			errlen = snprintf(errstr, MAX_ERR_LEN, "%s=%s", (yyvsp[-4].strtype), (yyvsp[-2].strtype));
			if (errlen < MAX_ERR_LEN)
				master_notify(errstr);
			else
				master_notify("error string too long");
			YYABORT;
		}
		strcpy((yyval.strtype), (yyvsp[-4].strtype));
		strcat((yyval.strtype), "=");
		strcat((yyval.strtype), (yyvsp[-2].strtype));
		strcat((yyval.strtype), ",");
		strcat((yyval.strtype), (yyvsp[0].strtype));
	}
#line 1986 "master_parse.tab.c"
    break;

  case 53: /* dnattr: DNATTR  */
#line 602 "master_parse.y"
        {
		master_notify((yyvsp[0].strtype));
		YYABORT;
	}
#line 1995 "master_parse.tab.c"
    break;

  case 54: /* dnattr: DNNAME  */
#line 607 "master_parse.y"
        {
		master_notify((yyvsp[0].strtype));
		YYABORT;
	}
#line 2004 "master_parse.tab.c"
    break;

  case 55: /* options: option  */
#line 613 "master_parse.y"
                {}
#line 2010 "master_parse.tab.c"
    break;

  case 56: /* options: options COMMA option  */
#line 614 "master_parse.y"
                               {}
#line 2016 "master_parse.tab.c"
    break;

  case 57: /* options: options option  */
#line 615 "master_parse.y"
                         {}
#line 2022 "master_parse.tab.c"
    break;

  case 58: /* options: options COMMA COMMA option  */
#line 617 "master_parse.y"
        {
		master_notify((yyvsp[-3].strtype));
		YYABORT;
	}
#line 2031 "master_parse.tab.c"
    break;

  case 59: /* options: options EQUAL  */
#line 622 "master_parse.y"
        {
		master_notify((yyvsp[-1].strtype));
		YYABORT;
	}
#line 2040 "master_parse.tab.c"
    break;

  case 61: /* option: mount_option  */
#line 629 "master_parse.y"
                       {}
#line 2046 "master_parse.tab.c"
    break;

  case 62: /* option: error  */
#line 631 "master_parse.y"
        {
		master_notify("bogus option");
		YYABORT;
	}
#line 2055 "master_parse.tab.c"
    break;

  case 63: /* daemon_option: OPT_TIMEOUT NUMBER  */
#line 637 "master_parse.y"
                                  { timeout = (yyvsp[0].longtype); }
#line 2061 "master_parse.tab.c"
    break;

  case 64: /* daemon_option: OPT_NTIMEOUT NUMBER  */
#line 638 "master_parse.y"
                              { negative_timeout = (yyvsp[0].longtype); }
#line 2067 "master_parse.tab.c"
    break;

  case 65: /* daemon_option: OPT_PTIMEOUT NUMBER  */
#line 639 "master_parse.y"
                              { positive_timeout = (yyvsp[0].longtype); }
#line 2073 "master_parse.tab.c"
    break;

  case 66: /* daemon_option: OPT_SYMLINK  */
#line 640 "master_parse.y"
                        { symlnk = 1; }
#line 2079 "master_parse.tab.c"
    break;

  case 67: /* daemon_option: OPT_STRICTEXPIRE  */
#line 641 "master_parse.y"
                           { strictexpire = 1; }
#line 2085 "master_parse.tab.c"
    break;

  case 68: /* daemon_option: OPT_SHARED  */
#line 642 "master_parse.y"
                        { propagation = PROPAGATION_SHARED; }
#line 2091 "master_parse.tab.c"
    break;

  case 69: /* daemon_option: OPT_SLAVE  */
#line 643 "master_parse.y"
                        { propagation = PROPAGATION_SLAVE; }
#line 2097 "master_parse.tab.c"
    break;

  case 70: /* daemon_option: OPT_PRIVATE  */
#line 644 "master_parse.y"
                        { propagation = PROPAGATION_PRIVATE; }
#line 2103 "master_parse.tab.c"
    break;

  case 71: /* daemon_option: OPT_NOBIND  */
#line 645 "master_parse.y"
                        { nobind = 1; }
#line 2109 "master_parse.tab.c"
    break;

  case 72: /* daemon_option: OPT_NOGHOST  */
#line 646 "master_parse.y"
                        { ghost = 0; }
#line 2115 "master_parse.tab.c"
    break;

  case 73: /* daemon_option: OPT_GHOST  */
#line 647 "master_parse.y"
                        { ghost = 1; }
#line 2121 "master_parse.tab.c"
    break;

  case 74: /* daemon_option: OPT_VERBOSE  */
#line 648 "master_parse.y"
                        { verbose = 1; }
#line 2127 "master_parse.tab.c"
    break;

  case 75: /* daemon_option: OPT_DEBUG  */
#line 649 "master_parse.y"
                        { debug = 1; }
#line 2133 "master_parse.tab.c"
    break;

  case 76: /* daemon_option: OPT_RANDOM  */
#line 650 "master_parse.y"
                        { random_selection = 1; }
#line 2139 "master_parse.tab.c"
    break;

  case 77: /* daemon_option: OPT_USE_WEIGHT  */
#line 651 "master_parse.y"
                         { use_weight = 1; }
#line 2145 "master_parse.tab.c"
    break;

  case 78: /* daemon_option: OPT_MODE OCTALNUMBER  */
#line 652 "master_parse.y"
                               { mode = (yyvsp[0].longtype); }
#line 2151 "master_parse.tab.c"
    break;

  case 79: /* mount_option: OPTION  */
#line 656 "master_parse.y"
        {
		tmp_argc++;
		tmp_argv = add_argv(tmp_argc, tmp_argv, (yyvsp[0].strtype));
		if (!tmp_argv) {
			master_error("memory allocation error");
			local_free_vars();
			YYABORT;
		}
	}
#line 2165 "master_parse.tab.c"
    break;


#line 2169 "master_parse.tab.c"

      default: break;
    }
  /* User semantic actions sometimes alter yychar, and that requires
     that yytoken be updated with the new translation.  We take the
     approach of translating immediately before every use of yytoken.
     One alternative is translating here after every semantic action,
     but that translation would be missed if the semantic action invokes
     YYABORT, YYACCEPT, or YYERROR immediately after altering yychar or
     if it invokes YYBACKUP.  In the case of YYABORT or YYACCEPT, an
     incorrect destructor might then be invoked immediately.  In the
     case of YYERROR or YYBACKUP, subsequent parser actions might lead
     to an incorrect destructor call or verbose syntax error message
     before the lookahead is translated.  */
  YY_SYMBOL_PRINT ("-> $$ =", YY_CAST (yysymbol_kind_t, yyr1[yyn]), &yyval, &yyloc);

  YYPOPSTACK (yylen);
  yylen = 0;

  *++yyvsp = yyval;

  /* Now 'shift' the result of the reduction.  Determine what state
     that goes to, based on the state we popped back to and the rule
     number reduced by.  */
  {
    const int yylhs = yyr1[yyn] - YYNTOKENS;
    const int yyi = yypgoto[yylhs] + *yyssp;
    yystate = (0 <= yyi && yyi <= YYLAST && yycheck[yyi] == *yyssp
               ? yytable[yyi]
               : yydefgoto[yylhs]);
  }

  goto yynewstate;


/*--------------------------------------.
| yyerrlab -- here on detecting error.  |
`--------------------------------------*/
yyerrlab:
  /* Make sure we have latest lookahead translation.  See comments at
     user semantic actions for why this is necessary.  */
  yytoken = yychar == YYEMPTY ? YYSYMBOL_YYEMPTY : YYTRANSLATE (yychar);
  /* If not already recovering from an error, report this error.  */
  if (!yyerrstatus)
    {
      ++yynerrs;
      yyerror (YY_("syntax error"));
    }

  if (yyerrstatus == 3)
    {
      /* If just tried and failed to reuse lookahead token after an
         error, discard it.  */

      if (yychar <= YYEOF)
        {
          /* Return failure if at end of input.  */
          if (yychar == YYEOF)
            YYABORT;
        }
      else
        {
          yydestruct ("Error: discarding",
                      yytoken, &yylval);
          yychar = YYEMPTY;
        }
    }

  /* Else will try to reuse lookahead token after shifting the error
     token.  */
  goto yyerrlab1;


/*---------------------------------------------------.
| yyerrorlab -- error raised explicitly by YYERROR.  |
`---------------------------------------------------*/
yyerrorlab:
  /* Pacify compilers when the user code never invokes YYERROR and the
     label yyerrorlab therefore never appears in user code.  */
  if (0)
    YYERROR;
  ++yynerrs;

  /* Do not reclaim the symbols of the rule whose action triggered
     this YYERROR.  */
  YYPOPSTACK (yylen);
  yylen = 0;
  YY_STACK_PRINT (yyss, yyssp);
  yystate = *yyssp;
  goto yyerrlab1;


/*-------------------------------------------------------------.
| yyerrlab1 -- common code for both syntax error and YYERROR.  |
`-------------------------------------------------------------*/
yyerrlab1:
  yyerrstatus = 3;      /* Each real token shifted decrements this.  */

  /* Pop stack until we find a state that shifts the error token.  */
  for (;;)
    {
      yyn = yypact[yystate];
      if (!yypact_value_is_default (yyn))
        {
          yyn += YYSYMBOL_YYerror;
          if (0 <= yyn && yyn <= YYLAST && yycheck[yyn] == YYSYMBOL_YYerror)
            {
              yyn = yytable[yyn];
              if (0 < yyn)
                break;
            }
        }

      /* Pop the current state because it cannot handle the error token.  */
      if (yyssp == yyss)
        YYABORT;


      yydestruct ("Error: popping",
                  YY_ACCESSING_SYMBOL (yystate), yyvsp);
      YYPOPSTACK (1);
      yystate = *yyssp;
      YY_STACK_PRINT (yyss, yyssp);
    }

  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  *++yyvsp = yylval;
  YY_IGNORE_MAYBE_UNINITIALIZED_END


  /* Shift the error token.  */
  YY_SYMBOL_PRINT ("Shifting", YY_ACCESSING_SYMBOL (yyn), yyvsp, yylsp);

  yystate = yyn;
  goto yynewstate;


/*-------------------------------------.
| yyacceptlab -- YYACCEPT comes here.  |
`-------------------------------------*/
yyacceptlab:
  yyresult = 0;
  goto yyreturnlab;


/*-----------------------------------.
| yyabortlab -- YYABORT comes here.  |
`-----------------------------------*/
yyabortlab:
  yyresult = 1;
  goto yyreturnlab;


/*-----------------------------------------------------------.
| yyexhaustedlab -- YYNOMEM (memory exhaustion) comes here.  |
`-----------------------------------------------------------*/
yyexhaustedlab:
  yyerror (YY_("memory exhausted"));
  yyresult = 2;
  goto yyreturnlab;


/*----------------------------------------------------------.
| yyreturnlab -- parsing is finished, clean up and return.  |
`----------------------------------------------------------*/
yyreturnlab:
  if (yychar != YYEMPTY)
    {
      /* Make sure we have latest lookahead translation.  See comments at
         user semantic actions for why this is necessary.  */
      yytoken = YYTRANSLATE (yychar);
      yydestruct ("Cleanup: discarding lookahead",
                  yytoken, &yylval);
    }
  /* Do not reclaim the symbols of the rule whose action triggered
     this YYABORT or YYACCEPT.  */
  YYPOPSTACK (yylen);
  YY_STACK_PRINT (yyss, yyssp);
  while (yyssp != yyss)
    {
      yydestruct ("Cleanup: popping",
                  YY_ACCESSING_SYMBOL (+*yyssp), yyvsp);
      YYPOPSTACK (1);
    }
#ifndef yyoverflow
  if (yyss != yyssa)
    YYSTACK_FREE (yyss);
#endif

  return yyresult;
}

#line 666 "master_parse.y"


#if YYDEBUG
static int master_fprintf(FILE *f, char *msg, ...)
{
	va_list ap;
	va_start(ap, msg);
	vsyslog(LOG_DEBUG, msg, ap);
	va_end(ap);
	return 1;
}
#endif

static char *master_strdup(char *str)
{
	char *tmp;

	tmp = strdup(str);
	if (!tmp)
		master_error("memory allocation error");
	return tmp;
}

static int master_error(const char *s)
{
	logmsg("%s while parsing map.", s);
	return 0;
}

static int master_notify(const char *s)
{
	logmsg("syntax error in map near [ %s ]", s);
	return(0);
}

static int master_msg(const char *s)
{
	logmsg("%s", s);
	return 0;
}

static void local_init_vars(void)
{
	path = NULL;
	type = NULL;
	format = NULL;
	verbose = 0;
	debug = 0;
	timeout = -1;
	negative_timeout = 0;
	symlnk = 0;
	strictexpire = 0;
	propagation = PROPAGATION_SLAVE;
	nobind = 0;
	ghost = defaults_get_browse_mode();
	random_selection = global_selection_options & MOUNT_FLAG_RANDOM_SELECT;
	use_weight = 0;
	mode = 0;
	tmp_argv = NULL;
	tmp_argc = 0;
	local_argv = NULL;
	local_argc = 0;
}

static void local_free_vars(void)
{
	if (path)
		free(path);

	if (type)
		free(type);

	if (format)
		free(format);

	if (local_argv) {
		free_argv(local_argc, (const char **) local_argv);
		local_argv = NULL;
		local_argc = 0;
	}

	if (tmp_argv) {
		free_argv(tmp_argc, (const char **) tmp_argv);
		tmp_argv = NULL;
		tmp_argc = 0;
	}
}

static void trim_maptype(char *type)
{
	char *tmp;

	tmp = strchr(type, ':');
	if (tmp)
		*tmp = '\0';
	else {
		int len = strlen(type);
		while (len-- && isblank(type[len]))
			type[len] = '\0';
	}
	return;
}

static int add_multi_mapstr(void)
{
	if (type) {
		/* If type given and format is non-null add it back */
		if (format) {
			int len = strlen(type) + strlen(format) + 2;
			char *tmp = realloc(type, len);
			if (!tmp)
				return 0;
			type = tmp;
			strcat(type, ",");
			strcat(type, format);
			free(format);
			format = NULL;
		}

		local_argc++;
		local_argv = add_argv(local_argc, local_argv, type);
		if (!local_argv) {
			free(type);
			type = NULL;
			return 0;
		}

		free(type);
		type = NULL;
	}

	local_argv = append_argv(local_argc, local_argv, tmp_argc, tmp_argv);
	if (!local_argv) {
		free(type);
		type = NULL;
		return 0;
	}
	local_argc += tmp_argc;

	tmp_argc = 0;
	tmp_argv = NULL;

	return 1;
}

void master_init_scan(void)
{
	lineno = 0;
}

int master_parse_entry(const char *buffer, unsigned int default_timeout, unsigned int logging, time_t age)
{
	struct master *master = master_list;
	struct mapent_cache *nc;
	struct master_mapent *entry, *new;
	struct map_source *source;
	unsigned int logopt = logging;
	unsigned int m_logopt = master->logopt;
	size_t mp_len;
	int ret;

	local_init_vars();

	lineno++;

	master_set_scan_buffer(buffer);

	ret = master_parse();
	if (ret != 0) {
		local_free_vars();
		return 0;
	}

	mp_len = strlen(path);
	while (mp_len && path[--mp_len] == '/')
		path[mp_len] = 0;

	nc = master->nc;

	/* Add null map entries to the null map cache */
	if (type && !strcmp(type, "null")) {
		cache_update(nc, NULL, path, NULL, lineno);
		local_free_vars();
		return 1;
	}

	/* Ignore all subsequent matching nulled entries */
	if (cache_lookup_distinct(nc, path)) {
		local_free_vars();
		return 1;
	}

	if (debug || verbose) {
		logopt = (debug ? LOGOPT_DEBUG : 0);
		logopt |= (verbose ? LOGOPT_VERBOSE : 0);
	}

	new = NULL;
	entry = master_find_mapent(master, path);
	if (!entry) {
		new = master_new_mapent(master, path, age);
		if (!new) {
			local_free_vars();
			return 0;
		}
		entry = new;
	} else {
		if (entry->age && entry->age == age) {
			if (strcmp(path, "/-")) {
				info(m_logopt,
				    "ignoring duplicate indirect mount %s",
				     path);
				local_free_vars();
				return 0;
			}
		}
	}

	if (!format) {
		if (conf_amd_mount_section_exists(path))
			format = strdup("amd");
	}

	if (format && !strcmp(format, "amd")) {
		unsigned int loglevel = conf_amd_get_log_options();
		unsigned int flags = conf_amd_get_flags(path);

		if (loglevel <= LOG_DEBUG && loglevel > LOG_INFO)
			logopt = LOGOPT_DEBUG;
		else if (loglevel <= LOG_INFO && loglevel > LOG_ERR)
			logopt = LOGOPT_VERBOSE;

		/* It isn't possible to provide the fullybrowsable amd
		 * browsing functionality within the autofs framework.
		 * This flag will not be set if browsable_dirs = full
		 * in the configuration or fullybrowsable is present as
		 * an option.
		 */
		if (flags & CONF_BROWSABLE_DIRS)
			ghost = 1;
	}

	if (!entry->ap) {
		ret = master_add_autofs_point(entry, logopt, nobind, ghost, 0);
		if (!ret) {
			error(m_logopt, "failed to add autofs_point");
			if (new)
				master_free_mapent(new);
			local_free_vars();
			return 0;
		}
	}
	entry->ap->flags &= ~(PROPAGATION_MASK);
	entry->ap->flags |= propagation;

	if (random_selection)
		entry->ap->flags |= MOUNT_FLAG_RANDOM_SELECT;
	if (use_weight)
		entry->ap->flags |= MOUNT_FLAG_USE_WEIGHT_ONLY;
	if (symlnk)
		entry->ap->flags |= MOUNT_FLAG_SYMLINK;
	if (strictexpire)
		entry->ap->flags |= MOUNT_FLAG_STRICTEXPIRE;
	if (negative_timeout)
		entry->ap->negative_timeout = negative_timeout;
	if (mode && mode < LONG_MAX)
		entry->ap->mode = mode;

	if (timeout < 0) {
		/*
		 * If no timeout is given get the timout from the
		 * autofs point, or the first map, or the config
		 * for amd maps.
		 */
		if (format && !strcmp(format, "amd"))
			timeout = conf_amd_get_dismount_interval(path);
		else
			timeout = get_exp_timeout(entry->ap, entry->maps);
	}

	if (format && !strcmp(format, "amd")) {
		char *opts = conf_amd_get_map_options(path);
		if (opts) {
			/* autofs uses the equivalent of cache:=inc,sync
			 * (except for file maps which use cache:=all,sync)
			 * but if the map is large then it may be necessary
			 * to read the whole map at startup even if browsing
			 * is is not enabled, so look for cache:=all in the
			 * map_options configuration entry.
			 */
			if (strstr(opts, "cache:=all"))
				entry->ap->flags |= MOUNT_FLAG_AMD_CACHE_ALL;
			free(opts);
		}
	}

/*
	source = master_find_map_source(entry, type, format,
					local_argc, (const char **) local_argv); 
	if (!source)
		source = master_add_map_source(entry, type, format, age, 
					local_argc, (const char **) local_argv);
	else
		source->age = age;
*/
	source = master_add_map_source(entry, type, format, age, 
					local_argc, (const char **) local_argv);
	if (!source) {
		error(m_logopt, "failed to add source");
		if (new)
			master_free_mapent(new);
		local_free_vars();
		return 0;
	}
	set_exp_timeout(entry->ap, source, timeout);
	source->master_line = lineno;

	entry->age = age;
	entry->current = NULL;

	if (new)
		master_add_mapent(master, entry);

	local_free_vars();

	return 1;
}

