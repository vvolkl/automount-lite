/* A Bison parser, made by GNU Bison 3.8.2.  */

/* Bison interface for Yacc-like parsers in C

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

/* DO NOT RELY ON FEATURES THAT ARE NOT DOCUMENTED in the manual,
   especially those whose name start with YY_ or yy_.  They are
   private implementation details that can be changed or removed.  */

#ifndef YY_MASTER_MASTER_PARSE_TAB_H_INCLUDED
# define YY_MASTER_MASTER_PARSE_TAB_H_INCLUDED
/* Debug traces.  */
#ifndef YYDEBUG
# define YYDEBUG 0
#endif
#if YYDEBUG
extern int master_debug;
#endif

/* Token kinds.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
  enum yytokentype
  {
    YYEMPTY = -2,
    YYEOF = 0,                     /* "end of file"  */
    YYerror = 256,                 /* error  */
    YYUNDEF = 257,                 /* "invalid token"  */
    COMMENT = 258,                 /* COMMENT  */
    MAP = 259,                     /* MAP  */
    OPT_TIMEOUT = 260,             /* OPT_TIMEOUT  */
    OPT_NTIMEOUT = 261,            /* OPT_NTIMEOUT  */
    OPT_PTIMEOUT = 262,            /* OPT_PTIMEOUT  */
    OPT_NOBIND = 263,              /* OPT_NOBIND  */
    OPT_NOGHOST = 264,             /* OPT_NOGHOST  */
    OPT_GHOST = 265,               /* OPT_GHOST  */
    OPT_VERBOSE = 266,             /* OPT_VERBOSE  */
    OPT_DEBUG = 267,               /* OPT_DEBUG  */
    OPT_RANDOM = 268,              /* OPT_RANDOM  */
    OPT_USE_WEIGHT = 269,          /* OPT_USE_WEIGHT  */
    OPT_SYMLINK = 270,             /* OPT_SYMLINK  */
    OPT_MODE = 271,                /* OPT_MODE  */
    OPT_STRICTEXPIRE = 272,        /* OPT_STRICTEXPIRE  */
    OPT_SHARED = 273,              /* OPT_SHARED  */
    OPT_SLAVE = 274,               /* OPT_SLAVE  */
    OPT_PRIVATE = 275,             /* OPT_PRIVATE  */
    COLON = 276,                   /* COLON  */
    COMMA = 277,                   /* COMMA  */
    NL = 278,                      /* NL  */
    DDASH = 279,                   /* DDASH  */
    PATH = 280,                    /* PATH  */
    QUOTE = 281,                   /* QUOTE  */
    NILL = 282,                    /* NILL  */
    SPACE = 283,                   /* SPACE  */
    EQUAL = 284,                   /* EQUAL  */
    MULTITYPE = 285,               /* MULTITYPE  */
    MAPTYPE = 286,                 /* MAPTYPE  */
    DNSERVER = 287,                /* DNSERVER  */
    DNATTR = 288,                  /* DNATTR  */
    DNNAME = 289,                  /* DNNAME  */
    MAPHOSTS = 290,                /* MAPHOSTS  */
    MAPNULL = 291,                 /* MAPNULL  */
    MAPXFN = 292,                  /* MAPXFN  */
    MAPNAME = 293,                 /* MAPNAME  */
    NUMBER = 294,                  /* NUMBER  */
    OCTALNUMBER = 295,             /* OCTALNUMBER  */
    OPTION = 296                   /* OPTION  */
  };
  typedef enum yytokentype yytoken_kind_t;
#endif

/* Value type.  */
#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED
union YYSTYPE
{
#line 108 "master_parse.y"

	char strtype[2048];
	int inttype;
	long longtype;

#line 111 "master_parse.tab.h"

};
typedef union YYSTYPE YYSTYPE;
# define YYSTYPE_IS_TRIVIAL 1
# define YYSTYPE_IS_DECLARED 1
#endif


extern YYSTYPE master_lval;


int master_parse (void);


#endif /* !YY_MASTER_MASTER_PARSE_TAB_H_INCLUDED  */
