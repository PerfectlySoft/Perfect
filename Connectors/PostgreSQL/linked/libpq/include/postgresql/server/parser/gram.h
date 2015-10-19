/* A Bison parser, made by GNU Bison 2.5.  */

/* Bison interface for Yacc-like parsers in C
   
      Copyright (C) 1984, 1989-1990, 2000-2011 Free Software Foundation, Inc.
   
   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

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


/* Tokens.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
   /* Put the tokens into the symbol table, so that GDB and other debuggers
      know about them.  */
   enum yytokentype {
     IDENT = 258,
     FCONST = 259,
     SCONST = 260,
     BCONST = 261,
     XCONST = 262,
     Op = 263,
     ICONST = 264,
     PARAM = 265,
     TYPECAST = 266,
     DOT_DOT = 267,
     COLON_EQUALS = 268,
     ABORT_P = 269,
     ABSOLUTE_P = 270,
     ACCESS = 271,
     ACTION = 272,
     ADD_P = 273,
     ADMIN = 274,
     AFTER = 275,
     AGGREGATE = 276,
     ALL = 277,
     ALSO = 278,
     ALTER = 279,
     ALWAYS = 280,
     ANALYSE = 281,
     ANALYZE = 282,
     AND = 283,
     ANY = 284,
     ARRAY = 285,
     AS = 286,
     ASC = 287,
     ASSERTION = 288,
     ASSIGNMENT = 289,
     ASYMMETRIC = 290,
     AT = 291,
     ATTRIBUTE = 292,
     AUTHORIZATION = 293,
     BACKWARD = 294,
     BEFORE = 295,
     BEGIN_P = 296,
     BETWEEN = 297,
     BIGINT = 298,
     BINARY = 299,
     BIT = 300,
     BOOLEAN_P = 301,
     BOTH = 302,
     BY = 303,
     CACHE = 304,
     CALLED = 305,
     CASCADE = 306,
     CASCADED = 307,
     CASE = 308,
     CAST = 309,
     CATALOG_P = 310,
     CHAIN = 311,
     CHAR_P = 312,
     CHARACTER = 313,
     CHARACTERISTICS = 314,
     CHECK = 315,
     CHECKPOINT = 316,
     CLASS = 317,
     CLOSE = 318,
     CLUSTER = 319,
     COALESCE = 320,
     COLLATE = 321,
     COLLATION = 322,
     COLUMN = 323,
     COMMENT = 324,
     COMMENTS = 325,
     COMMIT = 326,
     COMMITTED = 327,
     CONCURRENTLY = 328,
     CONFIGURATION = 329,
     CONNECTION = 330,
     CONSTRAINT = 331,
     CONSTRAINTS = 332,
     CONTENT_P = 333,
     CONTINUE_P = 334,
     CONVERSION_P = 335,
     COPY = 336,
     COST = 337,
     CREATE = 338,
     CROSS = 339,
     CSV = 340,
     CURRENT_P = 341,
     CURRENT_CATALOG = 342,
     CURRENT_DATE = 343,
     CURRENT_ROLE = 344,
     CURRENT_SCHEMA = 345,
     CURRENT_TIME = 346,
     CURRENT_TIMESTAMP = 347,
     CURRENT_USER = 348,
     CURSOR = 349,
     CYCLE = 350,
     DATA_P = 351,
     DATABASE = 352,
     DAY_P = 353,
     DEALLOCATE = 354,
     DEC = 355,
     DECIMAL_P = 356,
     DECLARE = 357,
     DEFAULT = 358,
     DEFAULTS = 359,
     DEFERRABLE = 360,
     DEFERRED = 361,
     DEFINER = 362,
     DELETE_P = 363,
     DELIMITER = 364,
     DELIMITERS = 365,
     DESC = 366,
     DICTIONARY = 367,
     DISABLE_P = 368,
     DISCARD = 369,
     DISTINCT = 370,
     DO = 371,
     DOCUMENT_P = 372,
     DOMAIN_P = 373,
     DOUBLE_P = 374,
     DROP = 375,
     EACH = 376,
     ELSE = 377,
     ENABLE_P = 378,
     ENCODING = 379,
     ENCRYPTED = 380,
     END_P = 381,
     ENUM_P = 382,
     ESCAPE = 383,
     EVENT = 384,
     EXCEPT = 385,
     EXCLUDE = 386,
     EXCLUDING = 387,
     EXCLUSIVE = 388,
     EXECUTE = 389,
     EXISTS = 390,
     EXPLAIN = 391,
     EXTENSION = 392,
     EXTERNAL = 393,
     EXTRACT = 394,
     FALSE_P = 395,
     FAMILY = 396,
     FETCH = 397,
     FILTER = 398,
     FIRST_P = 399,
     FLOAT_P = 400,
     FOLLOWING = 401,
     FOR = 402,
     FORCE = 403,
     FOREIGN = 404,
     FORWARD = 405,
     FREEZE = 406,
     FROM = 407,
     FULL = 408,
     FUNCTION = 409,
     FUNCTIONS = 410,
     GLOBAL = 411,
     GRANT = 412,
     GRANTED = 413,
     GREATEST = 414,
     GROUP_P = 415,
     HANDLER = 416,
     HAVING = 417,
     HEADER_P = 418,
     HOLD = 419,
     HOUR_P = 420,
     IDENTITY_P = 421,
     IF_P = 422,
     ILIKE = 423,
     IMMEDIATE = 424,
     IMMUTABLE = 425,
     IMPLICIT_P = 426,
     IN_P = 427,
     INCLUDING = 428,
     INCREMENT = 429,
     INDEX = 430,
     INDEXES = 431,
     INHERIT = 432,
     INHERITS = 433,
     INITIALLY = 434,
     INLINE_P = 435,
     INNER_P = 436,
     INOUT = 437,
     INPUT_P = 438,
     INSENSITIVE = 439,
     INSERT = 440,
     INSTEAD = 441,
     INT_P = 442,
     INTEGER = 443,
     INTERSECT = 444,
     INTERVAL = 445,
     INTO = 446,
     INVOKER = 447,
     IS = 448,
     ISNULL = 449,
     ISOLATION = 450,
     JOIN = 451,
     KEY = 452,
     LABEL = 453,
     LANGUAGE = 454,
     LARGE_P = 455,
     LAST_P = 456,
     LATERAL_P = 457,
     LC_COLLATE_P = 458,
     LC_CTYPE_P = 459,
     LEADING = 460,
     LEAKPROOF = 461,
     LEAST = 462,
     LEFT = 463,
     LEVEL = 464,
     LIKE = 465,
     LIMIT = 466,
     LISTEN = 467,
     LOAD = 468,
     LOCAL = 469,
     LOCALTIME = 470,
     LOCALTIMESTAMP = 471,
     LOCATION = 472,
     LOCK_P = 473,
     MAPPING = 474,
     MATCH = 475,
     MATERIALIZED = 476,
     MAXVALUE = 477,
     MINUTE_P = 478,
     MINVALUE = 479,
     MODE = 480,
     MONTH_P = 481,
     MOVE = 482,
     NAME_P = 483,
     NAMES = 484,
     NATIONAL = 485,
     NATURAL = 486,
     NCHAR = 487,
     NEXT = 488,
     NO = 489,
     NONE = 490,
     NOT = 491,
     NOTHING = 492,
     NOTIFY = 493,
     NOTNULL = 494,
     NOWAIT = 495,
     NULL_P = 496,
     NULLIF = 497,
     NULLS_P = 498,
     NUMERIC = 499,
     OBJECT_P = 500,
     OF = 501,
     OFF = 502,
     OFFSET = 503,
     OIDS = 504,
     ON = 505,
     ONLY = 506,
     OPERATOR = 507,
     OPTION = 508,
     OPTIONS = 509,
     OR = 510,
     ORDER = 511,
     ORDINALITY = 512,
     OUT_P = 513,
     OUTER_P = 514,
     OVER = 515,
     OVERLAPS = 516,
     OVERLAY = 517,
     OWNED = 518,
     OWNER = 519,
     PARSER = 520,
     PARTIAL = 521,
     PARTITION = 522,
     PASSING = 523,
     PASSWORD = 524,
     PLACING = 525,
     PLANS = 526,
     POSITION = 527,
     PRECEDING = 528,
     PRECISION = 529,
     PRESERVE = 530,
     PREPARE = 531,
     PREPARED = 532,
     PRIMARY = 533,
     PRIOR = 534,
     PRIVILEGES = 535,
     PROCEDURAL = 536,
     PROCEDURE = 537,
     PROGRAM = 538,
     QUOTE = 539,
     RANGE = 540,
     READ = 541,
     REAL = 542,
     REASSIGN = 543,
     RECHECK = 544,
     RECURSIVE = 545,
     REF = 546,
     REFERENCES = 547,
     REFRESH = 548,
     REINDEX = 549,
     RELATIVE_P = 550,
     RELEASE = 551,
     RENAME = 552,
     REPEATABLE = 553,
     REPLACE = 554,
     REPLICA = 555,
     RESET = 556,
     RESTART = 557,
     RESTRICT = 558,
     RETURNING = 559,
     RETURNS = 560,
     REVOKE = 561,
     RIGHT = 562,
     ROLE = 563,
     ROLLBACK = 564,
     ROW = 565,
     ROWS = 566,
     RULE = 567,
     SAVEPOINT = 568,
     SCHEMA = 569,
     SCROLL = 570,
     SEARCH = 571,
     SECOND_P = 572,
     SECURITY = 573,
     SELECT = 574,
     SEQUENCE = 575,
     SEQUENCES = 576,
     SERIALIZABLE = 577,
     SERVER = 578,
     SESSION = 579,
     SESSION_USER = 580,
     SET = 581,
     SETOF = 582,
     SHARE = 583,
     SHOW = 584,
     SIMILAR = 585,
     SIMPLE = 586,
     SMALLINT = 587,
     SNAPSHOT = 588,
     SOME = 589,
     STABLE = 590,
     STANDALONE_P = 591,
     START = 592,
     STATEMENT = 593,
     STATISTICS = 594,
     STDIN = 595,
     STDOUT = 596,
     STORAGE = 597,
     STRICT_P = 598,
     STRIP_P = 599,
     SUBSTRING = 600,
     SYMMETRIC = 601,
     SYSID = 602,
     SYSTEM_P = 603,
     TABLE = 604,
     TABLES = 605,
     TABLESPACE = 606,
     TEMP = 607,
     TEMPLATE = 608,
     TEMPORARY = 609,
     TEXT_P = 610,
     THEN = 611,
     TIME = 612,
     TIMESTAMP = 613,
     TO = 614,
     TRAILING = 615,
     TRANSACTION = 616,
     TREAT = 617,
     TRIGGER = 618,
     TRIM = 619,
     TRUE_P = 620,
     TRUNCATE = 621,
     TRUSTED = 622,
     TYPE_P = 623,
     TYPES_P = 624,
     UNBOUNDED = 625,
     UNCOMMITTED = 626,
     UNENCRYPTED = 627,
     UNION = 628,
     UNIQUE = 629,
     UNKNOWN = 630,
     UNLISTEN = 631,
     UNLOGGED = 632,
     UNTIL = 633,
     UPDATE = 634,
     USER = 635,
     USING = 636,
     VACUUM = 637,
     VALID = 638,
     VALIDATE = 639,
     VALIDATOR = 640,
     VALUE_P = 641,
     VALUES = 642,
     VARCHAR = 643,
     VARIADIC = 644,
     VARYING = 645,
     VERBOSE = 646,
     VERSION_P = 647,
     VIEW = 648,
     VIEWS = 649,
     VOLATILE = 650,
     WHEN = 651,
     WHERE = 652,
     WHITESPACE_P = 653,
     WINDOW = 654,
     WITH = 655,
     WITHIN = 656,
     WITHOUT = 657,
     WORK = 658,
     WRAPPER = 659,
     WRITE = 660,
     XML_P = 661,
     XMLATTRIBUTES = 662,
     XMLCONCAT = 663,
     XMLELEMENT = 664,
     XMLEXISTS = 665,
     XMLFOREST = 666,
     XMLPARSE = 667,
     XMLPI = 668,
     XMLROOT = 669,
     XMLSERIALIZE = 670,
     YEAR_P = 671,
     YES_P = 672,
     ZONE = 673,
     NULLS_FIRST = 674,
     NULLS_LAST = 675,
     WITH_ORDINALITY = 676,
     WITH_TIME = 677,
     POSTFIXOP = 678,
     UMINUS = 679
   };
#endif



#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED
typedef union YYSTYPE
{

/* Line 2068 of yacc.c  */
#line 179 "gram.y"

	core_YYSTYPE		core_yystype;
	/* these fields must match core_YYSTYPE: */
	int					ival;
	char				*str;
	const char			*keyword;

	char				chr;
	bool				boolean;
	JoinType			jtype;
	DropBehavior		dbehavior;
	OnCommitAction		oncommit;
	List				*list;
	Node				*node;
	Value				*value;
	ObjectType			objtype;
	TypeName			*typnam;
	FunctionParameter   *fun_param;
	FunctionParameterMode fun_param_mode;
	FuncWithArgs		*funwithargs;
	DefElem				*defelt;
	SortBy				*sortby;
	WindowDef			*windef;
	JoinExpr			*jexpr;
	IndexElem			*ielem;
	Alias				*alias;
	RangeVar			*range;
	IntoClause			*into;
	WithClause			*with;
	A_Indices			*aind;
	ResTarget			*target;
	struct PrivTarget	*privtarget;
	AccessPriv			*accesspriv;
	InsertStmt			*istmt;
	VariableSetStmt		*vsetstmt;



/* Line 2068 of yacc.c  */
#line 513 "gram.h"
} YYSTYPE;
# define YYSTYPE_IS_TRIVIAL 1
# define yystype YYSTYPE /* obsolescent; will be withdrawn */
# define YYSTYPE_IS_DECLARED 1
#endif



#if ! defined YYLTYPE && ! defined YYLTYPE_IS_DECLARED
typedef struct YYLTYPE
{
  int first_line;
  int first_column;
  int last_line;
  int last_column;
} YYLTYPE;
# define yyltype YYLTYPE /* obsolescent; will be withdrawn */
# define YYLTYPE_IS_DECLARED 1
# define YYLTYPE_IS_TRIVIAL 1
#endif



