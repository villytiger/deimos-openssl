/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

module deimos.openssl.asn1;

import deimos.openssl._d_util;

import deimos.openssl.asn1t; // Needed for ASN1_ITEM_st.

import core.stdc.time;
public import deimos.openssl.e_os2;
// TODO: +# include <openssl/opensslconf.h>
public import deimos.openssl.bio;
public import deimos.openssl.stack;
public import deimos.openssl.safestack;

public import deimos.openssl.symhacks;

public import deimos.openssl.ossl_typ;
version(OPENSSL_NO_DEPRECATED) {} else {
// TODO: +# if OPENSSL_API_COMPAT < 0x10100000L
public import deimos.openssl.bn;
}


extern (C):
nothrow:

enum V_ASN1_UNIVERSAL = 0x00;
enum V_ASN1_APPLICATION = 0x40;
enum V_ASN1_CONTEXT_SPECIFIC = 0x80;
enum V_ASN1_PRIVATE = 0xc0;

enum V_ASN1_CONSTRUCTED = 0x20;
enum V_ASN1_PRIMITIVE_TAG = 0x1f;
enum V_ASN1_PRIMATIVE_TAG = 0x1f;

enum V_ASN1_APP_CHOOSE = -2;	/* let the recipient choose */
enum V_ASN1_OTHER = -3;	/* used in ASN1_TYPE */
enum V_ASN1_ANY = -4;	/* used in ASN1 template code */

enum V_ASN1_UNDEF = -1;
/* ASN.1 tag values */
enum V_ASN1_EOC = 0;
enum V_ASN1_BOOLEAN = 1;	/**/
enum V_ASN1_INTEGER = 2;
enum V_ASN1_BIT_STRING = 3;
enum V_ASN1_OCTET_STRING = 4;
enum V_ASN1_NULL = 5;
enum V_ASN1_OBJECT = 6;
enum V_ASN1_OBJECT_DESCRIPTOR = 7;
enum V_ASN1_EXTERNAL = 8;
enum V_ASN1_REAL = 9;
enum V_ASN1_ENUMERATED = 10;
enum V_ASN1_UTF8STRING = 12;
enum V_ASN1_SEQUENCE = 16;
enum V_ASN1_SET = 17;
enum V_ASN1_NUMERICSTRING = 18;	/**/
enum V_ASN1_PRINTABLESTRING = 19;
enum V_ASN1_T61STRING = 20;
enum V_ASN1_TELETEXSTRING = 20;	/* alias */
enum V_ASN1_VIDEOTEXSTRING = 21;	/**/
enum V_ASN1_IA5STRING = 22;
enum V_ASN1_UTCTIME = 23;
enum V_ASN1_GENERALIZEDTIME = 24;	/**/
enum V_ASN1_GRAPHICSTRING = 25;	/**/
enum V_ASN1_ISO64STRING = 26;	/**/
enum V_ASN1_VISIBLESTRING = 26;	/* alias */
enum V_ASN1_GENERALSTRING = 27;	/**/
enum V_ASN1_UNIVERSALSTRING = 28;	/**/
enum V_ASN1_BMPSTRING = 30;

/*
 * NB the constants below are used internally by ASN1_INTEGER
 * and ASN1_ENUMERATED to indicate the sign. They are *not* on
 * the wire tag values.
 */

enum V_ASN1_NEG = 0x100;
enum V_ASN1_NEG_INTEGER = (2 | V_ASN1_NEG);
enum V_ASN1_NEG_ENUMERATED = (10 | V_ASN1_NEG);

/* For use with d2i_ASN1_type_bytes() */
enum B_ASN1_NUMERICSTRING = 0x0001;
enum B_ASN1_PRINTABLESTRING = 0x0002;
enum B_ASN1_T61STRING = 0x0004;
enum B_ASN1_TELETEXSTRING = 0x0004;
enum B_ASN1_VIDEOTEXSTRING = 0x0008;
enum B_ASN1_IA5STRING = 0x0010;
enum B_ASN1_GRAPHICSTRING = 0x0020;
enum B_ASN1_ISO64STRING = 0x0040;
enum B_ASN1_VISIBLESTRING = 0x0040;
enum B_ASN1_GENERALSTRING = 0x0080;
enum B_ASN1_UNIVERSALSTRING = 0x0100;
enum B_ASN1_OCTET_STRING = 0x0200;
enum B_ASN1_BIT_STRING = 0x0400;
enum B_ASN1_BMPSTRING = 0x0800;
enum B_ASN1_UNKNOWN = 0x1000;
enum B_ASN1_UTF8STRING = 0x2000;
enum B_ASN1_UTCTIME = 0x4000;
enum B_ASN1_GENERALIZEDTIME = 0x8000;
enum B_ASN1_SEQUENCE = 0x10000;

/* For use with ASN1_mbstring_copy() */
enum MBSTRING_FLAG = 0x1000;
enum MBSTRING_UTF8 = (MBSTRING_FLAG);
enum MBSTRING_ASC = (MBSTRING_FLAG|1);
enum MBSTRING_BMP = (MBSTRING_FLAG|2);
enum MBSTRING_UNIV = (MBSTRING_FLAG|4);

enum SMIME_OLDMIME = 0x400;
enum SMIME_CRLFEOL = 0x800;
enum SMIME_STREAM = 0x1000;

/+mixin DEFINE_STACK_OF!(X509_ALGOR);+/

enum ASN1_STRING_FLAG_BITS_LEFT = 0x08; /* Set if 0x07 has bits left value */
/*
 * This indicates that the ASN1_STRING is not a real value but just a place
 * holder for the location where indefinite length constructed data should be
 * inserted in the memory buffer
 */
enum ASN1_STRING_FLAG_NDEF = 0x010;

/*
 * This flag is used by the CMS code to indicate that a string is not
 * complete and is a place holder for content when it had all been accessed.
 * The flag will be reset when content has been written to it.
 */

enum ASN1_STRING_FLAG_CONT = 0x020;
/*
 * This flag is used by ASN1 code to indicate an ASN1_STRING is an MSTRING
 * type.
 */
enum ASN1_STRING_FLAG_MSTRING = 0x040;
/* String is embedded and only content should be freed */
enum ASN1_STRING_FLAG_EMBED = 0x080;
/* This is the base type that holds just about everything :-) */
struct asn1_string_st {
	int length;
	int type;
	ubyte* data;
    /*
     * The value of the following field depends on the type being held.  It
     * is mostly being used for BIT_STRING so if the input data has a
     * non-zero 'unused bits' value, it will be handled correctly
     */
	c_long flags;
	}

/*
 * ASN1_ENCODING structure: this is used to save the received encoding of an
 * ASN1 type. This is useful to get round problems with invalid encodings
 * which can break signatures.
 */

struct ASN1_ENCODING_st {
	ubyte* enc;	/* DER encoding */
	c_long len;		/* Length of encoding */
	int modified;		 /* set to 1 if 'enc' is invalid */
	}
alias ASN1_ENCODING_st ASN1_ENCODING;

/* Used with ASN1 LONG type: if a c_long is set to this it is omitted */
enum ASN1_LONG_UNDEF = 0x7fffffff;

enum STABLE_FLAGS_MALLOC = 0x01;
/*
 * A zero passed to ASN1_STRING_TABLE_new_add for the flags is interpreted
 * as "don't change" and STABLE_FLAGS_MALLOC is always set. By setting
 * STABLE_FLAGS_MALLOC only we can clear the existing value. Use the alias
 * STABLE_FLAGS_CLEAR to reflect this.
 */
enum STABLE_FLAGS_CLEAR = STABLE_FLAGS_MALLOC;
enum STABLE_NO_MASK = 0x02;
enum DIRSTRING_TYPE	= (B_ASN1_PRINTABLESTRING|B_ASN1_T61STRING|B_ASN1_BMPSTRING|B_ASN1_UTF8STRING);
enum PKCS9STRING_TYPE = (DIRSTRING_TYPE|B_ASN1_IA5STRING);

struct asn1_string_table_st {
	int nid;
	c_long minsize;
	c_long maxsize;
	c_ulong mask;
	c_ulong flags;
}
alias asn1_string_table_st ASN1_STRING_TABLE;

/+mixin DEFINE_STACK_OF!(ASN1_STRING_TABLE);+/

/* size limits: this stuff is taken straight from RFC2459 */

enum ub_name = 32768;
enum ub_common_name = 64;
enum ub_locality_name = 128;
enum ub_state_name = 128;
enum ub_organization_name = 64;
enum ub_organization_unit_name = 64;
enum ub_title = 64;
enum ub_email_address = 128;

/*
 * Declarations for template structures: for full definitions see asn1t.h
 */
alias ASN1_TEMPLATE_st ASN1_TEMPLATE;
import deimos.openssl.asn1t; /*struct ASN1_TLC_st;*/
alias ASN1_TLC_st ASN1_TLC;
/* This is just an opaque pointer */
struct ASN1_VALUE_st;
alias ASN1_VALUE_st ASN1_VALUE;

/* Declare ASN1 functions: the implement macro in in asn1t.h */
// Need to use string mixins here to avoid DMD mangling extern(C) symbol names.

template DECLARE_ASN1_FUNCTIONS(string type) {
	enum DECLARE_ASN1_FUNCTIONS = DECLARE_ASN1_FUNCTIONS_name!(type, type);
}

template DECLARE_ASN1_ALLOC_FUNCTIONS(string type) {
	enum DECLARE_ASN1_ALLOC_FUNCTIONS =
		DECLARE_ASN1_ALLOC_FUNCTIONS_name!(type, type);
}

template DECLARE_ASN1_FUNCTIONS_name(string type, string name) {
	enum DECLARE_ASN1_FUNCTIONS_name =
		DECLARE_ASN1_ALLOC_FUNCTIONS_name!(type, name) ~
		DECLARE_ASN1_ENCODE_FUNCTIONS!(type, name, name);
}

template DECLARE_ASN1_FUNCTIONS_fname(string type, string itname, string name) {
	enum DECLARE_ASN1_FUNCTIONS_fname =
		DECLARE_ASN1_ALLOC_FUNCTIONS_name!(type, name) ~
		DECLARE_ASN1_ENCODE_FUNCTIONS!(type, itname, name);
}

template DECLARE_ASN1_ENCODE_FUNCTIONS(string type, string itname, string name) {
	enum DECLARE_ASN1_ENCODE_FUNCTIONS = "
		" ~ type ~ "* d2i_" ~ name ~ "(" ~ type ~ "** a, const(ubyte)** in_, c_long len);
		int i2d_" ~ name ~ "(" ~ type ~ "* a, ubyte** out_);
	" ~ DECLARE_ASN1_ITEM!itname;
}

template DECLARE_ASN1_ENCODE_FUNCTIONS_const(string type, string name) {
	enum DECLARE_ASN1_ENCODE_FUNCTIONS_const = "
		" ~ type ~ "* d2i_" ~ name ~ "(" ~ type ~ "** a, const(ubyte)** in_, c_long len);
		int i2d_" ~ name ~ "(const(" ~ type ~ ")* a, ubyte** out_);
	" ~ DECLARE_ASN1_ITEM!name;
}

template DECLARE_ASN1_NDEF_FUNCTION(string name) {
	enum DECLARE_ASN1_NDEF_FUNCTION = "
		int i2d_" ~ name ~ "_NDEF(" ~ name ~ "* a, ubyte** out_);
	";
}

template DECLARE_ASN1_FUNCTIONS_const(string name) {
	enum DECLARE_ASN1_FUNCTIONS_const =
		DECLARE_ASN1_ALLOC_FUNCTIONS!name ~
		DECLARE_ASN1_ENCODE_FUNCTIONS_const!(name, name);
}

template DECLARE_ASN1_ALLOC_FUNCTIONS_name(string type, string name) {
	enum DECLARE_ASN1_ALLOC_FUNCTIONS_name = "
		extern(C) " ~ type ~ "* " ~ name ~ "_new();
		extern(C) void " ~ name ~ "_free(" ~ type ~ "* a);
	";
}

template DECLARE_ASN1_PRINT_FUNCTION(string stname) {
	enum DECLARE_ASN1_PRINT_FUNCTION =
		DECLARE_ASN1_PRINT_FUNCTION_fname!(stname, stname);
}

template DECLARE_ASN1_PRINT_FUNCTION_fname(string stname, string fname) {
	enum DECLARE_ASN1_PRINT_FUNCTION_fname = "
		int " ~ fname ~ "_print_ctx(BIO* out_, " ~ stname ~ "* x, int indent,
					 const(ASN1_PCTX)* pctx);
	";
}

template D2I_OF(type) {
    alias ExternC!(type* function(type**, const(ubyte)**, c_long)) D2I_OF;
}
template I2D_OF(type) {
    alias ExternC!(int function(type*, ubyte**)) I2D_OF;
}
template I2D_OF_const(type) {
    alias ExternC!(int function(const(type)*, ubyte**)) I2D_OF_const;
}

d2i_of_void* CHECKED_D2I_OF(type)(D2I_OF!type d2i) {
    return cast(d2i_of_void*) (1 ? d2i : null);
}
i2d_of_void* CHECKED_I2D_OF(type)(I2D_OF!type i2d) {
    return cast(i2d_of_void*) (1 ? i2d : null);
}
ExternC!(type* function()) CHECKED_NEW_OF(type)(ExternC!(type* function()) xnew) {
    return typeof(return)(1 ? xnew : null);
}
void* CHECKED_PTR_OF(type)(type* p) {
    return cast(void*)(1 ? p : null);
}
void* CHECKED_PPTR_OF(type)(type** p) {
    return cast(void**)(1 ? p : null);
}

template TYPEDEF_D2I_OF(string type) {
    enum TYPEDEF_D2I_OF = "alias typeof(D2I_OF!(" ~ type ~ ").init) d2i_of_" ~ type ~ ";";
}
template TYPEDEF_I2D_OF(string type) {
    enum TYPEDEF_I2D_OF = "alias typeof(I2D_OF!(" ~ type ~ ").init) i2d_of_" ~ type ~ ";";
}
template TYPEDEF_D2I2D_OF(string type) {
    enum TYPEDEF_D2I2D_OF = TYPEDEF_D2I_OF!type ~ TYPEDEF_I2D_OF!type;
}

// Probably due to a DMD @@BUG@@, the types are not available to all modules
// if the mixin is used.
// mixin(TYPEDEF_D2I2D_OF!"void");
alias typeof(*(D2I_OF!void).init) d2i_of_void;
alias typeof(*(I2D_OF!void).init) i2d_of_void;

/*-
 * The following macros and typedefs allow an ASN1_ITEM
 * to be embedded in a structure and referenced. Since
 * the ASN1_ITEM pointers need to be globally accessible
 * (possibly from shared libraries) they may exist in
 * different forms. On platforms that support it the
 * ASN1_ITEM structure itself will be globally exported.
 * Other platforms will export a function that returns
 * an ASN1_ITEM pointer.
 *
 * To handle both cases transparently the macros below
 * should be used instead of hard coding an ASN1_ITEM
 * pointer in a structure.
 *
 * The structure will look like this:
 *
 * struct SOMETHING_st {
 *     ...
 *     ASN1_ITEM_EXP* iptr;
 *     ...
 * }
alias SOMETHING_st SOMETHING;
 *
 * It would be initialised as e.g.:
 *
 * SOMETHING somevar = {...,ASN1_ITEM_ref(X509),...};
 *
 * and the actual pointer extracted with:
 *
 * const(ASN1_ITEM)* it = ASN1_ITEM_ptr(somevar.iptr);
 *
 * Finally an ASN1_ITEM pointer can be extracted from an
 * appropriate reference with: ASN1_ITEM_rptr(X509). This
 * would be used when a function takes an ASN1_ITEM* argument.
 *
 */

version (OPENSSL_EXPORT_VAR_AS_FUNCTION) {
	/*
         * Platforms that can't easily handle shared global variables are declared
	 * as functions returning ASN1_ITEM pointers.
	 */

	/* ASN1_ITEM pointer exported type */
	alias const(ASN1_ITEM)* ASN1_ITEM_EXP;

	/* Macro to obtain ASN1_ITEM pointer from exported type */
	template ASN1_ITEM_ptr(string iptr) {
		enum ASN1_ITEM_ptr = "(" ~ iptr ~ ")()";
	}

	/* Macro to include ASN1_ITEM pointer from base type */
	template ASN1_ITEM_ref(string iptr) {
		enum ASN1_ITEM_ref = "(" ~ iptr ~ "_it)";
	}

	template ASN1_ITEM_rptr(string ref_) {
		enum ASN1_ITEM_rptr = "(" ~ ref_ ~ "_it())";
	}

	template DECLARE_ASN1_ITEM(string name) {
		enum DECLARE_ASN1_ITEM = "extern(C) const(ASN1_ITEM)* " ~ name ~ "_it();";
	}
} else {
	/* ASN1_ITEM pointer exported type */
	alias const(ASN1_ITEM) ASN1_ITEM_EXP;

	/* Macro to obtain ASN1_ITEM pointer from exported type */
	template ASN1_ITEM_ptr(string iptr) {
		enum ASN1_ITEM_ptr = iptr;
	}

	/* Macro to include ASN1_ITEM pointer from base type */
	template ASN1_ITEM_ref(string iptr) {
		enum ASN1_ITEM_ref = "(&(" ~ iptr ~ "_it))";
	}

	template ASN1_ITEM_rptr(string ref_) {
		enum ASN1_ITEM_rptr = "(&(" ~ ref_ ~ "_it))";
	}

	template DECLARE_ASN1_ITEM(string name) {
		enum DECLARE_ASN1_ITEM = "extern const(ASN1_ITEM) " ~ name ~ "_it;";
	}
}

/* Parameters used by ASN1_STRING_print_ex() */

/*
 * These determine which characters to escape: RFC2253 special characters,
 * control characters and MSB set characters
 */

enum ASN1_STRFLGS_ESC_2253 = 1;
enum ASN1_STRFLGS_ESC_CTRL = 2;
enum ASN1_STRFLGS_ESC_MSB = 4;

/*
 * This flag determines how we do escaping: normally RC2253 backslash only,
 * set this to use backslash and quote.
 */

enum ASN1_STRFLGS_ESC_QUOTE = 8;


/* These three flags are internal use only. */

/* Character is a valid PrintableString character */
enum CHARTYPE_PRINTABLESTRING = 0x10;
/* Character needs escaping if it is the first character */
enum CHARTYPE_FIRST_ESC_2253 = 0x20;
/* Character needs escaping if it is the last character */
enum CHARTYPE_LAST_ESC_2253 = 0x40;

/*
 * NB the internal flags are safely reused below by flags handled at the top
 * level.
 */

/*
 * If this is set we convert all character strings to UTF8 first
 */

enum ASN1_STRFLGS_UTF8_CONVERT = 0x10;

/*
 * If this is set we don't attempt to interpret content: just assume all
 * strings are 1 byte per character. This will produce some pretty odd
 * looking output!
 */

enum ASN1_STRFLGS_IGNORE_TYPE = 0x20;

/* If this is set we include the string type in the output */
enum ASN1_STRFLGS_SHOW_TYPE = 0x40;

/*
 * This determines which strings to display and which to 'dump' (hex dump of
 * content octets or DER encoding). We can only dump non character strings or
 * everything. If we don't dump 'unknown' they are interpreted as character
 * strings with 1 octet per character and are subject to the usual escaping
 * options.
 */

enum ASN1_STRFLGS_DUMP_ALL = 0x80;
enum ASN1_STRFLGS_DUMP_UNKNOWN = 0x100;

/*
 * These determine what 'dumping' does, we can dump the content octets or the
 * DER encoding: both use the RFC2253 #XXXXX notation.
 */

enum ASN1_STRFLGS_DUMP_DER = 0x200;

/*
 * This flag specifies that RC2254 escaping shall be performed.
 */
enum ASN1_STRFLGS_ESC_2254 = 0x400;

/*
 * All the string flags consistent with RFC2253, escaping control characters
 * isn't essential in RFC2253 but it is advisable anyway.
 */

enum ASN1_STRFLGS_RFC2253 =	(ASN1_STRFLGS_ESC_2253 |
				ASN1_STRFLGS_ESC_CTRL |
				ASN1_STRFLGS_ESC_MSB |
				ASN1_STRFLGS_UTF8_CONVERT |
				ASN1_STRFLGS_DUMP_UNKNOWN |
				ASN1_STRFLGS_DUMP_DER);

/+mixin DEFINE_STACK_OF!(ASN1_INTEGER);+/

/+mixin DEFINE_STACK_OF!(ASN1_GENERALSTRING);+/

/+mixin DEFINE_STACK_OF(ASN1_UTF8STRING);+/

struct asn1_type_st
	{
	int type;
	union value_ {
		char* ptr;
		ASN1_BOOLEAN		boolean;
		ASN1_STRING* 		asn1_string;
		ASN1_OBJECT* 		object;
		ASN1_INTEGER* 		integer;
		ASN1_ENUMERATED* 	enumerated;
		ASN1_BIT_STRING* 	bit_string;
		ASN1_OCTET_STRING* 	octet_string;
		ASN1_PRINTABLESTRING* 	printablestring;
		ASN1_T61STRING* 	t61string;
		ASN1_IA5STRING* 	ia5string;
		ASN1_GENERALSTRING* 	generalstring;
		ASN1_BMPSTRING* 	bmpstring;
		ASN1_UNIVERSALSTRING* 	universalstring;
		ASN1_UTCTIME* 		utctime;
		ASN1_GENERALIZEDTIME* 	generalizedtime;
		ASN1_VISIBLESTRING* 	visiblestring;
		ASN1_UTF8STRING* 	utf8string;
		/*
                 * set and sequence are left complete and still
		 * contain the set or sequence bytes
                 */
		ASN1_STRING* 		set;
		ASN1_STRING* 		sequence;
		ASN1_VALUE* 		asn1_value;
		}
	value_ value;
	}
alias asn1_type_st ASN1_TYPE;

/+mixin DEFINE_STACK_OF!(ASN1_TYPE);+/

alias STACK_OF!(ASN1_TYPE) ASN1_SEQUENCE_ANY;

mixin(DECLARE_ASN1_ENCODE_FUNCTIONS_const!("ASN1_SEQUENCE_ANY", "ASN1_SEQUENCE_ANY"));
mixin(DECLARE_ASN1_ENCODE_FUNCTIONS_const!("ASN1_SEQUENCE_ANY", "ASN1_SET_ANY"));

/* This is used to contain a list of bit names */
struct BIT_STRING_BITNAME_st {
	int bitnum;
	const(char)* lname;
	const(char)* sname;
}
alias BIT_STRING_BITNAME_st BIT_STRING_BITNAME;

enum B_ASN1_TIME =
			B_ASN1_UTCTIME |
			B_ASN1_GENERALIZEDTIME;

enum B_ASN1_PRINTABLE =
			B_ASN1_NUMERICSTRING|
			B_ASN1_PRINTABLESTRING|
			B_ASN1_T61STRING|
			B_ASN1_IA5STRING|
			B_ASN1_BIT_STRING|
			B_ASN1_UNIVERSALSTRING|
			B_ASN1_BMPSTRING|
			B_ASN1_UTF8STRING|
			B_ASN1_SEQUENCE|
			B_ASN1_UNKNOWN;

enum B_ASN1_DIRECTORYSTRING =
			B_ASN1_PRINTABLESTRING|
			B_ASN1_TELETEXSTRING|
			B_ASN1_BMPSTRING|
			B_ASN1_UNIVERSALSTRING|
			B_ASN1_UTF8STRING;

enum B_ASN1_DISPLAYTEXT =
			B_ASN1_IA5STRING|
			B_ASN1_VISIBLESTRING|
			B_ASN1_BMPSTRING|
			B_ASN1_UTF8STRING;
mixin(DECLARE_ASN1_FUNCTIONS_fname!("ASN1_TYPE", "ASN1_ANY", "ASN1_TYPE"));

int ASN1_TYPE_get(const(ASN1_TYPE)* a);
void ASN1_TYPE_set(ASN1_TYPE* a, int type, void* value);
int ASN1_TYPE_set1(ASN1_TYPE* a, int type, const(void)* value);
int ASN1_TYPE_cmp(const(ASN1_TYPE)* a, const(ASN1_TYPE)* b);

ASN1_TYPE* ASN1_TYPE_pack_sequence(const(ASN1_ITEM)* it, void* s, ASN1_TYPE** t);
void* ASN1_TYPE_unpack_sequence(const(ASN1_ITEM)* it, const ASN1_TYPE* t);

ASN1_OBJECT* 	ASN1_OBJECT_new();
void		ASN1_OBJECT_free(ASN1_OBJECT* a);
int i2d_ASN1_OBJECT(const(ASN1_OBJECT)* a, ubyte** pp);
ASN1_OBJECT* 	d2i_ASN1_OBJECT(ASN1_OBJECT** a,const(ubyte)** pp,
			c_long length);

mixin(DECLARE_ASN1_ITEM!"ASN1_OBJECT");

/+mixin DEFINE_STACK_OF!(ASN1_OBJECT);+/

ASN1_STRING* 	ASN1_STRING_new();
void		ASN1_STRING_free(ASN1_STRING* a);
void ASN1_STRING_clear_free(ASN1_STRING* a);
int		ASN1_STRING_copy(ASN1_STRING* dst, const(ASN1_STRING)* str);
ASN1_STRING* 	ASN1_STRING_dup(const(ASN1_STRING)* a);
ASN1_STRING* 	ASN1_STRING_type_new(int type );
int 		ASN1_STRING_cmp(const(ASN1_STRING)* a, const(ASN1_STRING)* b);
  /*
   * Since this is used to store all sorts of things, via macros, for now,
   * make its data void *
   */
int 		ASN1_STRING_set(ASN1_STRING* str, const(void)* data, int len);
void		ASN1_STRING_set0(ASN1_STRING* str, void* data, int len);
int ASN1_STRING_length(const(ASN1_STRING)* x);
void ASN1_STRING_length_set(ASN1_STRING* x, int n);
int ASN1_STRING_type(const(ASN1_STRING)* x);
// TODO: +DEPRECATEDIN_1_1_0(unsigned char *ASN1_STRING_data(ASN1_STRING *x))
ubyte* ASN1_STRING_data(ASN1_STRING* x);
const(ubyte)* ASN1_STRING_get0_data(const(ASN1_STRING)* x);

mixin(DECLARE_ASN1_FUNCTIONS!"ASN1_BIT_STRING");
int ASN1_BIT_STRING_set(ASN1_BIT_STRING* a, ubyte* d, int length );
int ASN1_BIT_STRING_set_bit(ASN1_BIT_STRING* a, int n, int value);
int ASN1_BIT_STRING_get_bit(const(ASN1_BIT_STRING)* a, int n);
int ASN1_BIT_STRING_check(const(ASN1_BIT_STRING)* a,
                          const(ubyte)* flags, int flags_len);

int ASN1_BIT_STRING_name_print(BIO* out_, ASN1_BIT_STRING* bs,
                               BIT_STRING_BITNAME* tbl, int indent);
int ASN1_BIT_STRING_num_asc(const(char)* name, BIT_STRING_BITNAME* tbl);
int ASN1_BIT_STRING_set_asc(ASN1_BIT_STRING* bs, const(char)* name, int value,
                            BIT_STRING_BITNAME* tbl);

mixin(DECLARE_ASN1_FUNCTIONS!"ASN1_INTEGER");
ASN1_INTEGER* d2i_ASN1_UINTEGER(ASN1_INTEGER** a,const(ubyte)** pp,
			c_long length);
ASN1_INTEGER* 	ASN1_INTEGER_dup(const(ASN1_INTEGER)* x);
int ASN1_INTEGER_cmp(const(ASN1_INTEGER)* x, const(ASN1_INTEGER)* y);

mixin(DECLARE_ASN1_FUNCTIONS!"ASN1_ENUMERATED");

int ASN1_UTCTIME_check(const(ASN1_UTCTIME)* a);
ASN1_UTCTIME* ASN1_UTCTIME_set(ASN1_UTCTIME* s,time_t t);
ASN1_UTCTIME* ASN1_UTCTIME_adj(ASN1_UTCTIME* s, time_t t,
				int offset_day, c_long offset_sec);
int ASN1_UTCTIME_set_string(ASN1_UTCTIME* s, const(char)* str);
int ASN1_UTCTIME_cmp_time_t(const(ASN1_UTCTIME)* s, time_t t);

int ASN1_GENERALIZEDTIME_check(const(ASN1_GENERALIZEDTIME)* a);
ASN1_GENERALIZEDTIME* ASN1_GENERALIZEDTIME_set(ASN1_GENERALIZEDTIME* s,
                                               time_t t);
ASN1_GENERALIZEDTIME* ASN1_GENERALIZEDTIME_adj(ASN1_GENERALIZEDTIME* s,
                                               time_t t, int offset_day,
                                               c_long offset_sec);
int ASN1_GENERALIZEDTIME_set_string(ASN1_GENERALIZEDTIME* s, const(char)* str);
int ASN1_TIME_diff(int* pday, int* psec,
                   const(ASN1_TIME)* from, const(ASN1_TIME)* to);

mixin(DECLARE_ASN1_FUNCTIONS!"ASN1_OCTET_STRING");
ASN1_OCTET_STRING* 	ASN1_OCTET_STRING_dup(const(ASN1_OCTET_STRING)* a);
int ASN1_OCTET_STRING_cmp(const(ASN1_OCTET_STRING)* a,
                          const(ASN1_OCTET_STRING)* b);
int ASN1_OCTET_STRING_set(ASN1_OCTET_STRING* str,
                          const(ubyte)* data, int len);

mixin(DECLARE_ASN1_FUNCTIONS!"ASN1_VISIBLESTRING");
mixin(DECLARE_ASN1_FUNCTIONS!"ASN1_UNIVERSALSTRING");
mixin(DECLARE_ASN1_FUNCTIONS!"ASN1_UTF8STRING");
mixin(DECLARE_ASN1_FUNCTIONS!"ASN1_NULL");
mixin(DECLARE_ASN1_FUNCTIONS!"ASN1_BMPSTRING");

int UTF8_getc(const(char)* str, int len, c_ulong* val);
int UTF8_putc(char* str, int len, c_ulong value);

mixin(DECLARE_ASN1_FUNCTIONS_name!("ASN1_STRING", "ASN1_PRINTABLE"));

mixin(DECLARE_ASN1_FUNCTIONS_name!("ASN1_STRING", "DIRECTORYSTRING"));
mixin(DECLARE_ASN1_FUNCTIONS_name!("ASN1_STRING", "DISPLAYTEXT"));
mixin(DECLARE_ASN1_FUNCTIONS!"ASN1_PRINTABLESTRING");
mixin(DECLARE_ASN1_FUNCTIONS!"ASN1_T61STRING");
mixin(DECLARE_ASN1_FUNCTIONS!"ASN1_IA5STRING");
mixin(DECLARE_ASN1_FUNCTIONS!"ASN1_GENERALSTRING");
mixin(DECLARE_ASN1_FUNCTIONS!"ASN1_UTCTIME");
mixin(DECLARE_ASN1_FUNCTIONS!"ASN1_GENERALIZEDTIME");
mixin(DECLARE_ASN1_FUNCTIONS!"ASN1_TIME");

mixin(DECLARE_ASN1_ITEM!"ASN1_OCTET_STRING_NDEF");

ASN1_TIME* ASN1_TIME_set(ASN1_TIME* s,time_t t);
ASN1_TIME* ASN1_TIME_adj(ASN1_TIME* s,time_t t,
				int offset_day, c_long offset_sec);
int ASN1_TIME_check(const(ASN1_TIME)* t);
ASN1_GENERALIZEDTIME* ASN1_TIME_to_generalizedtime(ASN1_TIME* t, ASN1_GENERALIZEDTIME** out_);
int ASN1_TIME_set_string(ASN1_TIME* s, const(char)* str);

int i2a_ASN1_INTEGER(BIO* bp, const(ASN1_INTEGER)* a);
int a2i_ASN1_INTEGER(BIO* bp,ASN1_INTEGER* bs,char* buf,int size);
int i2a_ASN1_ENUMERATED(BIO* bp, const(ASN1_ENUMERATED)* a);
int a2i_ASN1_ENUMERATED(BIO* bp,ASN1_ENUMERATED* bs,char* buf,int size);
int i2a_ASN1_OBJECT(BIO* bp, const(ASN1_OBJECT)* a);
int a2i_ASN1_STRING(BIO* bp,ASN1_STRING* bs,char* buf,int size);
int i2a_ASN1_STRING(BIO* bp, const(ASN1_STRING)* a, int type);
int i2t_ASN1_OBJECT(char* buf,int buf_len, const(ASN1_OBJECT)* a);

int a2d_ASN1_OBJECT(ubyte* out_,int olen, const(char)* buf, int num);
ASN1_OBJECT* ASN1_OBJECT_create(int nid, ubyte* data,int len,
	const(char)* sn, const(char)* ln);

int ASN1_INTEGER_get_int64(long* pr, const(ASN1_INTEGER)* a);
int ASN1_INTEGER_set_int64(ASN1_INTEGER* a, long r);
int ASN1_INTEGER_get_uint64(long* pr, const(ASN1_INTEGER)* a);
int ASN1_INTEGER_set_uint64(ASN1_INTEGER* a, long r);

int ASN1_INTEGER_set(ASN1_INTEGER* a, c_long v);
c_long ASN1_INTEGER_get(const(ASN1_INTEGER)* a);
ASN1_INTEGER* BN_to_ASN1_INTEGER(const(BIGNUM)* bn, ASN1_INTEGER* ai);
BIGNUM* ASN1_INTEGER_to_BN(const(ASN1_INTEGER)* ai,BIGNUM* bn);

int ASN1_ENUMERATED_get_int64(long* pr, const(ASN1_ENUMERATED)* a);
int ASN1_ENUMERATED_set_int64(ASN1_ENUMERATED* a, long r);


int ASN1_ENUMERATED_set(ASN1_ENUMERATED* a, c_long v);
c_long ASN1_ENUMERATED_get(const(ASN1_ENUMERATED)* a);
ASN1_ENUMERATED* BN_to_ASN1_ENUMERATED(const(BIGNUM)* bn, ASN1_ENUMERATED* ai);
BIGNUM* ASN1_ENUMERATED_to_BN(const(ASN1_ENUMERATED)* ai,BIGNUM* bn);

/* General */
/* given a string, return the correct type, max is the maximum length */
int ASN1_PRINTABLE_type(const(ubyte)* s, int max);

c_ulong ASN1_tag2bit(int tag);

/* SPECIALS */
int ASN1_get_object(const(ubyte)** pp, c_long* plength, int* ptag,
	int* pclass, c_long omax);
int ASN1_check_infinite_end(ubyte** p,c_long len);
int ASN1_const_check_infinite_end(const(ubyte)** p,c_long len);
void ASN1_put_object(ubyte** pp, int constructed, int length,
	int tag, int xclass);
int ASN1_put_eoc(ubyte** pp);
int ASN1_object_size(int constructed, int length, int tag);

/* Used to implement other functions */
void* ASN1_dup(i2d_of_void* i2d, d2i_of_void* d2i, void* x);

auto ASN1_dup_of(type)(I2D_OF!type* i2d, D2I_OF!type* d2i, type* x) {
    return cast(type*)(ASN1_dup(CHECKED_I2D_OF!type(i2d),
		     CHECKED_D2I_OF!type(d2i),
		     CHECKED_PTR_OF!type(x)));
}

auto ASN1_dup_of_const(type)(I2D_OF!(const(type))* i2d, D2I_OF!type* d2i, const(type)* x) {
    return cast(type*)(ASN1_dup(CHECKED_I2D_OF!(const(type))(i2d),
		     CHECKED_D2I_OF!type(d2i),
		     CHECKED_PTR_OF!(const(type))(x)));
}

void* ASN1_item_dup(const(ASN1_ITEM)* it, void* x);

/* ASN1 alloc/free macros for when a type is only used internally */

template M_ASN1_new_of(string type) {
	enum M_ASN1_new_of = "(cast(" ~ type ~ "*)ASN1_item_new(ASN1_ITEM_rptr!`" ~ type ~ "`))";
}
template M_ASN1_free_of(string x, string type) {
	enum M_ASN1_free_of = "ASN1_item_free(CHECKED_PTR_OF!(" ~ type ~ ")(" ~ x ~ "), ASN1_ITEM_rptr!`" ~ type ~ "`))";
}

version (OPENSSL_NO_STDIO) {} else {
void* ASN1_d2i_fp(ExternC!(void* function()) xnew, d2i_of_void* d2i, FILE* in_, void** x);

type* ASN1_d2i_fp_of(type)(ExternC!(type* function()) xnew, d2i,in_,x) {
    return cast(type*)(ASN1_d2i_fp(CHECKED_NEW_OF!type(xnew),
			CHECKED_D2I_OF!type(d2i),
			in_,
			CHECKED_PPTR_OF!type(x)));
}

void* ASN1_item_d2i_fp(const(ASN1_ITEM)* it, FILE* in_, void* x);
int ASN1_i2d_fp(i2d_of_void* i2d,FILE* out_,void* x);

auto ASN1_i2d_fp_of(type)(I2D_OF!(type) i2d, FILE* out_, const(type)* x) {
	return ASN1_i2d_fp(CHECKED_I2D_OF!(type)(i2d), out_, CHECKED_PTR_OF!(type)(x));
}

auto ASN1_i2d_fp_of_const(type)(I2D_OF!(const(type)) i2d, FILE* out_, const(type)* x) {
	return ASN1_i2d_fp(CHECKED_I2D_OF!(const(type))(i2d), out_, CHECKED_PTR_OF!(const(type))(x));
}

int ASN1_item_i2d_fp(const(ASN1_ITEM)* it, FILE* out_, void* x);
int ASN1_STRING_print_ex_fp(FILE* fp, const(ASN1_STRING)* str, c_ulong flags);
}

int ASN1_STRING_to_UTF8(char** out_, const(ASN1_STRING)* in_);

void* ASN1_d2i_bio(ExternC!(void* function()) xnew, d2i_of_void* d2i, BIO* in_, void** x);

type* ASN1_d2i_bio_of(type)(ExternC!(type* function()) xnew, D2I_OF!type d2i, BIO* in_, type** x) {
	return cast(type*)ASN1_d2i_bio(CHECKED_NEW_OF!type(xnew),
		CHECKED_D2I_OF!type(d2i), in_, CHECKED_PPTR_OF!type(x));
}

void* ASN1_item_d2i_bio(const(ASN1_ITEM)* it, BIO* in_, void* x);
int ASN1_i2d_bio(i2d_of_void* i2d,BIO* out_, ubyte* x);

int ASN1_i2d_bio_of(type)(I2D_OF!type* i2d,BIO* out_,type* x) {
	return ASN1_i2d_bio(CHECKED_I2D_OF!type(i2d), out_, CHECKED_PTR_OF!type(x));
}

int ASN1_i2d_bio_of_const(type)(I2D_OF!(const(type))* i2d,BIO* out_,type* x) {
	return ASN1_i2d_bio(CHECKED_I2D_OF!type(i2d), out_, CHECKED_PTR_OF!(const(type))(x));
}

int ASN1_item_i2d_bio(const(ASN1_ITEM)* it, BIO* out_, void* x);
int ASN1_UTCTIME_print(BIO* fp, const(ASN1_UTCTIME)* a);
int ASN1_GENERALIZEDTIME_print(BIO* fp, const(ASN1_GENERALIZEDTIME)* a);
int ASN1_TIME_print(BIO* fp, const(ASN1_TIME)* a);
int ASN1_STRING_print(BIO* bp, const(ASN1_STRING)* v);
int ASN1_STRING_print_ex(BIO* out_, const(ASN1_STRING)* str, c_ulong flags);
int ASN1_buf_print(BIO* bp, const(ubyte)* buf, size_t buflen, int off);
int ASN1_bn_print(BIO* bp, const(char)* number, const(BIGNUM)* num,
				ubyte* buf, int off);
int ASN1_parse(BIO* bp,const(ubyte)* pp,c_long len,int indent);
int ASN1_parse_dump(BIO* bp, const(ubyte)* pp,c_long len,int indent,
                    int dump);
const(char)* ASN1_tag2str(int tag);

/* Used to load and write Netscape format cert */

int ASN1_UNIVERSALSTRING_to_string(ASN1_UNIVERSALSTRING* s);

int ASN1_TYPE_set_octetstring(ASN1_TYPE* a, ubyte* data, int len);
int ASN1_TYPE_get_octetstring(const(ASN1_TYPE)* a, ubyte* data, int max_len);
int ASN1_TYPE_set_int_octetstring(ASN1_TYPE* a, c_long num,
                                  ubyte* data, int len);
int ASN1_TYPE_get_int_octetstring(const(ASN1_TYPE)* a, c_long* num,
                                  ubyte* data, int max_len);

void* ASN1_item_unpack(const(ASN1_STRING)* oct, const(ASN1_ITEM)* it);

ASN1_STRING* ASN1_item_pack(void* obj, const(ASN1_ITEM)* it,
                            ASN1_OCTET_STRING** oct);

void ASN1_STRING_set_default_mask(c_ulong mask);
int ASN1_STRING_set_default_mask_asc(const(char)* p);
c_ulong ASN1_STRING_get_default_mask();
int ASN1_mbstring_copy(ASN1_STRING** out_, const(ubyte)* in_, int len,
					int inform, c_ulong mask);
int ASN1_mbstring_ncopy(ASN1_STRING** out_, const(ubyte)* in_, int len,
					int inform, c_ulong mask,
					c_long minsize, c_long maxsize);

ASN1_STRING* ASN1_STRING_set_by_NID(ASN1_STRING** out_,
                                    const(ubyte)* in_, int inlen,
                                    int inform, int nid);
ASN1_STRING_TABLE* ASN1_STRING_TABLE_get(int nid);
int ASN1_STRING_TABLE_add(int, c_long, c_long, c_ulong, c_ulong);
void ASN1_STRING_TABLE_cleanup();

/* ASN1 template functions */

/* Old API compatible functions */
ASN1_VALUE* ASN1_item_new(const(ASN1_ITEM)* it);
void ASN1_item_free(ASN1_VALUE* val, const(ASN1_ITEM)* it);
ASN1_VALUE* ASN1_item_d2i(ASN1_VALUE** val, const(ubyte)** in_,
                          c_long len, const(ASN1_ITEM)* it);
int ASN1_item_i2d(ASN1_VALUE* val, ubyte** out_, const(ASN1_ITEM)* it);
int ASN1_item_ndef_i2d(ASN1_VALUE* val, ubyte** out_,
                       const(ASN1_ITEM)* it);

void ASN1_add_oid_module();
void ASN1_add_stable_module();

ASN1_TYPE* ASN1_generate_nconf(const(char)* str, CONF* nconf);
ASN1_TYPE* ASN1_generate_v3(const(char)* str, X509V3_CTX* cnf);
int ASN1_str2mask(const(char)* str, c_ulong* pmask);

/* ASN1 Print flags */

/* Indicate missing OPTIONAL fields */
enum ASN1_PCTX_FLAGS_SHOW_ABSENT = 0x001;
/* Mark start and end of SEQUENCE */
enum ASN1_PCTX_FLAGS_SHOW_SEQUENCE = 0x002;
/* Mark start and end of SEQUENCE/SET OF */
enum ASN1_PCTX_FLAGS_SHOW_SSOF = 0x004;
/* Show the ASN1 type of primitives */
enum ASN1_PCTX_FLAGS_SHOW_TYPE = 0x008;
/* Don't show ASN1 type of ANY */
enum ASN1_PCTX_FLAGS_NO_ANY_TYPE = 0x010;
/* Don't show ASN1 type of MSTRINGs */
enum ASN1_PCTX_FLAGS_NO_MSTRING_TYPE = 0x020;
/* Don't show field names in SEQUENCE */
enum ASN1_PCTX_FLAGS_NO_FIELD_NAME = 0x040;
/* Show structure names of each SEQUENCE field */
enum ASN1_PCTX_FLAGS_SHOW_FIELD_STRUCT_NAME = 0x080;
/* Don't show structure name even at top level */
enum ASN1_PCTX_FLAGS_NO_STRUCT_NAME = 0x100;

int ASN1_item_print(BIO* out_, ASN1_VALUE* ifld, int indent,
				const(ASN1_ITEM)* it, const(ASN1_PCTX)* pctx);
ASN1_PCTX* ASN1_PCTX_new();
void ASN1_PCTX_free(ASN1_PCTX* p);
c_ulong ASN1_PCTX_get_flags(const(ASN1_PCTX)* p);
void ASN1_PCTX_set_flags(ASN1_PCTX* p, c_ulong flags);
c_ulong ASN1_PCTX_get_nm_flags(const(ASN1_PCTX)* p);
void ASN1_PCTX_set_nm_flags(ASN1_PCTX* p, c_ulong flags);
c_ulong ASN1_PCTX_get_cert_flags(const(ASN1_PCTX)* p);
void ASN1_PCTX_set_cert_flags(ASN1_PCTX* p, c_ulong flags);
c_ulong ASN1_PCTX_get_oid_flags(const(ASN1_PCTX)* p);
void ASN1_PCTX_set_oid_flags(ASN1_PCTX* p, c_ulong flags);
c_ulong ASN1_PCTX_get_str_flags(const(ASN1_PCTX)* p);
void ASN1_PCTX_set_str_flags(ASN1_PCTX* p, c_ulong flags);

ASN1_SCTX* ASN1_SCTX_new(ExternC!(int function(ASN1_SCTX* ctx)) scan_cb);
void ASN1_SCTX_free(ASN1_SCTX* p);
const(ASN1_ITEM)* ASN1_SCTX_get_item(ASN1_SCTX* p);
const(ASN1_TEMPLATE)* ASN1_SCTX_get_template(ASN1_SCTX* p);
c_ulong ASN1_SCTX_get_flags(ASN1_SCTX* p);
void ASN1_SCTX_set_app_data(ASN1_SCTX* p, void* data);
void* ASN1_SCTX_get_app_data(ASN1_SCTX* p);

const(BIO_METHOD)* BIO_f_asn1();

BIO* BIO_new_NDEF(BIO* out_, ASN1_VALUE* val, const(ASN1_ITEM)* it);

int i2d_ASN1_bio_stream(BIO* out_, ASN1_VALUE* val, BIO* in_, int flags,
				const(ASN1_ITEM)* it);
int PEM_write_bio_ASN1_stream(BIO* out_, ASN1_VALUE* val, BIO* in_, int flags,
                              const(char)* hdr, const(ASN1_ITEM)* it);
int SMIME_write_ASN1(BIO* bio, ASN1_VALUE* val, BIO* data, int flags,
                     int ctype_nid, int econt_nid,
                     STACK_OF!(X509_ALGOR) *mdalgs, const(ASN1_ITEM)* it);
ASN1_VALUE* SMIME_read_ASN1(BIO* bio, BIO** bcont, const(ASN1_ITEM)* it);
int SMIME_crlf_copy(BIO* in_, BIO* out_, int flags);
int SMIME_text(BIO* in_, BIO* out_);

/* BEGIN ERROR CODES */
/*
 * The following lines are auto generated by the script mkerr.pl. Any changes
 * made after this point may be overwritten when the script is next run.
 */
int ERR_load_ASN1_strings();

/* Error codes for the ASN1 functions. */

/* Function codes. */
enum ASN1_F_A2D_ASN1_OBJECT = 100;
enum ASN1_F_A2I_ASN1_INTEGER = 102;
enum ASN1_F_A2I_ASN1_STRING = 103;
enum ASN1_F_APPEND_EXP = 176;
enum ASN1_F_ASN1_BIT_STRING_SET_BIT = 183;
enum ASN1_F_ASN1_CB = 177;
enum ASN1_F_ASN1_CHECK_TLEN = 104;
enum ASN1_F_ASN1_COLLECT = 106;
enum ASN1_F_ASN1_D2I_EX_PRIMITIVE = 108;
enum ASN1_F_ASN1_D2I_FP = 109;
enum ASN1_F_ASN1_D2I_READ_BIO = 107;
enum ASN1_F_ASN1_DIGEST = 184;
enum ASN1_F_ASN1_DO_ADB = 110;
enum ASN1_F_ASN1_DO_LOCK = 233;
enum ASN1_F_ASN1_DUP = 111;
enum ASN1_F_ASN1_EX_C2I = 204;
enum ASN1_F_ASN1_FIND_END = 190;
enum ASN1_F_ASN1_GENERALIZEDTIME_ADJ = 216;
enum ASN1_F_ASN1_GENERATE_V3 = 178;
enum ASN1_F_ASN1_GET_INT64 = 224;
enum ASN1_F_ASN1_GET_OBJECT = 114;
enum ASN1_F_ASN1_GET_UINT64 = 225;
enum ASN1_F_ASN1_I2D_BIO = 116;
enum ASN1_F_ASN1_I2D_FP = 117;
enum ASN1_F_ASN1_ITEM_D2I_FP = 206;
enum ASN1_F_ASN1_ITEM_DUP = 191;
enum ASN1_F_ASN1_ITEM_EMBED_D2I = 120;
enum ASN1_F_ASN1_ITEM_EMBED_NEW = 121;
enum ASN1_F_ASN1_ITEM_I2D_BIO = 192;
enum ASN1_F_ASN1_ITEM_I2D_FP = 193;
enum ASN1_F_ASN1_ITEM_PACK = 198;
enum ASN1_F_ASN1_ITEM_SIGN = 195;
enum ASN1_F_ASN1_ITEM_SIGN_CTX = 220;
enum ASN1_F_ASN1_ITEM_UNPACK = 199;
enum ASN1_F_ASN1_ITEM_VERIFY = 197;
enum ASN1_F_ASN1_MBSTRING_NCOPY = 122;
enum ASN1_F_ASN1_OBJECT_NEW = 123;
enum ASN1_F_ASN1_OUTPUT_DATA = 214;
enum ASN1_F_ASN1_PCTX_NEW = 205;
enum ASN1_F_ASN1_SCTX_NEW = 221;
enum ASN1_F_ASN1_SIGN = 128;
enum ASN1_F_ASN1_STR2TYPE = 179;
enum ASN1_F_ASN1_STRING_GET_INT64 = 227;
enum ASN1_F_ASN1_STRING_GET_UINT64 = 230;
enum ASN1_F_ASN1_STRING_SET = 186;
enum ASN1_F_ASN1_STRING_TABLE_ADD = 129;
enum ASN1_F_ASN1_STRING_TO_BN = 228;
enum ASN1_F_ASN1_STRING_TYPE_NEW = 130;
enum ASN1_F_ASN1_TEMPLATE_EX_D2I = 132;
enum ASN1_F_ASN1_TEMPLATE_NEW = 133;
enum ASN1_F_ASN1_TEMPLATE_NOEXP_D2I = 131;
enum ASN1_F_ASN1_TIME_ADJ = 217;
enum ASN1_F_ASN1_TYPE_GET_INT_OCTETSTRING = 134;
enum ASN1_F_ASN1_TYPE_GET_OCTETSTRING = 135;
enum ASN1_F_ASN1_UTCTIME_ADJ = 218;
enum ASN1_F_ASN1_VERIFY = 137;
enum ASN1_F_B64_READ_ASN1 = 209;
enum ASN1_F_B64_WRITE_ASN1 = 210;
enum ASN1_F_BIO_NEW_NDEF = 208;
enum ASN1_F_BITSTR_CB = 180;
enum ASN1_F_BN_TO_ASN1_STRING = 229;
enum ASN1_F_C2I_ASN1_BIT_STRING = 189;
enum ASN1_F_C2I_ASN1_INTEGER = 194;
enum ASN1_F_C2I_ASN1_OBJECT = 196;
enum ASN1_F_C2I_IBUF = 226;
enum ASN1_F_COLLECT_DATA = 140;
enum ASN1_F_D2I_ASN1_OBJECT = 147;
enum ASN1_F_D2I_ASN1_UINTEGER = 150;
enum ASN1_F_D2I_AUTOPRIVATEKEY = 207;
enum ASN1_F_D2I_PRIVATEKEY = 154;
enum ASN1_F_D2I_PUBLICKEY = 155;
enum ASN1_F_DO_TCREATE = 222;
enum ASN1_F_I2D_ASN1_BIO_STREAM = 211;
enum ASN1_F_I2D_DSA_PUBKEY = 161;
enum ASN1_F_I2D_EC_PUBKEY = 181;
enum ASN1_F_I2D_PRIVATEKEY = 163;
enum ASN1_F_I2D_PUBLICKEY = 164;
enum ASN1_F_I2D_RSA_PUBKEY = 165;
enum ASN1_F_LONG_C2I = 166;
enum ASN1_F_OID_MODULE_INIT = 174;
enum ASN1_F_PARSE_TAGGING = 182;
enum ASN1_F_PKCS5_PBE2_SET_IV = 167;
enum ASN1_F_PKCS5_PBE2_SET_SCRYPT = 231;
enum ASN1_F_PKCS5_PBE_SET = 202;
enum ASN1_F_PKCS5_PBE_SET0_ALGOR = 215;
enum ASN1_F_PKCS5_PBKDF2_SET = 219;
enum ASN1_F_PKCS5_SCRYPT_SET = 232;
enum ASN1_F_SMIME_READ_ASN1 = 212;
enum ASN1_F_SMIME_TEXT = 213;
enum ASN1_F_STBL_MODULE_INIT = 223;
enum ASN1_F_X509_CRL_ADD0_REVOKED = 169;
enum ASN1_F_X509_INFO_NEW = 170;
enum ASN1_F_X509_NAME_ENCODE = 203;
enum ASN1_F_X509_NAME_EX_D2I = 158;
enum ASN1_F_X509_NAME_EX_NEW = 171;
enum ASN1_F_X509_PKEY_NEW = 173;

/* Reason codes. */
enum ASN1_R_ADDING_OBJECT = 171;
enum ASN1_R_ASN1_PARSE_ERROR = 203;
enum ASN1_R_ASN1_SIG_PARSE_ERROR = 204;
enum ASN1_R_AUX_ERROR = 100;
enum ASN1_R_BAD_TAG = 104;
enum ASN1_R_BMPSTRING_IS_WRONG_LENGTH = 214;
enum ASN1_R_BN_LIB = 105;
enum ASN1_R_BOOLEAN_IS_WRONG_LENGTH = 106;
enum ASN1_R_BUFFER_TOO_SMALL = 107;
enum ASN1_R_CIPHER_HAS_NO_OBJECT_IDENTIFIER = 108;
enum ASN1_R_CONTEXT_NOT_INITIALISED = 217;
enum ASN1_R_DATA_IS_WRONG = 109;
enum ASN1_R_DECODE_ERROR = 110;
enum ASN1_R_DEPTH_EXCEEDED = 174;
enum ASN1_R_DIGEST_AND_KEY_TYPE_NOT_SUPPORTED = 198;
enum ASN1_R_ENCODE_ERROR = 112;
enum ASN1_R_ERROR_GETTING_TIME = 173;
enum ASN1_R_ERROR_LOADING_SECTION = 172;
enum ASN1_R_ERROR_SETTING_CIPHER_PARAMS = 114;
enum ASN1_R_EXPECTING_AN_INTEGER = 115;
enum ASN1_R_EXPECTING_AN_OBJECT = 116;
enum ASN1_R_EXPLICIT_LENGTH_MISMATCH = 119;
enum ASN1_R_EXPLICIT_TAG_NOT_CONSTRUCTED = 120;
enum ASN1_R_FIELD_MISSING = 121;
enum ASN1_R_FIRST_NUM_TOO_LARGE = 122;
enum ASN1_R_HEADER_TOO_LONG = 123;
enum ASN1_R_ILLEGAL_BITSTRING_FORMAT = 175;
enum ASN1_R_ILLEGAL_BOOLEAN = 176;
enum ASN1_R_ILLEGAL_CHARACTERS = 124;
enum ASN1_R_ILLEGAL_FORMAT = 177;
enum ASN1_R_ILLEGAL_HEX = 178;
enum ASN1_R_ILLEGAL_IMPLICIT_TAG = 179;
enum ASN1_R_ILLEGAL_INTEGER = 180;
enum ASN1_R_ILLEGAL_NEGATIVE_VALUE = 226;
enum ASN1_R_ILLEGAL_NESTED_TAGGING = 181;
enum ASN1_R_ILLEGAL_NULL = 125;
enum ASN1_R_ILLEGAL_NULL_VALUE = 182;
enum ASN1_R_ILLEGAL_OBJECT = 183;
enum ASN1_R_ILLEGAL_OPTIONAL_ANY = 126;
enum ASN1_R_ILLEGAL_OPTIONS_ON_ITEM_TEMPLATE = 170;
enum ASN1_R_ILLEGAL_PADDING = 221;
enum ASN1_R_ILLEGAL_TAGGED_ANY = 127;
enum ASN1_R_ILLEGAL_TIME_VALUE = 184;
enum ASN1_R_ILLEGAL_ZERO_CONTENT = 222;
enum ASN1_R_INTEGER_NOT_ASCII_FORMAT = 185;
enum ASN1_R_INTEGER_TOO_LARGE_FOR_LONG = 128;
enum ASN1_R_INVALID_BIT_STRING_BITS_LEFT = 220;
enum ASN1_R_INVALID_BMPSTRING_LENGTH = 129;
enum ASN1_R_INVALID_DIGIT = 130;
enum ASN1_R_INVALID_MIME_TYPE = 205;
enum ASN1_R_INVALID_MODIFIER = 186;
enum ASN1_R_INVALID_NUMBER = 187;
enum ASN1_R_INVALID_OBJECT_ENCODING = 216;
enum ASN1_R_INVALID_SCRYPT_PARAMETERS = 227;
enum ASN1_R_INVALID_SEPARATOR = 131;
enum ASN1_R_INVALID_STRING_TABLE_VALUE = 218;
enum ASN1_R_INVALID_UNIVERSALSTRING_LENGTH = 133;
enum ASN1_R_INVALID_UTF8STRING = 134;
enum ASN1_R_INVALID_VALUE = 219;
enum ASN1_R_LIST_ERROR = 188;
enum ASN1_R_MIME_NO_CONTENT_TYPE = 206;
enum ASN1_R_MIME_PARSE_ERROR = 207;
enum ASN1_R_MIME_SIG_PARSE_ERROR = 208;
enum ASN1_R_MISSING_EOC = 137;
enum ASN1_R_MISSING_SECOND_NUMBER = 138;
enum ASN1_R_MISSING_VALUE = 189;
enum ASN1_R_MSTRING_NOT_UNIVERSAL = 139;
enum ASN1_R_MSTRING_WRONG_TAG = 140;
enum ASN1_R_NESTED_ASN1_STRING = 197;
enum ASN1_R_NON_HEX_CHARACTERS = 141;
enum ASN1_R_NOT_ASCII_FORMAT = 190;
enum ASN1_R_NOT_ENOUGH_DATA = 142;
enum ASN1_R_NO_CONTENT_TYPE = 209;
enum ASN1_R_NO_MATCHING_CHOICE_TYPE = 143;
enum ASN1_R_NO_MULTIPART_BODY_FAILURE = 210;
enum ASN1_R_NO_MULTIPART_BOUNDARY = 211;
enum ASN1_R_NO_SIG_CONTENT_TYPE = 212;
enum ASN1_R_NULL_IS_WRONG_LENGTH = 144;
enum ASN1_R_OBJECT_NOT_ASCII_FORMAT = 191;
enum ASN1_R_ODD_NUMBER_OF_CHARS = 145;
enum ASN1_R_SECOND_NUMBER_TOO_LARGE = 147;
enum ASN1_R_SEQUENCE_LENGTH_MISMATCH = 148;
enum ASN1_R_SEQUENCE_NOT_CONSTRUCTED = 149;
enum ASN1_R_SEQUENCE_OR_SET_NEEDS_CONFIG = 192;
enum ASN1_R_SHORT_LINE = 150;
enum ASN1_R_SIG_INVALID_MIME_TYPE = 213;
enum ASN1_R_STREAMING_NOT_SUPPORTED = 202;
enum ASN1_R_STRING_TOO_LONG = 151;
enum ASN1_R_STRING_TOO_SHORT = 152;
enum ASN1_R_THE_ASN1_OBJECT_IDENTIFIER_IS_NOT_KNOWN_FOR_THIS_MD = 154;
enum ASN1_R_TIME_NOT_ASCII_FORMAT = 193;
enum ASN1_R_TOO_LARGE = 223;
enum ASN1_R_TOO_LONG = 155;
enum ASN1_R_TOO_SMALL = 224;
enum ASN1_R_TYPE_NOT_CONSTRUCTED = 156;
enum ASN1_R_TYPE_NOT_PRIMITIVE = 195;
enum ASN1_R_UNEXPECTED_EOC = 159;
enum ASN1_R_UNIVERSALSTRING_IS_WRONG_LENGTH = 215;
enum ASN1_R_UNKNOWN_FORMAT = 160;
enum ASN1_R_UNKNOWN_MESSAGE_DIGEST_ALGORITHM = 161;
enum ASN1_R_UNKNOWN_OBJECT_TYPE = 162;
enum ASN1_R_UNKNOWN_PUBLIC_KEY_TYPE = 163;
enum ASN1_R_UNKNOWN_SIGNATURE_ALGORITHM = 199;
enum ASN1_R_UNKNOWN_TAG = 194;
enum ASN1_R_UNSUPPORTED_ANY_DEFINED_BY_TYPE = 164;
enum ASN1_R_UNSUPPORTED_PUBLIC_KEY_TYPE = 167;
enum ASN1_R_UNSUPPORTED_TYPE = 196;
enum ASN1_R_WRONG_INTEGER_TYPE = 225;
enum ASN1_R_WRONG_PUBLIC_KEY_TYPE = 200;
enum ASN1_R_WRONG_TAG = 168;
