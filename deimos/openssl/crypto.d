/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* ====================================================================
 * Copyright 2002 Sun Microsystems, Inc. ALL RIGHTS RESERVED.
 * ECDH support in OpenSSL originally developed by
 * SUN MICROSYSTEMS, INC., and contributed to the OpenSSL project.
 */

module deimos.openssl.crypto;

import deimos.openssl._d_util;

import core.stdc.stdlib;
import core.stdc.time;

public import deimos.openssl.e_os2;

version(OPENSSL_NO_NO_STDIO) {} else {
import core.stdc.stdio;
}

public import deimos.openssl.stack;
public import deimos.openssl.safestack;
public import deimos.openssl.opensslv;
public import deimos.openssl.ossl_typ;
public import deimos.openssl.opensslconf;

version (CHARSET_EBCDIC) {
public import deimos.openssl.ebcdic;
}

/*
 * Resolve problems on some operating systems with symbol names that clash
 * one way or another
 */
public import deimos.openssl.symhacks;

/+ TODO:
# if OPENSSL_API_COMPAT < 0x10100000L
#  include <openssl/opensslv.h>
# endif
+/

extern (C):
nothrow:

/+ TODO:
# if OPENSSL_API_COMPAT < 0x10100000L
+/
alias SSLeay OpenSSL_version_num;
alias SSLeay_version OpenSSL_version;
alias OPENSSL_VERSION_NUMBER SSLEAY_VERSION_NUMBER;
enum SSLEAY_VERSION = OPENSSL_VERSION;
enum SSLEAY_CFLAGS = OPENSSL_CFLAGS;
enum SSLEAY_BUILT_ON = OPENSSL_BUILT_ON;
enum SSLEAY_PLATFORM = OPENSSL_PLATFORM;
enum SSLEAY_DIR = OPENSSL_DIR;

/*
 * Old type for allocating dynamic locks. No longer used. Use the new thread
 * API instead.
 */
struct CRYPTO_dynlock {
    int dummy;
}

/+ TODO:
# endif /* OPENSSL_API_COMPAT */
+/

alias void CRYPTO_RWLOCK;

CRYPTO_RWLOCK* CRYPTO_THREAD_lock_new();
int CRYPTO_THREAD_read_lock(CRYPTO_RWLOCK* lock);
int CRYPTO_THREAD_write_lock(CRYPTO_RWLOCK* lock);
int CRYPTO_THREAD_unlock(CRYPTO_RWLOCK* lock);
void CRYPTO_THREAD_lock_free(CRYPTO_RWLOCK* lock);

int CRYPTO_atomic_add(int* val, int amount, int* ret, CRYPTO_RWLOCK* lock);

/*
 * The following can be used to detect memory leaks in the library. If
 * used, it turns on malloc checking
 */
enum CRYPTO_MEM_CHECK_OFF = 0x0;   /* Control only */
enum CRYPTO_MEM_CHECK_ON = 0x1;   /* Control and mode bit */
enum CRYPTO_MEM_CHECK_ENABLE = 0x2;   /* Control and mode bit */
enum CRYPTO_MEM_CHECK_DISABLE = 0x3;   /* Control only */

struct crypto_ex_data_st {
    STACK_OF!()* sk;
}
/+mixin DEFINE_STACK_OF!();+/

/*
 * Per class, we have a STACK of function pointers.
 */
enum CRYPTO_EX_INDEX_SSL = 0;
enum CRYPTO_EX_INDEX_SSL_CTX = 1;
enum CRYPTO_EX_INDEX_SSL_SESSION = 2;
enum CRYPTO_EX_INDEX_X509 = 3;
enum CRYPTO_EX_INDEX_X509_STORE = 4;
enum CRYPTO_EX_INDEX_X509_STORE_CTX = 5;
enum CRYPTO_EX_INDEX_DH = 6;
enum CRYPTO_EX_INDEX_DSA = 7;
enum CRYPTO_EX_INDEX_EC_KEY = 8;
enum CRYPTO_EX_INDEX_RSA = 9;
enum CRYPTO_EX_INDEX_ENGINE = 10;
enum CRYPTO_EX_INDEX_UI = 11;
enum CRYPTO_EX_INDEX_BIO = 12;
enum CRYPTO_EX_INDEX_APP = 13;
enum CRYPTO_EX_INDEX_COUNT = 14;

/*
 * This is the default callbacks, but we can have others as well: this is
 * needed in Win32 where the application malloc and the library malloc may
 * not be the same.
 */
auto OPENSSL_malloc_init()() {
    return CRYPTO_set_mem_functions(CRYPTO_malloc, CRYPTO_realloc, CRYPTO_free);
}

int CRYPTO_mem_ctrl(int mode);

auto OPENSSL_malloc(string file = __FILE__, size_t line = __LINE__)(size_t num) {
	return CRYPTO_malloc(num, file, line);
}
auto OPENSSL_zalloc(string file = __FILE__, size_t line = __LINE__)(size_t num) {
	return CRYPTO_zalloc(num, file, line);
}
auto OPENSSL_realloc(string file = __FILE__, size_t line = __LINE__)(void* addr, size_t num) {
	return CRYPTO_realloc(addr, num, file, line);
}
auto OPENSSL_clear_realloc(string file = __FILE__, size_t line = __LINE__)(void* addr, size_t old_num, size_t num) {
	CRYPTO_clear_realloc(addr, old_num, num, file, line);
}
auto OPENSSL_clear_free(string file = __FILE__, size_t line = __LINE__)(void* addr, size_t num) {
	return CRYPTO_clear_free(addr, num, file, line);
}
auto OPENSSL_free(string file = __FILE__, size_t line = __LINE__)(void* addr) {
	return CRYPTO_free(addr, file, line);
}
auto OPENSSL_memdup(string file = __FILE__, size_t line = __LINE__)(const(void)* str, size_t s) {
	return CRYPTO_memdup(str, s, file, line);
}
auto OPENSSL_strdup(string file = __FILE__, size_t line = __LINE__)(const(char)* str) {
	return CRYPTO_strdup(str, file, line);
}
auto OPENSSL_strndup(string file = __FILE__, size_t line = __LINE__)(const(char)* str, size_t s) {
	return CRYPTO_strndup(str, s, file, line);
}
auto OPENSSL_secure_malloc(string file = __FILE__, size_t line = __LINE__)(size_t num) {
	return CRYPTO_secure_malloc(num, file, line);
}
auto OPENSSL_secure_zalloc(string file = __FILE__, size_t line = __LINE__)(size_t num) {
	return CRYPTO_secure_zalloc(num, file, line);
}
auto OPENSSL_secure_free(string file = __FILE__, size_t line = __LINE__)(void* addr) {
	return CRYPTO_secure_free(addr, file, line);
}
auto OPENSSL_secure_actual_size(string file = __FILE__, size_t line = __LINE__)(void* ptr) {
	return CRYPTO_secure_actual_size(ptr, file, line);
}

size_t OPENSSL_strlcpy(char* dst, const(char)* src, size_t siz);
size_t OPENSSL_strlcat(char* dst, const(char)* src, size_t siz);
size_t OPENSSL_strnlen(const(char)* str, size_t maxlen);
char* OPENSSL_buf2hexstr(const(ubyte)* buffer, c_long len);
ubyte* OPENSSL_hexstr2buf(const(char)* str, long* len);
int OPENSSL_hexchar2int(ubyte c);

/+ TODO:
# define OPENSSL_MALLOC_MAX_NELEMS(type)  (((1U<<(sizeof(int)*8-1))-1)/sizeof(type))
+/

c_ulong OpenSSL_version_num();
const(char)* OpenSSL_version(int type);
enum OPENSSL_VERSION = 0;
enum OPENSSL_CFLAGS = 1;
enum OPENSSL_BUILT_ON = 2;
enum OPENSSL_PLATFORM = 3;
enum OPENSSL_DIR = 4;
enum OPENSSL_ENGINES_DIR = 5;

int OPENSSL_issetugid();

alias CRYPTO_EX_new = void function(void* parent, void* ptr, CRYPTO_EX_DATA* ad,
                                    int idx, c_long argl, void* argp);
alias CRYPTO_EX_free = void function(void* parent, void* ptr, CRYPTO_EX_DATA* ad,
                                     int idx, c_long argl, void* argp);
alias CRYPTO_EX_dup = int function(CRYPTO_EX_DATA* to, const(CRYPTO_EX_DATA)* from,
                                   void* srcp, int idx, c_long argl, void* argp);
// TODO: __owur
int CRYPTO_get_ex_new_index(int class_index, c_long argl, void* argp,
                            CRYPTO_EX_new* new_func, CRYPTO_EX_dup* dup_func,
                            CRYPTO_EX_free* free_func);
/* No longer use an index. */
int CRYPTO_free_ex_index(int class_index, int idx);

/*
 * Initialise/duplicate/free CRYPTO_EX_DATA variables corresponding to a
 * given class (invokes whatever per-class callbacks are applicable)
 */
int CRYPTO_new_ex_data(int class_index, void* obj, CRYPTO_EX_DATA* ad);
int CRYPTO_dup_ex_data(int class_index, CRYPTO_EX_DATA* to,
                       const(CRYPTO_EX_DATA)* from);
void CRYPTO_free_ex_data(int class_index, void* obj, CRYPTO_EX_DATA* ad);

/*
 * Get/set data in a CRYPTO_EX_DATA variable corresponding to a particular
 * index (relative to the class type involved)
 */
int CRYPTO_set_ex_data(CRYPTO_EX_DATA* ad, int idx, void* val);
void* CRYPTO_get_ex_data(const(CRYPTO_EX_DATA)* ad,int idx);

// TODO:
// # if OPENSSL_API_COMPAT < 0x10100000L
/*
 * This function cleans up all "ex_data" state. It mustn't be called under
 * potential race-conditions.
 */
void CRYPTO_cleanup_all_ex_data()() {}

/*
 * The old locking functions have been removed completely without compatibility
 * macros. This is because the old functions either could not properly report
 * errors, or the returned error values were not clearly documented.
 * Replacing the locking functions with with no-ops would cause race condition
 * issues in the affected applications. It is far better for them to fail at
 * compile time.
 * On the other hand, the locking callbacks are no longer used.  Consequently,
 * the callback management functions can be safely replaced with no-op macros.
 */
int CRYPTO_num_locks()() { return 1; }
void CRYPTO_set_locking_callback()(ExternC!(void function(int mode,int type,
                                                        const(char)* file,int line)) func) {}
ExternC!(void function(int mode,int type,const(char)* file,int line)) CRYPTO_get_locking_callback()() { return null; }
void CRYPTO_set_add_lock_callback()(ExternC!(int function(int* num,int mount,int type,
                                                          const(char)* file, int line)) func) {}
ExternC!(void function(int* num,int mount,int type,const(char)* file, int line)) CRYPTO_get_add_lock_callback()() { return null; }

/*
 * These defines where used in combination with the old locking callbacks,
 * they are not called anymore, but old code that's not called might still
 * use them.
 */
enum CRYPTO_LOCK = 1;
enum CRYPTO_UNLOCK = 2;
enum CRYPTO_READ = 4;
enum CRYPTO_WRITE = 8;

/* This structure is no longer used */
struct crypto_threadid_st {
    int dummy;
}
alias crypto_threadid_st CRYPTO_THREADID;
/* Only use CRYPTO_THREADID_set_[numeric|pointer]() within callbacks */
void CRYPTO_THREADID_set_numeric()(CRYPTO_THREADID* id, c_ulong val) {}
void CRYPTO_THREADID_set_pointer()(CRYPTO_THREADID* id, void* ptr) {}
int CRYPTO_THREADID_set_callback()(ExternC!(void function(CRYPTO_THREADID*)) threadid_func) { return 0; }
ExternC!(void function(CRYPTO_THREADID*)) CRYPTO_THREADID_get_callback()() { return null; }
void CRYPTO_THREADID_current()(CRYPTO_THREADID* id) {}
int CRYPTO_THREADID_cmp()(const(CRYPTO_THREADID)* a, const(CRYPTO_THREADID)* b) { return -1; }
void CRYPTO_THREADID_cpy()(CRYPTO_THREADID* dest, const(CRYPTO_THREADID)* src) {}
c_ulong CRYPTO_THREADID_hash()(const(CRYPTO_THREADID)* id) { return 0; }

/+ TODO:
#  if OPENSSL_API_COMPAT < 0x10000000L
+/
void CRYPTO_set_id_callback()(ExternC!(c_ulong function()) func) {}
ExternC!(c_ulong function()) CRYPTO_get_id_callback()() { return null; }
c_ulong CRYPTO_thread_id()() { return 0; }
/+ TODO:
#  endif /* OPENSSL_API_COMPAT < 0x10000000L */
+/

void CRYPTO_set_dynlock_create_callback()(ExternC!(CRYPTO_dynlock_value* function(const(char)* file, int line)) dyn_create_function) {}
void CRYPTO_set_dynlock_lock_callback()(ExternC!(void function(int mode, CRYPTO_dynlock_value* l, const(char)* file, int line)) dyn_lock_function) {}
void CRYPTO_set_dynlock_destroy_callback()(ExternC!(void function(CRYPTO_dynlock_value* l, const(char)* file, int line)) dyn_destroy_function) {}
ExternC!(CRYPTO_dynlock_value* function(const(char)* file,int line)) CRYPTO_get_dynlock_create_callback()() { return null; }
ExternC!(void function(int mode, CRYPTO_dynlock_value* l, const(char)* file,int line)) CRYPTO_get_dynlock_lock_callback()() { return null; }
ExternC!(void function(CRYPTO_dynlock_value* l, const(char)* file,int line)) CRYPTO_get_dynlock_destroy_callback()() { return null; }
/+ TODO:
# endif /* OPENSSL_API_COMPAT < 0x10100000L */
+/

int CRYPTO_set_mem_functions(ExternC!(void* function(size_t)) m,
                             ExternC!(void* function(void*,size_t)) r,
                             ExternC!(void function(void*)) f);
int CRYPTO_set_mem_debug(int flag);
void CRYPTO_get_mem_functions(ExternC!(void* function(size_t))* m,
                              ExternC!(void* function(void*, size_t))* r,
                              ExternC!(void function(void*))* f);

void* CRYPTO_malloc(size_t num, const(char)* file, int line);
void* CRYPTO_zalloc(size_t num, const(char)* file, int line);
char* CRYPTO_memdup(const(void)* str, size_t siz, const(char)* file, int line);
char* CRYPTO_strdup(const(char)* str, const(char)* file, int line);
char* CRYPTO_strndup(const(char)* str, size_t s, const(char)* file, int line);
void CRYPTO_free(void* ptr, const(char)* file, int line);
void CRYPTO_clear_free(void* ptr, size_t num, const(char)* file, int line);
void* CRYPTO_realloc(void* addr,size_t num, const(char)* file, int line);
void* CRYPTO_clear_realloc(void* addr,size_t old_num, size_t num,
                           const(char)* file, int line);

int CRYPTO_secure_malloc_init(size_t sz, int minsize);
int CRYPTO_secure_malloc_done();
void *CRYPTO_secure_malloc(size_t num, const(char)* file, int line);
void *CRYPTO_secure_zalloc(size_t num, const(char)* file, int line);
void CRYPTO_secure_free(void* ptr, const(char)* file, int line);
int CRYPTO_secure_allocated(const(void)* ptr);
int CRYPTO_secure_malloc_initialized();
size_t CRYPTO_secure_actual_size(void* ptr);
size_t CRYPTO_secure_used();

void OPENSSL_cleanse(void* ptr, size_t len);

version (OPENSSL_NO_CRYPTO_MDEBUG) {} else {
int OPENSSL_mem_debug_push(const(char)* info, string file = __FILE__, size_t line = __LINE__) {
        return CRYPTO_mem_debug_push(info, file, line);
}
int OPENSSL_mem_debug_pop()() {
        return CRYPTO_mem_debug_pop();
}
int CRYPTO_mem_debug_push(const(char)* info, const(char)* file, int line);
int CRYPTO_mem_debug_pop();

/*-
 * Debugging functions (enabled by CRYPTO_set_mem_debug(1))
 * The flag argument has the following significance:
 *   0:   called before the actual memory allocation has taken place
 *   1:   called after the actual memory allocation has taken place
 */
void CRYPTO_mem_debug_malloc(void* addr, size_t num, int flag,
        const(char)* file, int line);
void CRYPTO_mem_debug_realloc(void* addr1, void* addr2, size_t num, int flag,
        const(char)* file, int line);
void CRYPTO_mem_debug_free(void* addr, int flag,
        const(char)* file, int line);

version(OPENSSL_NO_NO_STDIO) {} else {
int CRYPTO_mem_leaks_fp(FILE*);
}
int CRYPTO_mem_leaks(BIO* bio);
}

/* die if we have to */
// TODO: ossl_noreturn
void OpenSSLDie(const(char)* assertion, int file, const(char)* line);
/+ TODO:
# if OPENSSL_API_COMPAT < 0x10100000L
#  define OpenSSLDie(f,l,a) OPENSSL_die((a),(f),(l))
# endif
+/
void OPENSSL_assert(string file = __FILE__, size_t line = __LINE__)(int e) {
    import std.conv: to;
    if (!e) OpenSSLDie("assertion failed: " ~ to!string(e), file, line); // No good way to translate.
}

int OPENSSL_isservice();

int FIPS_mode();
int FIPS_mode_set(int r);

void OPENSSL_init();

tm* OPENSSL_gmtime(const(time_t)* timer, tm* result);
int OPENSSL_gmtime_adj(tm* tm, int offset_day, long offset_sec);
int OPENSSL_gmtime_diff(int* pday, int* psec,
                        const(tm)* from, const(tm)* to);

/*
 * CRYPTO_memcmp returns zero iff the |len| bytes at |a| and |b| are equal.
 * It takes an amount of time dependent on |len|, but independent of the
 * contents of |a| and |b|. Unlike memcmp, it cannot be used to put elements
 * into a defined order as the return value when a != b is undefined, other
 * than to be non-zero.
 */
// TODO: volatile
int CRYPTO_memcmp(const(void)* in_a,
                  const(void)* in_b,
                  size_t len);

/* Standard initialisation options */
enum OPENSSL_INIT_NO_LOAD_CRYPTO_STRINGS = 0x00000001L;
enum OPENSSL_INIT_LOAD_CRYPTO_STRINGS = 0x00000002L;
enum OPENSSL_INIT_ADD_ALL_CIPHERS = 0x00000004L;
enum OPENSSL_INIT_ADD_ALL_DIGESTS = 0x00000008L;
enum OPENSSL_INIT_NO_ADD_ALL_CIPHERS = 0x00000010L;
enum OPENSSL_INIT_NO_ADD_ALL_DIGESTS = 0x00000020L;
enum OPENSSL_INIT_LOAD_CONFIG = 0x00000040L;
enum OPENSSL_INIT_NO_LOAD_CONFIG = 0x00000080L;
enum OPENSSL_INIT_ASYNC = 0x00000100L;
enum OPENSSL_INIT_ENGINE_RDRAND = 0x00000200L;
enum OPENSSL_INIT_ENGINE_DYNAMIC = 0x00000400L;
enum OPENSSL_INIT_ENGINE_OPENSSL = 0x00000800L;
enum OPENSSL_INIT_ENGINE_CRYPTODEV = 0x00001000L;
enum OPENSSL_INIT_ENGINE_CAPI = 0x00002000L;
enum OPENSSL_INIT_ENGINE_PADLOCK = 0x00004000L;
enum OPENSSL_INIT_ENGINE_AFALG = 0x00008000L;
/* OPENSSL_INIT flag 0x00010000 reserved for internal use */
/* OPENSSL_INIT flag range 0xfff00000 reserved for OPENSSL_init_ssl() */
/* Max OPENSSL_INIT flag value is 0x80000000 */

/* openssl and dasync not counted as builtin */
enum OPENSSL_INIT_ENGINE_ALL_BUILTIN =
    (OPENSSL_INIT_ENGINE_RDRAND | OPENSSL_INIT_ENGINE_DYNAMIC
    | OPENSSL_INIT_ENGINE_CRYPTODEV | OPENSSL_INIT_ENGINE_CAPI |
    OPENSSL_INIT_ENGINE_PADLOCK);


/* Library initialisation functions */
void OPENSSL_cleanup();
int OPENSSL_init_crypto(ulong opts, const(OPENSSL_INIT_SETTINGS)* settings);
int OPENSSL_atexit(ExternC!(void function()) handler);
void OPENSSL_thread_stop();

/* Low-level control of initialization */
OPENSSL_INIT_SETTINGS* OPENSSL_INIT_new();
version (OPENSSL_NO_STDIO) {} else {
int OPENSSL_INIT_set_config_appname(OPENSSL_INIT_SETTINGS* settings,
                                    const(char)* config_file);
}
void OPENSSL_INIT_free(OPENSSL_INIT_SETTINGS *settings);

/+ TODO:
# if defined(OPENSSL_THREADS) && !defined(CRYPTO_TDEBUG)
#  if defined(_WIN32)
#   if defined(BASETYPES) || defined(_WINDEF_H)
/* application has to include <windows.h> in order to use this */
typedef DWORD CRYPTO_THREAD_LOCAL;
typedef DWORD CRYPTO_THREAD_ID;

typedef LONG CRYPTO_ONCE;
#    define CRYPTO_ONCE_STATIC_INIT 0
#   endif
#  else
#   include <pthread.h>
typedef pthread_once_t CRYPTO_ONCE;
typedef pthread_key_t CRYPTO_THREAD_LOCAL;
typedef pthread_t CRYPTO_THREAD_ID;

#   define CRYPTO_ONCE_STATIC_INIT PTHREAD_ONCE_INIT
#  endif
# endif

# if !defined(CRYPTO_ONCE_STATIC_INIT)
typedef unsigned int CRYPTO_ONCE;
typedef unsigned int CRYPTO_THREAD_LOCAL;
typedef unsigned int CRYPTO_THREAD_ID;
#  define CRYPTO_ONCE_STATIC_INIT 0
# endif
+/

int CRYPTO_THREAD_run_once(CRYPTO_ONCE* once, ExternC!(void function()) init);

int CRYPTO_THREAD_init_local(CRYPTO_THREAD_LOCAL* key, ExternC!(void function(void*)) cleanup);
void* CRYPTO_THREAD_get_local(CRYPTO_THREAD_LOCAL* key);
int CRYPTO_THREAD_set_local(CRYPTO_THREAD_LOCAL* key, void* val);
int CRYPTO_THREAD_cleanup_local(CRYPTO_THREAD_LOCAL* key);

CRYPTO_THREAD_ID CRYPTO_THREAD_get_current_id();
int CRYPTO_THREAD_compare_id(CRYPTO_THREAD_ID a, CRYPTO_THREAD_ID b);

/* BEGIN ERROR CODES */
/*
 * The following lines are auto generated by the script mkerr.pl. Any changes
 * made after this point may be overwritten when the script is next run.
 */
void ERR_load_CRYPTO_strings();

/* Error codes for the CRYPTO functions. */

/* Function codes. */
enum CRYPTO_F_CRYPTO_DUP_EX_DATA = 110;
enum CRYPTO_F_CRYPTO_FREE_EX_DATA = 111;
enum CRYPTO_F_CRYPTO_GET_EX_NEW_INDEX = 100;
enum CRYPTO_F_CRYPTO_MEMDUP = 115;
enum CRYPTO_F_CRYPTO_NEW_EX_DATA = 112;
enum CRYPTO_F_CRYPTO_SET_EX_DATA = 102;
enum CRYPTO_F_FIPS_MODE_SET = 109;
enum CRYPTO_F_GET_AND_LOCK = 113;
enum CRYPTO_F_OPENSSL_BUF2HEXSTR = 117;
enum CRYPTO_F_OPENSSL_HEXSTR2BUF = 118;
enum CRYPTO_F_OPENSSL_INIT_CRYPTO = 116;

/* Reason codes. */
enum CRYPTO_R_FIPS_MODE_NOT_SUPPORTED = 101;
enum CRYPTO_R_ILLEGAL_HEX_DIGIT = 102;
enum CRYPTO_R_ODD_NUMBER_OF_DIGITS = 103;
