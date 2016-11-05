/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

module deimos.openssl.bio;

import deimos.openssl._d_util;

import core.stdc.stdarg;
public import deimos.openssl.e_os2;

version(OPENSSL_NO_STDIO) {} else {
import core.stdc.stdio;
}

// TODO: review imports
version(OPENSSL_NO_SCTP) {} else {
    version(OPENSSL_SYS_VMS)
        import inttypes;
    else
	import core.stdc.stdint;
}

version (Posix) {
	import core.sys.posix.netdb;
} else version (Windows) {
	import core.sys.windows.winsock2;
} else version (Win64) {
	import core.sys.windows.winsock2;
}

public import deimos.openssl.crypto;

extern (C):
nothrow:

/* There are the classes of BIOs */
enum BIO_TYPE_DESCRIPTOR = 0x0100; /* socket, fd, connect or accept */
enum BIO_TYPE_FILTER = 0x0200;
enum BIO_TYPE_SOURCE_SINK = 0x0400;

/* These are the 'types' of BIOs */
enum BIO_TYPE_NONE = 0;
enum BIO_TYPE_MEM = ( 1|BIO_TYPE_SOURCE_SINK);
enum BIO_TYPE_FILE = ( 2|BIO_TYPE_SOURCE_SINK);

enum BIO_TYPE_FD = ( 4|BIO_TYPE_SOURCE_SINK|BIO_TYPE_DESCRIPTOR);
enum BIO_TYPE_SOCKET = ( 5|BIO_TYPE_SOURCE_SINK|BIO_TYPE_DESCRIPTOR);
enum BIO_TYPE_NULL = ( 6|BIO_TYPE_SOURCE_SINK);
enum BIO_TYPE_SSL = ( 7|BIO_TYPE_FILTER);
enum BIO_TYPE_MD = ( 8|BIO_TYPE_FILTER);
enum BIO_TYPE_BUFFER = ( 9|BIO_TYPE_FILTER);
enum BIO_TYPE_CIPHER = (10|BIO_TYPE_FILTER);
enum BIO_TYPE_BASE64 = (11|BIO_TYPE_FILTER);
enum BIO_TYPE_CONNECT = (12|BIO_TYPE_SOURCE_SINK|BIO_TYPE_DESCRIPTOR);
enum BIO_TYPE_ACCEPT = (13|BIO_TYPE_SOURCE_SINK|BIO_TYPE_DESCRIPTOR);

enum BIO_TYPE_NBIO_TEST = (16|BIO_TYPE_FILTER);/* server proxy BIO */
enum BIO_TYPE_NULL_FILTER = (17|BIO_TYPE_FILTER);
enum BIO_TYPE_BIO = (19|BIO_TYPE_SOURCE_SINK);/* half a BIO pair */
enum BIO_TYPE_LINEBUFFER = (20|BIO_TYPE_FILTER);
enum BIO_TYPE_DGRAM = (21|BIO_TYPE_SOURCE_SINK|BIO_TYPE_DESCRIPTOR);
version (OPENSSL_NO_SCTP) {} else {
enum BIO_TYPE_DGRAM_SCTP = (24|BIO_TYPE_SOURCE_SINK|BIO_TYPE_DESCRIPTOR);
}

enum BIO_TYPE_START = 128;

/*
 * BIO_FILENAME_READ|BIO_CLOSE to open or close on free.
 * BIO_set_fp(in,stdin,BIO_NOCLOSE);
 */
enum BIO_NOCLOSE = 0x00;
enum BIO_CLOSE = 0x01;

/*
 * These are used in the following macros and are passed to BIO_ctrl()
 */
enum BIO_CTRL_RESET = 1;  /* opt - rewind/zero etc */
enum BIO_CTRL_EOF = 2;  /* opt - are we at the eof */
enum BIO_CTRL_INFO = 3;  /* opt - extra tit-bits */
enum BIO_CTRL_SET = 4;  /* man - set the 'IO' type */
enum BIO_CTRL_GET = 5;  /* man - get the 'IO' type */
enum BIO_CTRL_PUSH = 6;  /* opt - internal, used to signify change */
enum BIO_CTRL_POP = 7;  /* opt - internal, used to signify change */
enum BIO_CTRL_GET_CLOSE = 8;  /* man - set the 'close' on free */
enum BIO_CTRL_SET_CLOSE = 9;  /* man - set the 'close' on free */
enum BIO_CTRL_PENDING = 10;  /* opt - is their more data buffered */
enum BIO_CTRL_FLUSH = 11;  /* opt - 'flush' buffered output */
enum BIO_CTRL_DUP = 12;  /* man - extra stuff for 'duped' BIO */
enum BIO_CTRL_WPENDING = 13;  /* opt - number of bytes still to write */
enum BIO_CTRL_SET_CALLBACK = 14;  /* opt - set callback function */
enum BIO_CTRL_GET_CALLBACK = 15;  /* opt - set callback function */

enum BIO_CTRL_SET_FILENAME = 30;	/* BIO_s_file special */

/* dgram BIO stuff */
enum BIO_CTRL_DGRAM_CONNECT = 31;  /* BIO dgram special */
enum BIO_CTRL_DGRAM_SET_CONNECTED = 32;  /* allow for an externally connected
                                          * socket to be passed in */
enum BIO_CTRL_DGRAM_SET_RECV_TIMEOUT = 33; /* setsockopt, essentially */
enum BIO_CTRL_DGRAM_GET_RECV_TIMEOUT = 34; /* getsockopt, essentially */
enum BIO_CTRL_DGRAM_SET_SEND_TIMEOUT = 35; /* setsockopt, essentially */
enum BIO_CTRL_DGRAM_GET_SEND_TIMEOUT = 36; /* getsockopt, essentially */

enum BIO_CTRL_DGRAM_GET_RECV_TIMER_EXP = 37; /* flag whether the last */
enum BIO_CTRL_DGRAM_GET_SEND_TIMER_EXP = 38; /* I/O operation tiemd out */

/* #ifdef IP_MTU_DISCOVER */
enum BIO_CTRL_DGRAM_MTU_DISCOVER = 39; /* set DF bit on egress packets */
/* #endif */

enum BIO_CTRL_DGRAM_QUERY_MTU = 40; /* as kernel for current MTU */
enum BIO_CTRL_DGRAM_GET_FALLBACK_MTU = 47;
enum BIO_CTRL_DGRAM_GET_MTU = 41; /* get cached value for MTU */
enum BIO_CTRL_DGRAM_SET_MTU = 42;            /* set cached value for MTU.
                                              * want to use this if asking
                                              * the kernel fails */

enum BIO_CTRL_DGRAM_MTU_EXCEEDED = 43;       /* check whether the MTU was
                                              * exceed in the previous write
                                              * operation */

enum BIO_CTRL_DGRAM_GET_PEER = 46;
enum BIO_CTRL_DGRAM_SET_PEER = 44; /* Destination for the data */

enum BIO_CTRL_DGRAM_SET_NEXT_TIMEOUT = 45;   /* Next DTLS handshake timeout
                                              * to adjust socket timeouts */
enum BIO_CTRL_DGRAM_SET_DONT_FRAG = 48;

enum BIO_CTRL_DGRAM_GET_MTU_OVERHEAD = 49;

enum BIO_CTRL_DGRAM_SET_PEEK_MODE = 50;

version(OPENSSL_NO_SCTP) {} else {
    /* SCTP stuff */
    enum BIO_CTRL_DGRAM_SCTP_SET_IN_HANDSHAKE = 50;
    enum BIO_CTRL_DGRAM_SCTP_ADD_AUTH_KEY = 51;
    enum BIO_CTRL_DGRAM_SCTP_NEXT_AUTH_KEY = 52;
    enum BIO_CTRL_DGRAM_SCTP_AUTH_CCS_RCVD = 53;
    enum BIO_CTRL_DGRAM_SCTP_GET_SNDINFO = 60;
    enum BIO_CTRL_DGRAM_SCTP_SET_SNDINFO = 61;
    enum BIO_CTRL_DGRAM_SCTP_GET_RCVINFO = 62;
    enum BIO_CTRL_DGRAM_SCTP_SET_RCVINFO = 63;
    enum BIO_CTRL_DGRAM_SCTP_GET_PRINFO = 64;
    enum BIO_CTRL_DGRAM_SCTP_SET_PRINFO = 65;
    enum BIO_CTRL_DGRAM_SCTP_SAVE_SHUTDOWN = 70;
}

/* modifiers */
enum BIO_FP_READ = 0x02;
enum BIO_FP_WRITE = 0x04;
enum BIO_FP_APPEND = 0x08;
enum BIO_FP_TEXT = 0x10;

enum BIO_FLAGS_READ = 0x01;
enum BIO_FLAGS_WRITE = 0x02;
enum BIO_FLAGS_IO_SPECIAL = 0x04;
enum BIO_FLAGS_RWS = (BIO_FLAGS_READ|BIO_FLAGS_WRITE|BIO_FLAGS_IO_SPECIAL);
enum BIO_FLAGS_SHOULD_RETRY = 0x08;
/*
 * "UPLINK" flag denotes file descriptors provided by application. It
 * defaults to 0, as most platforms don't require UPLINK interface.
 */
enum BIO_FLAGS_UPLINK = 0;

enum BIO_FLAGS_BASE64_NO_NL = 0x100;

/*
 * This is used with memory BIOs:
 * BIO_FLAGS_MEM_RDONLY means we shouldn't free up or change the data in any way;
 * BIO_FLAGS_NONCLEAR_RST means we should't clear data on reset.
 */
enum BIO_FLAGS_MEM_RDONLY = 0x200;
enum BIO_FLAGS_NONCLEAR_RST = 0x400;

union bio_addr_st;
alias bio_addr_st BIO_ADDR;
struct bio_addrinfo_st;
alias bio_addrinfo_st BIO_ADDRINFO;

int BIO_get_new_index();
void BIO_set_flags(BIO* b, int flags);
int  BIO_test_flags(const(BIO)* b, int flags);
void BIO_clear_flags(BIO* b, int flags);

auto BIO_get_flags()(const(BIO)* b) { return BIO_test_flags(b, ~(0x0)); }
auto BIO_set_retry_special()(BIO* b) {
	return BIO_set_flags(b, (BIO_FLAGS_IO_SPECIAL|BIO_FLAGS_SHOULD_RETRY));
}
auto BIO_set_retry_read()(BIO* b) {
	return BIO_set_flags(b, (BIO_FLAGS_READ|BIO_FLAGS_SHOULD_RETRY));
}
auto BIO_set_retry_write()(BIO* b) {
	return BIO_set_flags(b, (BIO_FLAGS_WRITE|BIO_FLAGS_SHOULD_RETRY));
}

/* These are normally used internally in BIOs */
auto BIO_clear_retry_flags()(BIO* b) {
	return BIO_clear_flags(b, (BIO_FLAGS_RWS|BIO_FLAGS_SHOULD_RETRY));
}
auto BIO_get_retry_flags()(const(BIO)* b) {
	return BIO_test_flags(b, (BIO_FLAGS_RWS|BIO_FLAGS_SHOULD_RETRY));
}

/* These should be used by the application to tell why we should retry */
auto BIO_should_read()(const(BIO)* a) { return BIO_test_flags(a, BIO_FLAGS_READ); }
auto BIO_should_write()(const(BIO)* a) { return BIO_test_flags(a, BIO_FLAGS_WRITE); }
auto BIO_should_io_special()(const(BIO)* a) { return BIO_test_flags(a, BIO_FLAGS_IO_SPECIAL); }
auto BIO_retry_type()(const(BIO)* a) { return BIO_test_flags(a, BIO_FLAGS_RWS); }
auto BIO_should_retry()(const(BIO)* a) { return BIO_test_flags(a, BIO_FLAGS_SHOULD_RETRY); }

/*
 * The next three are used in conjunction with the BIO_should_io_special()
 * condition.  After this returns true, BIO *BIO_get_retry_BIO(BIO *bio, int
 * *reason); will walk the BIO stack and return the 'reason' for the special
 * and the offending BIO. Given a BIO, BIO_get_retry_reason(bio) will return
 * the code.
 */
/*
 * Returned from the SSL bio when the certificate retrieval code had an error
 */
enum BIO_RR_SSL_X509_LOOKUP = 0x01;
/* Returned from the connect BIO when a connect would have blocked */
enum BIO_RR_CONNECT = 0x02;
/* Returned from the accept BIO when an accept would have blocked */
enum BIO_RR_ACCEPT = 0x03;

/* These are passed by the BIO callback */
enum BIO_CB_FREE = 0x01;
enum BIO_CB_READ = 0x02;
enum BIO_CB_WRITE = 0x03;
enum BIO_CB_PUTS = 0x04;
enum BIO_CB_GETS = 0x05;
enum BIO_CB_CTRL = 0x06;

/*
 * The callback is called before and after the underling operation, The
 * BIO_CB_RETURN flag indicates if it is after the call
 */
enum BIO_CB_RETURN = 0x80;
auto BIO_CB_return()(int a) { return a|BIO_CB_RETURN; }
auto BIO_cb_pre()(int a) { return !((a)&BIO_CB_RETURN); }
auto BIO_cb_post()(int a) { return a&BIO_CB_RETURN; }

alias ExternC!(c_long function(BIO* b, int oper,const(char)* argp,int argi,
                               c_long argl, long ret)) BIO_callback_fn;
BIO_callback_fn BIO_get_callback(const(BIO)* b);
void BIO_set_callback(BIO* b, BIO_callback_fn callback);
char* BIO_get_callback_arg(const(BIO)* b);
void BIO_set_callback_arg(BIO* b, char* arg);

struct bio_method_st;
alias bio_method_st BIO_METHOD;

const(char)* BIO_method_name(const(BIO)* b);
int BIO_method_type(const(BIO)* b);

alias typeof(*(ExternC!(void function(BIO*, int, const(char)*, int, c_long, c_long))).init) bio_info_cb;

/+mixin DEFINE_STACK_OF!(BIO);+/

/* Prefix and suffix callback in ASN1 BIO */
alias typeof(*(ExternC!(int function(BIO* b, ubyte** pbuf, int* plen,
                                     void* parg))).init) asn1_ps_func;

version(OPENSSL_NO_SCTP) {} else {
/* SCTP parameter structs */
struct bio_dgram_sctp_sndinfo
	{
	uint16_t snd_sid;
	uint16_t snd_flags;
	uint32_t snd_ppid;
	uint32_t snd_context;
	};

struct bio_dgram_sctp_rcvinfo
	{
	uint16_t rcv_sid;
	uint16_t rcv_ssn;
	uint16_t rcv_flags;
	uint32_t rcv_ppid;
	uint32_t rcv_tsn;
	uint32_t rcv_cumtsn;
	uint32_t rcv_context;
	};

struct bio_dgram_sctp_prinfo
	{
	uint16_t pr_policy;
	uint32_t pr_value;
	};
}

/*
 * alias BIO_ctrl BIO_CONN_get_param_hostname;
 */

enum BIO_C_SET_CONNECT = 100;
enum BIO_C_DO_STATE_MACHINE = 101;
enum BIO_C_SET_NBIO = 102;
/* enum BIO_C_SET_PROXY_PARAM = 103; */
enum BIO_C_SET_FD = 104;
enum BIO_C_GET_FD = 105;
enum BIO_C_SET_FILE_PTR = 106;
enum BIO_C_GET_FILE_PTR = 107;
enum BIO_C_SET_FILENAME = 108;
enum BIO_C_SET_SSL = 109;
enum BIO_C_GET_SSL = 110;
enum BIO_C_SET_MD = 111;
enum BIO_C_GET_MD = 112;
enum BIO_C_GET_CIPHER_STATUS = 113;
enum BIO_C_SET_BUF_MEM = 114;
enum BIO_C_GET_BUF_MEM_PTR = 115;
enum BIO_C_GET_BUFF_NUM_LINES = 116;
enum BIO_C_SET_BUFF_SIZE = 117;
enum BIO_C_SET_ACCEPT = 118;
enum BIO_C_SSL_MODE = 119;
enum BIO_C_GET_MD_CTX = 120;
/* enum BIO_C_GET_PROXY_PARAM = 121; */
enum BIO_C_SET_BUFF_READ_DATA = 122; /* data to read first */
enum BIO_C_GET_CONNECT = 123;
enum BIO_C_GET_ACCEPT = 124;
enum BIO_C_SET_SSL_RENEGOTIATE_BYTES = 125;
enum BIO_C_GET_SSL_NUM_RENEGOTIATES = 126;
enum BIO_C_SET_SSL_RENEGOTIATE_TIMEOUT = 127;
enum BIO_C_FILE_SEEK = 128;
enum BIO_C_GET_CIPHER_CTX = 129;
enum BIO_C_SET_BUF_MEM_EOF_RETURN = 130;            /* return end of input
                                                     * value */
enum BIO_C_SET_BIND_MODE = 131;
enum BIO_C_GET_BIND_MODE = 132;
enum BIO_C_FILE_TELL = 133;
enum BIO_C_GET_SOCKS = 134;
enum BIO_C_SET_SOCKS = 135;

enum BIO_C_SET_WRITE_BUF_SIZE = 136;/* for BIO_s_bio */
enum BIO_C_GET_WRITE_BUF_SIZE = 137;
enum BIO_C_MAKE_BIO_PAIR = 138;
enum BIO_C_DESTROY_BIO_PAIR = 139;
enum BIO_C_GET_WRITE_GUARANTEE = 140;
enum BIO_C_GET_READ_REQUEST = 141;
enum BIO_C_SHUTDOWN_WR = 142;
enum BIO_C_NREAD0 = 143;
enum BIO_C_NREAD = 144;
enum BIO_C_NWRITE0 = 145;
enum BIO_C_NWRITE = 146;
enum BIO_C_RESET_READ_REQUEST = 147;
enum BIO_C_SET_MD_CTX = 148;

enum BIO_C_SET_PREFIX = 149;
enum BIO_C_GET_PREFIX = 150;
enum BIO_C_SET_SUFFIX = 151;
enum BIO_C_GET_SUFFIX = 152;

enum BIO_C_SET_EX_ARG = 153;
enum BIO_C_GET_EX_ARG = 154;

enum BIO_C_SET_CONNECT_MODE = 155;

auto BIO_set_app_data()(BIO* s, void* arg) { return BIO_set_ex_data(s,0,arg); }
auto BIO_get_app_data()(BIO* s) { return BIO_get_ex_data(s,0); }

auto BIO_set_nbio()(BIO* b,n)	{ return BIO_ctrl(b,BIO_C_SET_NBIO,(n),null); }

version (OPENSSL_NO_SOCK) {} else {
/* IP families we support, for BIO_s_connect() and BIO_s_accept() */
/* Note: the underlying operating system may not support some of them */
enum BIO_FAMILY_IPV4 = 4;
enum BIO_FAMILY_IPV6 = 6;
enum BIO_FAMILY_IPANY = 256;

/* BIO_s_connect() */
auto BIO_set_conn_hostname()(BIO* b, char* name) { return BIO_ctrl(b,BIO_C_SET_CONNECT,0,name); }
auto BIO_set_conn_port()(BIO* b, char* port) { return BIO_ctrl(b,BIO_C_SET_CONNECT,1,port); }
auto BIO_set_conn_address()(BIO* b, char* addr) { return BIO_ctrl(b,BIO_C_SET_CONNECT,2,addr); }
auto BIO_set_conn_ip_family()(BIO* b, int f) { return BIO_int_ctrl(b,BIO_C_SET_CONNECT,3,f); }
auto BIO_get_conn_hostname()(BIO* b) { return { return BIO_ptr_ctrl(b,BIO_C_GET_CONNECT,0); }; }
auto BIO_get_conn_port()(BIO* b) { return { return BIO_ptr_ctrl(b,BIO_C_GET_CONNECT,1); }; }
auto BIO_get_conn_address()(BIO* b) { return { return BIO_ptr_ctrl(b,BIO_C_GET_CONNECT,2); }; }
auto BIO_get_conn_conn_ip_family()(BIO* b) { return { return BIO_ctrl(b,BIO_C_GET_CONNECT,3); }; }
auto BIO_set_conn_conn_mode()(BIO* b, c_long n) { return { return BIO_ptr_ctrl(b,BIO_C_SET_CONNECT_MODE,n); }; }

/* BIO_s_accept() */
auto BIO_set_accept_name()(BIO* b,char* name) { return BIO_ctrl(b,BIO_C_SET_ACCEPT,0,name); }
auto BIO_set_accept_port()(BIO* b,char* port) { return BIO_ctrl(b,BIO_C_SET_ACCEPT,1,port); }
auto BIO_get_accept_name()(BIO* b)	{ return BIO_ptr_ctrl(b,BIO_C_GET_ACCEPT,0); }
auto BIO_get_accept_port()(BIO* b)	{ return BIO_ptr_ctrl(b,BIO_C_GET_ACCEPT,1); }
auto BIO_get_accept_peer_name()(BIO* b)	{ return BIO_ptr_ctrl(b,BIO_C_GET_ACCEPT,2); }
auto BIO_get_accept_peer_port()(BIO* b)	{ return BIO_ptr_ctrl(b,BIO_C_GET_ACCEPT,3); }
/* auto BIO_set_nbio()(BIO* b,n)	{ return BIO_ctrl(b,BIO_C_SET_NBIO,(n),null); } */
auto BIO_set_nbio_accept()(BIO* b,int n) { return BIO_ctrl(b,BIO_C_SET_ACCEPT,2,(n)?"a".ptr:null); }
auto BIO_set_accept_bios()(BIO* b,char* bio) { return BIO_ctrl(b,BIO_C_SET_ACCEPT,3,bio); }
auto BIO_set_accept_ip_family()(BIO* b,c_long f) { return BIO_int_ctrl(b,BIO_C_SET_ACCEPT,4,f); }
auto BIO_get_accept_ip_family()(BIO* b) { return BIO_ctrl(b,BIO_C_GET_ACCEPT,4,null); }

/* Aliases kept for backward compatibility */
enum BIO_BIND_NORMAL = 0;
enum BIO_BIND_REUSEADDR = BIO_SOCK_REUSEADDR;
enum BIO_BIND_REUSEADDR_IF_UNUSED = BIO_SOCK_REUSEADDR;
auto BIO_set_bind_mode()(BIO* b,c_long mode) { return BIO_ctrl(b,BIO_C_SET_BIND_MODE,mode,null); }
auto BIO_get_bind_mode()(BIO* b) { return BIO_ctrl(b,BIO_C_GET_BIND_MODE,0,null); }

/* BIO_s_accept() and BIO_s_connect() */
alias BIO_do_handshake BIO_do_connect;
alias BIO_do_handshake BIO_do_accept;
} /* OPENSSL_NO_SOCK */

auto BIO_do_handshake()(BIO* b) { return BIO_ctrl(b,BIO_C_DO_STATE_MACHINE,0,null); }

/* BIO_s_datagram(), BIO_s_fd(), BIO_s_socket(), BIO_s_accept() and BIO_s_connect() */
auto BIO_set_fd()(BIO* b,int fd, c_long c)	{ return BIO_int_ctrl(b,BIO_C_SET_FD,c,fd); }
auto BIO_get_fd()(BIO* b,c_long c)		{ return BIO_ctrl(b,BIO_C_GET_FD,0,cast(void*)c); }

/* BIO_s_file() */
auto BIO_set_fp()(BIO* b,FILE* fp,c_long c)	{ return BIO_ctrl(b,BIO_C_SET_FILE_PTR,c,fp); }
auto BIO_get_fp()(BIO* b,FILE** fpp)	{ return BIO_ctrl(b,BIO_C_GET_FILE_PTR,0,fpp); }

/* BIO_s_fd() and BIO_s_file() */
auto BIO_seek()(BIO* b,ofs)	{ return cast(int) BIO_ctrl(b,BIO_C_FILE_SEEK,ofs,null); }
auto BIO_tell()(BIO* b)	{ return cast(int) BIO_ctrl(b,BIO_C_FILE_TELL,0,null); }

/*
 * name is cast to lose const, but might be better to route through a
 * function so we can do it safely
 */
//#ifdef CONST_STRICT
/*
 * If you are wondering why this isn't defined, its because CONST_STRICT is
 * purely a compile-time kludge to allow const to be checked.
 */
//int BIO_read_filename(BIO* b,const(char)* name);
//#else
auto BIO_read_filename()(BIO* b,const(char)* name) { return BIO_ctrl(b,BIO_C_SET_FILENAME,BIO_CLOSE|BIO_FP_READ,name); }
//#endif
auto BIO_write_filename()(BIO* b,const(char)* name) { return BIO_ctrl(b,BIO_C_SET_FILENAME,BIO_CLOSE|BIO_FP_WRITE,name); }
auto BIO_append_filename()(BIO* b,const(char)* name) { return BIO_ctrl(b,BIO_C_SET_FILENAME,BIO_CLOSE|BIO_FP_APPEND,name); }
auto BIO_rw_filename()(BIO* b,const(char)* name) { return BIO_ctrl(b,BIO_C_SET_FILENAME,BIO_CLOSE|BIO_FP_READ|BIO_FP_WRITE,name); }

/*
 * WARNING WARNING, this ups the reference count on the read bio of the SSL
 * structure.  This is because the ssl read BIO is now pointed to by the
 * next_bio field in the bio.  So when you free the BIO, make sure you are
 * doing a BIO_free_all() to catch the underlying BIO.
 */
auto BIO_set_ssl()(BIO* b,SSL* ssl,c_long c) { return BIO_ctrl(b,BIO_C_SET_SSL,c,ssl); }
auto BIO_get_ssl()(BIO* b,SSL** sslp)	{ return BIO_ctrl(b,BIO_C_GET_SSL,0,sslp); }
auto BIO_set_ssl_mode()(BIO* b,c_long client)	{ return BIO_ctrl(b,BIO_C_SSL_MODE,client,null); }
auto BIO_set_ssl_renegotiate_bytes()(BIO* b,c_long num) {
	return BIO_ctrl(b,BIO_C_SET_SSL_RENEGOTIATE_BYTES,num,null);
};
auto BIO_get_num_renegotiates()(BIO* b) {
	return BIO_ctrl(b,BIO_C_GET_SSL_NUM_RENEGOTIATES,0,null);
};
auto BIO_set_ssl_renegotiate_timeout()(BIO* b,c_long seconds) {
	return BIO_ctrl(b,BIO_C_SET_SSL_RENEGOTIATE_TIMEOUT,seconds,null);
};

/* defined in evp.h */
/* auto BIO_set_md()(BIO* b,md)	{ return BIO_ctrl(b,BIO_C_SET_MD,1,(char*)md); } */

auto BIO_get_mem_data()(BIO* b,BUF_MEM** pp)	{ return BIO_ctrl(b,BIO_CTRL_INFO,0,pp); }
auto BIO_set_mem_buf()(BIO* b,BUF_MEM* bm,c_long c)	{ return BIO_ctrl(b,BIO_C_SET_BUF_MEM,c,bm); }
auto BIO_get_mem_ptr()(BIO* b,BUF_MEM** pp)	{ return BIO_ctrl(b,BIO_C_GET_BUF_MEM_PTR,0,pp); }
auto BIO_set_mem_eof_return()(BIO* b,c_long v) 				{ return BIO_ctrl(b,BIO_C_SET_BUF_MEM_EOF_RETURN,v,null); }

/* For the BIO_f_buffer() type */
auto BIO_get_buffer_num_lines()(BIO* b)	{ return BIO_ctrl(b,BIO_C_GET_BUFF_NUM_LINES,0,null); }
auto BIO_set_buffer_size()(BIO* b,size)	{ return BIO_ctrl(b,BIO_C_SET_BUFF_SIZE,size,null); }
auto BIO_set_read_buffer_size()(BIO* b,size) { return BIO_int_ctrl(b,BIO_C_SET_BUFF_SIZE,size,0); }
auto BIO_set_write_buffer_size()(BIO* b,size) { return BIO_int_ctrl(b,BIO_C_SET_BUFF_SIZE,size,1); }
auto BIO_set_buffer_read_data()(BIO* b,buf,num) { return BIO_ctrl(b,BIO_C_SET_BUFF_READ_DATA,num,buf); }

/* Don't use the next one unless you know what you are doing :-) */
auto BIO_dup_state()(BIO* b,void* ret)	{ return BIO_ctrl(b,BIO_CTRL_DUP,0,ret); }

auto BIO_reset()(BIO* b)		{ return cast(int) BIO_ctrl(b,BIO_CTRL_RESET,0,null); }
auto BIO_eof()(BIO* b)		{ return cast(int) BIO_ctrl(b,BIO_CTRL_EOF,0,null); }
auto BIO_set_close()(BIO* b,int c) { return cast(int) BIO_ctrl(b,BIO_CTRL_SET_CLOSE,c,null); }
auto BIO_get_close()(BIO* b)	{ return cast(int) BIO_ctrl(b,BIO_CTRL_GET_CLOSE,0,null); }
auto BIO_pending()(BIO* b)		{ return cast(int) BIO_ctrl(b,BIO_CTRL_PENDING,0,null); }
auto BIO_wpending()(BIO* b)		{ return cast(int) BIO_ctrl(b,BIO_CTRL_WPENDING,0,null); }
/* ...pending macros have inappropriate return type */
size_t BIO_ctrl_pending(BIO* b);
size_t BIO_ctrl_wpending(BIO* b);
auto BIO_flush()(BIO* b)		{ return cast(int) BIO_ctrl(b,BIO_CTRL_FLUSH,0,null); }
auto BIO_get_info_callback()(BIO* b,bio_info_cb** cbp) { return cast(int)BIO_ctrl(b,BIO_CTRL_GET_CALLBACK,0,cbp); }
auto BIO_set_info_callback()(BIO* b,bio_info_cb* cb) { return cast(int) BIO_callback_ctrl(b,BIO_CTRL_SET_CALLBACK,cb); }

/* For the BIO_f_buffer() type */
auto BIO_buffer_get_num_lines()(BIO* b) { return BIO_ctrl(b,BIO_CTRL_GET,0,null); }

/* For BIO_s_bio() */
auto BIO_set_write_buf_size()(BIO* b,size) { return cast(int) BIO_ctrl(b,BIO_C_SET_WRITE_BUF_SIZE,size,null); }
auto BIO_get_write_buf_size()(BIO* b,size) { return cast(size_t) BIO_ctrl(b,BIO_C_GET_WRITE_BUF_SIZE,size,null); }
auto BIO_make_bio_pair()(BIO* b1,b2)   { return cast(int) BIO_ctrl(b1,BIO_C_MAKE_BIO_PAIR,0,b2); }
auto BIO_destroy_bio_pair()(BIO* b)    { return cast(int) BIO_ctrl(b,BIO_C_DESTROY_BIO_PAIR,0,null); }
auto BIO_shutdown_wr()(BIO* b) { return cast(int) BIO_ctrl(b, BIO_C_SHUTDOWN_WR, 0, null); }
/* macros with inappropriate type -- but ...pending macros use int too: */
auto BIO_get_write_guarantee()(BIO* b) { return cast(int) BIO_ctrl(b,BIO_C_GET_WRITE_GUARANTEE,0,null); }
auto BIO_get_read_request()(BIO* b)    { return cast(int) BIO_ctrl(b,BIO_C_GET_READ_REQUEST,0,null); }
size_t BIO_ctrl_get_write_guarantee(BIO* b);
size_t BIO_ctrl_get_read_request(BIO* b);
int BIO_ctrl_reset_read_request(BIO* b);

/* ctrl macros for dgram */
auto BIO_ctrl_dgram_connect()(BIO* b,void* peer) { return cast(int) BIO_ctrl(b,BIO_CTRL_DGRAM_CONNECT,0, peer); }
auto BIO_ctrl_set_connected()(BIO* b, peer) { return cast(int) BIO_ctrl(b, BIO_CTRL_DGRAM_SET_CONNECTED, 0, peer); }
auto BIO_dgram_recv_timedout()(BIO* b) { return cast(int) BIO_ctrl(b, BIO_CTRL_DGRAM_GET_RECV_TIMER_EXP, 0, null); }
auto BIO_dgram_send_timedout()(BIO* b) { return cast(int) BIO_ctrl(b, BIO_CTRL_DGRAM_GET_SEND_TIMER_EXP, 0, null); }
auto BIO_dgram_get_peer()(BIO* b,void* peer) { return cast(int) BIO_ctrl(b, BIO_CTRL_DGRAM_GET_PEER, 0, peer); }
auto BIO_dgram_set_peer()(BIO* b,void* peer) { return cast(int) BIO_ctrl(b, BIO_CTRL_DGRAM_SET_PEER, 0, peer); }
auto BIO_dgram_get_mtu_overhead()(BIO* b) { return cast(uint) BIO_ctrl((b), BIO_CTRL_DGRAM_GET_MTU_OVERHEAD, 0, null); }

auto BIO_get_ex_new_index(c_long l, void* p, CRYPTO_EX_new* newf, CRYPTO_EX_dup* dupf, CRYPTO_EX_free* freef) {
    return CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_BIO, l, p, newf, dupf, freef);
}
int BIO_set_ex_data(BIO* bio,int idx,void* data);
void* BIO_get_ex_data(BIO* bio,int idx);
ulong BIO_number_read(BIO* bio);
ulong BIO_number_written(BIO* bio);

/* For BIO_f_asn1() */
int BIO_asn1_set_prefix(BIO* b, asn1_ps_func* prefix,
					asn1_ps_func* prefix_free);
int BIO_asn1_get_prefix(BIO* b, asn1_ps_func** pprefix,
					asn1_ps_func** pprefix_free);
int BIO_asn1_set_suffix(BIO* b, asn1_ps_func* suffix,
					asn1_ps_func* suffix_free);
int BIO_asn1_get_suffix(BIO* b, asn1_ps_func** psuffix,
					asn1_ps_func** psuffix_free);

const(BIO_METHOD)* BIO_s_file();
BIO* BIO_new_file(const(char)* filename, const(char)* mode);
version (OPENSSL_NO_STDIO) {} else {
BIO* BIO_new_fp(FILE* stream, int close_flag);
}
BIO* BIO_new(BIO_METHOD* type);
int BIO_free(BIO* a);
void BIO_set_data(BIO* a, void* ptr);
void* BIO_get_data(BIO *a);
void BIO_set_init(BIO* a, int init);
int BIO_get_init(BIO* a);
void BIO_set_shutdown(BIO* a, int shut);
int BIO_get_shutdown(BIO* a);
void BIO_vfree(BIO* a);
int BIO_up_ref(BIO* a);
int	BIO_read(BIO* b, void* data, int len);
int	BIO_gets(BIO* bp,char* buf, int size);
int	BIO_write(BIO* b, const(void)* data, int len);
int	BIO_puts(BIO* bp,const(char)* buf);
int	BIO_indent(BIO* b,int indent,int max);
c_long	BIO_ctrl(BIO* bp,int cmd,c_long larg,void* parg);
c_long BIO_callback_ctrl(BIO* b, int cmd,
                         ExternC!(void function(BIO*, int, const(char)*, int, c_long, c_long)) fp);
void* BIO_ptr_ctrl(BIO* bp,int cmd,c_long larg);
c_long	BIO_int_ctrl(BIO* bp,int cmd,c_long larg,int iarg);
BIO* 	BIO_push(BIO* b,BIO* append);
BIO* 	BIO_pop(BIO* b);
void	BIO_free_all(BIO* a);
BIO* 	BIO_find_type(BIO* b,int bio_type);
BIO* 	BIO_next(BIO* b);
void BIO_set_next(BIO* b, BIO* next);
BIO* 	BIO_get_retry_BIO(BIO* bio, int* reason);
int	BIO_get_retry_reason(BIO* bio);
void BIO_set_retry_reason(BIO* bio, int reason);
BIO* 	BIO_dup_chain(BIO* in_);

int BIO_nread0(BIO* bio, char** buf);
int BIO_nread(BIO* bio, char** buf, int num);
int BIO_nwrite0(BIO* bio, char** buf);
int BIO_nwrite(BIO* bio, char** buf, int num);

c_long BIO_debug_callback(BIO* bio,int cmd,const(char)* argp,int argi,
	c_long argl,c_long ret);

const(BIO_METHOD)* BIO_s_mem();
const(BIO_METHOD)* BIO_s_secmem();
BIO* BIO_new_mem_buf(const(void)* buf, int len);
version (OPENSSL_NO_SOCK) {} else {
const(BIO_METHOD)* BIO_s_socket();
const(BIO_METHOD)* BIO_s_connect();
const(BIO_METHOD)* BIO_s_accept();
}
const(BIO_METHOD)* BIO_s_fd();
const(BIO_METHOD)* BIO_s_log();
const(BIO_METHOD)* BIO_s_bio();
const(BIO_METHOD)* BIO_s_null();
const(BIO_METHOD)* BIO_f_null();
const(BIO_METHOD)* BIO_f_buffer();
const(BIO_METHOD)* BIO_f_linebuffer();
const(BIO_METHOD)* BIO_f_nbio_test();
version (OPENSSL_NO_DGRAM) {} else {
const(BIO_METHOD)* BIO_s_datagram();
int BIO_dgram_non_fatal_error(int error);
BIO* BIO_new_dgram(int fd, int close_flag);
version(OPENSSL_NO_SCTP) {} else {
const(BIO_METHOD) *BIO_s_datagram_sctp();
BIO* BIO_new_dgram_sctp(int fd, int close_flag);
int BIO_dgram_is_sctp(BIO* bio);
int BIO_dgram_sctp_notification_cb(BIO* b,
                                   ExternC!(void function       (BIO *bio,
                                                                 void *context,
                                                                 void *buf)) handle_notifications,
                                   void* context);
int BIO_dgram_sctp_wait_for_dry(BIO *b);
int BIO_dgram_sctp_msg_waiting(BIO *b);
}
}

version (OPENSSL_NO_SOCK) {} else {
int BIO_sock_should_retry(int i);
int BIO_sock_non_fatal_error(int error);
}

int BIO_fd_should_retry(int i);
int BIO_fd_non_fatal_error(int error);
int BIO_dump_cb(ExternC!(int function(const(void)* data, size_t len, void* u)) cb,
		void* u, const(char)* s, int len);
int BIO_dump_indent_cb(ExternC!(int function(const(void)* data, size_t len, void* u)) cb,
		       void* u, const(char)* s, int len, int indent);
int BIO_dump(BIO* b,const(char)* bytes,int len);
int BIO_dump_indent(BIO* b,const(char)* bytes,int len,int indent);
version (OPENSSL_NO_STDIO) {} else {
int BIO_dump_fp(FILE* fp, const(char)* s, int len);
int BIO_dump_indent_fp(FILE* fp, const(char)* s, int len, int indent);
}

version (OPENSSL_NO_SOCK) {} else {
BIO_ADDR* BIO_ADDR_new();
int BIO_ADDR_rawmake(BIO_ADDR* ap, int family,
                     const(void)* where, size_t wherelen, ushort port);
void BIO_ADDR_free(BIO_ADDR*);
void BIO_ADDR_clear(BIO_ADDR* ap);
int BIO_ADDR_family(const(BIO_ADDR)* ap);
int BIO_ADDR_rawaddress(const(BIO_ADDR)* ap, void* p, size_t* l);
ushort BIO_ADDR_rawport(const(BIO_ADDR)* ap);
char* BIO_ADDR_hostname_string(const(BIO_ADDR)* ap, int numeric);
char* BIO_ADDR_service_string(const(BIO_ADDR)* ap, int numeric);
char* BIO_ADDR_path_string(const(BIO_ADDR)* ap);

const(BIO_ADDRINFO)* BIO_ADDRINFO_next(const(BIO_ADDRINFO)* bai);
int BIO_ADDRINFO_family(const(BIO_ADDRINFO)* bai);
int BIO_ADDRINFO_socktype(const(BIO_ADDRINFO)* bai);
int BIO_ADDRINFO_protocol(const(BIO_ADDRINFO)* bai);
const(BIO_ADDR)* BIO_ADDRINFO_address(const(BIO_ADDRINFO)* bai);
void BIO_ADDRINFO_free(BIO_ADDRINFO* bai);

enum BIO_hostserv_priorities {
    BIO_PARSE_PRIO_HOST, BIO_PARSE_PRIO_SERV
}
int BIO_parse_hostserv(const(char)* hostserv, char** host, char** service,
                       BIO_hostserv_priorities hostserv_prio);
enum BIO_lookup_type {
    BIO_LOOKUP_CLIENT, BIO_LOOKUP_SERVER
}
int BIO_lookup(const(char)* host, const(char)* service,
               BIO_lookup_type lookup_type,
               int family, int socktype, BIO_ADDRINFO** res);
int BIO_sock_error(int sock);
int BIO_socket_ioctl(int fd, c_long type, void* arg);
int BIO_socket_nbio(int fd,int mode);
int BIO_sock_init();
// TODO:
// # if OPENSSL_API_COMPAT < 0x10100000L
void BIO_sock_cleanup();
// # endif
int BIO_set_tcp_ndelay(int sock,int turn_on);

/+ TODO:
DEPRECATEDIN_1_1_0(struct hostent *BIO_gethostbyname(const char *name))
DEPRECATEDIN_1_1_0(int BIO_get_port(const char *str, unsigned short *port_ptr))
DEPRECATEDIN_1_1_0(int BIO_get_host_ip(const char *str, unsigned char *ip))
DEPRECATEDIN_1_1_0(int BIO_get_accept_socket(char *host_port, int mode))
DEPRECATEDIN_1_1_0(int BIO_accept(int sock, char **ip_port))
+/
int BIO_get_port(const(char)* str, ushort* port_ptr);
int BIO_get_host_ip(const(char)* str, ubyte* ip);
int BIO_get_accept_socket(char* host_port,int mode);
int BIO_accept(int sock,char** ip_port);

union BIO_sock_info_u {
    BIO_ADDR* addr;
}
enum BIO_sock_info_type {
    BIO_SOCK_INFO_ADDRESS
}
int BIO_sock_info(int sock,
                  BIO_sock_info_type type, BIO_sock_info_u* info);

enum BIO_SOCK_REUSEADDR = 0x01;
enum BIO_SOCK_V6_ONLY = 0x02;
enum BIO_SOCK_KEEPALIVE = 0x04;
enum BIO_SOCK_NONBLOCK = 0x08;
enum BIO_SOCK_NODELAY = 0x10;

int BIO_socket(int domain, int socktype, int protocol, int options);
int BIO_connect(int sock, const(BIO_ADDR)* addr, int options);
int BIO_listen(int sock, const(BIO_ADDR)* addr, int options);
int BIO_accept_ex(int accept_sock, BIO_ADDR* addr, int options);
int BIO_closesocket(int sock);

BIO* BIO_new_socket(int sock, int close_flag);
BIO* BIO_new_connect(const(char)* host_port);
BIO* BIO_new_accept(const(char)* host_port);
} /* OPENSSL_NO_SOCK*/

BIO* BIO_new_fd(int fd, int close_flag);

int BIO_new_bio_pair(BIO** bio1, size_t writebuf1,
	BIO** bio2, size_t writebuf2);
/*
 * If successful, returns 1 and in *bio1, *bio2 two BIO pair endpoints.
 * Otherwise returns 0 and sets *bio1 and *bio2 to NULL. Size 0 uses default
 * value.
 */

void BIO_copy_next_retry(BIO* b);

/*
 * long BIO_ghbn_ctrl(int cmd,int iarg,char *parg);
 */

int BIO_printf(BIO* bio, const(char)* format, ...);
int BIO_vprintf(BIO* bio, const(char)* format, va_list args);
int BIO_snprintf(char* buf, size_t n, const(char)* format, ...);
int BIO_vsnprintf(char* buf, size_t n, const(char)* format, va_list args);

BIO_METHOD* BIO_meth_new(int type, const(char)* name);
void BIO_meth_free(BIO_METHOD* biom);
// TODO:
/+
int (*BIO_meth_get_write(BIO_METHOD *biom)) (BIO *, const char *, int);
int BIO_meth_set_write(BIO_METHOD *biom,
                       int (*write) (BIO *, const char *, int));
int (*BIO_meth_get_read(BIO_METHOD *biom)) (BIO *, char *, int);
int BIO_meth_set_read(BIO_METHOD *biom,
                      int (*read) (BIO *, char *, int));
int (*BIO_meth_get_puts(BIO_METHOD *biom)) (BIO *, const char *);
int BIO_meth_set_puts(BIO_METHOD *biom,
                      int (*puts) (BIO *, const char *));
int (*BIO_meth_get_gets(BIO_METHOD *biom)) (BIO *, char *, int);
int BIO_meth_set_gets(BIO_METHOD *biom,
                      int (*gets) (BIO *, char *, int));
long (*BIO_meth_get_ctrl(BIO_METHOD *biom)) (BIO *, int, long, void *);
int BIO_meth_set_ctrl(BIO_METHOD *biom,
                      long (*ctrl) (BIO *, int, long, void *));
int (*BIO_meth_get_create(BIO_METHOD *bion)) (BIO *);
int BIO_meth_set_create(BIO_METHOD *biom, int (*create) (BIO *));
int (*BIO_meth_get_destroy(BIO_METHOD *biom)) (BIO *);
int BIO_meth_set_destroy(BIO_METHOD *biom, int (*destroy) (BIO *));
long (*BIO_meth_get_callback_ctrl(BIO_METHOD *biom))
                                 (BIO *, int, bio_info_cb *);
int BIO_meth_set_callback_ctrl(BIO_METHOD *biom,
                               long (*callback_ctrl) (BIO *, int,
                                                      bio_info_cb *));
+/

/* BEGIN ERROR CODES */
/*
 * The following lines are auto generated by the script mkerr.pl. Any changes
 * made after this point may be overwritten when the script is next run.
 */
int ERR_load_BIO_strings();

/* Error codes for the BIO functions. */

/* Function codes. */
enum BIO_F_ACPT_STATE = 100;
enum BIO_F_ADDR_STRINGS = 134;
enum BIO_F_BIO_ACCEPT = 101;
enum BIO_F_BIO_ACCEPT_EX = 137;
enum BIO_F_BIO_ADDR_NEW = 144;
enum BIO_F_BIO_CALLBACK_CTRL = 131;
enum BIO_F_BIO_CONNECT = 138;
enum BIO_F_BIO_CTRL = 103;
enum BIO_F_BIO_GETS = 104;
enum BIO_F_BIO_GET_HOST_IP = 106;
enum BIO_F_BIO_GET_NEW_INDEX = 102;
enum BIO_F_BIO_GET_PORT = 107;
enum BIO_F_BIO_LISTEN = 139;
enum BIO_F_BIO_LOOKUP = 135;
enum BIO_F_BIO_MAKE_PAIR = 121;
enum BIO_F_BIO_NEW = 108;
enum BIO_F_BIO_NEW_FILE = 109;
enum BIO_F_BIO_NEW_MEM_BUF = 126;
enum BIO_F_BIO_NREAD = 123;
enum BIO_F_BIO_NREAD0 = 124;
enum BIO_F_BIO_NWRITE = 125;
enum BIO_F_BIO_NWRITE0 = 122;
enum BIO_F_BIO_PARSE_HOSTSERV = 136;
enum BIO_F_BIO_PUTS = 110;
enum BIO_F_BIO_READ = 111;
enum BIO_F_BIO_SOCKET = 140;
enum BIO_F_BIO_SOCKET_NBIO = 142;
enum BIO_F_BIO_SOCK_INFO = 141;
enum BIO_F_BIO_SOCK_INIT = 112;
enum BIO_F_BIO_WRITE = 113;
enum BIO_F_BUFFER_CTRL = 114;
enum BIO_F_CONN_CTRL = 127;
enum BIO_F_CONN_STATE = 115;
enum BIO_F_DGRAM_SCTP_READ = 132;
enum BIO_F_DGRAM_SCTP_WRITE = 133;
enum BIO_F_FILE_CTRL = 116;
enum BIO_F_FILE_READ = 130;
enum BIO_F_LINEBUFFER_CTRL = 129;
enum BIO_F_MEM_WRITE = 117;
enum BIO_F_SSL_NEW = 118;

/* Reason codes. */
enum BIO_R_ACCEPT_ERROR = 100;
enum BIO_R_ADDRINFO_ADDR_IS_NOT_AF_INET = 141;
enum BIO_R_AMBIGUOUS_HOST_OR_SERVICE = 129;
enum BIO_R_BAD_FOPEN_MODE = 101;
enum BIO_R_BROKEN_PIPE = 124;
enum BIO_R_CONNECT_ERROR = 103;
enum BIO_R_GETHOSTBYNAME_ADDR_IS_NOT_AF_INET = 107;
enum BIO_R_GETSOCKNAME_ERROR = 132;
enum BIO_R_GETSOCKNAME_TRUNCATED_ADDRESS = 133;
enum BIO_R_GETTING_SOCKTYPE = 134;
enum BIO_R_INVALID_ARGUMENT = 125;
enum BIO_R_INVALID_SOCKET = 135;
enum BIO_R_IN_USE = 123;
enum BIO_R_LISTEN_V6_ONLY = 136;
enum BIO_R_LOOKUP_RETURNED_NOTHING = 142;
enum BIO_R_MALFORMED_HOST_OR_SERVICE = 130;
enum BIO_R_NBIO_CONNECT_ERROR = 110;
enum BIO_R_NO_ACCEPT_ADDR_OR_SERVICE_SPECIFIED = 143;
enum BIO_R_NO_HOSTNAME_OR_SERVICE_SPECIFIED = 144;
enum BIO_R_NO_PORT_DEFINED = 113;
enum BIO_R_NO_SUCH_FILE = 128;
enum BIO_R_NULL_PARAMETER = 115;
enum BIO_R_UNABLE_TO_BIND_SOCKET = 117;
enum BIO_R_UNABLE_TO_CREATE_SOCKET = 118;
enum BIO_R_UNABLE_TO_KEEPALIVE = 137;
enum BIO_R_UNABLE_TO_LISTEN_SOCKET = 119;
enum BIO_R_UNABLE_TO_NODELAY = 138;
enum BIO_R_UNABLE_TO_REUSEADDR = 139;
enum BIO_R_UNAVAILABLE_IP_FAMILY = 145;
enum BIO_R_UNINITIALIZED = 120;
enum BIO_R_UNKNOWN_INFO_TYPE = 140;
enum BIO_R_UNSUPPORTED_IP_FAMILY = 146;
enum BIO_R_UNSUPPORTED_METHOD = 121;
enum BIO_R_UNSUPPORTED_PROTOCOL_FAMILY = 131;
enum BIO_R_WRITE_TO_READ_ONLY_BIO = 126;
enum BIO_R_WSASTARTUP = 122;
