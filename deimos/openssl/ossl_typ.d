/*
 * Copyright 2001-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

module deimos.openssl.ossl_typ;

import deimos.openssl._d_util;

public import deimos.openssl.e_os2;

version (NO_ASN1_TYPEDEFS) {
alias ASN1_STRING ASN1_INTEGER;
alias ASN1_STRING ASN1_ENUMERATED;
alias ASN1_STRING ASN1_BIT_STRING;
alias ASN1_STRING ASN1_OCTET_STRING;
alias ASN1_STRING ASN1_PRINTABLESTRING;
alias ASN1_STRING ASN1_T61STRING;
alias ASN1_STRING ASN1_IA5STRING;
alias ASN1_STRING ASN1_UTCTIME;
alias ASN1_STRING ASN1_GENERALIZEDTIME;
alias ASN1_STRING ASN1_TIME;
alias ASN1_STRING ASN1_GENERALSTRING;
alias ASN1_STRING ASN1_UNIVERSALSTRING;
alias ASN1_STRING ASN1_BMPSTRING;
alias ASN1_STRING ASN1_VISIBLESTRING;
alias ASN1_STRING ASN1_UTF8STRING;
alias int ASN1_BOOLEAN;
alias int ASN1_NULL;
} else {
import deimos.openssl.asn1;
alias asn1_string_st ASN1_INTEGER;
alias asn1_string_st ASN1_ENUMERATED;
alias asn1_string_st ASN1_BIT_STRING;
alias asn1_string_st ASN1_OCTET_STRING;
alias asn1_string_st ASN1_PRINTABLESTRING;
alias asn1_string_st ASN1_T61STRING;
alias asn1_string_st ASN1_IA5STRING;
alias asn1_string_st ASN1_GENERALSTRING;
alias asn1_string_st ASN1_UNIVERSALSTRING;
alias asn1_string_st ASN1_BMPSTRING;
alias asn1_string_st ASN1_UTCTIME;
alias asn1_string_st ASN1_TIME;
alias asn1_string_st ASN1_GENERALIZEDTIME;
alias asn1_string_st ASN1_VISIBLESTRING;
alias asn1_string_st ASN1_UTF8STRING;
alias asn1_string_st ASN1_STRING;
alias int ASN1_BOOLEAN;
alias int ASN1_NULL;
}

struct asn1_object_st;
alias asn1_object_st ASN1_OBJECT;

import deimos.openssl.asn1t;
alias ASN1_ITEM_st ASN1_ITEM;

struct asn1_pctx_st;
alias asn1_pctx_st ASN1_PCTX;

struct asn1_sctx_st;
alias asn1_sctx_st ASN1_SCTX;

//#ifdef _WIN32
//#undef X509_NAME
//#undef X509_EXTENSIONS
//#undef PKCS7_ISSUER_AND_SERIAL
//#undef PKCS7_SIGNER_INFO
//#undef OCSP_REQUEST
//#undef OCSP_RESPONSE
//#endif

//#ifdef BIGNUM
//#undef BIGNUM
//#endif
struct dane_st;
struct bio_st;
alias bio_st BIO;
import deimos.openssl.bn;
alias bignum_st BIGNUM;
struct bignum_ctx;
alias bignum_ctx BN_CTX;
struct bn_blinding_st;
alias bn_blinding_st BN_BLINDING;
alias bn_mont_ctx_st BN_MONT_CTX;
alias bn_recp_ctx_st BN_RECP_CTX;
alias bn_gencb_st BN_GENCB;

import deimos.openssl.buffer;
alias buf_mem_st BUF_MEM;

import deimos.openssl.evp;
alias evp_cipher_st EVP_CIPHER;
alias evp_cipher_ctx_st EVP_CIPHER_CTX;
struct evp_md_st;
alias evp_md_st EVP_MD;
struct evp_md_ctx_st;
alias evp_md_ctx_st EVP_MD_CTX;
alias evp_pkey_st EVP_PKEY;

struct evp_pkey_asn1_method_st;
alias evp_pkey_asn1_method_st EVP_PKEY_ASN1_METHOD;
struct evp_pkey_method_st;
alias evp_pkey_method_st EVP_PKEY_METHOD;
struct evp_pkey_ctx_st;
alias evp_pkey_ctx_st EVP_PKEY_CTX;

alias evp_Encode_Ctx_st EVP_ENCODE_CTX;

alias hmac_ctx_st HMAC_CTX;

import deimos.openssl.dh;
/*struct dh_st;*/
alias dh_st DH;
/*struct dh_method;*/
alias dh_method DH_METHOD;

import deimos.openssl.dsa;
/*struct dsa_st;*/
alias dsa_st DSA;
/*struct dsa_method;*/
alias dsa_method DSA_METHOD;

import deimos.openssl.rsa;
/*struct rsa_st;*/
alias rsa_st RSA;
/*struct rsa_meth_st;*/
alias rsa_meth_st RSA_METHOD;

struct ec_key_st;
alias ec_key_st EC_KEY;

struct ec_key_method_st;
alias ec_key_method_st EC_KEY_METHOD;

import deimos.openssl.rand;
alias rand_meth_st RAND_METHOD;

alias ssl_dane_st SSL_DANE;
import deimos.openssl.x509;
import deimos.openssl.x509_vfy;
alias x509_st X509;
alias X509_algor_st X509_ALGOR;
alias X509_crl_st X509_CRL;
struct x509_crl_method_st;
alias x509_crl_method_st X509_CRL_METHOD;
alias x509_revoked_st X509_REVOKED;
alias X509_name_st X509_NAME;
alias X509_pubkey_st X509_PUBKEY;
alias x509_store_st X509_STORE;
/*struct x509_store_ctx_st;*/
alias x509_store_ctx_st X509_STORE_CTX;

alias x509_object_st X509_OBJECT;
alias x509_lookup_st X509_LOOKUP;
alias x509_lookup_method_st X509_LOOKUP_METHOD;
alias X509_VERIFY_PARAM_st X509_VERIFY_PARAM;

alias pkcs8_priv_key_info_st PKCS8_PRIV_KEY_INFO;

import deimos.openssl.x509v3;
alias v3_ext_ctx X509V3_CTX;
import deimos.openssl.conf;
alias conf_st CONF;

alias ossl_init_settings_st OPENSSL_INIT_SETTINGS;

struct ui_st;
alias ui_st UI;
struct ui_method_st;
alias ui_method_st UI_METHOD;

struct engine_st;
alias engine_st ENGINE;

alias comp_ctx_st COMP_CTX;
alias comp_method_st COMP_METHOD;

struct X509_POLICY_NODE_st;
alias X509_POLICY_NODE_st X509_POLICY_NODE;
struct X509_POLICY_LEVEL_st;
alias X509_POLICY_LEVEL_st X509_POLICY_LEVEL;
struct X509_POLICY_TREE_st;
alias X509_POLICY_TREE_st X509_POLICY_TREE;
struct X509_POLICY_CACHE_st;
alias X509_POLICY_CACHE_st X509_POLICY_CACHE;

alias AUTHORITY_KEYID_st AUTHORITY_KEYID;
alias DIST_POINT_st DIST_POINT;
alias ISSUING_DIST_POINT_st ISSUING_DIST_POINT;
alias NAME_CONSTRAINTS_st NAME_CONSTRAINTS;

import deimos.openssl.crypto;
alias crypto_ex_data_st CRYPTO_EX_DATA;

import deimos.openssl.ocsp;
struct ocsp_req_ctx_st;
alias ocsp_req_ctx_st OCSP_REQ_CTX;
/*struct ocsp_response_st;*/
alias ocsp_response_st OCSP_RESPONSE;
/*struct ocsp_responder_id_st;*/
alias ocsp_responder_id_st OCSP_RESPID;

alias ct_st SCT;
alias sct_ctx_st SCT_CTX;
alias ctlog_st CTLOG;
alias ctlog_store_st CTLOG_STORE;
alias ct_policy_eval_ctx_st CT_POLICY_EVAL_CTX;

alias intmax_t ossl_intmax_t;
alias uintmax_t ossl_uintmax_t;
