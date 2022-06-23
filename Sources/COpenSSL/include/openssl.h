
#ifndef _COPENSSL_H_
#define _COPENSSL_H_

#include "../conf.h"
#include "../ssl.h"
#include "../err.h"
#include "../x509.h"
#include "../x509v3.h"
#include "../sha.h"
#include "../md5.h"
#include "../bio.h"
#include "../hmac.h"
#include "../rand.h"
#include "../cms.h"
#include "../evp.h"

static int copenssl_EVP_MD_size(const EVP_MD *md) {
	return EVP_MD_size(md);
}
static int copenssl_EVP_CIPHER_block_size(const EVP_CIPHER *cipher) {
	return EVP_CIPHER_block_size(cipher);
}
static int copenssl_EVP_CIPHER_key_length(const EVP_CIPHER *cipher) {
	return EVP_CIPHER_key_length(cipher);
}
static int copenssl_EVP_CIPHER_iv_length(const EVP_CIPHER *cipher) {
	return EVP_CIPHER_iv_length(cipher);
}
static EVP_MD_CTX * copenssl_EVP_MD_CTX_create() {
	return EVP_MD_CTX_create();
}

static void copenssl_EVP_MD_CTX_destroy(EVP_MD_CTX * ctx) {
	EVP_MD_CTX_destroy(ctx);
}

static void copenssl_SSL_library_init() {
	SSL_library_init();
	ERR_load_crypto_strings();
	SSL_load_error_strings();
	OPENSSL_add_all_algorithms_conf();
}
static size_t copenssl_stack_st_X509_NAME_num(struct stack_st_X509_NAME * p) {
	return sk_X509_NAME_num(p);
}

#if OPENSSL_VERSION_NUMBER < 0x10100000L
static void * copenssl_CRYPTO_malloc(size_t num, const char *file, int line) {
	return CRYPTO_malloc((int)num, file, line);
}
static void copenssl_CRYPTO_free(void * obj, const char *file, int line) {
	CRYPTO_free(obj);
}
static void copenssl_SSL_CTX_set_options(SSL_CTX * sslCtx) {
#ifdef SSL_CTRL_SET_ECDH_AUTO
	SSL_CTX_ctrl(sslCtx, SSL_CTRL_SET_ECDH_AUTO, 1, NULL);
#endif
	SSL_CTX_ctrl(sslCtx, SSL_CTRL_MODE, SSL_MODE_AUTO_RETRY, NULL);
	SSL_CTX_ctrl(sslCtx, SSL_CTRL_OPTIONS, SSL_OP_ALL, NULL);
}

#else
static void * copenssl_CRYPTO_malloc(size_t num, const char *file, int line) {
	return CRYPTO_malloc(num, file, line);
}
static void copenssl_CRYPTO_free(void * obj, const char *file, int line) {
	CRYPTO_free(obj, file, line);
}
static void copenssl_SSL_CTX_set_options(SSL_CTX * sslCtx) {
	SSL_CTX_set_options(sslCtx, SSL_OP_ALL);
}
#undef CRYPTO_set_locking_callback
static void CRYPTO_set_locking_callback(void (*func) (int mode, int type,
													  const char *file, int line)) {}
#undef CRYPTO_num_locks
static int CRYPTO_num_locks(void) {
	return 0;
}
#undef CRYPTO_set_id_callback
static void CRYPTO_set_id_callback(unsigned long (*func) (void)) {}
#undef SSL_CTX_get_ex_new_index
static int SSL_CTX_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func,
									CRYPTO_EX_dup *dup_func,
									CRYPTO_EX_free *free_func) {
	return CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_SSL_CTX, argl, argp,
								   new_func, dup_func, free_func);
}
#undef SSL_get_ex_new_index
static int SSL_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func,
								CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func) {
	return CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_SSL, argl, argp,
								   new_func, dup_func, free_func);
}

struct bio_method_st {};
struct asn1_object_st {};
struct ASN1_ITEM_st {};
struct asn1_pctx_st {};
struct asn1_sctx_st {};
struct dane_st {};
struct bio_st {};
struct bignum_st {};
struct bignum_ctx {};
struct bn_blinding_st {};
struct bn_mont_ctx_st {};
struct bn_recp_ctx_st {};
struct bn_gencb_st {};
struct evp_cipher_st {};
struct evp_cipher_ctx_st {};
struct evp_md_st {};
struct evp_md_ctx_st {};
struct evp_pkey_st {};
struct evp_pkey_asn1_method_st {};
struct evp_pkey_method_st {};
struct evp_pkey_ctx_st {};
struct evp_Encode_Ctx_st {};
struct hmac_ctx_st {};
struct dh_st {};
struct dh_method {};
struct dsa_st {};
struct dsa_method {};
struct rsa_st {};
struct rsa_meth_st {};
struct ec_key_st {};
struct ec_key_method_st {};
struct ssl_dane_st {};
struct x509_st {};
struct X509_crl_st {};
struct x509_crl_method_st {};
struct x509_revoked_st {};
struct X509_name_st {};
struct X509_pubkey_st {};
struct x509_store_st {};
struct x509_store_ctx_st {};
struct x509_object_st {};
struct x509_lookup_st {};
struct x509_lookup_method_st {};
struct X509_VERIFY_PARAM_st {};
struct pkcs8_priv_key_info_st {};
struct ossl_init_settings_st {};
struct ui_st {};
struct ui_method_st {};
struct engine_st {};
struct ssl_st {};
struct ssl_ctx_st {};
struct comp_ctx_st {};
struct comp_method_st {};
struct X509_POLICY_NODE_st {};
struct X509_POLICY_LEVEL_st {};
struct X509_POLICY_TREE_st {};
struct X509_POLICY_CACHE_st {};
struct ocsp_req_ctx_st {};
struct ocsp_response_st {};
struct ocsp_responder_id_st {};
struct sct_st {};
struct sct_ctx_st {};
struct ctlog_st {};
struct ctlog_store_st {};
struct ct_policy_eval_ctx_st {};
#endif

#if OPENSSL_VERSION_NUMBER < 0x10100000L

static void *OPENSSL_zalloc(size_t num)
{
   void *ret = OPENSSL_malloc(num);

   if (ret != NULL)
	   memset(ret, 0, num);
   return ret;
}

int RSA_set0_key(RSA *r, BIGNUM *n, BIGNUM *e, BIGNUM *d)
{
   /* If the fields n and e in r are NULL, the corresponding input
	* parameters MUST be non-NULL for n and e.  d may be
	* left NULL (in case only the public key is used).
	*/
   if ((r->n == NULL && n == NULL)
	   || (r->e == NULL && e == NULL))
	   return 0;

   if (n != NULL) {
	   BN_free(r->n);
	   r->n = n;
   }
   if (e != NULL) {
	   BN_free(r->e);
	   r->e = e;
   }
   if (d != NULL) {
	   BN_free(r->d);
	   r->d = d;
   }

   return 1;
}

int RSA_set0_factors(RSA *r, BIGNUM *p, BIGNUM *q)
{
   /* If the fields p and q in r are NULL, the corresponding input
	* parameters MUST be non-NULL.
	*/
   if ((r->p == NULL && p == NULL)
	   || (r->q == NULL && q == NULL))
	   return 0;

   if (p != NULL) {
	   BN_free(r->p);
	   r->p = p;
   }
   if (q != NULL) {
	   BN_free(r->q);
	   r->q = q;
   }

   return 1;
}

int RSA_set0_crt_params(RSA *r, BIGNUM *dmp1, BIGNUM *dmq1, BIGNUM *iqmp)
{
   /* If the fields dmp1, dmq1 and iqmp in r are NULL, the corresponding input
	* parameters MUST be non-NULL.
	*/
   if ((r->dmp1 == NULL && dmp1 == NULL)
	   || (r->dmq1 == NULL && dmq1 == NULL)
	   || (r->iqmp == NULL && iqmp == NULL))
	   return 0;

   if (dmp1 != NULL) {
	   BN_free(r->dmp1);
	   r->dmp1 = dmp1;
   }
   if (dmq1 != NULL) {
	   BN_free(r->dmq1);
	   r->dmq1 = dmq1;
   }
   if (iqmp != NULL) {
	   BN_free(r->iqmp);
	   r->iqmp = iqmp;
   }

   return 1;
}

void RSA_get0_key(const RSA *r,
				 const BIGNUM **n, const BIGNUM **e, const BIGNUM **d)
{
   if (n != NULL)
	   *n = r->n;
   if (e != NULL)
	   *e = r->e;
   if (d != NULL)
	   *d = r->d;
}

void RSA_get0_factors(const RSA *r, const BIGNUM **p, const BIGNUM **q)
{
   if (p != NULL)
	   *p = r->p;
   if (q != NULL)
	   *q = r->q;
}

void RSA_get0_crt_params(const RSA *r,
						const BIGNUM **dmp1, const BIGNUM **dmq1,
						const BIGNUM **iqmp)
{
   if (dmp1 != NULL)
	   *dmp1 = r->dmp1;
   if (dmq1 != NULL)
	   *dmq1 = r->dmq1;
   if (iqmp != NULL)
	   *iqmp = r->iqmp;
}

void DSA_get0_pqg(const DSA *d,
				 const BIGNUM **p, const BIGNUM **q, const BIGNUM **g)
{
   if (p != NULL)
	   *p = d->p;
   if (q != NULL)
	   *q = d->q;
   if (g != NULL)
	   *g = d->g;
}

int DSA_set0_pqg(DSA *d, BIGNUM *p, BIGNUM *q, BIGNUM *g)
{
   /* If the fields p, q and g in d are NULL, the corresponding input
	* parameters MUST be non-NULL.
	*/
   if ((d->p == NULL && p == NULL)
	   || (d->q == NULL && q == NULL)
	   || (d->g == NULL && g == NULL))
	   return 0;

   if (p != NULL) {
	   BN_free(d->p);
	   d->p = p;
   }
   if (q != NULL) {
	   BN_free(d->q);
	   d->q = q;
   }
   if (g != NULL) {
	   BN_free(d->g);
	   d->g = g;
   }

   return 1;
}

void DSA_get0_key(const DSA *d,
				 const BIGNUM **pub_key, const BIGNUM **priv_key)
{
   if (pub_key != NULL)
	   *pub_key = d->pub_key;
   if (priv_key != NULL)
	   *priv_key = d->priv_key;
}

int DSA_set0_key(DSA *d, BIGNUM *pub_key, BIGNUM *priv_key)
{
   /* If the field pub_key in d is NULL, the corresponding input
	* parameters MUST be non-NULL.  The priv_key field may
	* be left NULL.
	*/
   if (d->pub_key == NULL && pub_key == NULL)
	   return 0;

   if (pub_key != NULL) {
	   BN_free(d->pub_key);
	   d->pub_key = pub_key;
   }
   if (priv_key != NULL) {
	   BN_free(d->priv_key);
	   d->priv_key = priv_key;
   }

   return 1;
}

void DSA_SIG_get0(const DSA_SIG *sig, const BIGNUM **pr, const BIGNUM **ps)
{
   if (pr != NULL)
	   *pr = sig->r;
   if (ps != NULL)
	   *ps = sig->s;
}

int DSA_SIG_set0(DSA_SIG *sig, BIGNUM *r, BIGNUM *s)
{
   if (r == NULL || s == NULL)
	   return 0;
   BN_clear_free(sig->r);
   BN_clear_free(sig->s);
   sig->r = r;
   sig->s = s;
   return 1;
}

void ECDSA_SIG_get0(const ECDSA_SIG *sig, const BIGNUM **pr, const BIGNUM **ps)
{
   if (pr != NULL)
	   *pr = sig->r;
   if (ps != NULL)
	   *ps = sig->s;
}

int ECDSA_SIG_set0(ECDSA_SIG *sig, BIGNUM *r, BIGNUM *s)
{
   if (r == NULL || s == NULL)
	   return 0;
   BN_clear_free(sig->r);
   BN_clear_free(sig->s);
   sig->r = r;
   sig->s = s;
   return 1;
}

void DH_get0_pqg(const DH *dh,
				const BIGNUM **p, const BIGNUM **q, const BIGNUM **g)
{
   if (p != NULL)
	   *p = dh->p;
   if (q != NULL)
	   *q = dh->q;
   if (g != NULL)
	   *g = dh->g;
}

int DH_set0_pqg(DH *dh, BIGNUM *p, BIGNUM *q, BIGNUM *g)
{
   /* If the fields p and g in d are NULL, the corresponding input
	* parameters MUST be non-NULL.  q may remain NULL.
	*/
   if ((dh->p == NULL && p == NULL)
	   || (dh->g == NULL && g == NULL))
	   return 0;

   if (p != NULL) {
	   BN_free(dh->p);
	   dh->p = p;
   }
   if (q != NULL) {
	   BN_free(dh->q);
	   dh->q = q;
   }
   if (g != NULL) {
	   BN_free(dh->g);
	   dh->g = g;
   }

   if (q != NULL) {
	   dh->length = BN_num_bits(q);
   }

   return 1;
}

void DH_get0_key(const DH *dh, const BIGNUM **pub_key, const BIGNUM **priv_key)
{
   if (pub_key != NULL)
	   *pub_key = dh->pub_key;
   if (priv_key != NULL)
	   *priv_key = dh->priv_key;
}

int DH_set0_key(DH *dh, BIGNUM *pub_key, BIGNUM *priv_key)
{
   /* If the field pub_key in dh is NULL, the corresponding input
	* parameters MUST be non-NULL.  The priv_key field may
	* be left NULL.
	*/
   if (dh->pub_key == NULL && pub_key == NULL)
	   return 0;

   if (pub_key != NULL) {
	   BN_free(dh->pub_key);
	   dh->pub_key = pub_key;
   }
   if (priv_key != NULL) {
	   BN_free(dh->priv_key);
	   dh->priv_key = priv_key;
   }

   return 1;
}

int DH_set_length(DH *dh, long length)
{
   dh->length = length;
   return 1;
}

const unsigned char *EVP_CIPHER_CTX_iv(const EVP_CIPHER_CTX *ctx)
{
   return ctx->iv;
}

unsigned char *EVP_CIPHER_CTX_iv_noconst(EVP_CIPHER_CTX *ctx)
{
   return ctx->iv;
}

EVP_MD_CTX *EVP_MD_CTX_new(void)
{
   return OPENSSL_zalloc(sizeof(EVP_MD_CTX));
}

void EVP_MD_CTX_free(EVP_MD_CTX *ctx)
{
   EVP_MD_CTX_cleanup(ctx);
   OPENSSL_free(ctx);
}

RSA_METHOD *RSA_meth_dup(const RSA_METHOD *meth)
{
   RSA_METHOD *ret;

   ret = OPENSSL_malloc(sizeof(RSA_METHOD));

   if (ret != NULL) {
	   memcpy(ret, meth, sizeof(*meth));
	   ret->name = OPENSSL_strdup(meth->name);
	   if (ret->name == NULL) {
		   OPENSSL_free(ret);
		   return NULL;
	   }
   }

   return ret;
}

int RSA_meth_set1_name(RSA_METHOD *meth, const char *name)
{
   char *tmpname;

   tmpname = OPENSSL_strdup(name);
   if (tmpname == NULL) {
	   return 0;
   }

   OPENSSL_free((char *)meth->name);
   meth->name = tmpname;

   return 1;
}

int RSA_meth_set_priv_enc(RSA_METHOD *meth,
						 int (*priv_enc) (int flen, const unsigned char *from,
										  unsigned char *to, RSA *rsa,
										  int padding))
{
   meth->rsa_priv_enc = priv_enc;
   return 1;
}

int RSA_meth_set_priv_dec(RSA_METHOD *meth,
						 int (*priv_dec) (int flen, const unsigned char *from,
										  unsigned char *to, RSA *rsa,
										  int padding))
{
   meth->rsa_priv_dec = priv_dec;
   return 1;
}

int RSA_meth_set_finish(RSA_METHOD *meth, int (*finish) (RSA *rsa))
{
   meth->finish = finish;
   return 1;
}

void RSA_meth_free(RSA_METHOD *meth)
{
   if (meth != NULL) {
	   OPENSSL_free((char *)meth->name);
	   OPENSSL_free(meth);
   }
}

int RSA_bits(const RSA *r)
{
   return (BN_num_bits(r->n));
}

RSA *EVP_PKEY_get0_RSA(EVP_PKEY *pkey)
{
   if (pkey->type != EVP_PKEY_RSA) {
	   return NULL;
   }
   return pkey->pkey.rsa;
}

#endif

#endif
