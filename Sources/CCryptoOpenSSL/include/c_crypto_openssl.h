#ifndef C_CRYPTO_OPENSSL_H
#define C_CRYPTO_OPENSSL_H

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/pkcs12.h>
#include <openssl/x509v3.h>


int crypto_RSA_set(RSA *r, BIGNUM *n, BIGNUM *e, BIGNUM *d) {
#if (OPENSSL_VERSION_NUMBER < 0x10100000L) || defined(LIBRESSL_VERSION_NUMBER)
    r->n = n;
    r->e = e;
    r->d = d;
    return 0;
#else
    return RSA_set0_key(r, n, e, d);
#endif
}

#if (OPENSSL_VERSION_NUMBER < 0x10100000L) || defined(LIBRESSL_VERSION_NUMBER)
EVP_MD_CTX *EVP_MD_CTX_new(void) {
    return EVP_MD_CTX_create();
}

void EVP_MD_CTX_free(EVP_MD_CTX *ctx) {
    EVP_MD_CTX_cleanup(ctx);
    free(ctx);
}

HMAC_CTX *HMAC_CTX_new(void) {
    HMAC_CTX *ptr = malloc(sizeof(HMAC_CTX));
    HMAC_CTX_init(ptr);
    return ptr;
}

void HMAC_CTX_free(HMAC_CTX *ctx) {
    HMAC_CTX_cleanup(ctx);
    free(ctx);
}
#endif

#endif
