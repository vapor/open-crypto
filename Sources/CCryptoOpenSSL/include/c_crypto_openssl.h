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

#if (OPENSSL_VERSION_NUMBER < 0x10100000L) || defined(LIBRESSL_VERSION_NUMBER)
EVP_MD_CTX *EVP_MD_CTX_new() {
    return EVP_MD_CTX_create();
}

int EVP_MD_CTX_free(EVP_MD_CTX *ctx) {
    return EVP_MD_CTX_cleanup(ctx);
}

void RSA_set0_key(RSA *rsa, BIGNUM *n, BIGNUM *e, BIGNUM *d) {
    rsa->n = n;
    rsa->e = e;
    rsa-> d = d;
}

HMAC_CTX *HMAC_CTX_new() {
    HMAC_CTX *ptr = malloc(sizeof(HMAC_CTX));
    HMAC_CTX_init(ptr);
    return ptr;
}

void HMAC_CTX_free(HMAC_CTX *ptr) {
    HMAC_CTX_cleanup(ptr);
    free(ptr);
}
#endif

#endif
