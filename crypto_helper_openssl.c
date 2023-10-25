/* openssl based implementation of crypto functions
 *
 * Contributors can provide alternate implementations in future and make
 * changes to the makefile to compile/link against these alternate crypto
 * libraries. The same approach can also be used to support multiple
 * versions of openssl in cases where openssl makes API incompatibile
 * releases.
 */

#include "crypto_helper.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

static const EVP_MD* evp_md = NULL;

ngx_str_t* ngx_aws_auth__sign_sha256_hex(ngx_pool_t *pool, const ngx_str_t *blob,
    const ngx_str_t *signing_key) {

    unsigned int md_len;
    unsigned char md[EVP_MAX_MD_SIZE];
    ngx_str_t *const retval = ngx_palloc(pool, sizeof(ngx_str_t));

    if (evp_md == NULL) {
        evp_md = EVP_sha256();
    }

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, evp_md, NULL);
    EVP_DigestUpdate(mdctx, blob->data, blob->len);
    EVP_DigestFinal_ex(mdctx, md, &md_len);
    EVP_MD_CTX_free(mdctx);

    retval->data = ngx_palloc(pool, md_len * 2 + 1);
    retval->len = md_len * 2;
    ngx_hex_dump(retval->data, md, md_len);
    return retval;
}

ngx_str_t* ngx_aws_auth__hash_sha256(ngx_pool_t *pool, const ngx_str_t *blob) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    ngx_str_t *const retval = ngx_palloc(pool, sizeof(ngx_str_t));

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(mdctx, blob->data, blob->len);
    EVP_DigestFinal_ex(mdctx, hash, NULL);
    EVP_MD_CTX_free(mdctx);

    retval->data = ngx_palloc(pool, SHA256_DIGEST_LENGTH * 2 + 1);
    retval->len = SHA256_DIGEST_LENGTH * 2;
    ngx_hex_dump(retval->data, hash, sizeof(hash));
    return retval;
}
