/* openssl based implementation of crypto functions
 *
 * Contributors can provide alternate implementations in future and make
 * changes to the makefile to compile/link against these alternate crypto
 * libraries. The same approach can also be used to support multiple
 * versions of openssl in cases where openssl makes API incompatibile
 * releases.
 */

#include "crypto_helper.h"

#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

static const EVP_MD* evp_md = NULL;

ngx_str_t* ngx_aws_auth__sign_sha256_hex(ngx_pool_t *pool, const ngx_str_t *blob,
    const ngx_str_t *signing_key) {

    unsigned int      md_len;
    unsigned char     md[EVP_MAX_MD_SIZE];
	ngx_str_t *const retval = ngx_palloc(pool, sizeof(ngx_str_t));

    if (evp_md==NULL) {
       evp_md = EVP_sha256();
    }

    HMAC(evp_md, signing_key->data, signing_key->len, blob->data, blob->len, md, &md_len);
	retval->data = ngx_palloc(pool, md_len * 2 + 1);
	retval->len = md_len * 2;
	ngx_hex_dump(retval->data, md, md_len);
	return retval;
}

ngx_str_t* ngx_aws_auth__hash_sha256(ngx_pool_t *pool, const ngx_str_t *blob) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
	ngx_str_t *const retval = ngx_palloc(pool, sizeof(ngx_str_t));

    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, blob->data, blob->len);
    SHA256_Final(hash, &sha256);

    retval->data = ngx_palloc(pool, SHA256_DIGEST_LENGTH * 2 + 1);
    retval->len = SHA256_DIGEST_LENGTH * 2;
	ngx_hex_dump(retval->data, hash, sizeof(hash));
	return retval;
}
