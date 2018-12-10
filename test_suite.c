#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>

#include "vendor/cmocka/include/cmocka.h"

#include "aws_functions.h"

ngx_pool_t *pool;

static void assert_ngx_string_equal(ngx_str_t a, ngx_str_t b) {
	int len = a.len < b.len ?  a.len : b.len;
    assert_memory_equal(a.data, b.data, len);
}

static void null_test_success(void **state) {
    (void) state; /* unused */
}

static void host_header_ctor(void **state) {
	ngx_str_t bucket;
	const ngx_str_t* host;

    (void) state; /* unused */

	bucket.data = "test-es-three";
	bucket.len = strlen(bucket.data);
	host = ngx_aws_auth__host_from_bucket(pool, &bucket);
	assert_string_equal("test-es-three.s3.amazonaws.com", host->data);

	bucket.data = "complex.sub.domain.test";
	bucket.len = strlen(bucket.data);
	host = ngx_aws_auth__host_from_bucket(pool, &bucket);
	assert_string_equal("complex.sub.domain.test.s3.amazonaws.com", host->data);
}

static void x_amz_date(void **state) {
	time_t t;
	const ngx_str_t* date;

    (void) state; /* unused */

	t = 1;
	date = ngx_aws_auth__compute_request_time(pool, &t);
	assert_int_equal(date->len, 16);
	assert_string_equal("19700101T000001Z", date->data);

	t = 1456036272;
	date = ngx_aws_auth__compute_request_time(pool, &t);
	assert_int_equal(date->len, 16);
	assert_string_equal("20160221T063112Z", date->data);
}


static void hmac_sha256(void **state) {
    ngx_str_t key;
    ngx_str_t text;
    ngx_str_t* hash;
    (void) state; /* unused */

    key.data = "abc"; key.len=3;
    text.data = "asdf"; text.len=4;
    hash = ngx_aws_auth__sign_sha256_hex(pool, &text, &key);
	assert_int_equal(64, hash->len);
	assert_string_equal("07e434c45d15994e620bf8e43da6f652d331989be1783cdfcc989ddb0a2358e2", hash->data);

    key.data = "\011\001\057asf"; key.len=6;
    text.data = "lorem ipsum"; text.len=11;
    hash = ngx_aws_auth__sign_sha256_hex(pool, &text, &key);
	assert_int_equal(64, hash->len);
	assert_string_equal("827ce31c45e77292af25fef980c3e7afde23abcde622ecd8e82e1be6dd94fad3", hash->data);
}


static void sha256(void **state) {
    ngx_str_t text;
    ngx_str_t* hash;
    (void) state; /* unused */

    text.data = "asdf"; text.len=4;
    hash = ngx_aws_auth__hash_sha256(pool, &text);
	assert_int_equal(64, hash->len);
	assert_string_equal("f0e4c2f76c58916ec258f246851bea091d14d4247a2fc3e18694461b1816e13b", hash->data);

    text.len=0;
    hash = ngx_aws_auth__hash_sha256(pool, &text);
	assert_int_equal(64, hash->len);
	assert_string_equal("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", hash->data);
}

static void canon_header_string(void **state) {
    (void) state; /* unused */

    ngx_str_t bucket, date, hash, endpoint;
    struct AwsCanonicalHeaderDetails retval;

    bucket.data = "bugait"; bucket.len = 6;
    date.data = "20160221T063112Z"; date.len = 16;
    hash.data = "f0e4c2f76c58916ec258f246851bea091d14d4247a2fc3e18694461b1816e13b"; hash.len = 64;
    endpoint.data = "s3.amazonaws.com"; endpoint.len = 16;

    retval = ngx_aws_auth__canonize_headers(pool, NULL, &bucket, &date, &hash, &endpoint);
    assert_string_equal(retval.canon_header_str->data,
        "host:bugait.s3.amazonaws.com\nx-amz-content-sha256:f0e4c2f76c58916ec258f246851bea091d14d4247a2fc3e18694461b1816e13b\nx-amz-date:20160221T063112Z\n");
}

static void signed_headers(void **state) {
    (void) state; /* unused */

    ngx_str_t bucket, date, hash, endpoint;
    struct AwsCanonicalHeaderDetails retval;

    bucket.data = "bugait"; bucket.len = 6;
    date.data = "20160221T063112Z"; date.len = 16;
    hash.data = "f0e4c2f76c58916ec258f246851bea091d14d4247a2fc3e18694461b1816e13b"; hash.len = 64;
    endpoint.data = "s3.amazonaws.com"; endpoint.len = 16;

    retval = ngx_aws_auth__canonize_headers(pool, NULL, &bucket, &date, &hash, &endpoint);
    assert_string_equal(retval.signed_header_names->data, "host;x-amz-content-sha256;x-amz-date");
}

static void canonical_qs_empty(void **state) {
    (void) state; /* unused */
	ngx_http_request_t request;
	request.args = EMPTY_STRING;
  request.connection = NULL;

	const ngx_str_t *canon_qs = ngx_aws_auth__canonize_query_string(pool, &request);
    assert_ngx_string_equal(*canon_qs, EMPTY_STRING);
}

static void canonical_qs_single_arg(void **state) {
    (void) state; /* unused */
	ngx_http_request_t request;
	ngx_str_t args = ngx_string("arg1=val1");
	request.args = args;
  request.connection = NULL;

	const ngx_str_t *canon_qs = ngx_aws_auth__canonize_query_string(pool, &request);
    assert_ngx_string_equal(*canon_qs, args);
}

static void canonical_qs_two_arg_reverse(void **state) {
    (void) state; /* unused */
	ngx_http_request_t request;
	ngx_str_t args = ngx_string("brg1=val2&arg1=val1");
	ngx_str_t cargs = ngx_string("arg1=val1&brg1=val");
	request.args = args;
  request.connection = NULL;

	const ngx_str_t *canon_qs = ngx_aws_auth__canonize_query_string(pool, &request);
    assert_ngx_string_equal(*canon_qs, cargs);
}

static void canonical_qs_subrequest(void **state) {
    (void) state; /* unused */
	ngx_http_request_t request;
	ngx_str_t args = ngx_string("acl");
	ngx_str_t cargs = ngx_string("acl=");
	request.args = args;
  request.connection = NULL;

	const ngx_str_t *canon_qs = ngx_aws_auth__canonize_query_string(pool, &request);
    assert_ngx_string_equal(*canon_qs, cargs);
}

static void canonical_url_sans_qs(void **state) {
    (void) state; /* unused */

	ngx_http_request_t request;
	ngx_str_t url = ngx_string("foo.php");
	request.uri = url;
	request.uri_start = request.uri.data;
	request.args_start = url.data + url.len;
	request.args = EMPTY_STRING;
  request.connection = NULL;

	const ngx_str_t *canon_url = ngx_aws_auth__canon_url(pool, &request);
    assert_int_equal(canon_url->len, url.len);
    assert_ngx_string_equal(*canon_url, url);
}

static void canonical_url_with_qs(void **state) {
    (void) state; /* unused */

	ngx_http_request_t request;
	ngx_str_t url = ngx_string("foo.php?arg1=var1");
	ngx_str_t curl = ngx_string("foo.php");

	ngx_str_t args;
	args.data = url.data + 8;
	args.len = 9;

	request.uri = url;
	request.uri_start = request.uri.data;
	request.args_start = url.data + 8;
	request.args = args;
  request.connection = NULL;

	const ngx_str_t *canon_url = ngx_aws_auth__canon_url(pool, &request);
    assert_int_equal(canon_url->len, curl.len);
    assert_ngx_string_equal(*canon_url, curl);
}

static void canonical_url_with_special_chars(void **state) {
  (void) state; /* unused */

  ngx_str_t url = ngx_string("f&o@o/b ar.php");
  ngx_str_t expected_canon_url = ngx_string("f%26o%40o/b%20ar.php");

  ngx_http_request_t request;
  request.uri = url;
  request.uri_start = request.uri.data;
  request.args_start = url.data + url.len;
  request.args = EMPTY_STRING;
  request.connection = NULL;

  const ngx_str_t *canon_url = ngx_aws_auth__canon_url(pool, &request);
    assert_int_equal(canon_url->len, expected_canon_url.len);
    assert_ngx_string_equal(*canon_url, expected_canon_url);
}

static void canonical_request_sans_qs(void **state) {
    (void) state; /* unused */
	const ngx_str_t bucket = ngx_string("example");
	const ngx_str_t aws_date = ngx_string("20160221T063112Z");
	const ngx_str_t url = ngx_string("/");
	const ngx_str_t method = ngx_string("GET");
  const ngx_str_t endpoint = ngx_string("s3.amazonaws.com");

	struct AwsCanonicalRequestDetails result;
	ngx_http_request_t request;

	request.uri = url;
	request.method_name = method;
	request.args = EMPTY_STRING;
  request.connection = NULL;

	result = ngx_aws_auth__make_canonical_request(pool, &request, &bucket, &aws_date, &endpoint);
	assert_string_equal(result.canon_request->data, "GET\n\
/\n\
\n\
host:example.s3.amazonaws.com\n\
x-amz-content-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n\
x-amz-date:20160221T063112Z\n\
\n\
host;x-amz-content-sha256;x-amz-date\n\
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

static void basic_get_signature(void **state) {
    (void) state; /* unused */

	const ngx_str_t url = ngx_string("/");
	const ngx_str_t method = ngx_string("GET");
	const ngx_str_t key_scope = ngx_string("20150830/us-east-1/service/aws4_request");
	const ngx_str_t bucket = ngx_string("example");
  const ngx_str_t endpoint = ngx_string("s3.amazonaws.com");

	ngx_str_t signing_key, signing_key_b64e = ngx_string("k4EntTNoEN22pdavRF/KyeNx+e1BjtOGsCKu2CkBvnU=");
	ngx_http_request_t request;

	request.start_sec = 1440938160; /* 20150830T123600Z */
	request.uri = url;
	request.method_name = method;
	request.args = EMPTY_STRING;
  request.connection = NULL;

	signing_key.len = 64;
	signing_key.data = ngx_palloc(pool, signing_key.len );
	ngx_decode_base64(&signing_key, &signing_key_b64e);

	struct AwsSignedRequestDetails result = ngx_aws_auth__compute_signature(pool, &request,
								&signing_key, &key_scope, &bucket, &endpoint);
	assert_string_equal(result.signature->data, "4ed4ec875ff02e55c7903339f4f24f8780b986a9cc9eff03f324d31da6a57690");
}

int main() {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(null_test_success),
        cmocka_unit_test(x_amz_date),
        cmocka_unit_test(host_header_ctor),
        cmocka_unit_test(hmac_sha256),
        cmocka_unit_test(sha256),
        cmocka_unit_test(canon_header_string),
        cmocka_unit_test(canonical_qs_empty),
        cmocka_unit_test(canonical_qs_single_arg),
        cmocka_unit_test(canonical_qs_two_arg_reverse),
        cmocka_unit_test(canonical_qs_subrequest),
        cmocka_unit_test(canonical_url_sans_qs),
        cmocka_unit_test(canonical_url_with_qs),
        cmocka_unit_test(canonical_url_with_special_chars),
        cmocka_unit_test(signed_headers),
        cmocka_unit_test(canonical_request_sans_qs),
        cmocka_unit_test(basic_get_signature),
    };

	pool = ngx_create_pool(1000000, NULL);

	return cmocka_run_group_tests(tests, NULL, NULL);
}
