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

    ngx_str_t bucket, date, hash, endpoint, token;
    struct AwsCanonicalHeaderDetails retval;

    bucket.data = "bugait"; bucket.len = 6;
    date.data = "20160221T063112Z"; date.len = 16;
    hash.data = "f0e4c2f76c58916ec258f246851bea091d14d4247a2fc3e18694461b1816e13b"; hash.len = 64;
    endpoint.data = "s3.amazonaws.com"; endpoint.len = 16;
    token.data = ""; token.len=0;

    retval = ngx_aws_auth__canonize_headers(pool, NULL, &bucket, &date, &hash, &endpoint, &token);
    assert_string_equal(retval.canon_header_str->data,
        "host:bugait.s3.amazonaws.com\nx-amz-content-sha256:f0e4c2f76c58916ec258f246851bea091d14d4247a2fc3e18694461b1816e13b\nx-amz-date:20160221T063112Z\n");
}

static void canon_header_string_with_security_token(void **state) {
    (void) state; /* unused */

    ngx_str_t bucket, date, hash, endpoint;
    struct AwsCanonicalHeaderDetails retval;

    bucket.data = "bugait"; bucket.len = 6;
    date.data = "20160221T063112Z"; date.len = 16;
    hash.data = "f0e4c2f76c58916ec258f246851bea091d14d4247a2fc3e18694461b1816e13b"; hash.len = 64;
    endpoint.data = "s3.amazonaws.com"; endpoint.len = 16;
    ngx_str_t token = ngx_string("FwoGZXIvYXdzEGIaDGSJdkH/F9YHt9L5GiKsAewV1KBD2uklClV8PHR7yW9cPh9LiqSsJGx0yZF15enXMwsOUqgIbxj0ok7i4uML4P+EabLAvLPmW2Nmvax+h8kITdit0eABAvlE6yJLi2+din9xevrKOB+Q/wM1YDAiR1LaC4JZj2TQj9nzSIQ2rLwq/8qwxnBrVdekzh3ld8eKJG3BUKWJEXYE/XScaYB/nOY6gH2tsixksfbfb+e0cqLkPCXv21DOSLLejYAonoWS8QUyLRVTzPmq6av4/UNb6vm2GpPQxTP+PW8aH6UHLDWtn1EM9qe6ot3uLjDV+3spbg==");

    retval = ngx_aws_auth__canonize_headers(pool, NULL, &bucket, &date, &hash, &endpoint, &token);
    assert_string_equal(retval.canon_header_str->data,
        "host:bugait.s3.amazonaws.com\nx-amz-content-sha256:f0e4c2f76c58916ec258f246851bea091d14d4247a2fc3e18694461b1816e13b\nx-amz-date:20160221T063112Z\nx-amz-security-token:FwoGZXIvYXdzEGIaDGSJdkH/F9YHt9L5GiKsAewV1KBD2uklClV8PHR7yW9cPh9LiqSsJGx0yZF15enXMwsOUqgIbxj0ok7i4uML4P+EabLAvLPmW2Nmvax+h8kITdit0eABAvlE6yJLi2+din9xevrKOB+Q/wM1YDAiR1LaC4JZj2TQj9nzSIQ2rLwq/8qwxnBrVdekzh3ld8eKJG3BUKWJEXYE/XScaYB/nOY6gH2tsixksfbfb+e0cqLkPCXv21DOSLLejYAonoWS8QUyLRVTzPmq6av4/UNb6vm2GpPQxTP+PW8aH6UHLDWtn1EM9qe6ot3uLjDV+3spbg==\n");
}

static void signed_headers(void **state) {
    (void) state; /* unused */

    ngx_str_t bucket, date, hash, endpoint, token;
    struct AwsCanonicalHeaderDetails retval;

    bucket.data = "bugait"; bucket.len = 6;
    date.data = "20160221T063112Z"; date.len = 16;
    hash.data = "f0e4c2f76c58916ec258f246851bea091d14d4247a2fc3e18694461b1816e13b"; hash.len = 64;
    endpoint.data = "s3.amazonaws.com"; endpoint.len = 16;
    token.data = ""; token.len = 0;

    retval = ngx_aws_auth__canonize_headers(pool, NULL, &bucket, &date, &hash, &endpoint, &token);
    assert_string_equal(retval.signed_header_names->data, "host;x-amz-content-sha256;x-amz-date");
}

static void signed_headers_with_security_token(void **state) {
    (void) state; /* unused */

    ngx_str_t bucket, date, hash, endpoint;
    struct AwsCanonicalHeaderDetails retval;

    bucket.data = "bugait"; bucket.len = 6;
    date.data = "20160221T063112Z"; date.len = 16;
    hash.data = "f0e4c2f76c58916ec258f246851bea091d14d4247a2fc3e18694461b1816e13b"; hash.len = 64;
    endpoint.data = "s3.amazonaws.com"; endpoint.len = 16;
    ngx_str_t token = ngx_string("FwoGZXIvYXdzEGIaDGSJdkH/F9YHt9L5GiKsAewV1KBD2uklClV8PHR7yW9cPh9LiqSsJGx0yZF15enXMwsOUqgIbxj0ok7i4uML4P+EabLAvLPmW2Nmvax+h8kITdit0eABAvlE6yJLi2+din9xevrKOB+Q/wM1YDAiR1LaC4JZj2TQj9nzSIQ2rLwq/8qwxnBrVdekzh3ld8eKJG3BUKWJEXYE/XScaYB/nOY6gH2tsixksfbfb+e0cqLkPCXv21DOSLLejYAonoWS8QUyLRVTzPmq6av4/UNb6vm2GpPQxTP+PW8aH6UHLDWtn1EM9qe6ot3uLjDV+3spbg==");

    retval = ngx_aws_auth__canonize_headers(pool, NULL, &bucket, &date, &hash, &endpoint, &token);
    assert_string_equal(retval.signed_header_names->data, "host;x-amz-content-sha256;x-amz-date;x-amz-security-token");
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
    const ngx_str_t token = ngx_string("");

	struct AwsCanonicalRequestDetails result;
	ngx_http_request_t request;

	request.uri = url;
	request.method_name = method;
	request.args = EMPTY_STRING;
  request.connection = NULL;

	result = ngx_aws_auth__make_canonical_request(pool, &request, &bucket, &aws_date, &endpoint, &token);
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

static void canonical_request_sans_qs_with_security_token(void **state) {
    (void) state; /* unused */
	const ngx_str_t bucket = ngx_string("example");
	const ngx_str_t aws_date = ngx_string("20160221T063112Z");
	const ngx_str_t url = ngx_string("/");
	const ngx_str_t method = ngx_string("GET");
    const ngx_str_t endpoint = ngx_string("s3.amazonaws.com");
    const ngx_str_t token = ngx_string("FwoGZXIvYXdzEGIaDGSJdkH/F9YHt9L5GiKsAewV1KBD2uklClV8PHR7yW9cPh9LiqSsJGx0yZF15enXMwsOUqgIbxj0ok7i4uML4P+EabLAvLPmW2Nmvax+h8kITdit0eABAvlE6yJLi2+din9xevrKOB+Q/wM1YDAiR1LaC4JZj2TQj9nzSIQ2rLwq/8qwxnBrVdekzh3ld8eKJG3BUKWJEXYE/XScaYB/nOY6gH2tsixksfbfb+e0cqLkPCXv21DOSLLejYAonoWS8QUyLRVTzPmq6av4/UNb6vm2GpPQxTP+PW8aH6UHLDWtn1EM9qe6ot3uLjDV+3spbg==");

	struct AwsCanonicalRequestDetails result;
	ngx_http_request_t request;

	request.uri = url;
	request.method_name = method;
	request.args = EMPTY_STRING;
  request.connection = NULL;

	result = ngx_aws_auth__make_canonical_request(pool, &request, &bucket, &aws_date, &endpoint, &token);
	assert_string_equal(result.canon_request->data, "GET\n\
/\n\
\n\
host:example.s3.amazonaws.com\n\
x-amz-content-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n\
x-amz-date:20160221T063112Z\n\
\n\
host;x-amz-content-sha256;x-amz-date;x-amz-security-token\n\
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

static void basic_get_signature(void **state) {
    (void) state; /* unused */

	const ngx_str_t url = ngx_string("/");
	const ngx_str_t method = ngx_string("GET");
	const ngx_str_t key_scope = ngx_string("20150830/us-east-1/service/aws4_request");
	const ngx_str_t bucket = ngx_string("example");
    const ngx_str_t endpoint = ngx_string("s3.amazonaws.com");
    const ngx_str_t security_token = ngx_string("");

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
								&signing_key, &key_scope, &bucket, &endpoint, &security_token);
	assert_string_equal(result.signature->data, "4ed4ec875ff02e55c7903339f4f24f8780b986a9cc9eff03f324d31da6a57690");
}

static void basic_get_signature_with_security_token(void **state) {
    (void) state; /* unused */

	const ngx_str_t url = ngx_string("/");
	const ngx_str_t method = ngx_string("GET");
	const ngx_str_t key_scope = ngx_string("20150830/us-east-1/service/aws4_request");
	const ngx_str_t bucket = ngx_string("example");
    const ngx_str_t endpoint = ngx_string("s3.amazonaws.com");
    const ngx_str_t security_token = ngx_string("IQoJb3JpZ2luX2VjEGsaCXVzLWVhc3QtMSJGMEQCID6TMGyw8dapyAyoqK7nRRsWfs2UcGZlNge6gD67WouHAiBbxqJ6X61HRCges6DWx538dZlZnGDRtKM1dUcIi1HllirzAwjz//////////8BEAAaDDg0NzEzMDIwNzA1MCIMQXKhCFqhuwfirKHmKscD2kA3ab0pQdqJFH7Q5X5XX5OaHyiHkwAeLNyUKK+vwafYgixxMZqVHxyeZNWkFWMPbiHfW4TVEeG6D2/jG1QGOwbLJqTdkvrJqUoLU5bfqxdYIGyDO14k6q39NCg0EpXen54uIwRrDgPQZenPDASZy+NKnNnOnQ3EbJgXFOlxAQWLcUwP5Oab0s4BxLZ4F7c2DcCMJLLCpfIr0s9sYXM3cv6rDac/agjazkIooe3JfXOSqKQK9CBLFfYqXh+/pg4VwDJ6Y64Db1imRDdXZr98okg6P6+IXerOYnw9LilKnlLSfP9A0Hx4zkMToGJeNZVLhvQXfK23Ohv4k3ZgxS8WNlvGtyh13j7xEpmCLL1MbAMXQin8Zx8hePNdfH0+oPrAEHKORmYhF7Npp97vi4fZn4rJb0wyR+tzk4BUwU8bxsqo2QdNXj3JdBCeJtbcFOTkR9VRDNFKuxcCJ4YyHwSXegpRg64D/+eNvXEai74BR0CMlXD7ixo25zM+1qhAO8wtsDRZkuLq08KkccWFMJ7mtd5hF3a44qUtjzRnW4Oirt6HAegaotLvMsWxhlKEm6THfPN0B3GqVN4dx8I2/hlcRCoA/ytapSkwutyX8QU68AETTkURQmWBx8MMe3+fdNc6o6b9TgXXxeCMEnTHwF3lFaQIzI3v+V4WHF7IEU3FiH8Qc489d64D48l71akbXN89nArzgsKXB2MmmV2lM9YeCOnsKjmX8KDM0SXiEL2zF3sXQ6cpwXdHRFLWdM5neZxBxT2NXoCh8Xjx2VEzTJ20vLfq0qS/1WmOvzxa1Z4B4GJUx9Gho/2iLHXvrBh93kk72KbzHP15ZsKixGkF4CP2qqluraym5Mv2IXV1vZhipVedNBFCngOR603MyERCw0tKnYXuduDnvEV0J9Hgf+fyeiXSXH34K5Fq525/XZDKMm4=");

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
								&signing_key, &key_scope, &bucket, &endpoint, &security_token);
	assert_string_equal(result.signature->data, "c0979d16460957b789c4b31048e6e008e3888666e227e749d1a0bc5d5d8ab175");
}

int main() {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(null_test_success),
        cmocka_unit_test(x_amz_date),
        cmocka_unit_test(host_header_ctor),
        cmocka_unit_test(hmac_sha256),
        cmocka_unit_test(sha256),
        cmocka_unit_test(canon_header_string),
        cmocka_unit_test(canon_header_string_with_security_token),
        cmocka_unit_test(canonical_qs_empty),
        cmocka_unit_test(canonical_qs_single_arg),
        cmocka_unit_test(canonical_qs_two_arg_reverse),
        cmocka_unit_test(canonical_qs_subrequest),
        cmocka_unit_test(canonical_url_sans_qs),
        cmocka_unit_test(canonical_url_with_qs),
        cmocka_unit_test(canonical_url_with_special_chars),
        cmocka_unit_test(signed_headers),
        cmocka_unit_test(signed_headers_with_security_token),
        cmocka_unit_test(canonical_request_sans_qs),
        cmocka_unit_test(basic_get_signature),
        cmocka_unit_test(basic_get_signature_with_security_token),
    };

	pool = ngx_create_pool(1000000, NULL);

	return cmocka_run_group_tests(tests, NULL, NULL);
}
