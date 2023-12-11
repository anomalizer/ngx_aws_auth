#!/usr/bin/env python
from datetime import datetime
from hashlib import sha1, sha256
import hmac
import base64
import sys
from xml.dom.minidom import parseString
import unittest

try:
    from urllib.request import Request, urlopen, HTTPError  # Python 3
except:
    from urllib2 import Request, urlopen, HTTPError  # Python 2

'''

CanonicalRequest
================
<HTTPMethod>\n
<CanonicalURI>\n
<CanonicalQueryString>\n
<CanonicalHeaders>\n
<SignedHeaders>\n
<HashedPayload>



String to Sign
==============
"AWS4-HMAC-SHA256" + "\n" +
timeStampISO8601Format + "\n" +
<Scope> + "\n" +
Hex(SHA256Hash(<CanonicalRequest>))


SigningKey
==========
DateKey              = HMAC-SHA256("AWS4"+"<SecretAccessKey>", "<YYYYMMDD>")
DateRegionKey        = HMAC-SHA256(<DateKey>, "<aws-region>")
DateRegionServiceKey = HMAC-SHA256(<DateRegionKey>, "<aws-service>")
SigningKey           = HMAC-SHA256(<DateRegionServiceKey>, "aws4_request")



HMAC-SHA256(SigningKey, StringToSign)


'''

def long_date(yyyymmdd):
    return yyyymmdd+'T000000Z'


def canon_querystring(qs_map):
    return {'cqs':'', 'qsmap':{}} # TODO: impl


def make_headers(req_time, bucket, aws_headers, content_hash, security_token):
    headers = []
    headers.append(['x-amz-content-sha256', content_hash])
    headers.append(['x-amz-date', req_time])
    headers.append(['Host', '%s.s3.amazonaws.com' % (bucket)])
    if security_token:
        headers.append(['x-amz-security-token', security_token])

    hmap = {}
    for x in headers:
        x[0] = x[0].lower()
        x[1] = x[1].strip()
        hmap[x[0]] = x[1]

    headers.sort(key =lambda x:x[0])

    signed_headers = ';'.join([x[0] for x in headers])
    canon_headers = ''
    for h in [':'.join(x) for x in headers]:
        canon_headers = '%s%s\n' % (canon_headers, h)

    return {'hmap': hmap, 'sh': signed_headers, 'ch': canon_headers }


def canon_request(req_time, bucket, url, qs_map, token, aws_headers):
    qs = canon_querystring(qs_map)
    payload_hash = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' #hardcoded
    header_info = make_headers(req_time, bucket, None, payload_hash, token)
    cr = "\n".join(('GET', url, qs['cqs'], header_info['ch'], header_info['sh'], payload_hash)) # hardcoded method
    print cr

    return {'cr_str': cr, 'headers': header_info['hmap'], 'qs': qs, 'sh': header_info['sh']}


def sign_body(body=None):
    return 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' # TODO: fix hardcoding


def get_scope(dt, region):
    return '%s/%s/s3/aws4_request' % (dt, region)

def str_to_sign_v4(req_time, scope, bucket, url, qs_map, token, aws_headers):
    cr_info = canon_request(req_time, bucket, url, qs_map, token, aws_headers)
    h265 = sha256()
    h265.update(cr_info['cr_str'])
    hd = h265.hexdigest()
    s2s = "\n".join(('AWS4-HMAC-SHA256', cr_info['headers']['x-amz-date'], scope, hd))
    print s2s
    return {'s2s': s2s, 'headers': cr_info['headers'], 'qs':cr_info['qs'], 'scope': scope, 'sh': cr_info['sh']}

def sign(req_time, access_id, key, scope, bucket, url, qs_map, token, aws_headers):
    s2s = str_to_sign_v4(req_time, scope, bucket, url, qs_map, token, aws_headers)
    retval = hmac.new(key, s2s['s2s'], sha256)
    sig = retval.hexdigest()
    auth_header = 'AWS4-HMAC-SHA256 Credential=%s/%s,SignedHeaders=%s,Signature=%s' % (
        access_id, s2s['scope'], s2s['sh'], sig)
    s2s['headers']['Authorization'] = auth_header
    return {'headers': s2s['headers'], 'qs':s2s['qs'], 'sig': sig}


def get_data(req_time, access_id, key, scope, bucket, url, qs_map, token, aws_headers):
    s = sign(req_time, access_id, key, scope, bucket, url, qs_map, token, aws_headers)
    rurl = "https://%s.s3.amazonaws.com%s" % (bucket, url)
#    print rurl
#    print s
    q = Request(rurl)
    for k,v in s['headers'].iteritems():
        q.add_header(k, v)
    try:
        return urlopen(q).read()
    except HTTPError as e:
        exml = "".join(e.readlines())
        xml = parseString(exml)
        print 'Got exception\n-------------------------\n\n', xml.toprettyxml()

'''
if __name__ == '__main__':
    aid = sys.argv[1]
    b64_key = sys.argv[2]
    scope = sys.argv[3]
    bucket = sys.argv[4]
    path = sys.argv[5]
    token = sys.argv[6]
    request_time = datetime.utcnow().strftime('%Y%m%dT%H%M%SZ') if len(sys.argv) == 7 else sys.argv[7]
    print "Request time is %s" % request_time
    print get_data(request_time, aid, base64.b64decode(b64_key), scope, bucket, path, {}, token, {})
'''

class TestStringMethods(unittest.TestCase):
    def test_simple_get(self):
        now = '20150830T123600Z'
        key = base64.b64decode('k4EntTNoEN22pdavRF/KyeNx+e1BjtOGsCKu2CkBvnU=')
        aid = 'AKIDEXAMPLE'
        scope = '20150830/us-east-1/service/aws4_request'
        s = sign(now, aid, key, scope, 'example', '/', {}, None, {})
        self.assertEqual(s['sig'], '4ed4ec875ff02e55c7903339f4f24f8780b986a9cc9eff03f324d31da6a57690')

    def test_simple_get_with_security_token(self):
        now = '20150830T123600Z'
        key = base64.b64decode('k4EntTNoEN22pdavRF/KyeNx+e1BjtOGsCKu2CkBvnU=')
        aid = 'AKIDEXAMPLE'
        scope = '20150830/us-east-1/service/aws4_request'
        token = 'IQoJb3JpZ2luX2VjEGsaCXVzLWVhc3QtMSJGMEQCID6TMGyw8dapyAyoqK7nRRsWfs2UcGZlNge6gD67WouHAiBbxqJ6X61HRCges6DWx538dZlZnGDRtKM1dUcIi1HllirzAwjz//////////8BEAAaDDg0NzEzMDIwNzA1MCIMQXKhCFqhuwfirKHmKscD2kA3ab0pQdqJFH7Q5X5XX5OaHyiHkwAeLNyUKK+vwafYgixxMZqVHxyeZNWkFWMPbiHfW4TVEeG6D2/jG1QGOwbLJqTdkvrJqUoLU5bfqxdYIGyDO14k6q39NCg0EpXen54uIwRrDgPQZenPDASZy+NKnNnOnQ3EbJgXFOlxAQWLcUwP5Oab0s4BxLZ4F7c2DcCMJLLCpfIr0s9sYXM3cv6rDac/agjazkIooe3JfXOSqKQK9CBLFfYqXh+/pg4VwDJ6Y64Db1imRDdXZr98okg6P6+IXerOYnw9LilKnlLSfP9A0Hx4zkMToGJeNZVLhvQXfK23Ohv4k3ZgxS8WNlvGtyh13j7xEpmCLL1MbAMXQin8Zx8hePNdfH0+oPrAEHKORmYhF7Npp97vi4fZn4rJb0wyR+tzk4BUwU8bxsqo2QdNXj3JdBCeJtbcFOTkR9VRDNFKuxcCJ4YyHwSXegpRg64D/+eNvXEai74BR0CMlXD7ixo25zM+1qhAO8wtsDRZkuLq08KkccWFMJ7mtd5hF3a44qUtjzRnW4Oirt6HAegaotLvMsWxhlKEm6THfPN0B3GqVN4dx8I2/hlcRCoA/ytapSkwutyX8QU68AETTkURQmWBx8MMe3+fdNc6o6b9TgXXxeCMEnTHwF3lFaQIzI3v+V4WHF7IEU3FiH8Qc489d64D48l71akbXN89nArzgsKXB2MmmV2lM9YeCOnsKjmX8KDM0SXiEL2zF3sXQ6cpwXdHRFLWdM5neZxBxT2NXoCh8Xjx2VEzTJ20vLfq0qS/1WmOvzxa1Z4B4GJUx9Gho/2iLHXvrBh93kk72KbzHP15ZsKixGkF4CP2qqluraym5Mv2IXV1vZhipVedNBFCngOR603MyERCw0tKnYXuduDnvEV0J9Hgf+fyeiXSXH34K5Fq525/XZDKMm4='
        s = sign(now, aid, key, scope, 'example', '/', {}, token, {})
        self.assertEqual(s['sig'], 'c0979d16460957b789c4b31048e6e008e3888666e227e749d1a0bc5d5d8ab175')


if __name__ == '__main__':
    unittest.main()
