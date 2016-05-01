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


def make_headers(req_time, bucket, aws_headers, content_hash):
    headers = []
    headers.append(['x-amz-content-sha256', content_hash])
    headers.append(['x-amz-date', req_time])
    headers.append(['Host', '%s.s3.amazonaws.com' % (bucket)])

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


def canon_request(req_time, bucket, url, qs_map, aws_headers):
    qs = canon_querystring(qs_map)
    payload_hash = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' #hardcoded
    header_info = make_headers(req_time, bucket, None, payload_hash)
    cr = "\n".join(('GET', url, qs['cqs'], header_info['ch'], header_info['sh'], payload_hash)) # hardcoded method
    print cr

    return {'cr_str': cr, 'headers': header_info['hmap'], 'qs': qs, 'sh': header_info['sh']}


def sign_body(body=None):
    return 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' # TODO: fix hardcoding


def get_scope(dt, region):
    return '%s/%s/s3/aws4_request' % (dt, region)

def str_to_sign_v4(req_time, scope, bucket, url, qs_map, aws_headers):
    cr_info = canon_request(req_time, bucket, url, qs_map, aws_headers)
    h265 = sha256()
    h265.update(cr_info['cr_str'])
    hd = h265.hexdigest()
    s2s = "\n".join(('AWS4-HMAC-SHA256', cr_info['headers']['x-amz-date'], scope, hd))
    print s2s
    return {'s2s': s2s, 'headers': cr_info['headers'], 'qs':cr_info['qs'], 'scope': scope, 'sh': cr_info['sh']}

def sign(req_time, access_id, key, scope, bucket, url, qs_map, aws_headers):
    s2s = str_to_sign_v4(req_time, scope, bucket, url, qs_map, aws_headers)
    retval = hmac.new(key, s2s['s2s'], sha256)
    sig = retval.hexdigest()
    auth_header = 'AWS4-HMAC-SHA256 Credential=%s/%s,SignedHeaders=%s,Signature=%s' % (
        access_id, s2s['scope'], s2s['sh'], sig)
    s2s['headers']['Authorization'] = auth_header
    return {'headers': s2s['headers'], 'qs':s2s['qs'], 'sig': sig}


def get_data(req_time, access_id, key, scope, bucket, url, qs_map, aws_headers):
    s = sign(req_time, access_id, key, scope, bucket, url, qs_map, aws_headers)
    rurl = "http://%s.s3.amazonaws.com%s" % (bucket, url)
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
    request_time = datetime.utcnow().strftime('%Y%m%dT%H%M%SZ') if len(sys.argv) == 4 else sys.argv[4]
    print "Request time is %s" % request_time
    get_data(request_time, aid, base64.b64decode(b64_key), scope, 'hw.anomalizer', '/lock.txt', {}, {})
'''

class TestStringMethods(unittest.TestCase):
    def test_simple_get(self):
        now = '20150830T123600Z'
        key = base64.b64decode('k4EntTNoEN22pdavRF/KyeNx+e1BjtOGsCKu2CkBvnU=')
        aid = 'AKIDEXAMPLE'
        scope = '20150830/us-east-1/service/aws4_request'
        s = sign(now, aid, key, scope, 'example', '/', {}, {})
        self.assertEqual(s['sig'], '5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31')


if __name__ == '__main__':
    unittest.main()
