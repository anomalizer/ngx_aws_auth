#!/usr/bin/python3
import os
import http.client
import json
import hmac
import hashlib
import base64
import subprocess
from datetime import datetime
import io
import logging
import sys

level = logging.DEBUG if '-d' in sys.argv or '--debug' in sys.argv else logging.INFO
logging.basicConfig(stream=sys.stdout, level=level, format='%(asctime)s - %(name)s - %(levelname)s\n%(message)s')

credentials_host = '169.254.170.2'
credentials_path = os.environ['AWS_CONTAINER_CREDENTIALS_RELATIVE_URI']
aws_region = os.environ['AWS_REGION']
aws_bucket_domain = os.environ['BUCKET_DOMAIN']
aws_bucket = aws_bucket_domain.split('.')[0]
aws_service = 's3'

def get_timestamps():
    if os.path.exists('/etc/timestamps'):
        with open('/etc/timestamps') as fp:
            exp = fp.readline().strip()
            created = fp.readline().strip()

            exp = datetime.strptime(exp, '%Y-%m-%dT%H:%M:%SZ')
            created = datetime.strptime(created, '%Y-%m-%dT%H:%M:%SZ')

            return (exp, created)
    return (None, None)

def get_current_creds():
    try:
        conn = http.client.HTTPConnection(credentials_host, timeout=5)
        conn.request('GET', credentials_path)
        res = conn.getresponse()
    
        creds = json.loads(res.readline().decode('utf8'))
    except:
        logging.error("Unexpected error: %s" % (sys.exc_info()[0]))
        raise

    return (creds['AccessKeyId'], creds['SecretAccessKey'], creds['Token'], creds['Expiration'])

def sign(key, val):
    return hmac.new(key, val.encode('utf-8'), hashlib.sha256).digest()

def get_signature_key(key, dateStamp, regionName, serviceName):
    kDate = sign(("AWS4" + key).encode("utf-8"), dateStamp)
    kRegion = sign(kDate, regionName)
    kService = sign(kRegion, serviceName)
    kSigning = sign(kService, "aws4_request")
    return kSigning

def encode_signature(signature):
    return base64.b64encode(signature).decode('ascii')

def get_key_scope(ymd, region, service):
    return '%s/%s/%s/aws4_request' % (ymd, region, service)

def refresh_credentials(access_key, secret, security_token, signing_key, scope, expiration):

    def export_credentials():
        os.environ['_AWS_ACCESS_KEY'] = access_key
        os.environ['_AWS_SIGNING_KEY'] = signing_key
        os.environ['_AWS_SIGNING_SCOPE'] = scope
        os.environ['_AWS_SECURITY_TOKEN'] = security_token
        os.environ['_AWS_BUCKET'] = aws_bucket
        os.environ['_AWS_BUCKET_DOMAIN'] = aws_bucket_domain
        with open('/etc/timestamps', 'w') as fp:
            fp.write('%s\n%s\n' % (expiration, datetime.utcnow()))

    def substitue_credentials():
        subprocess.run('envsubst \'${_AWS_BUCKET},${_AWS_BUCKET_DOMAIN},${_AWS_SIGNING_SCOPE},${_AWS_ACCESS_KEY},${_AWS_SIGNING_KEY},${_AWS_SECURITY_TOKEN}\' </tmp/nginx/s3proxy.conf > /etc/nginx/s3proxy.conf', shell=True)
    
    def logConfig():
        with open('/etc/nginx/s3proxy.conf') as fp:
            logging.debug(fp.read())

    export_credentials()
    substitue_credentials()
    logConfig()

def signal_nginx_reload():
    subprocess.run('nginx -s reload', shell=True)

def format_date(date):
    return '%04d%02d%02d' % (date.year, date.month, date.day)

def has_key_expired(exiration, last_created):
    now = datetime.utcnow()
    return now >= expiration or now.date() > last_created.date()

logging.info('Checking Access Credentials...')

(expiration, last_created) = get_timestamps()
now = datetime.utcnow()

logging.debug('Expiration: %s\nNow: %s\n' %\
    (expiration, now))

if has_key_expired(expiration, last_created):
    (aws_access_key, aws_secret_key, aws_security_token, expiration) = get_current_creds()
    ymd = format_date(datetime.utcnow().date())
    signature = get_signature_key(aws_secret_key, ymd, aws_region, aws_service)
    signature = encode_signature(signature)
    scope = get_key_scope(ymd, aws_region, aws_service)

    refresh_credentials(aws_access_key, aws_secret_key, aws_security_token, signature, scope, expiration)
    logging.info('Access Credentials Updated')

    logging.debug('Signature (base64): %s\nScope: %s' % (signature, scope))

    if '--no-reload' not in sys.argv:
        logging.info('Reloading Nginx Configuration')
        signal_nginx_reload()
else:
    logging.info('Access Credentials Current')