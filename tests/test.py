# -*- coding: utf-8 -*-

import unittest
from unittest import TestCase
import boto.s3.connection
from boto.s3.key import Key
import urllib, urllib2
import StringIO

s3_cred = { 'host': 'precise64',
            'port': 8000,
            #'port': 80,
            'access_key':'4WLAD43EZZ64EPK1CIRO', 
            'secret_key':'uGA3yy/NJqITgERIVmr9AgUZRBqUjPADvfQoxpKL',
            'bucket': 'test1',
          }

U_M_LIMIT = 5 * 1024 * 1024

class Tester():
    def __init__(self, host, port, akey, skey, bucket, fkey, content, content_type, multipart_file_size):
        self.fkey = fkey
        self.host = host
        self.bucket = bucket
        self.content = content
        self.content_type = content_type
        self.multipart_file_size = multipart_file_size
        self.conn = boto.s3.connection.S3Connection(host=host, port=port, is_secure=False, aws_access_key_id=akey, 
            aws_secret_access_key=skey, calling_format=boto.s3.connection.OrdinaryCallingFormat())
 
    def create_bucket(self):
        self.conn.create_bucket(self.bucket)
   
    def delete(self):
        bucket_obj = self.conn.get_bucket(self.bucket)
        k = Key(bucket_obj)
        k.key = self.fkey 
        bucket_obj.delete_key(k)
        
    def upload(self):
        bucket = self.conn.get_bucket(self.bucket)
        k = Key(bucket)
        k.key = self.fkey 
        k.set_contents_from_string(self.content, headers={'Content-Type': str(self.content_type)})        

    def upload_with_headers(self):
        bucket = self.conn.get_bucket(self.bucket)
        k = Key(bucket)
        k.key = self.fkey
        headers = {'Content-Type': str(self.content_type),
                   'x-amz-meta-origin': 'valtest',
                   'x-amz-meta-origin-a': 'valtest-a'}
        k.set_contents_from_string(self.content, headers=headers )        
        headers = {'Content-Type': str(self.content_type),
                   'x-amz-meta-origin-a': 'valtest-a'}
        k.set_contents_from_string(self.content, headers=headers )        
   
    def set_acl(self, policy):
        bucket = self.conn.get_bucket(self.bucket)
        k = Key(bucket)
        k.key = self.fkey
        k.set_acl(policy)
    
    def test_upload(self):
        self.delete()
        self.upload()
        self.set_acl('public-read')
 
        bucket = self.conn.get_bucket(self.bucket)
        k2 = Key(bucket)
        k2.key = self.fkey
        if k2.get_contents_as_string()!=self.content:
            return False
        return True
 
    def test_upload_with_headers(self):
        self.delete()
        self.upload_with_headers()
        self.set_acl('public-read')
 
        bucket = self.conn.get_bucket(self.bucket)
        k2 = Key(bucket)
        k2.key = self.fkey
        if k2.get_contents_as_string()!=self.content:
            return False
        return True

    def test_upload_private_acl(self):
        self.delete()
        self.upload()
        self.set_acl('private')
        try:
            urllib.urlretrieve('http://'+self.host+'/'+self.fkey)
        except urllib2.HTTPError, code:
            return False
        return True
    
    def test_get_metadata(self):
        self.delete()
        self.upload()
        bucket_obj = self.conn.get_bucket(self.bucket)
        k = bucket_obj.get_key(self.fkey)
        if 'dict' in str(type(k.metadata)):
            return True
        return False
    
    def test_delete(self):
        self.upload()
        self.delete()
        return True
        
        
    def test_public_read_acl(self):
        self.delete()
        self.upload()       
        self.set_acl('public-read')        
        bucket_obj = self.conn.get_bucket(self.bucket)
        
        acl_info = bucket_obj.get_acl(key_name=self.fkey)
        S3_PUBLIC_POLICY_URI = 'http://acs.amazonaws.com/groups/global/AllUsers'
        for aicg in acl_info.acl.grants:
            if aicg.uri == S3_PUBLIC_POLICY_URI:
                if aicg.permission == "READ":
                    return True
        return False

    def multipart_upload(self):
        fh = StringIO.StringIO('a' * self.multipart_file_size)
        bucket = self.conn.get_bucket(self.bucket)
        key = Key(bucket)
        key.key = self.fkey 
        mp = bucket.initiate_multipart_upload(key)
        try:
            fh.seek(0, 0)
            pos = 0
            part_num = 0
            while pos < self.multipart_file_size - 1:
                if pos + U_M_LIMIT > self.multipart_file_size:
                    part_size = self.multipart_file_size - pos
                else:
                    part_size = U_M_LIMIT
                part_num += 1
                mp.upload_part_from_file(fh, part_num, size=part_size)
                pos += part_size
            mp.complete_upload()
        except:
            mp.cancel_upload()
            raise
        return True

    def test_multipart_upload(self):
        self.multipart_upload()
        self.delete()
        return True


class BotoTest(TestCase):
    def setUp(self):
	self.boto_tester = Tester(s3_cred['host'], s3_cred['port'], s3_cred['access_key'], 
            s3_cred['secret_key'], s3_cred['bucket'], 'filename.txt', 'filecontentttttt', 'text/html', U_M_LIMIT + 100)

    #def test_create_bucket(self):
    #     self.assertEquals(self.boto_tester.create_bucket(), True)

    def test_upload(self):
        self.assertEquals(self.boto_tester.test_upload(), True)

    def test_upload_with_headers(self):
        self.assertEquals(self.boto_tester.test_upload_with_headers(), True)
   
    def test_delete(self):
        self.assertEquals(self.boto_tester.test_delete(), True)

    def test_public_read_acl(self):
        self.assertEquals(self.boto_tester.test_public_read_acl(), True)
        
    def test_upload_private_acl(self):
        self.assertEquals(self.boto_tester.test_upload_private_acl(), True)

    def test_upload_multipart(self):
        self.assertEquals(self.boto_tester.test_multipart_upload(), True)
        
#---------------------------------------

if __name__ == "__main__":
    unittest.main()
