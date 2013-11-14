# -*- coding: utf-8 -*-

import unittest
from unittest import TestCase
import boto.s3.connection
from boto.s3.key import Key
import urllib, urllib2

s3_cred = { 'host': 'precise64',
            'port': 8000,
            'access_key':'4WLAD43EZZ64EPK1CIRO', 
            'secret_key':'uGA3yy/NJqITgERIVmr9AgUZRBqUjPADvfQoxpKL',
            'bucket': 'test1',
          }

class Tester():
    def __init__(self, host, port, akey, skey, bucket, fkey, content, content_type):
        self.fkey = fkey
        self.host = host
        self.bucket = bucket
        self.content = content
        self.content_type = content_type
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


class BotoTest(TestCase):
    def setUp(self):
	self.boto_tester = Tester(s3_cred['host'], s3_cred['port'], s3_cred['access_key'], 
            s3_cred['secret_key'], s3_cred['bucket'], 'filename.txt', 'filecontentttttt', 'text/html')

    #def test_create_bucket(self):
    #     self.assertEquals(self.boto_tester.create_bucket(), True)

    def test_upload(self):
        self.assertEquals(self.boto_tester.test_upload(), True)
    
    def test_delete(self):
        self.assertEquals(self.boto_tester.test_delete(), True)

    def test_public_read_acl(self):
        self.assertEquals(self.boto_tester.test_public_read_acl(), True)
        
    def test_upload_private_acl(self):
        self.assertEquals(self.boto_tester.test_upload_private_acl(), True)
        
#---------------------------------------

if __name__ == "__main__":
    unittest.main()
