# AWS proxy module

This branch contains the legacy code based on the deprecated AWS V2 authentication protocol.
The code here is well tested in production. You can find the experimental support for the
V4 authentication protocol that will work with all new regions of AWS under the master branch

Implements proxying of authenticated requests to S3.

```nginx
  server {
    listen     8000;

    location / {
      proxy_pass http://your_s3_bucket.s3.amazonaws.com;

      aws_access_key your_aws_access_key;
      aws_secret_key the_secret_associated_with_the_above_access_key;
      s3_bucket your_s3_bucket;

      proxy_set_header Authorization $s3_auth_token;
      proxy_set_header x-amz-date $aws_date;
    }

    # This is an example that does not use the server root for the proxy root
	location /myfiles {
	
      rewrite /myfiles/(.*) /$1 break;
      proxy_pass http://your_s3_bucket.s3.amazonaws.com/$1;

      aws_access_key your_aws_access_key;
      aws_secret_key the_secret_associated_with_the_above_access_key;
      s3_bucket your_s3_bucket;
      chop_prefix /myfiles; # Take out this part of the URL before signing it, since '/myfiles' will not be part of the URI sent to Amazon  


      proxy_set_header Authorization $s3_auth_token;
      proxy_set_header x-amz-date $aws_date;
    }

  }
```


# Community

The project uses google groups for discussions. The group name is nginx-aws-auth. You can visit the web forum [here](https://groups.google.com/forum/#!forum/nginx-aws-auth)


Request signing & Amazon Cloudfront Service
-------------------------------------------


If Nginx is behind Amazon's CloudFront CDN service, you need to add this setting : 

```nginx
proxy_set_header x-amz-cf-id "";
```

into nginx.conf in order to clear X-Amz-Cf-Id header before signing the request to Amazon S3 bucket.


More info here : 

http://s3.amazonaws.com/doc/s3-developer-guide/RESTAuthentication.html


Credits:
========
Original idea based on http://nginx.org/pipermail/nginx/2010-February/018583.html and suggestion of moving to variables rather than patching the proxy module.

Subsequent contributions can be found in the commit logs of the project.

License
-------
This project uses the same license as ngnix does i.e. the 2 clause BSD / simplified BSD / FreeBSD license
