AWS proxy module
================

Implements proxying of authenticated requests to S3.
See nginx_conf_fragment.txt for the nginx directives

Request signing & Amazon Cloudfront Service
-------------------------------------------


If Nginx is behind Amazon's CloudFront CDN service, you need to add this setting : 

proxy_set_header x-amz-cf-id "";

right before

proxy_set_header x-amz-date $aws_date;

into nginx.conf in order to clear X-Amz-Cf-Id header before signing the request to Amazon S3 bucket.


More info here : 

http://s3.amazonaws.com/doc/s3-developer-guide/RESTAuthentication.html


Credits:
========
Based on http://nginx.org/pipermail/nginx/2010-February/018583.html and suggestion of moving to variables rather than patching the proxy module.

License
-------
This project uses the same license as ngnix does i.e. the 2 clause BSD / simplified BSD / FreeBSD license
