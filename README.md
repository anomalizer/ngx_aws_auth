# AWS proxy module

This nginx module can proxy requests to authenticated S3 backends using Amazon's
V4 authentication API. The first version of this module was written for the V2
authentication protocol and can be found in the 1.x branch.

## License
This project uses the same license as ngnix does i.e. the 2 clause BSD / simplified BSD / FreeBSD license

## Usage example

Implements proxying of authenticated requests to S3.

```nginx
  server {
    listen     8000;

    aws_access_key your_aws_access_key;
    aws_key_scope scope_of_generated_signing_key;
    aws_signing_key signing_key_generated_using_script;
	aws_s3_bucket your_s3_bucket;

    location / {
	  aws_sign;
      proxy_pass http://your_s3_bucket.s3.amazonaws.com;
    }

    # This is an example that does not use the server root for the proxy root
	location /myfiles {
	
      rewrite /myfiles/(.*) /$1 break;
      proxy_pass http://your_s3_bucket.s3.amazonaws.com/$1;


      aws_access_key your_aws_access_key;
      aws_key_scope scope_of_generated_signing_key;
      aws_signing_key signing_key_generated_using_script;
    }

  }
```

## Security considerations
The V4 protocol does not need access to the actual secret keys that one obtains 
from the IAM service. The correct way to use the IAM key is to actually generate
a scoped signing key and use this signing key to access S3. This nginx module
requires the signing key and not the actual secret key. It is an insecure practise
to let the secret key reside on your nginx server.

Note that signing keys have a validity of just one week. Hence, they need to
be refreshed constantly. Please useyour favourite configuration management
system such as saltstack, puppet, chef, etc. etc. to distribute the signing
keys to your nginx clusters. Do not forget to HUP the server after placing the new
signing key as nginx reads the configuration only at startup time.

A standalone python script has been provided to generate the signing key
```
./generate_signing_key -h
usage: generate_signing_key [-h] -k ACCESS_KEY -r REGION [-s SERVICE]
                            [-d DATE] [--no-base64] [-v]

Generate AWS S3 signing key in it's base64 encoded form

optional arguments:
  -h, --help            show this help message and exit
  -k SECRET_KEY, --secret-key SECRET_KEY
                        The secret key generated using AWS IAM. Do not confuse
                        this with the access key id
  -r REGION, --region REGION
                        The AWS region where this key would be used. Example:
                        us-east-1
  -s SERVICE, --service SERVICE
                        The AWS service for which this key would be used.
                        Example: s3
  -d DATE, --date DATE  The date on which this key is generated in yyyymmdd
                        format
  --no-base64           Disable output as a base64 encoded string. This NOT
                        recommended
  -v, --verbose         Produce verbose output on stderr

```

## Known limitations
The 2.x version of the module currently only has support for GET and HEAD calls. This is because
signing request body is complex and has not yet been implemented.


## Community

The project uses google groups for discussions. The group name is nginx-aws-auth. You can visit the web forum [here](https://groups.google.com/forum/#!forum/nginx-aws-auth)


## Credits
Original idea based on http://nginx.org/pipermail/nginx/2010-February/018583.html and suggestion of moving to variables rather than patching the proxy module.

Subsequent contributions can be found in the commit logs of the project.
