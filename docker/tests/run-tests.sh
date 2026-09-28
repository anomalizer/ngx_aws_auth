#!/bin/bash
cd $NGX_PATH
./configure --with-http_ssl_module --with-compat --add-module=/ngx_http_aws_auth_module && make
cd /ngx_http_aws_auth_module
cp -r /cmocka vendor/
make test