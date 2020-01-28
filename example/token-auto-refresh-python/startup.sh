#!/bin/sh

# substitute the domain and configure the first set of credentials
envsubst '${BUCKET},${BUCKET_DOMAIN},${_AWS_SIGNING_SCOPE},${_AWS_ACCESS_KEY},${_AWS_SIGNING_KEY},${TOKEN}' </tmp/nginx/server.conf > /tmp/nginx/server-tmp.conf
cp /tmp/nginx/server-tmp.conf /etc/nginx/server.conf

# start nginx (blocking call)
nginx -g "daemon off;"
