docker build . -f docker/tests/Dockerfile -t ngx_aws_auth_tests
docker run --rm --name ngx_aws_auth_tests ngx_aws_auth_tests