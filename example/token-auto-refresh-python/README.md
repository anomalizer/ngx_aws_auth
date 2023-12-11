# Automatically Recycling IAM Credentials via Python

This example sets up the nginx module to support passing the `x-amz-security-token` header when using
temporary IAM credentials. It's original use case is to retrieve credentials from a Fargate container,
but it can be adapted to support any environment.

## Build

You can build the environment with the following **from the root of the project**:

`docker build . -f example/token-auto-refresh-python/Dockerfile -t nginx-aws-auth-refresh`

## Run

When deploying to Fargate, the only environment variable required is the BUCKET_DOMAIN, which
should be your full bucket domain url.

For example:

`docker run --rm -p 5000:80 -e BUCKET_DOMAIN=public-encrypted-s3.s3.amazonaws.com nginx-aws-auth`

### Run Locally

If you would like to run this locally, you will need to retrieve your temporary credentials from
your hosting instance. If you are using Fargate, you can try deploying the image from here (https://github.com/BrutalSimplicity/fargate-ssh), to
allow you to ssh into the instance and view the credentials from that environment. Be sure to
read on how IAM roles are managed for details on how to access that information (https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-iam-roles.html).

After you have the credentials fill in the .env file in the root directory, and you can then run
it locally with something like `docker run --rm -p 5000:80 --env-file=example/token-auto-refresh-python/.env nginx-aws-auth-refresh:latest`