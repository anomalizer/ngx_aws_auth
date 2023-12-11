FROM ubuntu:18.04 as build
RUN apt update -y &&\
    apt-get install -yf \
        build-essential \
        wget \
        git \
        libpcre3-dev \
        zlib1g-dev \
        libssl-dev
RUN wget https://nginx.org/download/nginx-1.16.1.tar.gz &&\
    tar -xzvf nginx-1.16.1.tar.gz
COPY . /ngx_http_aws_auth_module
WORKDIR /nginx-1.16.1
RUN ./configure --with-compat --add-dynamic-module=../ngx_http_aws_auth_module --with-cc-opt="-D NO_AWS_AUTH_LOGS" &&\
    make modules

FROM nginx:1.16.1-alpine
RUN apk add --update \
    python3 \
    curl
RUN curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py &&\
    python3 get-pip.py &&\
    pip install boto3 &&\
    pip install watchtower
COPY example/token-auto-refresh-python/nginx /etc/nginx
COPY example/token-auto-refresh-python/nginx /tmp/nginx
COPY example/token-auto-refresh-python/startup.sh /startup.sh
COPY --from=build /nginx-1.16.1/objs/ngx_http_aws_auth_module.so /etc/nginx/modules
COPY example/token-auto-refresh-python/refresh_credentials.py /refresh_credentials.py
EXPOSE 80
STOPSIGNAL SIGTERM
CMD [ "./startup.sh" ]