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
RUN ./configure --with-compat --add-dynamic-module=../ngx_http_aws_auth_module &&\
    make modules

FROM nginx:1.16.1-alpine
COPY nginx /etc/nginx
COPY nginx /tmp/nginx
COPY docker/startup.sh /startup.sh
COPY --from=build /nginx-1.16.1/objs/ngx_http_aws_auth_module.so /etc/nginx/modules
EXPOSE 80
STOPSIGNAL SIGTERM
CMD [ "./startup.sh" ]