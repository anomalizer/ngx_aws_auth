FROM ubuntu:18.04 as build
RUN apt update -y &&\
    apt-get install -yf \
        build-essential \
        wget \
        git \
        libpcre3-dev \
        zlib1g-dev \
        libssl-dev \
        cmake \
        sudo
RUN wget https://nginx.org/download/nginx-1.16.1.tar.gz &&\
    tar -xzvf nginx-1.16.1.tar.gz
RUN git clone git://git.cryptomilk.org/projects/cmocka.git /cmocka
COPY docker/tests/run-tests.sh /run-tests.sh
COPY . /ngx_http_aws_auth_module
ENV NGX_PATH=/nginx-1.16.1
ENV LD_LIBRARY_PATH=/lib:/usr/lib:/usr/local/lib
CMD [ "./run-tests.sh" ]
