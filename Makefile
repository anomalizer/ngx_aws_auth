CC ?= gcc
CFLAGS=-g -I${NGX_PATH}/src/os/unix -I${NGX_PATH}/src/core -I${NGX_PATH}/src/http -I${NGX_PATH}/src/http/modules -I${NGX_PATH}/src/event -I${NGX_PATH}/objs/ -I.


all:

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

.PHONY: all clean test nginx prepare-travis-env


NGX_PATH := $(shell echo `pwd`/nginx)

prepare-travis-env:
	wget --no-verbose https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz
	tar -xzf nginx-${NGINX_VERSION}.tar.gz
	ln -s nginx-${NGINX_VERSION} ${NGX_PATH}
	cd ${NGX_PATH} && ./configure --with-http_ssl_module --with-cc=$(CC) --add-module=.

nginx:
	cd ${NGX_PATH} && rm -rf ${NGX_PATH}/objs/src/core/nginx.o && make

vendor/cmocka:
	git submodule init && git submodule update

.cmocka_build: vendor/cmocka
	mkdir .cmocka_build && cd .cmocka_build \
	&& cmake -DCMAKE_C_COMPILER=$(CC) -DCMAKE_MAKE_PROGRAM=make ../vendor/cmocka \
	&& make && sudo make install

test: .cmocka_build | nginx
	strip -N main -o ${NGX_PATH}/objs/src/core/nginx_without_main.o ${NGX_PATH}/objs/src/core/nginx.o \
	&& mv ${NGX_PATH}/objs/src/core/nginx_without_main.o ${NGX_PATH}/objs/src/core/nginx.o \
	&& $(CC) test_suite.c $(CFLAGS) -o test_suite -lcmocka `find ${NGX_PATH}/objs -name \*.o` -ldl -lpthread -lcrypt -lssl -lpcre -lcrypto -lz \
	&& ./test_suite

clean:
	rm -f *.o test_suite

# vim: ft=make ts=8 sw=8 noet
