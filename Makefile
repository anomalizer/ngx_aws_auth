CC ?= gcc
# CFLAGS applies only to the test-suite compile below. The module itself is built
# by nginx's own build system (prepare-nginx target), which uses its own flags.
CFLAGS=-g -D_GNU_SOURCE -I${NGX_PATH}/src/os/unix -I${NGX_PATH}/src/core -I${NGX_PATH}/src/http -I${NGX_PATH}/src/http/modules -I${NGX_PATH}/src/event -I${NGX_PATH}/objs/ -I.


all:

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

.PHONY: all clean test nginx prepare-nginx .cmocka_build


NGX_PATH := $(shell echo `pwd`/nginx)

prepare-nginx:
	wget --no-verbose -O nginx-${NGINX_VERSION}.tar.gz https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz
	rm -rf nginx-${NGINX_VERSION} ${NGX_PATH}
	tar -xzf nginx-${NGINX_VERSION}.tar.gz
	ln -s nginx-${NGINX_VERSION} ${NGX_PATH}
# NGX_CC_OPT: optional extra compiler flags for nginx's build (via --with-cc-opt)
	cd ${NGX_PATH} && ./configure --with-http_ssl_module --with-cc=$(CC) --with-cc-opt="$(NGX_CC_OPT)" --add-module=$(CURDIR)

nginx:
	cd ${NGX_PATH} && rm -rf ${NGX_PATH}/objs/src/core/nginx.o && make

vendor/cmocka:
	cd $(CURDIR) && git submodule init && git submodule update

# Always re-runs so `sudo make install` isn't skipped when a previous run left
# .cmocka_build behind (e.g. local reruns against a fresh container).
.cmocka_build:
	cd $(CURDIR) && git submodule init && git submodule update && mkdir -p .cmocka_build && cd .cmocka_build \
	&& cmake -DCMAKE_C_COMPILER=$(CC) -DCMAKE_MAKE_PROGRAM=make $(CURDIR)/vendor/cmocka \
	&& make && sudo make install

test: .cmocka_build | nginx
	strip -N main -o ${NGX_PATH}/objs/src/core/nginx_without_main.o ${NGX_PATH}/objs/src/core/nginx.o \
	&& mv ${NGX_PATH}/objs/src/core/nginx_without_main.o ${NGX_PATH}/objs/src/core/nginx.o \
	&& $(CC) test_suite.c $(CFLAGS) -o test_suite -lcmocka `find ${NGX_PATH}/objs -name \*.o` -ldl -lpthread -lcrypt -lssl -lpcre2-8 -lcrypto -lz \
	&& ./test_suite

clean:
	rm -f *.o test_suite

# vim: ft=make ts=8 sw=8 noet
