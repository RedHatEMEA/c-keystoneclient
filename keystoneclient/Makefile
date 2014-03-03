CFLAGS=-std=c99 -Wall -W -D_GNU_SOURCE -I../libkeystoneclient
LDLIBS=-L../libkeystoneclient -L../contrib/jansson-2.5/src/.libs -lcrypto -lcurl -ljansson -lkeystoneclient -lpthread

debug: CFLAGS+=-g
debug: keystoneclient

release: CFLAGS+=-O2 -s
release: keystoneclient

clean:
	rm -f keystoneclient

.PHONY: clean debug release
