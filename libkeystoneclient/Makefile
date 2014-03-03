CFLAGS+=-std=c99 -D_GNU_SOURCE -fPIC -Wall -W
CFLAGS+=-I../contrib/jansson-2.5/src
LDLIBS+=-L../contrib/jansson-2.5/src/.libs
LDLIBS+=-lcrypto -lcurl -ljansson -lpthread

debug: CFLAGS+=-g
debug: libkeystoneclient.so

release: CFLAGS+=-O2 -s
release: libkeystoneclient.so

libkeystoneclient.so: admintoken.o curl.o crypto.o keystoneclient.o revocation.o
	$(LD) $(LDFLAGS) -shared -soname $@.1 -o $@.1.0 $^ $(LDLIBS)
	ln -sf $@.1.0 $@.1
	ln -sf $@.1.0 $@

clean:
	rm -f *.o libkeystoneclient.*

.PHONY: clean debug release
