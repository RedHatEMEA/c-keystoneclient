mod_auth_keystone: libkeystoneclient
	cd $@ && $(MAKE)

keystoneclient: libkeystoneclient
	cd $@ && $(MAKE)

libkeystoneclient: jansson-2.5
	cd $@ && $(MAKE)

jansson-2.5: contrib/jansson-2.5/Makefile
	cd contrib/jansson-2.5 && $(MAKE)

contrib/jansson-2.5/Makefile:
	cd contrib/jansson-2.5 && ./configure

all: keystoneclient mod_auth_keystone

clean:
	cd contrib/jansson-2.5 && $(MAKE) distclean || true
	cd keystoneclient && $(MAKE) $@
	cd libkeystoneclient && $(MAKE) $@
	cd mod_auth_keystone && $(MAKE) $@

.PHONY: all clean jansson-2.5 keystoneclient libkeystoneclient mod_auth_keystone
