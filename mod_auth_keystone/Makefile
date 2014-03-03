mod_auth_keystone.la:

clean:
	rm -rf .libs mod_auth_keystone.{la,lo,o,slo}

install: mod_auth_keystone.la
	apxs -a -i $<

%.la: %.c
	apxs -c -Wc,-Wall -Wc,-W -I ../libkeystoneclient $< ../libkeystoneclient/*.o ../contrib/jansson-2.5/src/.libs/*.o -lcrypto -lcurl -lpthread

.PHONY: clean install
