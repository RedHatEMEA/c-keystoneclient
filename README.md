README for c-keystoneclient
===========================

Jim Minter \<jminter@redhat.com\>, 03/03/2014


Introduction
------------

c-keystoneclient is a C-based client library for OpenStack Keystone
authentication.  It includes mod_auth_keystone, an Apache HTTPD module
supporting keystone authentication to Apache HTTPD servers.
c-keystoneclient supports UUID or PKI-token-based authentication as
well as basic username/password verification.


Building, installing and running
--------------------------------

- Build everything:

  `$ make all`

- Install mod_auth_keystone:

  `$ cd mod_auth_keystone && sudo make install`
  `$ sudo fixfiles restore /usr/lib64/httpd/modules/mod_auth_keystone.so`

- For testing, run keystoneclient as follows:

  `$ LD_LIBRARY_PATH=contrib/jansson-2.5/src/.libs:libkeystoneclient keystoneclient/keystoneclient <args>`

- Clean up:

  `$ make clean`


mod_auth_keystone
-----------------

Apache HTTPD module supporting authentication against Keystone in
OpenStack Havana, using UUID or PKI token-based authentication (via
HTTP X-Auth-Token header) or basic authentication (username and
password, via HTTP Authorization header).  Links statically against
libjansson and libkeystoneclient for simple installation on RHEL 6
systems.  mod_auth_keystone provides the following top-level
configurables:

- **KeystoneURL url**

  Required.  url provides the Keystone 2.0 API endpoint,
  e.g. http://openstack:35357/ .

- **KeystoneAuth username password tenant**

  Required.  username, password and tenant provide the admin
  credentials required to authenticate libkeystoneclient to Keystone
  in order to retrieve the certificate revocation list.

- **KeystoneRefresh revoke_refresh**

  Optional, defaulting to 30.  revoke_refresh provides the number of
  seconds to sleep between successive retrievals of the PKI revocation
  list.  Currently, PKI token-based authentications will fail if the
  revocation list is more than 3 * revoke_refresh seconds old.

An example Apache configuration snippet follows:

```
LoadModule auth_keystone_module /usr/lib64/httpd/modules/mod_auth_keystone.so
LoadModule authz_user_module modules/mod_authz_user.so

KeystoneURL http://openstack:35357/
KeystoneAuth admin password admin

<Location />
  AuthType Keystone
  Require valid-user
</Location>
```


Configuration of mod_auth_keystone on OpenShift broker
------------------------------------------------------

1. **Create /var/www/openshift/broker/httpd/conf.d/openshift-origin-auth-remote-user-keystone.conf**

   If using OpenShift Enterprise 2.0, base this file on
   samples/broker-openshift-origin-auth-remote-user-keystone.conf.
   Don't forget to edit the KeystoneURL and KeystoneAuth parameters.

   Otherwise, base this file on
   /var/www/openshift/broker/httpd/conf.d/openshift-origin-auth-remote-user-basic.conf.sample
   and apply the patch below.  Don't forget to edit the KeystoneURL
   and KeystoneAuth parameters.

   ```
@@ -1,11 +1,11 @@
-LoadModule auth_basic_module modules/mod_auth_basic.so
-LoadModule authn_file_module modules/mod_authn_file.so
+LoadModule auth_keystone_module modules/mod_auth_keystone.so
 LoadModule authz_user_module modules/mod_authz_user.so
+KeystoneURL http://$KEYSTONEIP:35357/
+KeystoneAuth $USERNAME $PASSWORD $TENANT
 
 <Location /broker>
     AuthName "OpenShift broker API"
-    AuthType Basic
-    AuthUserFile /etc/openshift/htpasswd
+    AuthType Keystone
     require valid-user
 
     SetEnvIfNoCase Authorization Bearer passthrough
```

1. **Create /var/www/openshift/console/httpd/conf.d/openshift-origin-auth-remote-user-keystone.conf**

   If using OpenShift Enterprise 2.0, base this file on
   samples/console-openshift-origin-auth-remote-user-keystone.conf.
   Don't forget to edit the KeystoneURL and KeystoneAuth parameters.

   Otherwise, base this file on
   /var/www/openshift/console/httpd/conf.d/openshift-origin-auth-remote-user-basic.conf.sample
   and apply the patch below.  Don't forget to edit the KeystoneURL
   and KeystoneAuth parameters.

   ```
@@ -1,6 +1,7 @@
-LoadModule auth_basic_module modules/mod_auth_basic.so
-LoadModule authn_file_module modules/mod_authn_file.so
+LoadModule auth_keystone_module modules/mod_auth_keystone.so
 LoadModule authz_user_module modules/mod_authz_user.so
+KeystoneURL http://$KEYSTONEIP:35357/
+KeystoneAuth $USERNAME $PASSWORD $TENANT
 
 # Turn the authenticated remote-user into an Apache environment variable for the console security controller
 RewriteEngine On
@@ -10,8 +11,7 @@
 
 <Location /console>
     AuthName "OpenShift Developer Console"
-    AuthType Basic
-    AuthUserFile /etc/openshift/htpasswd
+    AuthType Keystone
     require valid-user
 
     # The node->broker auth is handled in the Ruby code
```

1. **Restart OpenShift services**

   `# service openshift-broker restart`
   `# service openshift-console restart`


libkeystoneclient
-----------------

C language OpenStack Keystone client library supporting UUID or
PKI-based tokens or basic authentication.  Uses libcrypto (OpenSSL),
libcurl, libjansson and libpthread internally.  A sample client
(keystoneclient) is included in this repository.  libkeystoneclient
provides the following core functions:

- **int ks_init(const struct ks_config *config);**

  Initialise library and worker thread.  struct ks_config is defined
  as follows:

  ```
struct ks_config {
  char *url;
  char *username;
  char *password;
  char *tenant;
  int revoke_refresh;
};
```

  - url provides the Keystone 2.0 API endpoint,
    e.g. http://openstack:35357/ .
  - username, password and tenant provide the admin credentials
    required to authenticate libkeystoneclient to Keystone in order to
    retrieve the revocation list.
  - revoke_refresh provides the number of seconds to sleep between
    successive retrievals of the PKI revocation list.  Currently, PKI
    token-based authentications will fail if the revocation list is
    more than 3 * revoke_refresh seconds old.

  If ks_init does not return 0, initialisation failed and ks_deinit()
  should not be called.

  Currently, libkeystoneclient is not aware when its containing
  process forks.  ks_init() should be called after forking.

- **void ks_deinit();**

  Deinitialise library and worker thread.  Not to be called if ks_init
  did not return 0.

- **char *ks_validate_login(const char *username, const char
  *password);**

  Validate the given credentials against Keystone (implies a
  round-trip to the Keystone server).  If unsuccessful, NULL is
  returned.  If successful, the username is returned.  The caller is
  responsible for freeing this string.
  
- **char *ks_validate_token(const char *token);**

  Validate the given token (signature, expiry date, revocation).  If
  the token is a UUID, this implies a round-trip to the Keystone
  server.  If unsuccessful, NULL is returned.  If successful, the
  username is returned.  The caller is responsible for freeing this
  string.


keystoneclient
--------------

Sample C client for libkeystoneclient.  Allows the ks_login,
ks_validate_login and ks_validate_token functions of libkeystoneclient
to be called from the command line.  All invocations require the
following mandatory arguments:

- \<keystone_url\>

  keystone_url provides the Keystone 2.0 API endpoint,
  e.g. "http://openstack:35357".

- -u \<username\> -p \<password\> -t \<tenant\>

  username, password and tenant provide the admin credentials required
  to authenticate keystoneclient to Keystone in order to retrieve the
  revocation list.

- validate_login | validate_token

  libkeystoneclient API function to call.  Following this argument,
  additional arguments are necessary; requirements exactly matching
  those documented in libkeystoneclient.

The following argument is optional:

- -r revoke_refresh

  Defaults to 30.  revoke_refresh provides the number of seconds to
  sleep between successive retrievals of the PKI revocation list.
  Currently, token-based authentications will fail if the revocation
  list is more than 3 * revoke_refresh seconds old.

An example invocation is as follows:

  `$ LD_LIBRARY_PATH=contrib/jansson-2.5/src/.libs:libkeystoneclient keystoneclient/keystoneclient http://openstack:35357 -u admin -p password -t admin validate_login myuser mypassword`
