/* Copyright 2014 Red Hat, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <openssl/cms.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509_vfy.h>
#include <string.h>


CMS_ContentInfo *PEM_read_bio_CMS(BIO *, CMS_ContentInfo **, pem_password_cb *,
				  void *);


static X509_STORE *store;
static STACK_OF(X509) *certs;


static X509 *
read_cert(const char *cert) {
  BIO *bio = BIO_new(BIO_s_mem());
  BIO_puts(bio, cert);
  X509 *x509 = PEM_read_bio_X509(bio, NULL, NULL, NULL);
  BIO_free(bio);

  return x509;
}


static BIO *
cms_message(const char *msg, int add_headers) {
  BIO *bio = BIO_new(BIO_s_mem());

  if(!add_headers) {
    BIO_puts(bio, msg);
    return bio;
  }

  BIO_puts(bio, "-----BEGIN CMS-----\n");

  for(int i = 0; *msg; i++, msg++) {
    char buf = *msg == '-' ? '/' : *msg;
    BIO_write(bio, &buf, 1);
    if(i == 76) {
      BIO_puts(bio, "\n");
      i = 0;
    }
  }
  BIO_puts(bio, "\n-----END CMS-----");
  return bio;
}


int
crypto_verify(const char *msg, char **out, int add_headers) {
  BIO *bio = cms_message(msg, add_headers);
  CMS_ContentInfo *cms = PEM_read_bio_CMS(bio, NULL, NULL, NULL);
  BIO_free(bio);

  BIO *bio_out = BIO_new(BIO_s_mem());

  int res = 0;
  if(cms) {
    res = CMS_verify(cms, certs, store, NULL, bio_out, 0);
    CMS_ContentInfo_free(cms);

    if(res) {
      char *bio_out_data;
      long len = BIO_get_mem_data(bio_out, &bio_out_data);
      *out = (char *)malloc(len + 1);
      memcpy(*out, bio_out_data, len);
      (*out)[len] = '\0';
    }

    BIO_free(bio_out);
  }

  ERR_print_errors_fp(stderr);
  return res;
}


void
crypto_deinit_thread() {
  ERR_remove_thread_state(NULL);
}


void
crypto_deinit() {
  X509_STORE_free(store);
  sk_X509_pop_free(certs, X509_free);

  ERR_free_strings();
  crypto_deinit_thread();
  CRYPTO_cleanup_all_ex_data();
  EVP_cleanup();
}


void
crypto_init(const char *cacert, const char *signingcert) {
  X509 *x509;

  OpenSSL_add_all_algorithms();
  ERR_load_crypto_strings();

  store = X509_STORE_new();
  certs = sk_X509_new_null();

  x509 = read_cert(cacert);
  X509_STORE_add_cert(store, x509);
  X509_free(x509);

  x509 = read_cert(signingcert);
  sk_X509_push(certs, x509);
}
