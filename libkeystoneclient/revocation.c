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

#include <curl/curl.h>
#include <openssl/md5.h>
#include <jansson.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "admintoken.h"
#include "crypto.h"
#include "curl.h"
#include "keystoneclient.h"


extern struct ks_config config;


static pthread_t thread;
static pthread_cond_t digest_cond = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t digest_mutex = PTHREAD_MUTEX_INITIALIZER;
static int initialised;
static int finish;
static char *digests;
static size_t num_digests;
static time_t last_refresh;


static int
digest_comparator(const void *a, const void *b) {
  return memcmp(a, b, MD5_DIGEST_LENGTH);
}


static inline void
hexcpy(char *dst, const char *src, size_t n) {
#define HEX(c) ((c) >= 'a' ? (c) - 'a' + 10 : (c) >= 'A' ? (c) - 'A' + 10 : (c) - '0')
  for(size_t i = 0; i < n; i++)
    dst[i] = (HEX(src[i * 2]) << 4) + HEX(src[i * 2 + 1]);
#undef HEX
}


int
is_revoked(const char *token) {
  unsigned char digest[MD5_DIGEST_LENGTH];
  MD5((const unsigned char *)token, strlen(token), digest);

  pthread_mutex_lock(&digest_mutex);

  int res = 1;
  if(time(NULL) - last_refresh > 3 * config.revoke_refresh)
    fprintf(stderr, "is_revoked: revocation list stale\n");
  else
    res = bsearch(digest, digests, num_digests, sizeof(digest),
		  digest_comparator) ? 1 : 0;

  pthread_mutex_unlock(&digest_mutex);

  return res;
}


static int
refresh_revocation_list(CURL *c) {
  int res = -1;

  char *token = admin_token(c);
  if(!token)
    goto out;

  json_t *json = sendreq_json(c, "/v2.0/tokens/revoked", token, NULL);
  if(!json)
    goto out_free;

  char *buf;
  if(!crypto_verify(json_string_value(json_object_get(json, "signed")),
		    &buf, 0))
    goto out_decref;

  json_decref(json);
  json = json_loads(buf, 0, NULL);

  json_t *array = json_object_get(json, "revoked");

  pthread_mutex_lock(&digest_mutex);

  num_digests = json_array_size(array);
  digests = (char *)realloc(digests, MD5_DIGEST_LENGTH * num_digests);

  for(size_t i = 0; i < num_digests; i++)
    hexcpy(digests + MD5_DIGEST_LENGTH * i,
	   json_string_value(json_object_get(json_array_get(array, i), "id")),
	   MD5_DIGEST_LENGTH);
  
  qsort(digests, num_digests, MD5_DIGEST_LENGTH, digest_comparator);

  last_refresh = time(NULL);

  pthread_mutex_unlock(&digest_mutex);

  res = 0;

  free(buf);
 out_decref:
  json_decref(json);
 out_free:
  free(token);
 out:
  return res;
}


static void *
worker() {
  CURL *c = curl_easy_init();

  while(!finish) {
    refresh_revocation_list(c);

    if(!initialised) {
      pthread_mutex_lock(&digest_mutex);
      initialised = 1;
      pthread_cond_signal(&digest_cond);
      pthread_mutex_unlock(&digest_mutex);
    }

    for(unsigned int i = 0; i < config.revoke_refresh * 10 && !finish; i++)
      usleep(100000);
  }

  curl_easy_cleanup(c);
  crypto_deinit_thread();

  return NULL;
}


void
revocation_deinit() {
  finish = 1;
  pthread_join(thread, NULL);

  if(digests)
    free(digests);
}


void
revocation_init() {
  pthread_create(&thread, NULL, worker, NULL);

  pthread_mutex_lock(&digest_mutex);
  while(!initialised)
    pthread_cond_wait(&digest_cond, &digest_mutex);
  pthread_mutex_unlock(&digest_mutex);
}
