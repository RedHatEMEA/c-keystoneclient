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
#include <jansson.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "admintoken.h"
#include "crypto.h"
#include "curl.h"
#include "keystoneclient.h"
#include "revocation.h"


struct ks_config config;


static char *
ks_validate_token_uuid(const char *uuid) {
  char *username = NULL;

  CURL *c = curl_easy_init();

  char *token = admin_token(c);
  if(!token)
    goto out_cleanup;

  char *url = NULL;
  asprintf(&url, "/v2.0/tokens/%s", uuid);

  json_t *output = sendreq_json(c, url, token, NULL);

  if(!output)
    goto out_free;

  json_unpack(output, "{s: {s: {s: s}}}", "access", "user", "username",
	      &username);

  if(username)
    username = strdup(username);
  else
    fprintf(stderr, "ks_validate_token_uuid: check failed\n");

  json_decref(output);
 out_free:
  free(url);
  free(token);
 out_cleanup:
  curl_easy_cleanup(c);
  return username;
}


static char *
ks_validate_token_pki(const char *enctoken) {
  char *username = NULL;

  char *token;
  if(!crypto_verify(enctoken, &token, 1)) {
    fprintf(stderr, "ks_validate_token_pki: token verification error\n");
    goto out;
  }

  json_t *json = json_loads(token, 0, NULL);

  const char *expires;
  if(json_unpack(json, "{s: {s: {s: s}, s: {s: s}}}", "access", "token",
		 "expires", &expires, "user", "username", &username)) {
    fprintf(stderr, "ks_validate_token_pki: json error\n");
    username = NULL;
    goto out_decref;
  }

  username = strdup(username);

  struct tm tm;
  memset(&tm, 0, sizeof(tm));
  strptime(expires, "%Y-%m-%dT%H:%M:%SZ", &tm);
  time_t exptime = timegm(&tm);

  if(exptime < time(NULL)) {
    fprintf(stderr, "ks_validate_token_pki: token expired\n");
    goto out_err;
  }

  if(is_revoked(enctoken)) {
    fprintf(stderr, "ks_validate_token_pki: token revoked\n");
    goto out_err;
  }

 out_decref:
  json_decref(json);
  free(token);
 out:
  return username;

 out_err:
  free(username);
  username = NULL;
  goto out_decref;
}


char *
ks_validate_token(const char *token) {
  for(const char *c = token; *c; c++)
    if(!(*c >= 'A' && *c <= 'Z') && !(*c >= 'a' && *c <= 'z') &&
       !(*c >= '0' && *c <= '9') && *c != '+' && *c != '-' && *c != '=') {
      fprintf(stderr, "ks_validate_token: token contains invalid "
	      "character(s)\n");
      return NULL;
    }

  if(strlen(token) == 32)
    return ks_validate_token_uuid(token);
  else
    return ks_validate_token_pki(token);
}


char *
ks_validate_login(const char *username, const char *password) {
  CURL *c = curl_easy_init();

  char *enctoken = login(c, username, password, NULL);

  if(enctoken)
    free(enctoken);
  else
    fprintf(stderr, "ks_validate_login: login failed\n");

  curl_easy_cleanup(c);

  return enctoken ? strdup(username) : NULL;
}


void
ks_deinit() {
  revocation_deinit();
  admin_token_deinit();
  curl_global_cleanup();
  crypto_deinit();

  free(config.url);
  free(config.username);
  free(config.password);
  free(config.tenant);
}


int
ks_init(const struct ks_config *_config) {
  if(!_config->url || !_config->username || !_config->password ||
     !_config->tenant)
    return -1;

  config.url = strdup(_config->url);
  config.username = strdup(_config->username);
  config.password = strdup(_config->password);
  config.tenant = strdup(_config->tenant);
  config.revoke_refresh = _config->revoke_refresh;

  if(curl_global_init(CURL_GLOBAL_DEFAULT))
    return -1;

  CURL *c = curl_easy_init();

  char *token = admin_token(c);
  if(!token) {
    curl_easy_cleanup(c);
    curl_global_cleanup();
    return -1;
  }

  char *cacert = sendreq(c, "/v2.0/certificates/ca", token, NULL, NULL);
  char *signingcert = sendreq(c, "/v2.0/certificates/signing", token, NULL,
			      NULL);

  curl_easy_cleanup(c);
  free(token);

  crypto_init(cacert, signingcert);

  free(cacert);
  free(signingcert);

  revocation_init();

  return 0;
}
