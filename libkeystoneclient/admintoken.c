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

#include <jansson.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include "curl.h"
#include "keystoneclient.h"


extern struct ks_config config;


static pthread_mutex_t token_mutex = PTHREAD_MUTEX_INITIALIZER;
static char *token;
static time_t token_last_login;


char *
login(CURL *c, const char *username, const char *password, const char *tenant) {
  char *res = NULL;

  json_t *input;
  if(tenant)
    input = json_pack("{s: {s: {s: s, s: s}, s: s}}",
		      "auth", "passwordCredentials",
		      "username", username,
		      "password", password,
		      "tenantName", tenant);
  else
    input = json_pack("{s: {s: {s: s, s: s}}}",
		      "auth", "passwordCredentials",
		      "username", username,
		      "password", password);

  json_t *output = sendreq_json(c, "/v2.0/tokens", NULL, input);

  if(!output)
    goto out;

  if(!json_unpack(output, "{s: {s: {s: s}}}", "access", "token", "id", &res))
    res = strdup(res);

  json_decref(output);
 out:
  json_decref(input);
  return res;
}


char *
admin_token(CURL *c) {
  pthread_mutex_lock(&token_mutex);

  time_t now = time(NULL);
  if(now - token_last_login > 3600) {
    if(token)
      free(token);
    
    token = login(c, config.username, config.password, config.tenant);

    if(token)
      token_last_login = now;
    else
      fprintf(stderr, "admin_token: ks_login failed\n");
  }

  char *res = token ? strdup(token) : NULL;

  pthread_mutex_unlock(&token_mutex);

  return res;
}


void
admin_token_deinit() {
  pthread_mutex_lock(&token_mutex);

  if(token)
    free(token);

  token = NULL;
  token_last_login = 0;

  pthread_mutex_unlock(&token_mutex);
}
