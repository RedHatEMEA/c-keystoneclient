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
#include <string.h>
#include "keystoneclient.h"


extern struct ks_config config;


typedef struct {
  char *buf;
  size_t len;
} membuf_t;


static size_t
curl_write_function(void *ptr, size_t size, size_t nmemb, membuf_t *mb) {
  size_t len = size * nmemb;

  mb->buf = realloc(mb->buf, mb->len + len + 1);
  if(!mb->buf)
    return 0;

  memcpy(mb->buf + mb->len, ptr, len);
  mb->len += len;
  mb->buf[mb->len] = '\0';
 
  return len;
}


char *
sendreq(CURL *c, const char *href, const char *token,
	struct curl_slist *_headers, const char *input) {
  // curl_easy_setopt(c, CURLOPT_VERBOSE, 1);

  struct curl_slist *headers = NULL;
  for(struct curl_slist *h = _headers; h; h = h->next)
    headers = curl_slist_append(headers, h->data);

  if(token) {
    char *xauthtoken = NULL;
    asprintf(&xauthtoken, "X-Auth-Token: %s", token);
    headers = curl_slist_append(headers, xauthtoken);
    free(xauthtoken);
  }

  if(input)
    curl_easy_setopt(c, CURLOPT_POSTFIELDS, input);
  else
    curl_easy_setopt(c, CURLOPT_HTTPGET, 1);

  membuf_t mb = { NULL, 0 };

  char *url = NULL;
  asprintf(&url, "%s%s", config.url, href);
  curl_easy_setopt(c, CURLOPT_URL, url);
  free(url);
  
  curl_easy_setopt(c, CURLOPT_HTTPHEADER, headers);
  curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, curl_write_function);
  curl_easy_setopt(c, CURLOPT_WRITEDATA, &mb);

  CURLcode res = curl_easy_perform(c);

  if(res) {
    fprintf(stderr, "sendreq: curl_easy_perform returned %u\n", res);
    goto out_err;
  }

  long code;
  curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &code);
  if(code != 200) {
    fprintf(stderr, "sendreq: status code %ld\n", code);
    goto out_err;
  }

 out:
  if(headers)
    curl_slist_free_all(headers);

  return mb.buf;

 out_err:
  if(mb.buf) {
    free(mb.buf);
    mb.buf = NULL;
  }
  goto out;
}


json_t *
sendreq_json(CURL *c, const char *href, const char *token,
	     const json_t *jsoninput) {
  char *input = NULL;
  struct curl_slist *headers = NULL;

  if(jsoninput) {
    input = json_dumps(jsoninput, 0);
    headers = curl_slist_append(headers, "Content-Type: application/json");
  }

  char *output = sendreq(c, href, token, headers, input);

  json_t *res = NULL;

  if(output) {
    res = json_loads(output, 0, NULL);
    free(output);
  }

  if(input)
    free(input);

  if(headers)
    curl_slist_free_all(headers);

  return res;
}
