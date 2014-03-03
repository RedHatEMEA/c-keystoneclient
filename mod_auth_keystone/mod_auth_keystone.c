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

#include <keystoneclient.h>
#include "apr_strings.h"
#include "apr_base64.h"
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_request.h"


module AP_MODULE_DECLARE_DATA auth_keystone_module;


static void *
auth_keystone_config_new(apr_pool_t *p, __attribute__((unused)) server_rec *s) {
  struct ks_config *config = apr_pcalloc(p, sizeof(struct ks_config));
  config->revoke_refresh = 30;
  return config;
}


static const char *
auth_keystone_config(cmd_parms *cmd, __attribute__((unused)) void *cfg,
		     const char *arg) {
  struct ks_config *config = ap_get_module_config(cmd->server->module_config,
						  &auth_keystone_module);

  if(!strcmp(cmd->info, "url"))
    config->url = apr_pstrdup(cmd->pool, arg);
  else if(!strcmp(cmd->info, "refresh"))
    config->revoke_refresh = atoi(arg);

  return NULL;
}


static const char *
auth_keystone_config_auth(cmd_parms *cmd, __attribute__((unused)) void *cfg,
			  const char *username, const char *password,
			  const char *tenant) {
  struct ks_config *config = ap_get_module_config(cmd->server->module_config,
						  &auth_keystone_module);

  config->username = apr_pstrdup(cmd->pool, username);
  config->password = apr_pstrdup(cmd->pool, password);
  config->tenant = apr_pstrdup(cmd->pool, tenant);

  return NULL;
}


static const command_rec auth_keystone_cmds[] = {
  AP_INIT_TAKE1("KeystoneURL", auth_keystone_config, "url", RSRC_CONF, ""),
  AP_INIT_TAKE3("KeystoneAuth", auth_keystone_config_auth, NULL, RSRC_CONF, ""),
  AP_INIT_TAKE1("KeystoneRefresh", auth_keystone_config, "refresh", RSRC_CONF,
		""),
  { NULL }
};


static void
note_basic_auth_failure(request_rec *r) {
  apr_table_setn(r->err_headers_out, "WWW-Authenticate",
		 apr_pstrcat(r->pool, "Basic realm=\"Keystone\"", NULL));
}


static int
get_basic_auth(request_rec *r, char **username, char **password) {
  const char *auth_line;
  char *decoded_line;
  int length;

  auth_line = apr_table_get(r->headers_in, "Authorization");

  if(!auth_line) {
    note_basic_auth_failure(r);
    return HTTP_UNAUTHORIZED;
  }

  if(strcasecmp(ap_getword(r->pool, &auth_line, ' '), "Basic")) {
    note_basic_auth_failure(r);
    return HTTP_UNAUTHORIZED;
  }

  decoded_line = apr_palloc(r->pool, apr_base64_decode_len(auth_line) + 1);
  length = apr_base64_decode(decoded_line, auth_line);
  decoded_line[length] = '\0';

  *username = ap_getword_nulls(r->pool, (const char **)&decoded_line, ':');
  *password = decoded_line;

  return OK;
}


static int
check_user_id(request_rec *r) {
  const char *current_auth = ap_auth_type(r);
  if(!current_auth || strcasecmp(current_auth, "Keystone"))
    return DECLINED;

  r->ap_auth_type = "Keystone";

  const char *token_line = apr_table_get(r->headers_in, "X-Auth-Token");
  if(token_line) {
    char *username = ks_validate_token(token_line);
    if(!username)
      return HTTP_UNAUTHORIZED;

    r->user = apr_pstrdup(r->pool, username);
    free(username);

    return OK;
  }

  char *username, *password;
  int res = get_basic_auth(r, &username, &password);
  if(res)
    return res;

  username = ks_validate_login(username, password);

  if(!username)
    return HTTP_UNAUTHORIZED;

  r->user = apr_pstrdup(r->pool, username);
  free(username);

  return OK;
}


static void
child_init(__attribute__((unused)) apr_pool_t *p, server_rec *s) {
  struct ks_config *config = ap_get_module_config(s->module_config,
						  &auth_keystone_module);
  ks_init(config);
}


static void
register_hooks(__attribute__((unused)) apr_pool_t *p) {
  ap_hook_child_init(child_init, NULL, NULL, APR_HOOK_MIDDLE);
  ap_hook_check_user_id(check_user_id, NULL, NULL, APR_HOOK_MIDDLE);
}


module AP_MODULE_DECLARE_DATA auth_keystone_module = {
  STANDARD20_MODULE_STUFF,
  NULL,					/* dir config creater */
  NULL,					/* dir merger --- default is to override */
  auth_keystone_config_new,		/* server config */
  NULL,					/* merge server config */
  auth_keystone_cmds,			/* command apr_table_t */
  register_hooks			/* register hooks */
};
