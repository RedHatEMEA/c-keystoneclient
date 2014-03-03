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

#include <errno.h>
#include <keystoneclient.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


int
usage() {
  fprintf(stderr, "usage: %s <keystone_url> -u <username> -p <password> -t <tenant> [-r <refresh>] validate_login <username> <password>\n", program_invocation_short_name);
  fprintf(stderr, "     | %s <keystone_url> -u <username> -p <password> -t <tenant> [-r <refresh>] validate_token <enctoken>\n", program_invocation_short_name);

  return 1;
}


int
main(int argc, char **argv) {
  struct ks_config config;
  memset(&config, 0, sizeof(struct ks_config));
  config.revoke_refresh = 30;

  int c;
  while((c = getopt(argc, argv, "u:p:t:r:")) != -1)
    switch(c) {
    case 'u':
      config.username = optarg;
      break;
    case 'p':
      config.password = optarg;
      break;
    case 't':
      config.tenant = optarg;
      break;
    case 'r':
      config.revoke_refresh = atoi(optarg);
      break;
    default:
      return usage();
    }

  if(optind + 2 > argc || !config.username || !config.password ||
     !config.tenant || !config.revoke_refresh)
    return usage();

  config.url = argv[optind++];

  if(argc - optind == 3 && !strcasecmp(argv[optind], "validate_login")) {
    if(ks_init(&config))
      return 1;

    char *username = ks_validate_login(argv[optind + 1], argv[optind + 2]);
    if(username) {
      printf("%s\n", username);
      free(username);
    }
    ks_deinit();

  } else if(argc - optind == 2 && !strcasecmp(argv[optind], "validate_token")) {
    if(ks_init(&config))
      return 1;

    char *username = ks_validate_token(argv[optind + 1]);
    if(username) {
      printf("%s\n", username);
      free(username);
    }
    ks_deinit();

  } else
    return usage();

  return 0;
}
