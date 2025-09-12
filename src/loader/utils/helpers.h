#pragma once

#include "a2s_query_servers.h"

void cleanup();
void parse_config_file(struct server_config *cfg);
void termination_handler();