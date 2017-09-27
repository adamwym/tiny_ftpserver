//
// Created by adamwang on 17-9-23.
//

#ifndef TINY_FTPSERVER_PARSE_CONF_H
#define TINY_FTPSERVER_PARSE_CONF_H

#include <glib.h>

int conf_parse(const char *_conf_file);
int conf_has_key(const char *_key);
int conf_get_bool_YES_NO(const char *_key);
char *conf_get_string(const char *_key);
void conf_free();

#endif //TINY_FTPSERVER_PARSE_CONF_H
