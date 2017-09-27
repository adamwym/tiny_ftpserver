//
// Created by adamwang on 17-9-23.
//
#include <string.h>
#include "parse_conf.h"
#include "ftp_def.h"

GKeyFile *keyfile = NULL;
int conf_parse(const char *_conf_file)
{
    if (keyfile)
    {
        g_key_file_free(keyfile);
        keyfile = NULL;
    }
    keyfile = g_key_file_new();
    return g_key_file_load_from_file(keyfile, _conf_file, G_KEY_FILE_NONE, NULL);
}
void conf_free()
{
    g_key_file_free(keyfile);
    keyfile = NULL;
}
int conf_has_key(const char *_key)
{
    return g_key_file_has_key(keyfile, CONF_GROUP_NAME, _key, NULL);
}
int conf_get_bool_YES_NO(const char *_key)
{
    char *str = g_key_file_get_string(keyfile, CONF_GROUP_NAME, _key, NULL);
    return !strcmp(str, "YES") ? 1 : !strcmp(str, "NO") ? 0 : -1;

}
char *conf_get_string(const char *_key)
{
    return g_key_file_get_string(keyfile, CONF_GROUP_NAME, _key, NULL);
}
