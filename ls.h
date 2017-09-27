//
// Created by adamwang on 17-9-24.
//

#ifndef TINY_FTPSERVER_LS_H
#define TINY_FTPSERVER_LS_H

#include <vector>

struct info_type
{
    char m_name[256];
    char m_uid[256];
    char m_gid[256];
    mode_t m_mode;
    nlink_t m_link;
    off_t m_size;
    struct timespec m_time;
};
struct max_info_type
{
    size_t max_name = 0, max_size = 0, max_uid = 0, max_gid = 0, max_link = 0;
};
struct ls_type
{
    std::vector<info_type> infos;
    max_info_type max_info;
    unsigned int outputed_num = 0;
};
int ls_generate_ls_type(struct ls_type &_ls_type, const char *_path, int _ignore_hidden_files, int _is_anon);
int ls_to_str(struct ls_type &_ls_type, char *_buff, const int _max_size);
#endif //TINY_FTPSERVER_LS_H
