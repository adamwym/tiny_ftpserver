//
// Created by adamwang on 17-9-24.
//
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <vector>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <pwd.h>
#include <grp.h>
#include <ctime>
#include "ls.h"
#include "log.h"


void get_mod(mode_t _mode, char *_buff)
{
    if (S_ISDIR(_mode))
        _buff[0] = 'd';
    else if (S_ISREG(_mode))
        _buff[0] = '-';
    else if (S_ISLNK(_mode))
        _buff[0] = 'l';
    else if (S_ISBLK(_mode))
        _buff[0] = 'b';
    else if (S_ISCHR(_mode))
        _buff[0] = 'c';
    else if (S_ISFIFO(_mode))
        _buff[0] = 'p';
    else if (S_ISSOCK(_mode))
        _buff[0] = 's';
    _buff[1] = (_mode & S_IRUSR ? 'r' : '-');
    _buff[2] = (_mode & S_IWUSR ? 'w' : '-');
    _buff[3] = (_mode & S_ISUID ? 'S' : (_mode & S_IXUSR ? 'x' : '-'));
    _buff[4] = (_mode & S_IRGRP ? 'r' : '-');
    _buff[5] = (_mode & S_IWGRP ? 'w' : '-');
    _buff[6] = (_mode & S_ISGID ? 'S' : (_mode & S_IXGRP ? 'x' : '-'));
    _buff[7] = (_mode & S_IROTH ? 'r' : '-');
    _buff[8] = (_mode & S_IWOTH ? 'w' : '-');
    _buff[9] = (_mode & S_IXOTH ? 'x' : '-');
}
size_t get_digit(long long _num)
{
    int count = 0;
    while (_num)
    {
        ++count;
        _num /= 10;
    }
    return count;
}
info_type generate_dirs_file(const char *_dir, max_info_type *_max_info, int _is_anon)
{
    struct stat filestat;
    struct passwd *pass = nullptr;
    struct group *grp = nullptr;
    if (lstat(_dir, &filestat))
    {
        ftp_log(FTP_LOG_ERR, "error lstat %s:%m.", _dir);
    }
    if (!_is_anon && !(pass = getpwuid(filestat.st_uid)))
    {
        ftp_log(FTP_LOG_ERR, "error getpw %s:%m.", _dir);
    }
    if (!_is_anon && !(grp = getgrgid(filestat.st_gid)))
    {
        ftp_log(FTP_LOG_ERR, "error getgr %s:%m.", _dir);
    }
    info_type info;
    strcpy(info.m_name, _dir);
    strcpy(info.m_uid, pass ? pass->pw_name : "ftp");
    strcpy(info.m_gid, grp ? grp->gr_name : "ftp");
    info.m_mode = filestat.st_mode;
    info.m_link = filestat.st_nlink;
    info.m_size = filestat.st_size;
    info.m_time = filestat.st_mtim;
    //fill
    if (_max_info)
    {
        size_t length = 0;
        length = strlen(info.m_uid);
        if (_max_info->max_uid < length)
            _max_info->max_uid = length;
        length = strlen(info.m_gid);
        if (_max_info->max_gid < length)
            _max_info->max_gid = length;
        length = strlen(info.m_name);
        if (_max_info->max_name < length)
            _max_info->max_name = length;
        length = get_digit(filestat.st_nlink);
        if (_max_info->max_link < length)
            _max_info->max_link = length;
        length = get_digit(filestat.st_size);
        if (_max_info->max_size < length)
            _max_info->max_size = length;
    }
    return info;
}
int generate_dirs(ls_type &_ls_type, const char *_path, int _ignore_hidden_file, int _is_anon)
{
    struct dirent *dir;
    DIR *dp;
    max_info_type max;
    if (!(dp = opendir(_path)))
    {
        ftp_log(FTP_LOG_WARNING, "open %s failed", _path);
        return -1;
    }
    while ((dir = readdir(dp)))
    {
        if (_ignore_hidden_file)
        {
            if (strstr(dir->d_name, ".") == dir->d_name || strstr(dir->d_name, "..") == dir->d_name)
                continue;
        }
        _ls_type.infos.push_back(generate_dirs_file(dir->d_name, &max, _is_anon));
    }
    closedir(dp);
    _ls_type.max_info = max;
    return 0;
}
int ls_to_str(struct ls_type &_ls_type, char *_buff, const int _max_size)
{
    if (_ls_type.infos.size() && _ls_type.outputed_num != _ls_type.infos.size())
    {
        char mod[11];
        char time[256];
        mod[10] = '\0';
        char size_str[128];
        int size = 0;
        info_type &item = _ls_type.infos[_ls_type.outputed_num];
        get_mod(item.m_mode, mod);
        strftime(time, 256, "%b %2d %H:%M ", localtime(&item.m_time.tv_sec));
        char format_str[256];
        sprintf(format_str, "%%s %%%dd %%-%ds %%-%ds %%%dd %%s %%s", _ls_type.max_info.max_link, _ls_type.max_info.max_uid, _ls_type.max_info.max_gid, _ls_type.max_info.max_size);
        size += sprintf(_buff, format_str, mod, item.m_link, item.m_uid, item.m_gid, item.m_size, time, item.m_name);
        if (size + 2 >= _max_size)
        {
            ftp_log(FTP_LOG_WARNING, "ls buffer overflow.");
            return -1;
        }
        _buff += size;
        if (mod[0] == 'l')
        {
            char link_name[256];
            link_name[readlink(item.m_name, link_name, 256)] = '\0';
            int added_size = sprintf(_buff, " -> %s", link_name);
            size += added_size;
            if (size + 2 >= _max_size)
            {
                ftp_log(FTP_LOG_WARNING, "ls buffer overflow.");
                return -1;
            }
            _buff += added_size;
        }
        *_buff = '\r';
        *(_buff + 1) = '\n';
        size += 2;
        ++_ls_type.outputed_num;
        return size;
    } else
    {
        return 0;
    }
}
int ls_generate_ls_type(struct ls_type &_ls_type, const char *_path, int _ignore_hidden_files, int _is_anon)
{
    return generate_dirs(_ls_type, _path, _ignore_hidden_files, _is_anon);
}