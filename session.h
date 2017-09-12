//
// Created by adamwang on 17-6-21.
//

#ifndef TINY_FTPSERVER_SESSION_H
#define TINY_FTPSERVER_SESSION_H

#include "ftp_def.h"
#include <stddef.h>
#include <limits.h>

//forward declaration
struct passwd;


class ftp_session
{
public:
    ftp_session(int _socketfd, int _fd_transfer_fd) : m_ctl_socket(_socketfd), m_fd_transfer_fd(_fd_transfer_fd),
                                                      m_data_socket(-1), m_pass(nullptr), m_status() {}

    void ftp_init();

    void start_handle();
    int parse_command(char **_cmd, size_t _length);
    int send_ctl(int _num);
    int send_message(int _num);
    int recv_message();
    int recv_ctl();
    int get_message(char *_src, char *_dst, size_t);
    void rm_CRLF(char *_ptr);
    void close_ctl_socket();
    void close_message_socket();

private:
    void cmd_user_handler(char *_buff);
    void cmd_pass_handler(char *_buff);
    void cmd_syst_handler();
    void cmd_quit_handler();
    void cmd_pwd_handler();
    void cmd_cwd_handler(char *_buff);
    void cmd_pasv_handler();
    void cmd_list_handler();
    void cmd_type_handler(char *_buff);
    void cmd_retr_handler(char *_buff);
    void cmd_stor_handler(char *_buff);
    void cmd_mkd_handler(char *_buff);
    void cmd_rmd_handler(char *_buff);
    void cmd_dele_handler(char *_buff);
    void cmd_rnfr_handler(char *_buff);
    void cmd_rnto_handler(char *_buff);
    void cmd_cdup_handler();
    void cmd_port_handler(char *_buff);
    void send_ctl_error(int _err_code, const char *_err_message, int _close = 1);

    struct ftp_status
    {
        int is_login = 0;
        int specifyed_user = 0;
        int is_passive = 0;
        int opened_message_fd = -1;
        int type_mode = -1;
        int wait_rnto = 0;
        char rn_buff[NAME_MAX + 1];
        int port_socket = -1;
    };
    char m_buff[FTP_BUFF_SIZE + 1];
    int m_ctl_socket;
    int m_data_socket;
    int m_fd_transfer_fd;
    struct passwd *m_pass;
    ftp_status m_status;
};
#endif //TINY_FTPSERVER_SESSION_H
