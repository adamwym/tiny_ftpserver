//
// Created by adamwang on 17-6-21.
//

#ifndef TINY_FTPSERVER_SESSION_H
#define TINY_FTPSERVER_SESSION_H

#include "ftp_def.h"
#include <stddef.h>
#include <limits.h>
#include <openssl/ssl.h>


//forward declaration
struct passwd;

static void sigurg_handler(int);
class ftp_session
{
public:
    ftp_session(int _socketfd, int _fd_transfer_fd, conf_status *_conf) : m_ctl_socket(_socketfd),
                                                                          m_fd_transfer_fd(_fd_transfer_fd),
                                                                          m_data_socket(-1), m_pass(nullptr),
                                                                          m_status(), m_conf(_conf),
                                                                          m_speed_ctl(0) {}
    friend void sigurg_handler(int);
    void ftp_init();

    void start_handle();
    //int parse_command(char **_cmd, size_t _length);
    int send_ctl(int _num);
    int send_message(int _num);
    int recv_message();
    int recv_ctl();
    int get_message(char *_src, char *_dst, size_t);
    void rm_CRLF(char *_ptr);
    void close_ctl_socket();
    void close_message_socket();
    void shutdown_message_wait();

private:
#define x(a, b) void cmd_##b##_handler(char *_buff);
    FTP_LIST_NEED_LOGIN
    FTP_LIST_NO_NEED_LOGIN
#undef x
    void send_ctl_error(int _err_code, const char *_err_message, int _close = 1);

    struct ftp_status
    {
        int is_anon = 0;
        int is_login = 0;
        int specifyed_user = 0;
        int is_passive = 0;
        int opened_message_fd = -1;
        int type_mode = -1;
        int wait_rnto = 0;
        char rn_buff[NAME_MAX + 1];
        int is_urg_abort_recved = 0;
        int is_auth_mode = 0;
        char prot_value = 'C';
        SSL *ctl_socket_ssl = NULL;
        SSL *data_socket_ssl = NULL;
    };
    class speed_control
    {
    public:
        speed_control(int _speed_limit) : m_speed_limit(_speed_limit), m_send_num(0) {}
#define MILLION 1000000
        int send_start(int);
        void send_end();
        void recv_start();
        void recv_end(int);
        void set_speed_limit(int);
    private:
        void do_end(long);
    private:
        int m_send_num;
        int m_recv_num;
        int m_speed_limit;
        timeval m_send_start;
        timeval m_send_end;
        timeval m_recv_start;
        timeval m_recv_end;
    };
    char m_buff[FTP_BUFF_SIZE + 1];
    int m_ctl_socket;
    int m_data_socket;
    int m_fd_transfer_fd;
    conf_status *m_conf;
    struct passwd *m_pass;
    ftp_status m_status;
    speed_control m_speed_ctl;
};
#endif //TINY_FTPSERVER_SESSION_H
