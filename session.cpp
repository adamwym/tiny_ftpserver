//
// Created by adamwang on 17-6-21.
//

#include "session.h"
#include <arpa/inet.h>
#include <stdio.h>
#include "ftp_def.h"
#include "fd_transfer.h"
#include <string.h>
#include <unistd.h>
#include <crypt.h>
#include <shadow.h>
#include <pwd.h>
#include <sys/stat.h>
#include <assert.h>
#include <limits.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/time.h>
#include <openssl/ssl.h>
#include "ls.h"
#include "log.h"
#include "utility.h"

ftp_session *ftp = NULL;
static void sigurg_handler(int)
{
    ftp_log(FTP_LOG_DEBUG, "urgent");
    assert(ftp);
    if (ftp->m_status.opened_message_fd == -1)
    {
        ftp->send_ctl_error(FTP_ABOR_NO_CONN, "No transfer to abort.", 0);
        return;
    }
    int n = ftp->recv_ctl();
    if (n == -1)
    {
        ftp_log(FTP_LOG_NOTICE, "error recv while handling SIGURG %s.", errno == EAGAIN ? ":timeout" : "");
        ftp->close_message_socket();
        ftp->close_ctl_socket();
        exit(1);
    }
    if (strstr(ftp->m_buff, "ABOR"))
    {
        ftp->m_status.is_urg_abort_recved = 1;
        ftp_log(FTP_LOG_DEBUG, "Urgent data received.");
    } else
    {
        ftp->send_ctl_error(FTP_NON_EXEC, "Error urgent data.", 0);
    }
}

void ftp_session::ftp_init()
{
    ftp = this;
    signal(SIGURG, sigurg_handler);
    signal(SIGPIPE, SIG_IGN);
    if (fcntl(m_ctl_socket, F_SETOWN, getpid()) == -1)
    {
        ftp_log(FTP_LOG_ERR, "set fd owner error");
    }
    struct timeval timeout;
    memset(&timeout, 0, sizeof(struct timeval));
    timeout.tv_sec = m_conf->conf_idle_session_timeout;
    set_recv_timeout(m_ctl_socket, &timeout);
    timeout.tv_sec = m_conf->conf_transmission_timeout;
    set_send_timeout(m_ctl_socket, &timeout);
    int n = sprintf(m_buff, "%d (tiny_ftp)\r\n", FTP_READY);
    send_ctl(n);
}
void ftp_session::send_ctl_error(int _err_code, const char *_err_message, int _close/*=1*/ )
{
    int n = sprintf(m_buff, "%d %s\r\n", _err_code, _err_message);
    send_ctl(n);
    if (m_status.opened_message_fd != -1)
    {
        close_message_socket();
    }
    if (_close)
    {
        close_ctl_socket();
        exit(1);
    }
}
void ftp_session::close_ctl_socket()
{
    if (m_status.ctl_socket_ssl)
    {
        SSL_shutdown(m_status.ctl_socket_ssl);
        SSL_free(m_status.ctl_socket_ssl);
        m_status.ctl_socket_ssl = NULL;
    }
    shutdown(m_ctl_socket, SHUT_WR);
    while (recv(m_ctl_socket, m_buff, 256, 0) > 0);
    close(m_ctl_socket);
    if (m_conf->conf_ctx)
        SSL_CTX_free(m_conf->conf_ctx);
    m_conf->conf_ctx = NULL;
}
int ftp_session::send_ctl(int _num)
{
    int i = 0;
    if (m_status.ctl_socket_ssl)
    {
        i = SSL_write(m_status.ctl_socket_ssl, m_buff, _num);
    } else
    {
        i = send(m_ctl_socket, m_buff, _num, 0);
    }
    if (i == -1)
    {
        ftp_log(FTP_LOG_NOTICE, "error send_ctl %s", errno == EAGAIN ? ":timeout" : "");
        close_message_socket();
        close_ctl_socket();
        exit(1);
    }
    return i;
}
int ftp_session::recv_ctl()
{
    int i = 0;
    if (m_status.ctl_socket_ssl)
    {
        i = SSL_read(m_status.ctl_socket_ssl, m_buff, FTP_BUFF_SIZE);
    } else
    {
        i = recv(m_ctl_socket, m_buff, FTP_BUFF_SIZE, 0);
    }
    m_buff[i] = '\0';
    return i;
}
int ftp_session::recv_message()
{
    m_speed_ctl.recv_start();
    int i = 0;
    if (m_status.data_socket_ssl)
    {
        i = SSL_read(m_status.data_socket_ssl, m_buff, FTP_BUFF_SIZE);
    } else
    {
        i = recv(m_status.opened_message_fd, m_buff, FTP_BUFF_SIZE, 0);
    }
    if (i == -1)
    {
        ftp_log(FTP_LOG_WARNING, "error while recv_message %s.", errno == EAGAIN ? ":timeout" : "");
    }
    m_speed_ctl.recv_end(i);
    m_buff[i] = '\0';
    return i;
}
int ftp_session::send_message(int _num)
{
    int num, send_num, remain_num = _num, sended_num = 0;
    const char *buff = m_buff;
    while (remain_num)
    {
        num = m_speed_ctl.send_start(remain_num);
        if (m_status.data_socket_ssl)
        {
            send_num = SSL_write(m_status.data_socket_ssl, buff, num);
        } else
            send_num = send(m_status.opened_message_fd, buff, num, 0);
        if (send_num == -1)
        {
            ftp_log(FTP_LOG_WARNING, "error while send_message %s.", errno == EAGAIN ? ":timeout" : "");
            return -1;
        }
        if (send_num != num)
            return sended_num + send_num;
        sended_num += num;
        remain_num -= num;
        buff += send_num;
        m_speed_ctl.send_end();
    }
    return sended_num;
}
void ftp_session::close_message_socket()
{
    if (m_status.data_socket_ssl)
    {
        SSL_shutdown(m_status.data_socket_ssl);
        SSL_free(m_status.data_socket_ssl);
        m_status.data_socket_ssl = NULL;
    }
    shutdown(m_status.opened_message_fd, SHUT_RDWR);
    close(m_status.opened_message_fd);
    m_status.opened_message_fd = -1;
}
void ftp_session::shutdown_message_wait()
{
    if (m_status.data_socket_ssl)
    {
        SSL_shutdown(m_status.data_socket_ssl);
        SSL_free(m_status.data_socket_ssl);
        m_status.data_socket_ssl = NULL;
    }
    shutdown(m_status.opened_message_fd, SHUT_WR);
    while (recv(m_status.opened_message_fd, m_buff, LINE_MAX, 0));
    shutdown(m_status.opened_message_fd, SHUT_RD);
    close(m_status.opened_message_fd);
    m_status.opened_message_fd = -1;
}
int ftp_session::get_message(char *_src, char *_dst, size_t _max_num)
{
    size_t n = strlen(_src);
    if (n - 2 + 1 >= _max_num)
        return -1;
    memcpy(_dst, _src, n - 2);
    _dst[n - 2] = '\0';
    return 0;
}
void ftp_session::rm_CRLF(char *_ptr)
{
    size_t n = strlen(_ptr);
    *(_ptr + n - 2) = '\0';
}
void ftp_session::start_handle()
{
    int n = -1;
    while ((n = recv_ctl()) > 0)
    {
        for (int i = 0; i < n; ++i)
        {
            char cmd_char = *(m_buff + i);
            if (cmd_char != ' ' && cmd_char != '\r' && cmd_char)
            {
                *(m_buff + i) = (char) toupper(cmd_char);
            } else
                break;
        }
        char *buff = m_buff;
#define x(a, b) if(strstr(buff,#b)==buff){buff+=strlen(#b)+1;cmd_##b##_handler(buff);continue;}
        FTP_LIST_NO_NEED_LOGIN
#undef x
#define x(a, b) if(strstr(buff,#b)==buff){if(!m_status.is_login) {send_ctl_error(FTP_NON_LOGIN_INET, "Please login first.", 0); continue;}buff+=strlen(#b)+1;cmd_##b##_handler(buff);continue;}
        FTP_LIST_NEED_LOGIN
#undef x
        send_ctl_error(FTP_NON_EXEC, "Unsupported command.", 0);
    }
    if (n == -1)
    {
        ftp_log(FTP_LOG_NOTICE, "error while recv %s.", errno == EAGAIN ? ":timeout" : "");
    }
    close_message_socket();
    close(m_data_socket);
    close(m_fd_transfer_fd);
    close_ctl_socket();
}
void ftp_session::cmd_USER_handler(char *_buff)
{
    if (m_status.is_login)
    {
        send_ctl_error(FTP_NON_LOGIN_INET, "Can't change user.", 0);
        return;
    }
    char username[256];
    get_message(_buff, username, 256);
    bool login_as_anon = m_conf->conf_anon_enable && !m_conf->conf_anon_user.compare(username);
    if (m_conf->conf_ctx && !m_status.is_auth_mode && (!login_as_anon || m_conf->conf_force_anon_logins_ssl))
    {
        send_ctl_error(FTP_DENIED_FOR_POLICY_REASONS, "SSL is enabled,please send AUTH before login.", 0);
        return;
    }
    if (login_as_anon)
    {
        m_pass = m_conf->conf_anon_login_as;
        m_status.is_anon = 1;
        m_speed_ctl.set_speed_limit(m_conf->conf_anon_max_rate);
        ftp_log(FTP_LOG_DEBUG, "login in as anon");
    } else
    {
        m_pass = getpwnam(username);
        m_speed_ctl.set_speed_limit(m_conf->conf_local_max_rate);
        ftp_log(FTP_LOG_DEBUG, "login in with username:%s", username);
    }
    m_status.specifyed_user = 1;
    int n = sprintf(m_buff, "%d please specify password\r\n", FTP_NEED_PASS);
    send_ctl(n);
}
void ftp_session::cmd_PASS_handler(char *_buff)
{
    char passwd[256];
    get_message(_buff, passwd, 256);
    struct spwd *sp;
    if (!m_pass ||
        !m_status.is_anon && (!m_conf->conf_local_enable ||
                              (!(sp = getspnam(m_pass->pw_name)) || strcmp(sp->sp_pwdp, crypt(passwd, sp->sp_pwdp)))))
    {
        send_ctl_error(FTP_NON_LOGIN_INET, "login failed");
    }
    if (m_status.is_anon && chroot(m_conf->conf_anon_root.c_str()))
        send_ctl_error(FTP_FILE_UNAVAILABLE, "chroot error");
    setgid(m_pass->pw_gid);
    setuid(m_pass->pw_uid);
    if (chdir(m_status.is_anon ? "/" : m_pass->pw_dir))
        send_ctl_error(FTP_NON_LOGIN_INET, "login failed.");
    m_status.is_login = 1;
    send_ctl(sprintf(m_buff, "%d login successful\r\n", FTP_LOGIN_INET));
}
void ftp_session::cmd_SYST_handler(char *_buff)
{
    send_ctl(sprintf(m_buff, "%d UNIX Type: L8\r\n", FTP_SYS_TYPE));
}

void ftp_session::cmd_QUIT_handler(char *_buff)
{
    int n = sprintf(m_buff, "%d goodbye\r\n", FTP_QUIT_INET);
    send_ctl(n);
    close_message_socket();
    close_ctl_socket();
    exit(0);
}
void ftp_session::cmd_PWD_handler(char *_buff)
{
    char *path = getcwd(nullptr, 0);
    int n = sprintf(m_buff, "%d \"%s\" is the current directory\r\n", FTP_PATH_CREATED, path);
    free(path);
    send_ctl(n);
}
void ftp_session::cmd_CWD_handler(char *_buff)
{
    _buff[strlen(_buff) - 2] = '\0';
    if (chdir(_buff) < 0)
    {
        send_ctl_error(FTP_FILE_UNAVAILABLE, "Failed to change directory.", 0);
    } else
    {
        int n = sprintf(m_buff, "%d Directory successfully changed.\r\n", FTP_FIN_FILEB);
        send_ctl(n);
    }
}
void ftp_session::cmd_PASV_handler(char *_buff)
{
    struct sockaddr_in sock;
    memset(&sock, 0, sizeof(sock));
    struct timeval timeout{m_conf->conf_transmission_timeout, 0};
    if (m_data_socket == -1)
    {
        socklen_t len = sizeof(sock);
        getsockname(m_ctl_socket, (struct sockaddr *) &sock, &len);
        m_data_socket = socket(AF_INET, SOCK_STREAM, 0);
        set_recv_timeout(m_data_socket, &timeout);
        sock.sin_port = htons(0);
        bind(m_data_socket, (struct sockaddr *) &sock, sizeof(sock));
        listen(m_data_socket, 10);
    }
    socklen_t n = sizeof(sock);
    getsockname(m_data_socket, (struct sockaddr *) &sock, &n);
    u_char *port = (u_char *) &sock.sin_port;
    u_char *addr = (u_char *) &sock.sin_addr.s_addr;
    int num = sprintf(m_buff, "%d Entering passive mode (%d,%d,%d,%d,%d,%d)\r\n", FTP_PASSIVE_MODE, addr[0], addr[1], addr[2], addr[3], port[0], port[1]);
    send_ctl(num);
    m_status.opened_message_fd = accept(m_data_socket, nullptr, nullptr);
    if (m_status.opened_message_fd == -1)
    {
        num = sprintf(m_buff, "%d Entering passive mode failed.\r\n", FTP_NON_LOGIN_INET);
        send_ctl(num);
        return;
    }
    set_send_timeout(m_status.opened_message_fd, &timeout);
    set_recv_timeout(m_status.opened_message_fd, &timeout);
    if (m_conf->conf_ctx && m_status.is_auth_mode)
    {
        m_status.data_socket_ssl = SSL_new(m_conf->conf_ctx);
        SSL_set_fd(m_status.data_socket_ssl, m_status.opened_message_fd);
        SSL_accept(m_status.data_socket_ssl);
    }
    m_status.is_passive = 1;
}
void ftp_session::cmd_LIST_handler(char *_buff)
{
    if (m_status.opened_message_fd == -1)
    {
        send_ctl_error(FTP_CAN_NOT_OPEN_CONNECTION, "Error: no message connection opened.", 0);
        return;
    }
    rm_CRLF(_buff);
    int ignore_hidden_file = 1;
    int num = strlen(_buff);
    if (num >= 2 && *_buff == '-' && strstr(_buff, "a"))
    {
        ignore_hidden_file = 0;
    }
    int n = sprintf(m_buff, "%d Here comes the directories list.\r\n", FTP_OPEN_CONN);
    send_ctl(n);
    ls_type ls;
    ls_generate_ls_type(ls, ".", ignore_hidden_file, m_status.is_anon);
    while ((n = ls_to_str(ls, m_buff, FTP_BUFF_SIZE + 1)) != -1 && n)
        if (send_message(n) == -1)
            break;
    //close_message_socket();
    shutdown_message_wait();
    n = sprintf(m_buff, "%d Directories send OK\r\n", FTP_CLOSE_DATA_CONN);
    send_ctl(n);
}

void ftp_session::cmd_TYPE_handler(char *_buff)
{
    char buff[5];
    const char *str;
    get_message(_buff, buff, 5);
    if (!strcmp(buff, "I"))
    {
        str = "Switching to binary mode.";
        m_status.type_mode = FTP_TYPE_BINARY;
    } else if (!strcmp(buff, "A"))
    {
        str = "Switching to Ascii mode.";
        m_status.type_mode = FTP_TYPE_ASCII;
    } else
    {
        send_ctl_error(FTP_NON_EXEC, "Unsupported command.", 0);
        return;
    }
    int n = sprintf(m_buff, "%d %s\r\n", FTP_SUCCESS, str);
    send_ctl(n);
}
void ftp_session::cmd_RETR_handler(char *_buff)
{
    if (m_status.opened_message_fd == -1)
    {
        send_ctl_error(FTP_CAN_NOT_OPEN_CONNECTION, "Error: no message connection opened.", 0);
        return;
    }
    char buff[256];
    const char *type;
    get_message(_buff, buff, 256);
    struct stat filestat;
    if (lstat(buff, &filestat))
    {
        send_ctl_error(FTP_FILE_UNAVAILABLE, "Failed to open file.", 0);
        return;
    }
    if (m_status.type_mode == FTP_TYPE_BINARY)
    {
        type = "BINARY";
    } else if (m_status.type_mode == FTP_TYPE_ASCII)
    {
        type = "ASCII";
    } else
    {
        send_ctl_error(FTP_NON_EXEC, "Unsupported mode.");
    }

    int n = sprintf(m_buff, "%d opening %s mode data connection for %s.\r\n", FTP_OPEN_CONN, type, buff);
    send_ctl(n);
    FILE *fp = fopen(buff, "r");
    while (!feof(fp))
    {
        if (m_status.is_urg_abort_recved)
        {
            m_status.is_urg_abort_recved = 0;
            n = sprintf(m_buff, "%d Abort successful.\r\n", FTP_CLOSE_DATA_CONN);
            send_ctl(n);
            break;
        }
        n = fread(m_buff, 1, FTP_BUFF_SIZE, fp);
        if (send_message(n) == -1)
            break;
    }
    fclose(fp);
    //close_message_socket();
    shutdown_message_wait();
    n = sprintf(m_buff, "%d Transfer complete.\r\n", FTP_CLOSE_DATA_CONN);
    send_ctl(n);
}
void ftp_session::cmd_STOR_handler(char *_buff)
{
    if (m_status.opened_message_fd == -1)
    {
        send_ctl_error(FTP_CAN_NOT_OPEN_CONNECTION, "Error: no message connection opened.", 0);
        return;
    }
    if (m_conf->conf_read_only || m_status.is_anon && m_conf->conf_anon_read_only)
    {
        send_ctl_error(FTP_FILE_UNAVAILABLE, FTP_ERROR_MESSAGE_PERMISSION_DENIED, 0);
        close_message_socket();
        return;
    }
    char buff[256];
    get_message(_buff, buff, 256);
    FILE *fp;
    if (!(fp = fopen(buff, "w+")))
    {
        send_ctl_error(FTP_FILE_UNAVAILABLE, "Failed to create file.", 0);
        return;
    }
    int n = sprintf(m_buff, "%d OK to send data.\r\n", FTP_OPEN_CONN);
    send_ctl(n);
    while (!m_status.is_urg_abort_recved && (n = recv_message()) > 0)
    {
        fwrite(m_buff, 1, n, fp);
    }
    if (m_status.is_urg_abort_recved)
    {
        m_status.is_urg_abort_recved = 0;
        n = sprintf(m_buff, "%d Abort successful.\r\n", FTP_CLOSE_DATA_CONN);
        send_ctl(n);
    }
    fclose(fp);
    close_message_socket();
    n = sprintf(m_buff, "%d Transfer complete.\r\n", FTP_CLOSE_DATA_CONN);
    send_ctl(n);
}
void ftp_session::cmd_MKD_handler(char *_buff)
{
    if (m_conf->conf_read_only || m_status.is_anon && m_conf->conf_anon_read_only)
    {
        send_ctl_error(FTP_FILE_UNAVAILABLE, FTP_ERROR_MESSAGE_PERMISSION_DENIED, 0);
        return;
    }
    char buff[PATH_MAX + 1];
    rm_CRLF(_buff);
    if (mkdir(_buff, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH))
    {
        send_ctl_error(FTP_FILE_UNAVAILABLE, errno == EEXIST ? "Create directory operation failed(File exists)."
                                                             : "Create directory operation failed.", 0);
        return;
    }
    getcwd(buff, PATH_MAX + 1);
    size_t len = strlen(buff);
    buff[len++] = '/';
    strcpy(buff + len, _buff);
    int n = sprintf(m_buff, "%d \"%s\" created.\r\n", FTP_PATH_CREATED, buff);
    send_ctl(n);
}
void ftp_session::cmd_RMD_handler(char *_buff)
{
    if (m_conf->conf_read_only || m_status.is_anon && m_conf->conf_anon_read_only)
    {
        send_ctl_error(FTP_FILE_UNAVAILABLE, FTP_ERROR_MESSAGE_PERMISSION_DENIED, 0);
        return;
    }
    rm_CRLF(_buff);
    if (rmdir(_buff))
    {
        send_ctl_error(FTP_FILE_UNAVAILABLE,
                       errno == ENOTEMPTY ? "Remove directory operation failed(Directory not empty)."
                                          : "Remove directory operation failed.", 0);
        return;
    }
    int n = sprintf(m_buff, "%d Remove directory operation successful.\r\n", FTP_FIN_FILEB);
    send_ctl(n);
}
void ftp_session::cmd_DELE_handler(char *_buff)
{
    if (m_conf->conf_read_only || m_status.is_anon && m_conf->conf_anon_read_only)
    {
        send_ctl_error(FTP_FILE_UNAVAILABLE, FTP_ERROR_MESSAGE_PERMISSION_DENIED, 0);
        return;
    }
    rm_CRLF(_buff);
    if (unlink(_buff))
    {
        send_ctl_error(FTP_FILE_UNAVAILABLE, "Delete operation failed.", 0);
        return;
    }
    int n = sprintf(m_buff, "%d Delete operation successful.\r\n", FTP_FIN_FILEB);
    send_ctl(n);
}
void ftp_session::cmd_RNFR_handler(char *_buff)
{
    if (m_conf->conf_read_only || m_status.is_anon && m_conf->conf_anon_read_only)
    {
        send_ctl_error(FTP_FILE_UNAVAILABLE, FTP_ERROR_MESSAGE_PERMISSION_DENIED, 0);
        m_status.wait_rnto = 0;
        return;
    }
    rm_CRLF(_buff);
    if (access(_buff, F_OK))
    {
        send_ctl_error(FTP_FILE_UNAVAILABLE, "RNFR command failed.", 0);
        m_status.wait_rnto = 0;
        return;
    }
    memcpy(m_status.rn_buff, _buff, strlen(_buff) + 1);
    m_status.wait_rnto = 1;
    int n = sprintf(m_buff, "%d Ready for RNTO.\r\n", FTP_FILEB_PAUSED);
    send_ctl(n);
}
void ftp_session::cmd_RNTO_handler(char *_buff)
{
    if (!m_status.wait_rnto)
    {
        send_ctl_error(FTP_SEQ_ERROR, "RNTO command failed.", 0);
        return;
    }
    rm_CRLF(_buff);
    if (rename(m_status.rn_buff, _buff))
    {
        send_ctl_error(FTP_NAME_UNAVAILABLE, "Rename failed.", 0);
        m_status.wait_rnto = 0;
        return;
    }
    m_status.wait_rnto = 0;
    int n = sprintf(m_buff, "%d Rename successful.\r\n", FTP_FIN_FILEB);
    send_ctl(n);
}
void ftp_session::cmd_CDUP_handler(char *_buff)
{
    if (chdir(".."))
    {
        send_ctl_error(FTP_FILE_UNAVAILABLE, "Directory changed failed.", 0);
        return;
    }
    int n = sprintf(m_buff, "%d Directory successfully changed.\r\n", FTP_FIN_FILEB);
    send_ctl(n);
}
void ftp_session::cmd_NOOP_handler(char *_buff)
{
    int n = sprintf(m_buff, "%d \r\n", FTP_SUCCESS);
    send_ctl(n);
}
void ftp_session::cmd_PORT_handler(char *_buff)
{
    rm_CRLF(_buff);
    uint16_t port;
    char *ptr = strrchr(_buff, ',');
    port = atoi(ptr + 1);
    *ptr = '\0';
    ptr = strrchr(_buff, ',');
    port += atoi(ptr + 1) * 256;
    *ptr = '\0';
    for (int i = 0; i < strlen(_buff); ++i)
    {
        if (_buff[i] == ',')
            _buff[i] = '.';
    }
    send_request(m_fd_transfer_fd, _buff, port);
    m_status.opened_message_fd = recv_fd(m_fd_transfer_fd);
    if (m_status.opened_message_fd < 0)
    {
        send_ctl_error(FTP_NON_LOGIN_INET, "PORT command failed.", 0);
        return;
    }
    struct timeval timeout{m_conf->conf_transmission_timeout, 0};
    set_send_timeout(m_status.opened_message_fd, &timeout);
    set_recv_timeout(m_status.opened_message_fd, &timeout);
    if (m_conf->conf_ctx && m_status.is_auth_mode)
    {
        m_status.data_socket_ssl = SSL_new(m_conf->conf_ctx);
        SSL_set_fd(m_status.data_socket_ssl, m_status.opened_message_fd);
        SSL_accept(m_status.data_socket_ssl);
    }
    int n = sprintf(m_buff, "%d PORT command successful. Consider using PASV.\r\n", FTP_SUCCESS);
    send_ctl(n);
    m_status.is_passive = 0;
}
void ftp_session::cmd_SIZE_handler(char *_buff)
{
    rm_CRLF(_buff);
    struct stat filestat;
    if (stat(_buff, &filestat) || !S_ISREG(filestat.st_mode))
    {
        send_ctl_error(FTP_FILE_UNAVAILABLE, "Could not get file size.", 0);
        return;
    }
    int n = sprintf(m_buff, "%d %ld\r\n", FTP_FILE_STATUS_RESPONSE, filestat.st_size);
    send_ctl(n);
}
void ftp_session::cmd_ABOR_handler(char *_buff)
{
    send_ctl_error(FTP_ABOR_NO_CONN, "No transfer to abort.", 0);
}
void ftp_session::cmd_PBSZ_handler(char *_buff)
{
    if (!m_conf->conf_ctx || !m_status.is_auth_mode)
    {
        send_ctl_error(FTP_FILE_UNAVAILABLE, "Permission denied.", 0);
        return;
    } else
    {
        strcpy(m_buff, "200 PBSZ is always 0.\r\n");
        send_ctl(strlen(m_buff));
    }
}
void ftp_session::cmd_PROT_handler(char *_buff)
{
    if (!m_conf->conf_ctx || !m_status.is_auth_mode)
    {
        send_ctl_error(FTP_FILE_UNAVAILABLE, "Permission denied.", 0);
        return;
    } else
    {
        rm_CRLF(_buff);
        if (*_buff == 'P')
        {
            m_status.prot_value = 'P';
            strcpy(m_buff, "200 PROT now Private.\r\n");
            send_ctl(strlen(m_buff));
        } else if (*_buff == 'C')
        {
            m_status.prot_value = 'C';
            strcpy(m_buff, "200 PROT now Clear.\r\n");
            send_ctl(strlen(m_buff));
        } else
        {
            send_ctl_error(FTP_ARG_NOT_IMPLEMENT, "PROT not implemented.", 0);
        }
    }
}
void ftp_session::cmd_AUTH_handler(char *_buff)
{
    //already login or sended AUTH command before
    //in this case,entering or changing AUTH mode is not allowed
    if (m_status.is_auth_mode || m_status.is_login || m_status.specifyed_user)
    {
        send_ctl_error(FTP_DENIED_FOR_POLICY_REASONS, "(Re)Entering AUTH mode is not allowed.", 0);
        return;
    }
    if (!m_conf->conf_ctx)
    {
        send_ctl_error(FTP_NON_LOGIN_INET, "Please login with USER and PASS.", 0);
        return;
    }
    rm_CRLF(_buff);
    if (strcmp(_buff, "TLS"))
    {
        send_ctl_error(FTP_DENIED_FOR_POLICY_REASONS, "Authentication mode not supported.", 0);
        return;
    }
    m_status.is_auth_mode = 1;
    int n = sprintf(m_buff, "%d Proceed with negotiation.\r\n", FTP_SECURITY_DATA_EXCHANGED);
    send_ctl(n);
    m_status.ctl_socket_ssl = SSL_new(m_conf->conf_ctx);
    SSL_set_fd(m_status.ctl_socket_ssl, m_ctl_socket);
    SSL_accept(m_status.ctl_socket_ssl);
}
int ftp_session::speed_control::send_start(int _num)
{
    if (m_speed_limit > 0)
    {
        _num = _num > m_speed_limit ? m_speed_limit : _num;
        if (!m_send_num || _num == m_speed_limit)
        {
            gettimeofday(&m_send_start, NULL);
        }
        m_send_num += _num;
    }
    return _num;
}
void ftp_session::speed_control::send_end()
{
    if (m_speed_limit > 0)
    {
        if (m_send_num >= m_speed_limit)
        {
            gettimeofday(&m_send_end, NULL);
            long diff = (MILLION * m_send_end.tv_sec + m_send_end.tv_usec) -
                        (MILLION * m_send_start.tv_sec + m_send_start.tv_usec);
            if (diff < MILLION)
            {
                diff = MILLION - diff;
                do_end(diff);
            }
            m_send_num = 0;
        }
    }
}
void ftp_session::speed_control::recv_start()
{
    if (m_speed_limit > 0)
    {
        if (!m_recv_num)
        {
            gettimeofday(&m_recv_start, NULL);
        }
    }
}
void ftp_session::speed_control::recv_end(int _num)
{
    if (m_speed_limit > 0)
    {
        m_recv_num += _num;
        if (m_recv_num >= m_speed_limit)
        {
            gettimeofday(&m_recv_end, NULL);
            long time_diff = (MILLION * m_recv_end.tv_sec + m_recv_end.tv_usec) -
                             (MILLION * m_recv_start.tv_sec + m_recv_start.tv_usec);
            long t = (m_recv_num) / ((double) m_speed_limit / MILLION);
            long diff = t - time_diff;
            if (diff > 0)
                do_end(diff);
            m_recv_num = 0;
        }
    }
}

void ftp_session::speed_control::do_end(long _diff)
{
    timeval tv;
    tv.tv_sec = _diff / MILLION;
    tv.tv_usec = _diff % MILLION;
    int error;
    do
    {
        error = select(0, NULL, NULL, NULL, &tv);
    } while (error < 0 && errno == EINTR);
}
void ftp_session::speed_control::set_speed_limit(int _speed_limit)
{
    this->m_speed_limit = _speed_limit;
}
