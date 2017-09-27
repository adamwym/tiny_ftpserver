//
// Created by adamwang on 17-6-21.
//

#include "session.h"
#include <arpa/inet.h>
#include <stdio.h>
#include "ftp_def.h"
#include "fd_transfer.h"
//#include <malloc.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <crypt.h>
#include <shadow.h>
#include <iostream>
#include <pwd.h>
#include <sys/stat.h>
#include <assert.h>
#include <limits.h>
#include "ls.h"

void ftp_session::ftp_init()
{
    int n = sprintf(m_buff, "%d (tiny_ftp)\r\n", FTP_READY);
    send_ctl(n);
}
int ftp_session::parse_command(char **_cmd, size_t _length)
{
    int int_return = -1;
    do
    {
        if (strstr(*_cmd, "STOR") == *_cmd)
        {
            *_cmd += 5;
            int_return = FTP_CMD_STOR;
            break;
        }
        if (strstr(*_cmd, "MKD") == *_cmd)
        {
            *_cmd += 4;
            int_return = FTP_CMD_MKD;
            break;
        }
        if (strstr(*_cmd, "RMD") == *_cmd)
        {
            *_cmd += 4;
            int_return = FTP_CMD_RMD;
            break;
        }
        if (strstr(*_cmd, "DELE") == *_cmd)
        {
            *_cmd += 5;
            int_return = FTP_CMD_DELE;
            break;
        }
        if (strstr(*_cmd, "RNFR") == *_cmd)
        {
            *_cmd += 5;
            int_return = FTP_CMD_RNFR;
            break;
        }
        if (strstr(*_cmd, "RNTO") == *_cmd)
        {
            *_cmd += 5;
            int_return = FTP_CMD_RNTO;
            break;
        }
        if (strstr(*_cmd, "USER") == *_cmd)
        {
            *_cmd += 5;
            int_return = FTP_CMD_USER;
            break;
        }
        if (strstr(*_cmd, "PASS") == *_cmd)
        {
            *_cmd += 5;
            int_return = FTP_CMD_PASS;
            break;
        }
        if (strstr(*_cmd, "SYST") == *_cmd)
        {
            int_return = FTP_CMD_SYST;
            break;
        }
        if (strstr(*_cmd, "PASV") == *_cmd)
        {
            int_return = FTP_CMD_PASV;
            break;
        }
        if (strstr(*_cmd, "LIST") == *_cmd)
        {
            *_cmd += 5;
            int_return = FTP_CMD_LIST;
            break;
        }
        if (strstr(*_cmd, "QUIT") == *_cmd)
        {
            int_return = FTP_CMD_QUIT;
            break;
        }
        if (strstr(*_cmd, "PWD") == *_cmd)
        {
            int_return = FTP_CMD_PWD;
            break;
        }
        if (strstr(*_cmd, "CWD") == *_cmd)
        {
            *_cmd += 4;
            int_return = FTP_CMD_CWD;
            break;
        }
        if (strstr(*_cmd, "TYPE") == *_cmd)
        {
            *_cmd += 5;
            int_return = FTP_CMD_TYPE;
            break;
        }
        if (strstr(*_cmd, "RETR") == *_cmd)
        {
            *_cmd += 5;
            int_return = FTP_CMD_RETR;
            break;
        }
        if (strstr(*_cmd, "CDUP") == *_cmd)
        {
            int_return = FTP_CMD_CDUP;
            break;
        }
        if (strstr(*_cmd, "NOOP") == *_cmd)
        {
            int_return = FTP_CMD_NOOP;
            break;
        }
        if (strstr(*_cmd, "PORT") == *_cmd)
        {
            *_cmd += 5;
            int_return = FTP_CMD_PORT;
            break;
        }
        if (strstr(*_cmd, "SIZE") == *_cmd)
        {
            *_cmd += 5;
            int_return = FTP_CMD_SIZE;
            break;
        }
    } while (0);
    return int_return;
}
void ftp_session::close_ctl_socket()
{
    shutdown(m_ctl_socket, SHUT_WR);
    while (recv(m_ctl_socket, m_buff, 256, 0) > 0);
    close(m_ctl_socket);
}
int ftp_session::send_ctl(int _num)
{
    return send(m_ctl_socket, m_buff, _num, 0);
}
int ftp_session::recv_ctl()
{
    int i = recv(m_ctl_socket, m_buff, FTP_BUFF_SIZE, 0);
    m_buff[i] = '\0';
    return i;
}
int ftp_session::recv_message()
{
    int i = recv(m_status.opened_message_fd, m_buff, FTP_BUFF_SIZE + 1, 0);
    m_buff[i] = '\0';
    return i;
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
    char *buff = m_buff;
    while ((n = recv_ctl()) > 0)
    {
        buff = m_buff;
        switch (parse_command(&buff, n))
        {
            case FTP_CMD_USER:
                cmd_user_handler(buff);
                break;
            case FTP_CMD_PASS:
                cmd_pass_handler(buff);
                break;
            case FTP_CMD_SYST:
                cmd_syst_handler();
                break;
            case FTP_CMD_PASV:
                cmd_pasv_handler();
                break;
            case FTP_CMD_LIST:
                cmd_list_handler(buff);
                break;
            case FTP_CMD_QUIT:
                cmd_quit_handler();
                break;
            case FTP_CMD_PWD:
                cmd_pwd_handler();
                break;
            case FTP_CMD_CWD:
                cmd_cwd_handler(buff);
                break;
            case FTP_CMD_TYPE:
                cmd_type_handler(buff);
                break;
            case FTP_CMD_RETR:
                cmd_retr_handler(buff);
                break;
            case FTP_CMD_STOR:
                cmd_stor_handler(buff);
                break;
            case FTP_CMD_MKD:
                cmd_mkd_handler(buff);
                break;
            case FTP_CMD_RMD:
                cmd_rmd_handler(buff);
                break;
            case FTP_CMD_DELE:
                cmd_dele_handler(buff);
                break;
            case FTP_CMD_RNFR:
                cmd_rnfr_handler(buff);
                break;
            case FTP_CMD_RNTO:
                cmd_rnto_handler(buff);
                break;
            case FTP_CMD_CDUP:
                cmd_cdup_handler();
                break;
            case FTP_CMD_NOOP:
                cmd_noop_handler();
                break;
            case FTP_CMD_PORT:
                cmd_port_handler(buff);
                break;
            case FTP_CMD_SIZE:
                cmd_size_handler(buff);
                break;
            default:
                send_ctl_error(FTP_NON_EXEC, "Unsupported command.", 0);
                break;
        }
    }
    if (n == 0)
    {
        close(m_data_socket);
        close(m_fd_transfer_fd);
        close_ctl_socket();
    }
    if (n == -1)
    {
        std::cerr << "error while recv" << std::endl;
        exit(1);
    }
}
void ftp_session::cmd_user_handler(char *_buff)
{
    if (m_status.is_login)
    {
        send_ctl_error(FTP_NON_LOGIN_INET, "Can't change user.", 0);
        return;
    }
    char username[256];
    get_message(_buff, username, 256);
    write(1, username, strlen(username));
    if (m_conf->conf_anon_enable && !m_conf->conf_anon_user.compare(username))
    {
        m_pass = m_conf->conf_anon_login_as;
        m_status.is_anon = 1;
        write(1, "anon\n", 5);
    } else
    {
        m_pass = getpwnam(username);
    }
    m_status.specifyed_user = 1;
    int n = sprintf(m_buff, "%d please specify password\r\n", FTP_NEED_PASS);
    send_ctl(n);
}
void ftp_session::cmd_pass_handler(char *_buff)
{
    char passwd[256];
    get_message(_buff, passwd, 256);
    struct spwd *sp;
    if (!m_pass ||
        !m_status.is_anon && (!(sp = getspnam(m_pass->pw_name)) || strcmp(sp->sp_pwdp, crypt(passwd, sp->sp_pwdp))))
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
void ftp_session::cmd_syst_handler()
{
    send_ctl(sprintf(m_buff, "%d UNIX Type: L8\r\n", FTP_SYS_TYPE));
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
void ftp_session::cmd_quit_handler()
{
    int n = sprintf(m_buff, "%d goodbye\r\n", FTP_QUIT_INET);
    send_ctl(n);
}
void ftp_session::cmd_pwd_handler()
{
    char *path = getcwd(nullptr, 0);
    int n = sprintf(m_buff, "%d \"%s\" is the current directory\r\n", FTP_PATH_CREATED, path);
    free(path);
    send_ctl(n);
}
void ftp_session::cmd_cwd_handler(char *_buff)
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
void ftp_session::cmd_pasv_handler()
{
    struct sockaddr_in sock;
    memset(&sock, 0, sizeof(sock));
    if (m_data_socket == -1)
    {
        socklen_t len = sizeof(sock);
        getsockname(m_ctl_socket, (struct sockaddr *) &sock, &len);
        m_data_socket = socket(AF_INET, SOCK_STREAM, 0);
        //sock.sin_family = AF_INET;
        //sock.sin_addr.s_addr = *(in_addr_t *) netaddrptr;
        sock.sin_port = htons(0);
        bind(m_data_socket, (struct sockaddr *) &sock, sizeof(sock));
        listen(m_data_socket, 10);
    }
    socklen_t n = sizeof(sock);
    getsockname(m_data_socket, (struct sockaddr *) &sock, &n);
    u_char *port = (u_char *) &sock.sin_port;
    u_char *addr = (u_char *) &sock.sin_addr.s_addr;
    int num = sprintf(m_buff, "%d Entering passive mode (%d,%d,%d,%d,%d,%d)\r\n", FTP_PASSIVE_MODE, addr[0], addr[1], addr[2], addr[3], port[0], port[1]);
    m_status.is_passive = 1;
    send_ctl(num);
    m_status.opened_message_fd = accept(m_data_socket, nullptr, nullptr);
}
void ftp_session::cmd_list_handler(char *_buff)
{
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
        send_message(n);
    close_message_socket();
    n = sprintf(m_buff, "%d Directories send OK\r\n", FTP_CLOSE_DATA_CONN);
    send_ctl(n);
}
int ftp_session::send_message(int _num)
{
    return send(m_status.opened_message_fd, m_buff, _num, 0);
}
void ftp_session::close_message_socket()
{
    shutdown(m_status.opened_message_fd, SHUT_RDWR);
    close(m_status.opened_message_fd);
    m_status.opened_message_fd = -1;
}
void ftp_session::cmd_type_handler(char *_buff)
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
void ftp_session::cmd_retr_handler(char *_buff)
{
    char buff[256];
    const char *type;
    get_message(_buff, buff, 256);
    struct stat filestat;
    if (lstat(buff, &filestat))
    {
        send_ctl_error(FTP_FILE_UNAVAILABLE, "Failed to open file.", 0);
        return;
    }
    assert(m_status.opened_message_fd != -1);
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
        n = fread(m_buff, 1, FTP_BUFF_SIZE, fp);
        send_message(n);
    }
    fclose(fp);
    close_message_socket();
    n = sprintf(m_buff, "%d Transfer complete.\r\n", FTP_CLOSE_DATA_CONN);
    send_ctl(n);
}
void ftp_session::cmd_stor_handler(char *_buff)
{
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
    assert(m_status.opened_message_fd != -1);
    int n = sprintf(m_buff, "%d OK to send data.\r\n", FTP_OPEN_CONN);
    send_ctl(n);
    while ((n = recv_message()))
    {
        fwrite(m_buff, 1, n, fp);
    }
    fclose(fp);
    close_message_socket();
    n = sprintf(m_buff, "%d Transfer complete.\r\n", FTP_CLOSE_DATA_CONN);
    send_ctl(n);
}
void ftp_session::cmd_mkd_handler(char *_buff)
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
void ftp_session::cmd_rmd_handler(char *_buff)
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
void ftp_session::cmd_dele_handler(char *_buff)
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
void ftp_session::cmd_rnfr_handler(char *_buff)
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
void ftp_session::cmd_rnto_handler(char *_buff)
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
void ftp_session::cmd_cdup_handler()
{
    if (chdir(".."))
    {
        send_ctl_error(FTP_FILE_UNAVAILABLE, "Directory changed failed.", 0);
        return;
    }
    int n = sprintf(m_buff, "%d Directory successfully changed.\r\n", FTP_FIN_FILEB);
    send_ctl(n);
}
void ftp_session::cmd_noop_handler()
{
    int n = sprintf(m_buff, "%d\r\n", FTP_SUCCESS);
    send_ctl(n);
}
void ftp_session::cmd_port_handler(char *_buff)
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
        send_ctl_error(FTP_NON_LOGIN_INET, "PORT command failed.");
    }
    int n = sprintf(m_buff, "%d PORT command successful. Consider using PASV.\r\n", FTP_SUCCESS);
    send_ctl(n);
    m_status.is_passive = 0;
}
void ftp_session::cmd_size_handler(char *_buff)
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
