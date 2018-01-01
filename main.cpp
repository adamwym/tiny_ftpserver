
#include <pwd.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <sys/socket.h>
#include <net/if.h>
#include <cstring>
#include <libnet.h>
#include <wait.h>
#include <vector>
#include <openssl/ssl.h>
#include "session.h"
#include "fd_transfer.h"
#include "parse_conf.h"
#include "log.h"
#include "utility.h"

using namespace std;
conf_status *conf = NULL;
SSL_CTX *ctx = NULL;
static int argc = 1;
static char **argv = NULL;
void sigchild_handler(int i)
{
    pid_t pid;
    while ((pid = waitpid(-1, nullptr, WNOHANG)) > 0)
        ftp_log(FTP_LOG_DEBUG, "one client disconnected with pid %d.", pid);
}

void read_conf()
{
    if (conf)
    {
        conf->~conf_status();
        free(conf);
    }
    if (ctx)
    {
        SSL_CTX_free(ctx);
    }
    ctx = SSL_CTX_new(TLS_server_method());
    conf = (conf_status *) malloc(sizeof(conf_status));
    new(conf) conf_status;
    const char *conf_file = NULL;
    if (argv && argc == 2)
        conf_file = argv[1];
    else
        conf_file = "/etc/tiny_ftpserver.conf";
    if (conf_parse(conf_file) != 1)
    {
        ftp_log(FTP_LOG_WARNING, "load conf file failed,using default settings.");
        goto set_default_passwd;
    } else
    {
        ftp_log(FTP_LOG_DEBUG, "loaded %s", conf_file);
        int status;
        if (conf_has_key(CONF_READONLY) && (status = conf_get_bool_YES_NO(CONF_READONLY)) != -1)
        {
            conf->conf_read_only = status;
        }
        if (conf_has_key(CONF_ANON_ENABLED) && (status = conf_get_bool_YES_NO(CONF_ANON_ENABLED)) != -1)
        {
            conf->conf_anon_enable = status;
            ftp_log(FTP_LOG_DEBUG, "anon enabled :%d", conf->conf_anon_enable);
        }
        if (conf_has_key(CONF_ANON_READONLY) && (status = conf_get_bool_YES_NO(CONF_ANON_READONLY)) != -1)
        {
            conf->conf_anon_read_only = status;
            ftp_log(FTP_LOG_DEBUG, "anon readonly :%d", conf->conf_anon_read_only);
        }
        if (conf_has_key(CONF_ANON_ROOT) && !access(conf_get_string(CONF_ANON_ROOT), F_OK))
        {
            conf->conf_anon_root = conf_get_string(CONF_ANON_ROOT);
            ftp_log(FTP_LOG_DEBUG, "anon root :%s", conf->conf_anon_root.c_str());
        }
        if (conf_has_key(CONF_ANON_USER))
        {
            conf->conf_anon_user = conf_get_string(CONF_ANON_USER);
            ftp_log(FTP_LOG_DEBUG, "anon user :%s", conf->conf_anon_user.c_str());
        }
        if (conf_has_key(CONF_LOCAL_ENABLE) && (status = conf_get_bool_YES_NO(CONF_LOCAL_ENABLE)) != -1)
        {
            conf->conf_local_enable = status;
            ftp_log(FTP_LOG_DEBUG, "local enable :%d", conf->conf_local_enable);
            if (!conf->conf_anon_enable && !conf->conf_local_enable)
            {
                ftp_log(FTP_LOG_WARNING, "Waring :both local and anonymous users are disabled ,which means no one can log in.");
            }
        }
        if (conf_has_key(CONF_LOCAL_MAX_RATE))
        {
            conf->conf_local_max_rate = conf_get_int(CONF_LOCAL_MAX_RATE);
            ftp_log(FTP_LOG_DEBUG, "local_max_rate :%d", conf->conf_local_max_rate);
        }
        if (conf_has_key(CONF_ANON_MAX_RATE))
        {
            conf->conf_anon_max_rate = conf_get_int(CONF_ANON_MAX_RATE);
            ftp_log(FTP_LOG_DEBUG, "anon_max_rate :%d", conf->conf_anon_max_rate);
        }
        if (conf_has_key(CONF_IDLE_SESSION_TIMEOUT))
        {
            conf->conf_idle_session_timeout = conf_get_int(CONF_IDLE_SESSION_TIMEOUT);
            ftp_log(FTP_LOG_DEBUG, "idle_session_timeout :%d", conf->conf_idle_session_timeout);
        }
        if (conf_has_key(CONF_TRANSMISSION_TIMEOUT))
        {
            conf->conf_transmission_timeout = conf_get_int(CONF_TRANSMISSION_TIMEOUT);
            ftp_log(FTP_LOG_DEBUG, "transmission_timeout :%d", conf->conf_transmission_timeout);
        }
        if (conf_has_key(CONF_SSL_TLSV1_ENABLE) && !strcmp(conf_get_string(CONF_SSL_TLSV1_ENABLE), "YES"))
        {
            if (conf_has_key(CONF_RSA_CERT_FILE) && conf_has_key(CONF_RSA_PRIVATE_KEY_FILE) &&
                SSL_CTX_use_certificate_file(ctx, conf_get_string(CONF_RSA_CERT_FILE), SSL_FILETYPE_PEM) &&
                SSL_CTX_use_RSAPrivateKey_file(ctx, conf_get_string(CONF_RSA_PRIVATE_KEY_FILE), SSL_FILETYPE_PEM))
            {
                conf->conf_ctx = ctx;
                ftp_log(FTP_LOG_DEBUG, "FTP over TLS enabled");
            } else
            {
                ftp_log(FTP_LOG_ERR, "TLS:pem or key file setting error");
            }
        }

        if (!conf_has_key(CONF_ANON_LOGIN_AS) ||
            !(conf->conf_anon_login_as = getpwnam(conf_get_string(CONF_ANON_LOGIN_AS))))
        {
            set_default_passwd:
            if (!(conf->conf_anon_login_as = getpwnam("ftp")))
            {
                ftp_log(FTP_LOG_ERR, "anon_login_as:user ftp not exists");
            }
        }
    }
    conf_free();
}
void sighup_handler(int i)
{
    ftp_log(FTP_LOG_DEBUG, "get sighup,reload conf file.");
    read_conf();
}
int main(int _argc, char **_argv)
{

#ifdef RUN_AS_DAEMON
    daemon(0, 0);
#endif
    ftp_log_init();
    argc = _argc;
    argv = _argv;
    signal(SIGCHLD, sigchild_handler);
    signal(SIGHUP, sighup_handler);
    if (getuid() != 0)
    {
        ftp_log(FTP_LOG_ERR, "error: not running as su");
    }
    SSL_library_init();
    read_conf();
    int socketfd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_port = htons(21);
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    if (bind(socketfd, (struct sockaddr *) &server_addr, sizeof(server_addr)))
    {
        ftp_log(FTP_LOG_ERR, "error while binding");
    }
    listen(socketfd, 10);
    int sockaccept = -1;
    int forknum = -1;
    vector<int> fd_arry;
    fd_set result, fdset;
    int maxfd = socketfd;
    FD_ZERO(&fdset);
    FD_SET(socketfd, &fdset);
    for (;;)
    {
        result = fdset;
        if (select(maxfd + 1, &result, NULL, NULL, NULL) == -1)
        {
            if (errno == EINTR)
                continue;
            ftp_log(FTP_LOG_ERR, "select error");
        }
        if (FD_ISSET(socketfd, &result))
        {
            sockaccept = accept(socketfd, NULL, NULL);
            ftp_log(FTP_LOG_DEBUG, "one client connected");
            int forkpid;
            int fd[2];
            socketpair(AF_UNIX, SOCK_STREAM, 0, fd);
            if ((forkpid = fork()) == 0)//child
            {
                close(socketfd);
                close(fd[0]);
                ftp_session sess(sockaccept, fd[1], conf);
                sess.ftp_init();
                sess.start_handle();
                exit(0);
            } else if (forkpid > 0)
            {
                close(sockaccept);
                close(fd[1]);
                if (fd[0] > maxfd)
                    maxfd = fd[0];
                FD_SET(fd[0], &fdset);
                fd_arry.push_back(fd[0]);
            } else
            {
                close(sockaccept);
                continue;
            }
        }
        for (auto i = fd_arry.begin(); i != fd_arry.end();)
        {
            if (FD_ISSET(*i, &result))
            {
                struct sockaddr_in sockaddr, socklocal;
                if (recv_request(*i, &sockaddr))
                {
                    memset(&socklocal, 0, sizeof(socklocal));
                    socklocal.sin_port = htons(20);
                    socklocal.sin_family = AF_INET;
                    socklocal.sin_addr.s_addr = sockaddr.sin_addr.s_addr;
                    int sock_to_send = socket(AF_INET, SOCK_STREAM, 0);
                    int flag = 1;
                    setsockopt(sock_to_send, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(int));
                    bind(sock_to_send, (struct sockaddr *) &socklocal, sizeof(socklocal));
                    struct timeval timeout{conf->conf_transmission_timeout, 0};
                    set_send_timeout(sock_to_send, &timeout);//set connect timeout to avoid blocking the main process
                    if (connect(sock_to_send, (struct sockaddr *) &sockaddr, sizeof(struct sockaddr_in)) == -1)
                    {
                        ftp_log(FTP_LOG_WARNING, "error while connecting with PORT mode.");
                        send_fd(*i, -1);
                    } else
                        send_fd(*i, sock_to_send);
                    close(sock_to_send);
                    ++i;
                } else
                {
                    //child closed,remove fd
                    close(*i);
                    FD_CLR(*i, &fdset);
                    ftp_log(FTP_LOG_DEBUG, "one client deleted");
                    fd_arry.erase(i);
                }
            } else
                ++i;
        }
    }
    free(conf);
    return 0;
}