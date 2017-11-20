//
// Created by adamwang on 17-11-17.
//

#include "utility.h"
#include "log.h"
#include <libnet.h>

void set_recv_timeout(int _fd, struct timeval *_timeout)
{
    int result = setsockopt(_fd, SOL_SOCKET, SO_RCVTIMEO, _timeout, sizeof(struct timeval));
    if (result)
    {
        ftp_log(FTP_LOG_ERR, "error while setsockopt: SO_RCVTIMEO");
    }
}
void get_recv_timeout(int _fd, struct timeval *_timeout)
{
    socklen_t len = sizeof(struct timeval);
    if (getsockopt(_fd, SOL_SOCKET, SO_RCVTIMEO, _timeout, &len))
    {
        ftp_log(FTP_LOG_ERR, "error while getsockopt: SO_RCVTIMEO");
    }
}
void set_send_timeout(int _fd, struct timeval *_timeout)
{
    int result = setsockopt(_fd, SOL_SOCKET, SO_SNDTIMEO, _timeout, sizeof(struct timeval));
    if (result)
    {
        ftp_log(FTP_LOG_ERR, "error while setsockopt: SO_SNDTIMEO");
    }
}
void get_send_timeout(int _fd, struct timeval *_timeout)
{
    socklen_t len = sizeof(struct timeval);
    if (getsockopt(_fd, SOL_SOCKET, SO_SNDTIMEO, _timeout, &len))
    {
        ftp_log(FTP_LOG_ERR, "error while getsockopt: SO_SNDTIMEO");
    }
}
