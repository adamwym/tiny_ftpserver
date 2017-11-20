//
// Created by adamwang on 17-11-17.
//

#ifndef TINY_FTPSERVER_UTILITY_H
#define TINY_FTPSERVER_UTILITY_H

#include <time.h>

void set_recv_timeout(int _fd, struct timeval *_timeout);

void get_recv_timeout(int _fd, struct timeval *_timeout);

void set_send_timeout(int _fd, struct timeval *_timeout);

void get_send_timeout(int _fd, struct timeval *_timeout);
#endif //TINY_FTPSERVER_UTILITY_H
