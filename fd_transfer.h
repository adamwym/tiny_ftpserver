//
// Created by adamwang on 17-9-11.
//

#ifndef TINY_FTPSERVER_FD_TRANSFER_H
#define TINY_FTPSERVER_FD_TRANSFER_H

#include <cstdint>

int send_fd(int sock, int fd_to_send);
int recv_fd(int sock);
int send_request(int sock, const char *_ip_add, uint16_t _port);
struct sockaddr_in *recv_request(int sock, struct sockaddr_in *_addr);
#endif //TINY_FTPSERVER_FD_TRANSFER_H
