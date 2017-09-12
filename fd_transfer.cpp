//
// Created by adamwang on 17-9-11.
//
#include <stdio.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <malloc.h>
#include <stdio.h>
#include <unistd.h>
#include <assert.h>
#include <cstring>
#include <netinet/in.h>
#include <libnet.h>
#include "fd_transfer.h"
int send_fd(int sock, int fd_to_send)
{
    iovec iov[1];
    char buff[1];
    iov[0].iov_base=buff;
    iov[0].iov_len=sizeof(buff);
    buff[0]=0;
    int cmsgsize=CMSG_LEN(sizeof(int));
    cmsghdr *cmptr = (cmsghdr *) malloc(cmsgsize);
    cmptr->cmsg_level=SOL_SOCKET;
    cmptr->cmsg_type=SCM_RIGHTS;
    cmptr->cmsg_len=cmsgsize;
    msghdr msg;
    msg.msg_iov=iov;
    msg.msg_iovlen=1;
    msg.msg_name=NULL;
    msg.msg_namelen=0;
    msg.msg_control=cmptr;
    msg.msg_controllen=cmsgsize;
    *(int*)CMSG_DATA(cmptr)=fd_to_send;
    int result=sendmsg(sock, &msg, 0);
    free(cmptr);
    return result;
}
int send_request(int sock,const char* _ip_add,uint16_t _port){
    iovec iov[1];
    char buff[23];
    int n=sprintf(buff, "1%s %hu", _ip_add, _port);
    assert(n<=sizeof(buff));
//    iov[0].iov_base=buff;
//    iov[0].iov_len=sizeof(buff);
//    int cmsgsize=CMSG_LEN(sizeof(int));
//    cmsghdr *cmptr = (cmsghdr *) malloc(cmsgsize);
//    cmptr->cmsg_level=SOL_SOCKET;
//    cmptr->cmsg_type=SCM_RIGHTS;
//    cmptr->cmsg_len=cmsgsize;
//    msghdr msg;
//    msg.msg_iov=iov;
//    msg.msg_iovlen=1;
//    msg.msg_name=NULL;
//    msg.msg_namelen=0;
//    msg.msg_control=cmptr;
//    msg.msg_controllen=cmsgsize;
//    *(int*)CMSG_DATA(cmptr)=fd_to_send;
//    int result=sendmsg(sock, &msg, 0);
//    free(cmptr);
//    return result;
    if (write(sock, buff,strlen(buff))==strlen(buff))
        return 0;
    else
        return -1;
}
int recv_fd(int sock)
{
    int cmsgsize=CMSG_LEN(sizeof(int));
    cmsghdr *cmptr = (cmsghdr *) malloc(cmsgsize);
    char buff[23];
    iovec iov[1];
    iov[0].iov_base=buff;
    iov[0].iov_len=sizeof(buff);
    msghdr msg;
    msg.msg_iov=iov;
    msg.msg_iovlen=1;
    msg.msg_name=NULL;
    msg.msg_namelen=0;
    msg.msg_control=cmptr;
    msg.msg_controllen=cmsgsize;
    int num=recvmsg(sock,&msg,0);
    if (buff[0]){
        free(cmptr);
        return -1;
    }
    int getedfd=*(int*)CMSG_DATA(cmptr);
    free(cmptr);
    return getedfd;
}
struct sockaddr_in* recv_request(int sock,struct sockaddr_in* _addr){
    assert(_addr);
    int cmsgsize=CMSG_LEN(sizeof(int));
    cmsghdr *cmptr = (cmsghdr *) malloc(cmsgsize);
    char buff[23];
    iovec iov[1];
    iov[0].iov_base=buff;
    iov[0].iov_len=sizeof(buff);
    msghdr msg;
    msg.msg_iov=iov;
    msg.msg_iovlen=1;
    msg.msg_name=NULL;
    msg.msg_namelen=0;
    msg.msg_control=cmptr;
    msg.msg_controllen=cmsgsize;
    int num=recvmsg(sock,&msg,0);
    char ip_buff[INET_ADDRSTRLEN];
    uint16_t port;
    if (buff[0]!=1)
    {
        free(cmptr);
        return NULL;
    }
    scanf("1%s %hu", ip_buff, &port);
    memset(_addr,0,sizeof(struct sockaddr_in));
    _addr->sin_port = htons(port);
    _addr->sin_family=AF_INET;
    _addr->sin_addr.s_addr = inet_addr(ip_buff);
    free(cmptr);
    return _addr;
}
