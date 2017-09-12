#include <iostream>
#include <arpa/inet.h>
#include <ifaddrs.h>
//#include <netdb.h>
#include <sys/socket.h>
#include <net/if.h>
//#include <sys/ioctl.h>
#include <cstring>
#include <libnet.h>
#include <wait.h>
#include <vector>
#include "session.h"
#include "fd_transfer.h"

using namespace std;
void sigchild_handler(int i)
{
    pid_t pid;
    while ((pid = waitpid(-1, nullptr, WNOHANG)) > 0)
        cout << "one client disconnected with pid " << pid << endl;
}

int main()
{
    signal(SIGCHLD, sigchild_handler);
    if (getuid() != 0)
    {
        cout << "error: not running as su" << endl;
        exit(1);
    }

//    struct ifaddrs *ifaddr = nullptr;
//
//    char addrbuff[INET_ADDRSTRLEN];
//    getifaddrs(&ifaddr);
//    while (ifaddr)
//    {
//        if (ifaddr->ifa_addr->sa_family == AF_INET && ifaddr->ifa_name[0] == 'w' | ifaddr->ifa_name[0] == 'e')
//        {
//            //if (ifaddr->ifa_addr->sa_family==AF_INET){
//            netaddrptr = &((struct sockaddr_in *) ifaddr->ifa_addr)->sin_addr;
//            //inet_ntop(AF_INET, netaddrptr, addrbuff, INET_ADDRSTRLEN);
//            break;
//        }
//        ifaddr = ifaddr->ifa_next;
//    }
    int socketfd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_port = htons(21);
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    if (bind(socketfd, (struct sockaddr *) &server_addr, sizeof(server_addr)))
    {
        cout << "error while binding" << endl;
        exit(1);
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
            cout << "select error" << endl;
            exit(1);
        }
        if (FD_ISSET(socketfd, &result))
        {
            cout << "one client connected" << endl;
            sockaccept = accept(socketfd, NULL, NULL);
            int forkpid;
            int fd[2];
            socketpair(AF_UNIX, SOCK_STREAM, 0, fd);
            if ((forkpid = fork()) == 0)//child
            {
                close(socketfd);
                close(fd[0]);
                ftp_session sess(sockaccept, fd[1]);
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
                    connect(sock_to_send, (struct sockaddr *) &sockaddr, sizeof(struct sockaddr_in));
                    send_fd(*i, sock_to_send);
                    close(sock_to_send);
                    ++i;
                } else
                {
                    //child closed,remove fd
                    close(*i);
                    FD_CLR(*i, &fdset);
                    cout << "one client deleted" << endl;
                    fd_arry.erase(i);
                }
            } else
                ++i;
        }
    }

    return 0;
}