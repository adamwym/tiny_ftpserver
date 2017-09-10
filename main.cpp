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
#include "session.h"

using namespace std;
void sigchild_handler(int i)
{
    pid_t pid;
    while((pid= waitpid(-1, nullptr, WNOHANG))>0)
        cout << "one client disconnected with pid " << pid << endl;
}

//void *netaddrptr = nullptr;
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
        cout<<"error while binding"<<endl;
        exit(1);
    }
    listen(socketfd, 10);
    int sockaccept = -1;
    int forknum = -1;
    while ((sockaccept = accept(socketfd, nullptr, nullptr)) != -1)
    {
        cout << "one client connected" << endl;
        if ((forknum = fork()) == 0)//child
        {
            close(socketfd);
            ftp_session sess(sockaccept);
            sess.ftp_init();
            sess.start_handle();
            //sess.close_ctl_socket();
            exit(0);
        } else//parent
        {
            close(sockaccept);
        }
    }
//    char buff[256];
//    while ((sockaccept=accept(socketfd, nullptr, nullptr))!=-1){
//        cout<<"one client connect"<<endl;
//        int n=sprintf(buff,"%d %s\r\n",220,"(tiny_ftpserver)");
//        send(sockaccept,buff,n,0);
//        //while ((n=recv(sockaccept,buff,256,0))>0){
//        recv(sockaccept,buff,256,0);
//        cout<<buff<<endl;
//               send(sockaccept,"331 pass\r\n",10,0);
//        recv(sockaccept,buff,256,0);
//        send(sockaccept,"230 ok\r\n",8,0);
//        recv(sockaccept,buff,256,0);
//        send(sockaccept,"215 UNIX Type: L8\r\n",19,0);
//        //}
//        close(sockaccept);
//        cout<<"disconnect"<<endl;
//    }
    return 0;
}