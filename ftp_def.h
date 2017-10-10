//
// Created by adamwang on 17-6-21.
//

#ifndef TINY_FTPSERVER_FTP_DEF_H
#define TINY_FTPSERVER_FTP_DEF_H

#include <string>

#define FTP_BUFF_SIZE 4096

#define FTP_READY 220
#define FTP_QUIT_INET 221
#define  FTP_NEED_PASS 331
#define FTP_LOGIN_INET 230
#define FTP_SYS_TYPE 215
#define FTP_FIN_FILEB 250
#define FTP_PASV 227
#define FTP_OPEN_CONN 150
#define FTP_CLOSE_DATA_CONN 226
#define FTP_NON_LOGIN_INET 530
#define FTP_PATH_CREATED 257
#define FTP_FILE_UNAVAILABLE 550
#define FTP_NAME_UNAVAILABLE 553
#define FTP_NON_EXEC 502
#define FTP_SEQ_ERROR 503
#define FTP_PASSIVE_MODE 227
#define FTP_SUCCESS 200
#define FTP_FILEB_PAUSED 350
#define FTP_FILE_STATUS_RESPONSE 213
#define FTP_ABOR_NO_CONN 225

#define FTP_ERROR_MESSAGE_PERMISSION_DENIED "Permission denied."

#define IAC 0377
#define IP 0364
#define DM 0362

#define FTP_LIST \
        x(FTP_CMD_USER,USER)\
        x(FTP_CMD_PASS,PASS)\
        x(FTP_CMD_SYST,SYST)\
        x(FTP_CMD_PASV,PASV)\
        x(FTP_CMD_LIST,LIST)\
        x(FTP_CMD_QUIT,QUIT)\
        x(FTP_CMD_PWD,PWD)\
        x(FTP_CMD_CWD,CWD)\
        x(FTP_CMD_TYPE,TYPE)\
        x(FTP_CMD_RETR,RETR)\
        x(FTP_CMD_STOR,STOR)\
        x(FTP_CMD_MKD,MKD)\
        x(FTP_CMD_RMD,RMD)\
        x(FTP_CMD_DELE,DELE)\
        x(FTP_CMD_RNFR,RNFR)\
        x(FTP_CMD_RNTO,RNTO)\
        x(FTP_CMD_CDUP,CDUP)\
        x(FTP_CMD_NOOP,NOOP)\
        x(FTP_CMD_PORT,PORT)\
        x(FTP_CMD_SIZE,SIZE)\
        x(FTP_CMD_ABOR,ABOR)
enum
{
    FTP_TYPE_ASCII,
    FTP_TYPE_BINARY,

#define x(a, b) a,
    FTP_LIST
#undef x
};

#define CONF_GROUP_NAME "tiny_ftpserver"
struct conf_status
{
    bool conf_read_only = 0;
    bool conf_local_enable = 1;
    bool conf_anon_enable = 0;
    int conf_local_max_rate = 0;
    int conf_anon_max_rate = 0;
    std::string conf_anon_user = "anonymous";
    bool conf_anon_read_only = 1;
    std::string conf_anon_root = "/var/ftp";
    struct passwd *conf_anon_login_as = NULL;
};
#endif //TINY_FTPSERVER_FTP_DEF_H
