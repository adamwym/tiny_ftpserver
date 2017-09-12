//
// Created by adamwang on 17-6-21.
//

#ifndef TINY_FTPSERVER_FTP_DEF_H
#define TINY_FTPSERVER_FTP_DEF_H

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

enum
{
    FTP_TYPE_ASCII,
    FTP_TYPE_BINARY,


    FTP_CMD_USER,
    FTP_CMD_PASS,
    FTP_CMD_SYST,
    FTP_CMD_PASV,
    FTP_CMD_LIST,
    FTP_CMD_QUIT,
    FTP_CMD_PWD,
    FTP_CMD_CWD,
    FTP_CMD_TYPE,
    FTP_CMD_RETR,
    FTP_CMD_STOR,
    FTP_CMD_MKD,
    FTP_CMD_RMD,
    FTP_CMD_DELE,
    FTP_CMD_RNFR,
    FTP_CMD_RNTO,
    FTP_CMD_CDUP,
    FTP_CMD_NOOP
};
#endif //TINY_FTPSERVER_FTP_DEF_H
