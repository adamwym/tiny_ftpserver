//
// Created by adamwang on 17-9-27.
//

#ifndef TINY_FTPSERVER_LOG_H
#define TINY_FTPSERVER_LOG_H

#include <syslog.h>

#define FTP_LOG_DEBUG LOG_DEBUG
#define FTP_LOG_ERR LOG_ERR
#define FTP_LOG_NOTICE LOG_NOTICE
#define FTP_LOG_INFO LOG_INFO
#define FTP_LOG_WARNING LOG_WARNING
#define FTP_LOG_EMERG LOG_EMERG

void ftp_log(int _log_level ,const char* _str,...);

#endif //TINY_FTPSERVER_LOG_H
