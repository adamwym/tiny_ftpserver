//
// Created by adamwang on 17-9-27.
//
#include "log.h"
#include <stdlib.h>
#include <stdarg.h>
#include <limits.h>
#include <iostream>

using namespace std;
void ftp_log(int _log_level, const char *_str, ...)
{
    va_list ag;
    va_start(ag, _str);
#ifdef RUN_AS_DAEMON
    vsyslog(_log_level, _str, ag);
    if (_log_level == FTP_LOG_EMERG)
        exit(1);
#else
        char buff[LINE_MAX + 1];
        vsnprintf(buff, LINE_MAX + 1, _str, ag);
        if (_log_level >= FTP_LOG_INFO)
            cout << buff << endl;
        else
            cerr << buff << endl;
        if (_log_level == FTP_LOG_EMERG)
            exit(1);
#endif
    va_end(ag);
}
void ftp_log_init()
{
#ifdef RUN_AS_DAEMON
    openlog("tiny_ftpserver", LOG_PID, LOG_FTP);
#endif
}
