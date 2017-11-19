//
// Created by adamwang on 17-9-27.
//
#include "log.h"
#include <stdlib.h>
#include <stdarg.h>
#include <limits.h>
#include <iostream>
#include <signal.h>

using namespace std;
void ftp_log(int _log_level, const char *_str, ...)
{
    sigset_t new_mask, old_mask;
    sigemptyset(&new_mask);
    sigaddset(&new_mask, SIGCHLD);
    sigprocmask(SIG_BLOCK, &new_mask, &old_mask);
    va_list ag;
    va_start(ag, _str);
#ifdef RUN_AS_DAEMON
    vsyslog(_log_level, _str, ag);
    if (_log_level == FTP_LOG_ERR)
        exit(1);
#else
        char buff[LINE_MAX + 1];
        vsnprintf(buff, LINE_MAX + 1, _str, ag);
        if (_log_level >= FTP_LOG_INFO)
            cout << buff << endl;
        else
            cerr << buff << endl;
        if (_log_level == FTP_LOG_ERR)
            exit(1);
#endif
    va_end(ag);
    sigprocmask(SIG_SETMASK, &old_mask, NULL);
}
void ftp_log_init()
{
#ifdef RUN_AS_DAEMON
    openlog("tiny_ftpserver", LOG_PID, LOG_FTP);
#endif
}
