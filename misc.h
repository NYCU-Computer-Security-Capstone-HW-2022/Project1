#ifndef MISC_H_INCLUDED
#define MISC_H_INCLUDED

#include <errno.h>
#include <sys/socket.h>
#include <cstdio>
#include <cstdlib>

void err_sys(const char* s) {
    perror(s);
    exit(1);
}

int Socket(int domain, int type, int protocol) {
    int sockfd = socket(domain, type, protocol);
    if (sockfd == -1) err_sys("Socket Error: ");
    return sockfd;
}

void Setsockopt(int socket, int level, int option_name, const void *option_value, socklen_t option_len) {
    int status = setsockopt(socket, level, option_name, option_value, option_len);
    if (status < 0) err_sys("Set socket option error: ");
}


#endif