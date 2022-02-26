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

void Close(int connfd) {
    int status;
    if ((status = close(connfd)) == -1) err_sys("Close Error: ");
}

void Setsockopt(int socket, int level, int option_name, const void *option_value, socklen_t option_len) {
    int status = setsockopt(socket, level, option_name, option_value, option_len);
    if (status < 0) err_sys("Set socket option error: ");
}

unsigned short getCheckSum(unsigned short *buffer, int nwords) {
    unsigned short* now = buffer;
    unsigned long sum = 0;

    while (nwords--) {
        sum += *now;
        now++;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);

    return (unsigned short)(~sum);
}

#endif
