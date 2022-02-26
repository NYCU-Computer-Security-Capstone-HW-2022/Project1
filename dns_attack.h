#ifndef DNS_ATTACK
#define DNS_ATTACK

#include "misc.h"
#include <string>
#include <iostream>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in.h>

class dns_attack {
private:
	std::string Victim_IP, Server_IP;
	int Source_Port;
public:
	void attack();
	dns_attack();
	dns_attack(std::string Victim_IP, int Source_Port, std::string Server_IP) : Victim_IP(Victim_IP), Source_Port(Source_Port), Server_IP(Server_IP) {};
};


dns_attack::dns_attack() {
	Source_Port = 0;
	Victim_IP = "";
	Server_IP = "";
}

void dns_attack::attack() {
	int sockfd = Socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
	{
		int one = 1;
		const int *val = &one;
		Setsockopt(sockfd, IPPROTO_UDP, IP_HDRINCL, val, sizeof(int));
	}

}


#endif
