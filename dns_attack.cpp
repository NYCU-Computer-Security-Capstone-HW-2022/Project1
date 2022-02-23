#include"dns_attack.h"
using namespace std;

int main(int argc, char* argv[]) {
	cout << argc << endl;
	for (int i = 1; i < argc; ++i)
		printf("%s\n", argv[i]);
}
