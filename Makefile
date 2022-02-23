OUT = dns_attack
FILE_NAME = dns_attack.cpp
CFLAGS = -Wall -std=c++17
CC = gcc

all: ${FILE_NAME}
	@if [ "$(suffix $<)" = ".cpp" ]; then\
		g++ ${CFLAGS} $< -o ${OUT};\
	else\
		echo "There is no dns_attack.cpp file in the src/ folder.";\
    fi

clean: ${OUT}
	@rm -f ${OUT}
