


#include "packet.h"

void analyze(void* p, size_t l)
{
	printf("recv packet len=%zd\n", l);
	hexdump(p, l);
}

int main()
{
  uint8_t data[1000];
  int fd = open_socket("lo");

	while (1) {
		size_t rlen = recv_packet(fd, data, sizeof(data));
		analyze(data, rlen);
	}
}


