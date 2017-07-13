


#include "packet.h"
#define IFNAME "wlp2s0"

void analyze(void* p, size_t l)
{
	printf("recv packet len=%zd\n", l);
	hexdump(p, l);
}

int main()
{
  uint8_t data[1000];
  int fd = open_socket(IFNAME);

	while (1) {
		size_t rlen = recv_packet(fd, data, sizeof(data));
		analyze(data, rlen);
	}
}


