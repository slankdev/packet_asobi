


#include "packet.h"
#define IFNAME "wlp2s0"

void analyze_eth(void* p, size_t l)
{
	printf("Packet Recv len=%zd\n", l);
	hexdump(p, l);
}

int main()
{
  int fd = open_socket(IFNAME);

	while (1) {
		uint8_t data[1000];
		size_t rlen = recv_packet(fd, data, sizeof(data));
		analyze_eth(data, rlen);
		printf("-------------------------\n");
	}
}


