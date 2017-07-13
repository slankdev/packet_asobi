


#include "packet.h"
#define IFNAME "wlp2s0"

struct Eth_Hdr {
	uint8_t dst[6];
	uint8_t src[6];
	uint16_t type;
	uint8_t data[];
};

struct IP_Hdr {
	uint16_t h;
	uint16_t total_length;
	uint16_t id;
	uint16_t flags;
	uint8_t  ttl;
	uint8_t  protocol;
	uint16_t checksum;
	uint32_t src_addr;
	uint32_t dst_addr;
	uint8_t  data[];
};

struct UDP_Hdr {
	uint16_t src_port;
	uint16_t dst_port;
	uint16_t len;
	uint16_t checksum;
	uint8_t  data[];
};

struct DNS_Hdr {
	uint16_t id;
	uint16_t hoge;
	uint16_t qd_cnt;
	uint16_t an_cnt;
	uint16_t ns_cnt;
	uint16_t ar_cnt;
	uint8_t data[];
};


void analyze_dns(void* p, size_t l)
{
	printf("DNS\n");
	struct DNS_Hdr* dh = (struct DNS_Hdr*)(p);
	printf( "id: %u \n"    , ntohs(dh->id));
	printf( "qd_cnt: %u \n", ntohs(dh->qd_cnt));
	printf( "an_cnt: %u \n", ntohs(dh->an_cnt));
	printf( "ns_cnt: %u \n", ntohs(dh->ns_cnt));
	printf( "ar_cnt: %u \n", ntohs(dh->ar_cnt));

	hexdump(dh->data, l - sizeof(struct DNS_Hdr));
	/* const char* s = (const char*)(dh->data); */
	/* printf(" q: %s \n", s); */
	exit(-1);
}

void analyze_udp(void* p, size_t l)
{
	struct UDP_Hdr* uh = (struct UDP_Hdr*)(p);
	printf("UDP\n");
	printf(" src port: %u \n", ntohs(uh->src_port));
	printf(" dst port: %u \n", ntohs(uh->dst_port));
	printf(" len: %u \n"     , ntohs(uh->len));
	printf(" checksum: %u \n", ntohs(uh->checksum));
	if (ntohs(uh->src_port)==53 || ntohs(uh->dst_port)==53) {
		analyze_dns(uh->data, l - sizeof(struct UDP_Hdr));
	}
}

void analyze_ip(void* p, size_t l)
{
	struct IP_Hdr* ih = (struct IP_Hdr*)(p);
	printf("IP version 4\n");
	printf(" proto: %d ", ih->protocol);
	switch (ih->protocol) {
		case 1: printf("ICMP\n");  break;
		case 6: printf("TCP\n");   break;
		case 17: printf("UDP\n");  break;
		default: printf("unknown\n"); break;
	}
	printf(" src: 0x%08x\n", ntohl(ih->src_addr));
	printf(" dst: 0x%08x\n", ntohl(ih->dst_addr));

	uint8_t hlen = ((ntohs(ih->h) & 0x0f00) >> 8)<<2;
	switch (ih->protocol) {
		case 17:
			analyze_udp(ih->data, l-hlen);
		  break;
	}
}
void analyze_eth(void* p, size_t l)
{
	struct Eth_Hdr* eh = (struct Eth_Hdr*)(p);
	printf("Ethernet\n");
	printf(" src: ");
	for (int i=0; i<6; i++) printf("%02x:", eh->src[i]);
	printf("\n");
	printf(" dst: ");
	for (int i=0; i<6; i++) printf("%02x:", eh->dst[i]);
	printf("\n");
	printf(" type: 0x%04x \n", ntohs(eh->type));
	switch (ntohs(eh->type)) {
		case 0x0800:
			analyze_ip(eh->data, l - sizeof(struct Eth_Hdr)) ;
			break;
	}
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


