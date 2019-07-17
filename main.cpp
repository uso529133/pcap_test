#include <pcap.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>

char *g_packet = "\x00\x30\x0d\xc2\x55\xed\x98\x2c\xbc\x6d\x42\x9b\x08\x00\x45\x00" \
				"\x00\x28\xc0\x06\x40\x00\x80\x06\x00\x00\xc0\xa8\x19\x3b\x01\xe1" \
				"\x23\x2d\xd3\x85\x01\xbb\x2c\x38\x8f\x24\xa3\xa5\x4e\xf7\x50\x10" \
				"\x02\x02\xff\x0b\x00\x00\x12\x34\x56";


struct eth_hdr {
	uint8_t dst_mac[6];
	uint8_t src_mac[6];
	uint16_t type;
};

struct ipv4_hdr {
	uint8_t version;
	uint8_t type_of_service;
	uint16_t total_packet_len;
	uint16_t fragment_identification;
	uint16_t flags;
	uint8_t ttl;
	uint8_t protocol;
	uint16_t checksum;
	uint8_t src_ip[4];
	uint8_t dst_ip[4];
};

struct tcp_hdr {
	uint16_t src_port;
	uint16_t dst_port;
	uint32_t seq_num;
	uint32_t ack_num;
	uint16_t flags;
	uint16_t window_size;
	uint16_t checksum;
	uint16_t urgent_ptr;
	uint8_t data[10];
};

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

bool check_type_1(eth_hdr *p) {
	return p->type == htons(0x0800);
}

void print_mac(eth_hdr *p) {
	uint8_t *smac = p->src_mac;
	uint8_t *dmac = p->dst_mac;
	
	printf("source mac : %02x:%02x:%02x:%02x:%02x:%02x\n", smac[0], smac[1], smac[2], smac[3], smac[4], smac[5]);
	printf("destination mac : %02x:%02x:%02x:%02x:%02x:%02x\n", dmac[0], dmac[1], dmac[2], dmac[3], dmac[4], dmac[5]);
}

void print_ip(ipv4_hdr *p) {
	uint8_t *src_ip = p->src_ip;
	uint8_t *dst_ip = p->dst_ip;

	// uint8_t tmp[] = { 0x01, 0xe1, 0x23, 0x2d };
	// src_ip = (uint8_t *)&tmp;

	printf("source ip : %u.%u.%u.%u\n", src_ip[0], src_ip[1], src_ip[2], src_ip[3]);
	printf("destination ip : %u.%u.%u.%u\n", dst_ip[0], dst_ip[1], dst_ip[2], dst_ip[3]);
}

void print_port(tcp_hdr *p) {
	uint16_t src_port = p->src_port;
	uint16_t dst_port = p->dst_port;

	printf("source port : %ld\n", htons(src_port));
	printf("destination port : %ld\n", htons(dst_port));
}

void print_tcp_data(tcp_hdr *p, uint8_t len) {
	uint8_t data = *p->data;

	printf("data : \"");
	for (uint8_t i = 0; i < len; ++i) {
		printf("\\x%x", p->data[i]);
	}
	printf("\"\n");
}

int main(int argc, char* argv[]) {
	
	if (argc != 2) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
		return -1;
	}

  while (true) {
   	struct pcap_pkthdr* header;
   	const u_char* packet;
   	int res = pcap_next_ex(handle, &header, &packet);
	// timeout
	if (res == 0) continue;
	// error / got EOF
   	if (res == -1 || res == -2) break;
		printf("\n\n%u bytes captured\n", header->caplen);
	
		eth_hdr* eth_ptr = (eth_hdr*)packet;
		print_mac(eth_ptr);

		if (eth_ptr->type != 8) continue;

		ipv4_hdr* ipv4_ptr = (ipv4_hdr*) (packet + 14);
		print_ip(ipv4_ptr);

		if (ipv4_ptr->protocol != 6) continue;

		tcp_hdr* tcp_ptr = (tcp_hdr*) (packet + 34);
		print_port(tcp_ptr);

		uint8_t data_len = 54 - header->caplen;
		if (data_len > 10) data_len = 10;

		print_tcp_data(tcp_ptr, data_len);


	}


	pcap_close(handle);

	return 0;
}
