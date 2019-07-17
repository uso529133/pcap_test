#include <pcap.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>

struct eth_hdr {
	uint8_t dst_mac[6];
	uint8_t src_mac[6];
	uint16_t type;
};

struct ipv4_hdr {
	uint8_t header_len : 4;
	uint8_t version : 4;
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
	uint8_t header_len : 4;
	uint16_t flags : 12;
	uint16_t window_size;
	uint16_t checksum;
	uint16_t urgent_ptr;
	uint8_t data[10];
};

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
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

	printf("data(%d) : \"", len);
	if (len > 10) len = 10;
	for (uint8_t i = 0; i < len; ++i) {
		printf("\\x%02x", p->data[i]);
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

	uint8_t eth_len;
	uint8_t ipv4_len;
	uint8_t tcp_len;

	if (res == 0) continue;
   	if (res == -1 || res == -2) break;
		eth_hdr* eth_ptr = (eth_hdr*)packet;
		if (eth_ptr->type != 8) continue;
		eth_len = 14;
		ipv4_hdr* ipv4_ptr = (ipv4_hdr*) (packet + eth_len);
		if (ipv4_ptr->protocol != 6) continue;
		ipv4_len = ipv4_ptr->header_len * 4;
		tcp_hdr* tcp_ptr = (tcp_hdr*) (packet + eth_len + ipv4_len);
		tcp_len = (tcp_ptr->flags) * 4;

		printf("\n\n%u bytes captured\n", header->caplen);
		print_mac(eth_ptr);
		print_ip(ipv4_ptr);
		print_port(tcp_ptr);
		
		uint8_t data_len = header->caplen - (eth_len + ipv4_len + tcp_len);

		print_tcp_data(tcp_ptr, data_len);
	}

	pcap_close(handle);

	return 0;
}
