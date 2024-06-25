#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

// Ethernet header length
#define SIZE_ETHERNET 14

// Define constants for SMBv2
#define SMB2_HEADER_LENGTH 64
#define SMB2_WRITE_REQUEST 0x0009
#define SMB2_READ_REQUEST  0x0008
#define SMB2_WRITE_RESPONSE 0x0009
#define SMB2_READ_RESPONSE  0x0008

// Metadata structure
struct metadata {
    char filename[256];
    uint32_t filesize;
    char src_ip[16];
    uint16_t src_port;
    char dst_ip[16];
    uint16_t dst_port;
};

// Function prototypes
void parse_pcap(const char *filename);
void handle_packet(const struct pcap_pkthdr *header, const u_char *packet);

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <pcap file>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    parse_pcap(argv[1]);

    return 0;
}

void parse_pcap(const char *filename) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline(filename, errbuf);

    if (handle == NULL) {
        fprintf(stderr, "Could not open pcap file %s: %s\n", filename, errbuf);
        exit(EXIT_FAILURE);
    }

    struct pcap_pkthdr header;
    const u_char *packet;

    while ((packet = pcap_next(handle, &header)) != NULL) {
        handle_packet(&header, packet);
    }

    pcap_close(handle);
}

void handle_packet(const struct pcap_pkthdr *header, const u_char *packet) {
    // Parse Ethernet header
    struct ether_header *eth_header = (struct ether_header *)packet;
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
        return;
    }

    // Parse IP header
    struct ip *ip_header = (struct ip *)(packet + SIZE_ETHERNET);
    int ip_header_length = ip_header->ip_hl * 4;

    // Parse TCP header
    struct tcphdr *tcp_header = (struct tcphdr *)(packet + SIZE_ETHERNET + ip_header_length);
    int tcp_header_length = tcp_header->th_off * 4;

    // Parse SMBv2 packet
    const u_char *payload = packet + SIZE_ETHERNET + ip_header_length + tcp_header_length;
    int payload_length = header->caplen - (SIZE_ETHERNET + ip_header_length + tcp_header_length);

    // Handle SMBv2 packets
    if (payload_length >= SMB2_HEADER_LENGTH) {
        // Extract information and process based on the SMB2 command type
        uint16_t command = ntohs(*(uint16_t *)(payload + 12));
        if (command == SMB2_WRITE_REQUEST || command == SMB2_WRITE_RESPONSE) {
            // Extract file attachment and metadata
        } else if (command == SMB2_READ_REQUEST || command == SMB2_READ_RESPONSE) {
            // Extract file attachment and metadata
        }
    }
}