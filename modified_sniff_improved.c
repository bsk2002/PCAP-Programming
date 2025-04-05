#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <ctype.h>

/* Ethernet header */
struct ethheader {
    u_char  ether_dhost[6]; /* destination host address */
    u_char  ether_shost[6]; /* source host address */
    u_short ether_type;     /* protocol type (IP, ARP, RARP, etc) */
};

/* IP Header */
struct ipheader {
    unsigned char      iph_ihl:4, //IP header length
                     iph_ver:4; //IP version
    unsigned char      iph_tos; //Type of service
    unsigned short int iph_len; //IP Packet length (data + header)
    unsigned short int iph_ident; //Identification
    unsigned short int iph_flag:3, //Fragmentation flags
                       iph_offset:13; //Flags offset
    unsigned char      iph_ttl; //Time to Live
    unsigned char      iph_protocol; //Protocol type
    unsigned short int iph_chksum; //IP datagram checksum
    struct  in_addr    iph_sourceip; //Source IP address
    struct  in_addr    iph_destip;   //Destination IP address
};

// print MAC address
void print_mac(const u_char *mac) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}



void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    struct ethheader *eth = (struct ethheader *)packet;
    if (ntohs(eth->ether_type) == 0x0800) { // 0x0800 is IP type
        // print MAC, src, dst IP
        printf("\n=== Ethernet Header ===\n");
        printf("Source MAC: ");
        print_mac(eth->ether_shost);
        printf("\n");
        printf("Destination MAC: ");
        print_mac(eth->ether_dhost);
        printf("\n");
        
        // get IP header
        struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));
        
        // get IP Header length
        unsigned int ip_header_len = (ip->iph_ihl & 0x0F) * 4;
        
        // if TCP packet
        if (ip->iph_protocol == IPPROTO_TCP) {
            // print src, dst IP
            printf("\n=== IP Header ===\n");
            printf("Source IP: %s\n", inet_ntoa(ip->iph_sourceip));
            printf("Destination IP: %s\n", inet_ntoa(ip->iph_destip));
            
            // get start position of TCP Header
            unsigned char *tcp_header = packet + sizeof(struct ethheader) + ip_header_len;
            
            // get src, dst Port
            unsigned short src_port = ntohs(*(unsigned short *)(tcp_header));
            unsigned short dst_port = ntohs(*(unsigned short *)(tcp_header + 2));
            
            // print src, dst IP
            printf("\n=== TCP Header ===\n");
            printf("Source Port: %d\n", src_port);
            printf("Destination Port: %d\n", dst_port);
            
            // get TCP Header length (upper 4 bits of 12th byte)
            unsigned int tcp_header_len = (tcp_header[12] >> 4) * 4;
            
            // get start position and length of data
            unsigned int data_offset = sizeof(struct ethheader) + ip_header_len + tcp_header_len;
            unsigned int data_len = ntohs(ip->iph_len) - ip_header_len - tcp_header_len;
            
			// print message data
            if (data_len > 0) {
                printf("\n=== Message ===\n");
                // maximun data_len = 50
                int print_len = (data_len < 50) ? data_len : 50;
                // print by hex
                printf("  Hex: ");
                for (int i = 0; i < print_len; i++) {
                    printf("%02x ", packet[data_offset + i]);
                }
                // print by ASCII
                printf("\n  ASCII: ");
                for (int i = 0; i < print_len; i++) {
                    unsigned char c = packet[data_offset + i];
                    printf("%c", isprint(c) ? c : '.');
                }
                // if more messages exist
                if (data_len > print_len) {
                    printf("\n  ... %d more bytes\n", data_len - print_len);
                }
                printf("\n");
            } else {
                printf("\n=== No Data ===\n");
            }
            printf("\n------------------------------------\n");
        }
    }
}

int main()
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp";
    bpf_u_int32 net;

    // Step 1: Open live pcap session on NIC with name enp0s1
    handle = pcap_open_live("enp0s1", BUFSIZ, 1, 1000, errbuf);

    // Step 2: Compile filter_exp into BPF psuedo-code
    pcap_compile(handle, &fp, filter_exp, 0, net);
    if (pcap_setfilter(handle, &fp) != 0) {
        pcap_perror(handle, "Error:");
        exit(EXIT_FAILURE);
    }

    // Step 3: Capture packets
    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle);   //Close the handle
    return 0;
}
