#include <fcntl.h>
#include <math.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <iomanip>
#include <iostream>
#include <string>
#include <unordered_map>
#include <vector>

#include "next.h"
#include "stdbool.h"

#define TCP_PROTOCOL_NUMBER 6
#define UDP_PROTOCOL_NUMBER 17
#define HEADER_LEN_SCALING_FACTOR 4
#define REQUIRED_ARGC 4
#define UDP_HEADER_SIZE_BYTES 8
#define MANDATORY_ERR "Mandatory args missing!\n"
#define MODE_ERR "Invalid mode selection!\n"
#define IO_ERR "Unable to create a file descriptor to read trace_file given\n"
#define ERROR 1
#define SUCCESS 0
using namespace std;

void errexit(char *msg) {
    fprintf(stdout, "%s\n", msg);
    exit(ERROR);
}

/* Prints usage information and exits the program */
int usage(char *progname) {
    fprintf(stderr, "usage: %s -t trace_file -s|-l|-p|-m\n", progname);
    exit(ERROR);
}

/* fd - an open file to read packets from
   pinfo - allocated memory to put packet info into for one packet

   returns:
   1 - a packet was read and pinfo is setup for processing the packet
   0 - we have hit the end of the file and no packet is available
 */
unsigned short next_packet(int fd, struct pkt_info *pinfo) {
    struct meta_info meta;
    long unsigned int bytes_read;

    memset(pinfo, 0x0, sizeof(struct pkt_info));
    memset(&meta, 0x0, sizeof(struct meta_info));

    /* read the meta information */
    bytes_read = read(fd, &meta, sizeof(meta));
    if (bytes_read == 0)
        return (0);
    if (bytes_read < sizeof(meta))
        errexit((char *)"cannot read meta information");
    pinfo->caplen = ntohs(meta.caplen);
    /* set pinfo->now based on meta.secs & meta.usecs */
    pinfo->now = (double)(ntohl(meta.secs)) + (double)((double)(ntohl(meta.usecs)) / (double)(pow(10, 6)));
    if (pinfo->caplen == 0)
        return (1);
    if (pinfo->caplen > MAX_PKT_SIZE)
        errexit((char *)"packet too big");
    /* read the packet contents */
    bytes_read = read(fd, pinfo->pkt, pinfo->caplen);
    if (bytes_read < 0)
        errexit((char *)"error reading packet");
    if (bytes_read < pinfo->caplen)
        errexit((char *)"unexpected end of file encountered");
    if (bytes_read < sizeof(struct ether_header))
        return (1);
    pinfo->ethh = (struct ether_header *)pinfo->pkt;
    pinfo->ethh->ether_type = ntohs(pinfo->ethh->ether_type);
    if (pinfo->ethh->ether_type != ETHERTYPE_IP)
        /* nothing more to do with non-IP packets */
        return (1);
    if (pinfo->caplen == sizeof(struct ether_header))
        /* we don't have anything beyond the ethernet header to process */
        return (1);
    /* set pinfo->iph to start of IP header */
    pinfo->iph = (struct iphdr *)(pinfo->pkt + sizeof(struct ether_header));
    int iphdr_size = (pinfo->iph->ihl) * 4;
    /* if TCP packet,
          set pinfo->tcph to the start of the TCP header
          setup values in pinfo->tcph, as needed */
    /* if UDP packet,
          set pinfo->udph to the start of the UDP header,
          setup values in pinfo->udph, as needed */
    if (pinfo->iph->protocol == 6) {
        pinfo->tcph = (struct tcphdr *)(pinfo->pkt + iphdr_size + sizeof(struct ether_header));
    } else if (pinfo->iph->protocol == 17) {
        pinfo->udph = (struct udphdr *)(pinfo->pkt + iphdr_size + sizeof(struct ether_header));
    }
    return (1);
}

void handle_summary_mode(char *trace_file_path) {
    int total_number_of_pkts = 0;
    int num_of_ip_pkts = 0;
    double first_time = 0;
    double last_time = 0;
    struct pkt_info packet;
    int fd = open(trace_file_path, O_RDONLY);

    if (fd == -1) {
        errexit((char *)IO_ERR);
    }

    while (1) {
        if (next_packet(fd, &packet)) {
            if (first_time == 0) {
                first_time = packet.now;
            }
            last_time = packet.now;
            if (packet.ethh->ether_type == ETHERTYPE_IP) {
                num_of_ip_pkts += 1;
            }
            total_number_of_pkts += 1;
        } else {
            break;
        }
    }
    printf("FIRST PKT: %0.6f\n", first_time);
    printf("LAST PKT: %0.6f\n", last_time);
    printf("TOTAL PACKETS: %d\n", total_number_of_pkts);
    printf("IP PACKETS: %d\n", num_of_ip_pkts);
}

void handle_length_mode(char *trace_file_path) {
    int fd = open(trace_file_path, O_RDONLY);
    struct pkt_info packet;

    if (fd == -1) {
        errexit((char *)IO_ERR);
    }

    while (1) {
        double ts = 0.0;            // timestamp
        unsigned short caplen = 0;  // from meta information
        string ip_len;              // total length of IPV4 packet
        string iphl;                // IPV4 packet header length
        string transport;           // T for TCP, U for UDP, ? for others and  - for no IP hdr
        string transport_hl;
        string payload_len;
        if (next_packet(fd, &packet)) {
            // only if ethh present and is an IPV4 pkt, we print a single line of output for each IPV4 packet
            if ((packet.ethh) && (packet.ethh->ether_type == ETHERTYPE_IP)) {
                ts = packet.now;
                caplen = packet.caplen;
                // only if IP header is present
                if (packet.iph) {
                    ip_len = to_string(ntohs(packet.iph->tot_len));  // total length of IPV4 packet
                    iphl = to_string((packet.iph->ihl) * 4);         // IPV4 packet header length
                    // TCP transport protocol
                    if (packet.iph->protocol == TCP_PROTOCOL_NUMBER) {
                        transport = "T";  // T for TCP
                        // if tcp header is present, grab header length
                        if (packet.tcph) {
                            transport_hl = to_string((packet.tcph->th_off) * HEADER_LEN_SCALING_FACTOR);
                            payload_len = to_string(stoi(ip_len) - stoi(iphl) - stoi(transport_hl));
                        } else {
                            transport_hl = "-";  // TCP header not included in the packet trace
                            payload_len = "-";
                        }
                    }
                    // UDP transport protocol
                    else if (packet.iph->protocol == UDP_PROTOCOL_NUMBER) {
                        transport = "U";  // U for UDP
                        if (packet.udph) {
                            transport_hl = to_string(UDP_HEADER_SIZE_BYTES);
                            payload_len = to_string(stoi(ip_len) - stoi(iphl) - stoi(transport_hl));
                        } else {
                            transport_hl = "-";  // UDP header not included in the packet trace
                            payload_len = "-";
                        }
                    } else {
                        transport = "?";     // ? for other protocols
                        transport_hl = "?";  // ? for size of transport header by other protocols besides TCP and UDP
                        payload_len = "?";   // ? for other protocols
                    }
                } else {
                    // if IP header is not present
                    ip_len = "-";        // IPV4 packet header length
                    iphl = "-";          // IPV4 packet header length
                    transport = "-";     // protocol will be - for no IP hdr
                    transport_hl = "-";  // transport header length cannot be determined since IPV4 header is not included
                    payload_len = "-";   // IPV4 header is not present, num of application payload bytes cannot be determined
                }
                cout << ts << " " << caplen << " " << ip_len << " " << iphl << " " << transport << " " << transport_hl << " " << payload_len << endl;
                ip_len.clear();
                iphl.clear();
                transport.clear();
                transport_hl.clear();
                payload_len.clear();
            }
        } else {
            break;
        }
    }
}

int main(int argc, char *argv[]) {
    int opt;
    char *trace_file_path;
    bool IS_TRACE_FILE_GIVEN = false;
    vector<bool> trace_mode = {false,   // IS_SUMMARY_MODE
                               false,   // IS_LENGTH_MODE
                               false,   // IS_PACKET_PRINTING_MODE
                               false};  // IS_TRAFFIC_MATRIX_MODE
    // unordered_map<string, pkt_info> tcp_pkts;  // only to hold TCP packets for the matrix mode

    /* There should only be 4 elements in argv, without which we terminate the program execution. */
    if (argc != REQUIRED_ARGC) {
        usage(argv[0]);
    }

    while (optind < argc) {
        //  To disable the automatic error printing, a colon is added as the first character in optstring:
        if ((opt = getopt(argc, argv, ":t:slpm")) != -1) {
            switch (opt) {
                case 't':
                    IS_TRACE_FILE_GIVEN = true;
                    trace_file_path = optarg;
                    break;
                case 's':
                    trace_mode[0] = true;  // IS_SUMMARY_MODE
                    break;
                case 'l':
                    trace_mode[1] = true;  // IS_LENGTH_MODE
                    break;
                case 'p':
                    trace_mode[2] = true;  // IS_PACKET_PRINTING_MODE
                    break;
                case 'm':
                    trace_mode[3] = true;  // IS_TRAFFIC_MATRIX_MODE
                    break;
                case '?':
                    printf("Unknown option: %c\n", optopt);
                    break;
                case ':':
                    printf("Missing arg for %c\n", optopt);
                    usage(argv[0]);
                    break;
            }
        } else {
            optind += 1;
        }
    }

    /* Mandatory arguments check */
    if (!IS_TRACE_FILE_GIVEN) {
        printf(MANDATORY_ERR);
        usage(argv[0]);
    }

    /* Ensure that only one of the mode is selected */
    // int number_of_modes_selected = count(trace_mode.begin(), trace_mode.end(), true);
    // if (number_of_modes_selected != 1) {
    //     printf(MODE_ERR);
    //     usage(argv[0]);
    // }

    cout << setprecision(6) << fixed;
    if (trace_mode[0]) {
        handle_summary_mode(trace_file_path);
    } else if (trace_mode[1]) {
        handle_length_mode(trace_file_path);
    } else if (trace_mode[2]) {
        // handle_packet_printing_mode();
    } else {
        // handle_traffic_matrix_mode();
    }
}
