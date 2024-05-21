#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pcap.h>
#include <time.h>
#include <netinet/in.h>
#include <arpa/inet.h>

// Declaration
#define ETHERNET_LEN 14
#define HEADER_LEN 40
#define TRANSPORT_LAYOR_OFFSET 54
#define MAX_CONNECTIONS 1000 // 최대 연결 수 제한

typedef unsigned char u_char;
typedef unsigned int u_int;
typedef unsigned short u_short;
typedef struct
{
    char connection[200];
    u_int total_bytes;
    u_int last_seq;
    u_int next_expected_seq;
} Connection;
// Function Initialize
void Local_Time(const struct pcap_pkthdr *);
void Length_Info(const struct pcap_pkthdr *, const u_char *);
void IP_ADDR(const u_char *);
void Traffic_Flow_Info(const u_char *);
void IP_Payload_Length(const u_char *);
void Port_Number(const struct pcap_pkthdr *, const u_char *);
void print_TCP_Values(const struct pcap_pkthdr *, const u_char *);
void print_UDP_Values(const struct pcap_pkthdr *, const u_char *);
void Application_Type(const struct pcap_pkthdr *, const u_char *);
void Count_Connections(const struct pcap_pkthdr *, const u_char *);
// Global Variables
u_int packet_number = 1;
u_int max_tcp_payload = 0;
u_int max_udp_payload = 0;
Connection connections[MAX_CONNECTIONS]; // 연결 목록 배열
int connection_count = 0;                // 현재 연결 수

// #1. Print Local Time
void Local_Time(const struct pcap_pkthdr *pkthdr)
{
    struct tm *local_time;
    char output[16];
    time_t time_sec = pkthdr->ts.tv_sec;
    time_t time_usec = pkthdr->ts.tv_usec;
    // Convert the timestamp to readable format
    local_time = localtime(&time_sec);
    strftime(output, sizeof(output), "%H:%M:%S", local_time);
    // Append microseconds to the time string
    sprintf(output + strlen(output), ".%06d", time_usec);

    // Output the local time
    printf("Local time: %s\n", output);
}

// #2. caplen & len & IP Header length
void Length_Info(const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    u_int cap_len = pkthdr->caplen;
    u_int len = pkthdr->len;
    u_char payload_length = HEADER_LEN;
    // u_char payload_length = ((packet[18] << 8) | packet[19]);

    printf("Captured length: %u bytes || ", cap_len);
    printf("Actual length: %u bytes || ", len);
    printf("Length in the IP header: %u bytes\n", payload_length);
}

// #3. SRCIP to DSTIP
void IP_ADDR(const u_char *packet)
{
    char src_ip[40], dst_ip[40];

    // Format the source IP address
    sprintf(src_ip, "%x:%x:%x:%x:%x:%x:%x:%x",
            (packet[22] << 8) | packet[23], (packet[24] << 8) | packet[25],
            (packet[26] << 8) | packet[27], (packet[28] << 8) | packet[29],
            (packet[30] << 8) | packet[31], (packet[32] << 8) | packet[33],
            (packet[34] << 8) | packet[35], (packet[36] << 8) | packet[37]);

    // Format the destination IP address
    sprintf(dst_ip, "%x:%x:%x:%x:%x:%x:%x:%x",
            (packet[38] << 8) | packet[39], (packet[40] << 8) | packet[41],
            (packet[42] << 8) | packet[43], (packet[44] << 8) | packet[45],
            (packet[46] << 8) | packet[47], (packet[48] << 8) | packet[49],
            (packet[50] << 8) | packet[51], (packet[52] << 8) | packet[53]);

    // Print the source and destination IP addresses
    printf("Source IP: %s  --->  Destination IP: %s\n", src_ip, dst_ip);
}
// #4. Traffic class & flow label
void Traffic_Flow_Info(const u_char *packet)
{
    // Traffic class
    // Last 4bit of 14'th Byte + First 4bit of 15'th Byte
    u_char traffic_class = ((packet[14] & 0x0F) << 4) | ((packet[15] & 0xF0) >> 4);

    // Flow label
    // Last 4bit of 15'th Byte + 16'th Byte + 17'th Byte
    u_int flow_label = ((packet[15] & 0x0F) << 16) | (packet[16] << 8) | packet[17];

    printf("Traffic Class: 0x%02x\n", traffic_class);
    printf("Flow Label: 0x%05x\n", flow_label);
}

// #5. Payload Length
void IP_Payload_Length(const u_char *packet)
{
    // 18'th Byte and 19'th Byte
    u_int ipv6_payload_length = (packet[18] << 8) | packet[19];

    printf("Paylod Length: %d bytes\n", ipv6_payload_length);
}

// #6. SRCPort & DSTPort
void Port_Number(const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    // Extract Next Header field to determine protocol (TCP or UDP)
    u_char next_header = packet[20];

    u_short src_port, dst_port;
    src_port = (packet[TRANSPORT_LAYOR_OFFSET] << 8) | packet[TRANSPORT_LAYOR_OFFSET + 1];
    dst_port = (packet[TRANSPORT_LAYOR_OFFSET + 2] << 8) | packet[TRANSPORT_LAYOR_OFFSET + 3];
    printf("Source Port: %u ", src_port);
    printf("Destination Port: %u\n", dst_port);
    // Check for TCP or UDP
    if (next_header == 6)
    {
        printf("------------TCP------------\n");
        print_TCP_Values(pkthdr, packet);
    }
    else if (next_header == 17)
    {
        printf("------------UDP------------\n");
        print_UDP_Values(pkthdr, packet);
    }
}

// Printing TCP Values
void print_TCP_Values(const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    // #7. Sequence Number
    // Extract the starting sequence number (4 bytes starting from offset 54)
    u_int start_seqence_number = (packet[TRANSPORT_LAYOR_OFFSET + 4] << 24) | (packet[TRANSPORT_LAYOR_OFFSET + 5] << 16) | (packet[TRANSPORT_LAYOR_OFFSET + 6] << 8) | packet[TRANSPORT_LAYOR_OFFSET + 7];
    // Extract the TCP header length (in 32-bit words)
    u_char tcp_header_length = ((packet[TRANSPORT_LAYOR_OFFSET + 12] & 0xF0) >> 4) * 4; // Header Len 가중치 4

    // Calculate the TCP payload length
    u_int payload_size = pkthdr->len - (TRANSPORT_LAYOR_OFFSET + tcp_header_length);

    // Calculate the ending sequence number
    u_int end_seqence_number = start_seqence_number + payload_size;

    printf("Starting Sequence Number(raw): %u\n", start_seqence_number);
    if (payload_size != 0)
    {
        printf("Ending Sequence Number(raw): %u\n", end_seqence_number);
    }

    // #8. Acknowledgement Number
    u_int ack_number = (packet[TRANSPORT_LAYOR_OFFSET + 8] << 24) | (packet[TRANSPORT_LAYOR_OFFSET + 9] << 16) | (packet[TRANSPORT_LAYOR_OFFSET + 10] << 8) | packet[TRANSPORT_LAYOR_OFFSET + 11];

    printf("Acknowledgement Number: %u\n", ack_number);

    // #9. Payload Size
    if (payload_size > max_tcp_payload)
    {
        max_tcp_payload = payload_size;
    }
    printf("Payload Size: %u\n", payload_size);

    // #10. Window Size
    u_int window_size = (packet[TRANSPORT_LAYOR_OFFSET + 14] << 8) | packet[TRANSPORT_LAYOR_OFFSET + 15];
    printf("Window Size: %u\n", window_size);

    // #11. Flags
    u_char tcp_flags = packet[TRANSPORT_LAYOR_OFFSET + 13];
    u_char f_urg = 0, f_ack = 0, f_psh = 0, f_rst = 0, f_syn = 0, f_fin = 0;
    if (tcp_flags & 0x01)
        f_fin = 1;
    if (tcp_flags & 0x02)
        f_syn = 1;
    if (tcp_flags & 0x04)
        f_rst = 1;
    if (tcp_flags & 0x08)
        f_psh = 1;
    if (tcp_flags & 0x10)
        f_ack = 1;
    if (tcp_flags & 0x20)
        f_urg = 1;
    printf("Flags\n");
    printf("urg: %u | ack: %u | psh: %u | rst: %u | syn: %u | fin: %u\n", f_urg, f_ack, f_psh, f_rst, f_syn, f_fin);

    // #12. TCP Options (if exist)
    // TCP 옵션의 시작 위치
    int OPTIONS_OFFSET = TRANSPORT_LAYOR_OFFSET + 20;

    // TCP 옵션의 길이
    int options_length = tcp_header_length - 20;
    if (options_length > 0)
    {
        printf("Options(Total Length: %u)\n", options_length);
        for (int i = 0; i < options_length;)
        {
            // 옵션 종류
            u_char option_kind_number = packet[OPTIONS_OFFSET + i];
            char option_kind[16];
            switch (option_kind_number)
            {
            case 0:
                sprintf(option_kind, "No more options");
                break;
            case 1:
                sprintf(option_kind, "No Operation (NOP)");
                break;
            case 2:
                sprintf(option_kind, "Maximum Segment Size");
                break;
            case 3:
                sprintf(option_kind, "Window Scale");
                break;
            case 4:
                sprintf(option_kind, "SACK Permitted");
                break;
            case 5:
                sprintf(option_kind, "SACK");
                break;
            case 6:
                sprintf(option_kind, "Echo");
                break;
            case 7:
                sprintf(option_kind, "Echo Reply");
                break;
            case 8:
                sprintf(option_kind, "Timestamps");
                break;
            }
            // 옵션 길이
            u_char option_length = 0;
            if (option_kind_number == 0 || option_kind_number == 1) // End of Options 또는 No-Operation
            {
                option_length = 1;
            }
            else
            {
                option_length = packet[OPTIONS_OFFSET + i + 1];
            }
            printf("  Option Kind: %s, Length: %u\n", option_kind, option_length);
            i += option_length; // 다음 옵션으로 이동.
        }
    }
}

// Printing TCP Values
void print_UDP_Values(const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    // #13. Payload size
    // UDP Length - 8B
    u_int udp_payload_size = ((packet[TRANSPORT_LAYOR_OFFSET + 4] << 8) | packet[TRANSPORT_LAYOR_OFFSET + 5]) - 8;
    if (udp_payload_size > max_udp_payload)
    {
        max_udp_payload = udp_payload_size;
        // max_ucp_packet_number = packet_number;
    }
    printf("Payload Size: %u bytes\n", udp_payload_size);
}

// #15. Application type in segment if they are known
void Application_Type(const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    u_char next_header = packet[20];

    u_short src_port, dst_port;
    if (next_header == 6 || next_header == 17) // TCP or UDP
    {
        src_port = (packet[TRANSPORT_LAYOR_OFFSET] << 8) | packet[TRANSPORT_LAYOR_OFFSET + 1];
        dst_port = (packet[TRANSPORT_LAYOR_OFFSET + 2] << 8) | packet[TRANSPORT_LAYOR_OFFSET + 3];

        printf("Application Type: ");
        if (src_port == 21 || dst_port == 21)
        {
            printf("FTP");
        }
        else if (src_port == 22 || dst_port == 22)
        {
            printf("SSH");
        }
        else if (src_port == 25 || dst_port == 25)
        {
            printf("SMTP");
        }
        else if (src_port == 53 || dst_port == 53)
        {
            printf("DNS");
        }
        else if (src_port == 80 || dst_port == 80)
        {
            printf("HTTP");
        }
        else if (src_port == 110 || dst_port == 110)
        {
            printf("POP");
        }
        else if (src_port == 123 || dst_port == 123)
        {
            printf("NTP");
        }
        else if (src_port == 143 || dst_port == 143)
        {
            printf("IMAP");
        }
        else if (src_port == 443 || dst_port == 443)
        {
            printf("HTTPS");
        }
        else if (src_port == 631 || dst_port == 631)
        {
            printf("IPP");
        }
        else
        {
            printf("unknown");
        }

        printf("\n");
    }
    else
    {
        printf("Not a TCP or UDP packet.\n");
    }
}

// #16. Number of Connections based on 5 tuples
void Count_Connections(const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    // Extract Next Header field to determine if the protocol is TCP or UDP
    u_char next_header = packet[20];
    // if (next_header == 17) // UDP
    if (next_header == 6 || next_header == 17) // TCP or UDP
    {
        // Extract source and destination IP addresses (16 bytes each for IPv6)
        char src_ip[40], dst_ip[40];

        sprintf(src_ip, "%x:%x:%x:%x:%x:%x:%x:%x",
                (packet[22] << 8) | packet[23], (packet[24] << 8) | packet[25],
                (packet[26] << 8) | packet[27], (packet[28] << 8) | packet[29],
                (packet[30] << 8) | packet[31], (packet[32] << 8) | packet[33],
                (packet[34] << 8) | packet[35], (packet[36] << 8) | packet[37]);

        sprintf(dst_ip, "%x:%x:%x:%x:%x:%x:%x:%x",
                (packet[38] << 8) | packet[39], (packet[40] << 8) | packet[41],
                (packet[42] << 8) | packet[43], (packet[44] << 8) | packet[45],
                (packet[46] << 8) | packet[47], (packet[48] << 8) | packet[49],
                (packet[50] << 8) | packet[51], (packet[52] << 8) | packet[53]);

        // Extract source and destination ports
        u_short src_port = (packet[TRANSPORT_LAYOR_OFFSET] << 8) | packet[TRANSPORT_LAYOR_OFFSET + 1];
        u_short dst_port = (packet[TRANSPORT_LAYOR_OFFSET + 2] << 8) | packet[TRANSPORT_LAYOR_OFFSET + 3];

        // Sequence Number and Payload Length
        u_int seq_num = ntohl(*(u_int *)(packet + TRANSPORT_LAYOR_OFFSET + 4));
        u_int payload_len = pkthdr->len - TRANSPORT_LAYOR_OFFSET;

        // Create a string representation of the 5-tuple
        char connection_tuple1[200], connection_tuple2[200];
        snprintf(connection_tuple1, sizeof(connection_tuple1), "%s:%u -> %s:%u -> (protocal: %u)", src_ip, src_port, dst_ip, dst_port, next_header);
        snprintf(connection_tuple2, sizeof(connection_tuple2), "%s:%u -> %s:%u -> (protocal: %u)", dst_ip, dst_port, src_ip, src_port, next_header);

        // Check if this connection already exists in the list
        int found = 0, i = 0;
        for (i = 0; i < connection_count; i++)
        {
            if ((strcmp(connections[i].connection, connection_tuple1) == 0) || (strcmp(connections[i].connection, connection_tuple2) == 0))
            {
                found = 1;
                break;
            }
        }

        // Connection does not exist, add it to the list
        if (!found)
        {
            if (connection_count < MAX_CONNECTIONS)
            {
                strcpy(connections[connection_count].connection, connection_tuple1);
                if (next_header == 6)
                {
                    connections[connection_count].last_seq = seq_num;
                    connections[connection_count].next_expected_seq = seq_num + payload_len;
                }
                connections[connection_count].total_bytes = pkthdr->len;
                connection_count++;
            }
            else
            {
                printf("Error: Maximum number of connections reached.\n");
            }
        }
        // Connection Exist
        else
        {
            // TCP Only
            if (next_header == 6)
            {
                if (seq_num < connections[i].next_expected_seq)
                {
                    if (seq_num > connections[i].last_seq)
                    {
                        printf("Packet Loss Detected: %u\n", seq_num);
                    }
                    else if (seq_num < connections[i].last_seq)
                    {
                        printf("Duplicated Sequence Detected: %u\n", seq_num);
                    }
                }
                else if (seq_num > connections[i].next_expected_seq)
                {
                    printf("Out of Order Sequence Detected: seq_num: %u - expected_seq_num %u\n", seq_num, connections[i].next_expected_seq);
                }
                connections[i].last_seq = seq_num;
                connections[i].next_expected_seq = seq_num + payload_len;
            }

            connections[i].total_bytes += pkthdr->len;
        }
    }
}

void packet_analize(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{

    printf("\n[Packet #%d]\n", packet_number);
    // # 1. Local Time
    Local_Time(pkthdr);

    // #2. caplen & len & IP Header length
    Length_Info(pkthdr, packet);

    // #3. SRCIP to DSTIP
    IP_ADDR(packet);

    // #4. Traffic class & flow label
    Traffic_Flow_Info(packet);

    // #5. Payload Length
    IP_Payload_Length(packet);

    // #6. SRCPort & DSTPort
    // TCP: #7 ~ #12
    // UDP: #13
    Port_Number(pkthdr, packet);

    // #15. Application Type
    Application_Type(pkthdr, packet);

    // #16. Connections Count
    Count_Connections(pkthdr, packet);
    // }
    packet_number++;
}

int main(int argc, char *argv[])
{
    pcap_t *handle;                  // Packet capture handle
    char errbuf[PCAP_ERRBUF_SIZE];   // Error string
    const char *file = "trace.pcap"; // File name to analyze
    if (argc >= 2)
    {
        file = argv[1]; // Get file name from command line
    }
    // Open file
    handle = pcap_open_offline(file, errbuf);
    if (!handle)
    {
        fprintf(stderr, "Error Occured: pcap_open_offline() %s\n", errbuf);
        return 1;
    }
    // Loop to process packets
    if (pcap_loop(handle, 0, packet_analize, NULL) < 0)
    {
        fprintf(stderr, "Error Occured: pcap_loop() %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return 1;
    }
    // #14. print Max Payload for TCP and UDP
    printf("Max TCP Payload Size: %u\n", max_tcp_payload);
    printf("Max UDP Payload Size: %u\n", max_udp_payload);

    // #16. Connections Count
    printf("Number of unique connections: %d\n", connection_count);
    for (int i = 0; i < connection_count; i++)
    {
        printf("Connection: %s, Total Bytes:%d \n", connections[i].connection, connections[i].total_bytes);
    }

    // Cleanup
    pcap_close(handle);
    return 0;
}