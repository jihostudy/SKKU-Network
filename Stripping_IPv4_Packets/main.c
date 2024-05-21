#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pcap.h>
#include <time.h>

// Declaration
#define MAC_LEN 6
typedef unsigned char u_char;
typedef unsigned int u_int;
typedef unsigned short u_short;
// Function Initialize
void Local_Time(const struct pcap_pkthdr *);
void Length_Info(const struct pcap_pkthdr *, const u_char *);
void MAC_ADDR(const u_char *);
void IP_ADDR(const u_char *);
void Protocol(const u_char *);
void ID_Flags(const u_char *);
void TTL(const u_char *);
void TOS(const u_char *);
// Global Variables
u_int packet_number = 1;

// #0. Endian Swap (Host: Little Endian, Network: Big Endian)
void Endian_Converter(u_char *arr, int length)
{
    for (int i = 0; i < length / 2; i++)
    {
        u_char tmp = arr[i];
        arr[i] = arr[length - i - 1];
        arr[length - i - 1] = tmp;
    }
}

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
    u_short ip_header_len = (packet[14] & 0x0F) * 4; // IHL 필드는 4바이트 단위로 표시되므로 4를 곱하여 바이트 단위로 변환
    // Print captured length, actual length, and length in the IP header
    printf("Captured length: %u bytes || ", cap_len);
    printf("Actual length: %u bytes || ", len);

    printf("Length in the IP header: %u bytes\n", ip_header_len);
}

// #3. SRCMAC to DSTMAC
void MAC_ADDR(const u_char *packet)
{
    int i;
    u_char src_MAC[MAC_LEN];
    u_char dst_MAC[MAC_LEN];

    for (i = 0; i < MAC_LEN; i++)
    {
        dst_MAC[i] = packet[i];
    }
    for (i = 0; i < MAC_LEN; i++)
    {
        src_MAC[i] = packet[i + MAC_LEN];
    }

    // Swap bytes for Endian
    // Endian_Converter(src_MAC, MAC_LEN);
    // Endian_Converter(dst_MAC, MAC_LEN);
    // Extract source MAC address
    printf("Source MAC: ");
    for (i = 0; i < MAC_LEN; i++)
    {
        printf("%02x", src_MAC[i]);
        if (i < MAC_LEN - 1)
        {
            printf(":");
        }
    }
    printf("  --->  ");

    // Extract destination MAC address
    printf("Destination MAC: ");
    for (i = 0; i < MAC_LEN; i++)
    {
        printf("%02x", dst_MAC[i]);
        if (i < MAC_LEN - 1)
        {
            printf(":");
        }
    }
    printf("\n");
}

// #4. SRCIP to DSTIP
void IP_ADDR(const u_char *packet)
{
    // Extract source IP address
    printf("Source IP: %d.%d.%d.%d", packet[26], packet[27], packet[28], packet[29]);
    printf("  --->  ");

    // Extract destination IP address
    printf("Destination IP: %d.%d.%d.%d\n", packet[30], packet[31], packet[32], packet[33]);
}

// #5. Protocol
void Protocol(const u_char *packet)
{
    // Extract protocol from IP payload
    char protocol_val = packet[23];
    char protocol[6];

    switch (protocol_val)
    {
    // ICMP
    case 1:
        strcpy(protocol, "ICMP");
        break;
    // IGMP
    case 2:
        strcpy(protocol, "IGMP");
        break;
    // IP in IP
    case 3:
        strcpy(protocol, "IP/IP");
        break;
    // TCP
    case 6:
        strcpy(protocol, "TCP");
        break;
    // UDP
    case 17:
        strcpy(protocol, "UDP");
        break;
    // IPv6
    case 41:
        strcpy(protocol, "IPv6");
        break;
    // GRE
    case 47:
        strcpy(protocol, "GRE");
        break;
    // OSPF
    case 89:
        strcpy(protocol, "OSPF");
        break;
    // L2TP
    case 115:
        strcpy(protocol, "L2TP");
        break;
    }
    printf("Protocol: %s\n", protocol);
}

// #6. Identification & Flags(DF || MF)
void ID_Flags(const u_char *packet)
{
    // Extract Identification and Flags from the packet
    u_short identification = (packet[18] << 8) | packet[19];
    u_short flags_fragment_offset = (packet[20] << 8) + packet[21];
    u_short flags = flags_fragment_offset >> 13;

    // Extract DF flag
    int DF = (flags & 0x2) >> 1;
    // Extract MF flag
    int MF = flags & 0x1;

    printf("Identification: %d || ", identification);
    printf("Flags: ");
    if (DF)
    {
        printf("DF\n");
        return;
    }
    if (MF)
    {
        printf("MF\n");
        return;
    }
    if (!DF && !MF)
        printf("Not set\n");
}

// #7. TTL
void TTL(const u_char *packet)
{
    // Extract TTL from the packet
    u_short ttl = packet[22];

    printf("TTL: %u\n", ttl);
}

// #8. Type of Service

void TOS(const u_char *packet)
{
    // Extract Type of Service (TOS) from the packet
    u_short tos_val = packet[15];
    char tos[21];

    // 7~5 bits are used
    switch (tos_val)
    {
    // 0000 0000
    case 0:
        strcpy(tos, "Routine");
        break;

    // 0010 0000
    case 32:
        strcpy(tos, "Priority");
        break;

    // 0100 0000
    case 64:
        strcpy(tos, "Immediate");
        break;

    // 0110 0000
    case 96:
        strcpy(tos, "Flash");
        break;

    // 1000 0000
    case 128:
        strcpy(tos, "Flash Override");
        break;

    // 1010 0000
    case 160:
        strcpy(tos, "CRITIC/ECP");
        break;

    // 1100 0000
    case 192:
        strcpy(tos, "Internetwork Control");
        break;
    // 1110 0000
    case 224:
        strcpy(tos, "Network Control");
        break;
    default:
        strcpy(tos, "Unknown");
        break;
    }
    printf("Type of Service: %u(%s)\n", tos_val, tos);
}
void packet_analize(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    printf("\n[Packet #%d]\n", packet_number++);

    // #1. Local Time
    Local_Time(pkthdr);

    // #2. caplen & len & IP Header length
    Length_Info(pkthdr, packet);

    // #3. SRCMAC to DSTMAC
    MAC_ADDR(packet);

    // #4. SRCIP to DSTIP
    IP_ADDR(packet);

    // #5. Protocol
    Protocol(packet);

    // #6. ID & Flags
    ID_Flags(packet);

    // #7. TTL
    TTL(packet);

    // #8. Type of Service
    TOS(packet);
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
    // Cleanup
    pcap_close(handle);
    return 0;
}