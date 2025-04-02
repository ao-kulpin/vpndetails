#include <stdlib.h>
#include <stdio.h>

#include <pcap.h>

#ifdef _WIN32
#include <tchar.h>

#pragma comment(lib, "ws2_32.lib") // Линковка с библиотекой Winsock

/* IPv4 header */
typedef struct ip_header
{
	u_char	ver_ihl;		// Version (4 bits) + Internet header length (4 bits)
	u_char	tos;			// Type of service 
	u_short tlen;			// Total length 
	u_short identification; // Identification
	u_short flags_fo;		// Flags (3 bits) + Fragment offset (13 bits)
	u_char	ttl;			// Time to live
	u_char	proto;			// Protocol
	u_short crc;			// Header checksum
	struct in_addr	saddr;	// Source address
	struct in_addr	daddr;	// Destination address
////	u_int	op_pad;			// Option + Padding
}ip_header;

typedef struct icmp_header {
    uint8_t type;      // Type of ICMP message
    uint8_t code;      // Code associated with the type
    uint16_t checksum; // Checksum for error-checking
    uint16_t id;       // Identifier (used for matching requests and replies)
    uint16_t sequence; // Sequence number (used for matching requests and replies)
} icmp_header;

// Функция для вычисления контрольной суммы
unsigned short checksum(void *b, int len) {
    unsigned short *buf = b;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2)
        sum += *buf++;
    
    if (len == 1)
        sum += *(unsigned char *)buf;

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

uint16_t ip_checksum(void *b, int len) {
    uint16_t *buf = b;
    uint32_t sum = 0;
    
    for (sum = 0; len > 1; len -= 2) {
        sum += *buf++;
    }
    
    if (len == 1) {
        sum += *(uint8_t *)buf;
    }
    
    sum = (sum >> 16) + (sum & 0xFFFF); // Сложение с переносом
    sum += (sum >> 16);                 // Добавление остатка от переноса
    
    return ~sum;                        // Инверсия битов
}


BOOL LoadNpcapDlls()
{
	_TCHAR npcap_dir[512];
	UINT len;
	len = GetSystemDirectory(npcap_dir, 480);
	if (!len) {
		fprintf(stderr, "Error in GetSystemDirectory: %x", GetLastError());
		return FALSE;
	}
	_tcscat_s(npcap_dir, 512, _T("\\Npcap"));
	if (SetDllDirectory(npcap_dir) == 0) {
		fprintf(stderr, "Error in SetDllDirectory: %x", GetLastError());
		return FALSE;
	}
	return TRUE;
}
#endif

/* case-insensitive string comparison that may mix up special characters and numbers */
int close_enough(char *one, char *two)
{
	while (*one && *two)
	{
		if ( *one != *two && !(
			(*one >= 'a' && *one - *two == 0x20) ||
			(*two >= 'a' && *two - *one == 0x20)
			))
		{
			return 0;
		}
		one++;
		two++;
	}
	if (*one || *two)
	{
		return 0;
	}
	return 1;
}

#define ORIG_PACKET_LEN 42 // 64
int main(int argc, char **argv)
{
	pcap_t *fp;
	char errbuf[PCAP_ERRBUF_SIZE] = {0};
	u_char packet[ORIG_PACKET_LEN] = 
		/* Ethernet frame header */
//		"\xff\xff\xff\xff\xff\xff" /* dst mac */
		"\xb0\x95\x75\xf2\x16\xf8"

//		"\x02\x02\x02\x02\x02\x02" /* src mac */
		"\x88\xa4\xc2\x4a\x67\x84"

		"\x08\x00" /* ethertype IPv4 */
		/* IPv4 packet header */
		"\x45\x00\x00\x00" /* IPv4, minimal header, length TBD */
		"\x12\x34\x00\x00" /* IPID 0x1234, no fragmentation */
		"\x10\x11\x00\x00" /* TTL 0x10, UDP, checksum (not required) */
		"\x00\x00\x00\x00" /* src IP (TBD) */
		"\xff\xff\xff\xff" /* dst IP (broadcast) */
		/* UDP header */
		"\x00\x07\x00\x07" /* src port 7, dst port 7 (echo) */
		"\x00\x00\x00\x00" /* length TBD, cksum 0 (unset) */
	;
	u_char *sendme = packet;
	size_t packet_len = ORIG_PACKET_LEN;
	pcap_if_t *ifaces = NULL;
	pcap_if_t *dev = NULL;
	pcap_addr_t *addr = NULL;

#ifdef _WIN32
	/* Load Npcap and its functions. */
	if (!LoadNpcapDlls())
	{
		fprintf(stderr, "Couldn't load Npcap\n");
		exit(1);
	}
#endif

	/* Check the validity of the command line */
	if (argc != 3)
	{
		printf("usage: %s interface dest IP", argv[0]);
		return 1;
	}
    
	if (0 != pcap_init(PCAP_CHAR_ENC_LOCAL, errbuf)) {
		fprintf(stderr, "Failed to initialize pcap lib: %s\n", errbuf);
		return 2;
	}

	/* Find the IPv4 address of the device */
	if (0 != pcap_findalldevs(&ifaces, errbuf)) {
		fprintf(stderr, "Failed to get list of devices: %s\n", errbuf);
		return 2;
	}

	for (dev = ifaces; dev != NULL; dev = dev->next)
	{
		if (close_enough(dev->name, argv[1]))
		{
			break;
		}
	}
	if (dev == NULL) {
		fprintf(stderr, "Could not find %s in the list of devices\n", argv[1]);
		return 3;
	}

	for (addr = dev->addresses; addr != NULL; addr = addr->next)
	{
		if (addr->addr->sa_family == AF_INET)
		{
			break;
		}
	}
	if (addr == NULL) {
		fprintf(stderr, "Could not find IPv4 address for %s\n", argv[1]);
		return 3;
	}

	/* Fill in the length and source addr and calculate checksum */
//	packet[14 + 2] = 0xff & ((ORIG_PACKET_LEN - 14) >> 8);
//	packet[14 + 3] = 0xff & (ORIG_PACKET_LEN - 14);
	/* UDP length */
//////	packet[14 + 20 + 4] = 0xff & ((ORIG_PACKET_LEN - 14 - 20) >> 8);
////	packet[14 + 20 + 5] = 0xff & (ORIG_PACKET_LEN - 14 - 20);

	printf("*** source IP: %s\n", 
		inet_ntoa(((struct sockaddr_in *)(addr->addr))->sin_addr));

//	*(u_long *)(packet + 14 + 12) = ((struct sockaddr_in *)(addr->addr))->sin_addr.S_un.S_addr;

	ip_header* iph = (ip_header*)(packet + 14);
	iph->proto = 1; // icmp
	iph->tlen = ntohs(sizeof * iph + sizeof(struct icmp_header));
	iph->crc = 0;

	iph->ttl = 120;
	iph->saddr = ((struct sockaddr_in*)(addr->addr))->sin_addr;

	if (argc > 2) {
		if (inet_pton(AF_INET, argv[2], &iph->daddr) <= 0) {
			fprintf(stderr, "Invalid dest IP: %s\n", argv[2]);
		    return 3;
		}
	}

	iph->crc = 0;
//	iph->crc = // htons
	//			 (ip_checksum(iph, sizeof *iph));

	icmp_header* ich = (icmp_header*)(iph + 1);
	ich->type = 8; // echo request
	ich->code = 0;
	ich->sequence = htons(1);
	ich->id = htons(getpid());
	ich->checksum = 0;
	ich->checksum = // htons
						(checksum(ich, sizeof *ich));


#if 0
	uint32_t cksum = 0;
	for (int i=14; i < 14 + 4 * (packet[14] & 0xf); i += 2)
	{
		cksum += *(uint16_t *)(packet + i);
	}
	while (cksum>>16)
		cksum = (cksum & 0xffff) + (cksum >> 16);
	cksum = ~cksum;
	*(uint16_t *)(packet + 14 + 10) = cksum;
#endif

	/* Open the adapter */
	if ((fp = pcap_open_live(argv[1],		// name of the device
							 0, // portion of the packet to capture. 0 == no capture.
							 0, // non-promiscuous mode
							 1000,			// read timeout
							 errbuf			// error buffer
							 )) == NULL)
	{
		fprintf(stderr,"\nUnable to open the adapter. %s is not supported by Npcap\n", argv[1]);
		return 2;
	}
	
	switch(pcap_datalink(fp))
	{
		case DLT_NULL:
			/* Skip Ethernet header, retreat NULL header length */
#define NULL_VS_ETH_DIFF (14 - 4)
			sendme = packet + NULL_VS_ETH_DIFF;
			packet_len -= NULL_VS_ETH_DIFF;
			// Pretend IPv4
			sendme[0] = 2;
			sendme[1] = 0;
			sendme[2] = 0;
			sendme[3] = 0;
			break;
		case DLT_EN10MB:
			/* Already set up */
			sendme = packet;
			break;
		default:
			fprintf(stderr, "\nError, unknown data-link type %u\n", pcap_datalink(fp));
			return 4;
	}
	
	for (int i = 0; i < 10; ++i) {
		iph->identification = i;
		iph->crc = 0;
		iph->crc = // htons
				 (ip_checksum(iph, sizeof *iph));

		/* Send down the packet */
		if (pcap_sendpacket(fp,	// Adapter
			sendme, // buffer with the packet
			packet_len // size
		) != 0)
		{
			fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr(fp));
			return 3;
		}
		printf("Packet is sent %d\n", i);
	}

	pcap_close(fp);	
	return 0;
}
