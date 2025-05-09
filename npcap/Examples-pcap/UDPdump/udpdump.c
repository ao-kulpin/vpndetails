/*
 * Copyright (c) 1999 - 2005 NetGroup, Politecnico di Torino (Italy)
 * Copyright (c) 2005 - 2006 CACE Technologies, Davis (California)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Politecnico di Torino, CACE Technologies 
 * nor the names of its contributors may be used to endorse or promote 
 * products derived from this software without specific prior written 
 * permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifdef _MSC_VER
/*
 * we do not want the warnings about the old deprecated and unsecure CRT functions
 * since these examples can be compiled under *nix as well
 */
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <pcap.h>
#include <time.h>

#ifdef _WIN32
#include <tchar.h>
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

/* 4 bytes IP address */
typedef struct ip_address
{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}ip_address;

typedef struct vlan_eth_header {
    uint8_t  ether_dhost[6];  // MAC ����������
    uint8_t  ether_shost[6];  // MAC �����������
    uint16_t vlan_tag;        // 0x8100 (VLAN)
    uint16_t tci;             // Tag Control Information (PCP, DEI, VID)
    uint16_t ether_type;      // ����������������� ��������
} vlan_eth_header;

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
	ip_address	saddr;		// Source address
	ip_address	daddr;		// Destination address
	u_int	op_pad;			// Option + Padding
}ip_header;

/* UDP header*/
typedef struct udp_header
{
	u_short sport;			// Source port
	u_short dport;			// Destination port
	u_short len;			// Datagram length
	u_short crc;			// Checksum
}udp_header;

// Define the TCP header structure
typedef struct tcp_header {
    uint16_t source_port;       // Source port
    uint16_t dest_port;         // Destination port
    uint32_t seq_number;        // Sequence number
    uint32_t ack_number;        // Acknowledgment number
    uint8_t  data_offset;       // Data offset (4 bits) + Reserved (3 bits) + Control flags (9 bits)
    uint8_t  flags;             // Control flags (URG, ACK, PSH, RST, SYN, FIN)
    uint16_t window_size;       // Window size
    uint16_t checksum;          // Checksum
    uint16_t urgent_pointer;    // Urgent pointer
} tcp_header;

typedef struct icmp_header {
    uint8_t type;      // Type of ICMP message
    uint8_t code;      // Code associated with the type
    uint16_t checksum; // Checksum for error-checking
    uint16_t id;       // Identifier (used for matching requests and replies)
    uint16_t sequence; // Sequence number (used for matching requests and replies)
} icmp_header;

/* prototype of the packet handler */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);


int main()
{
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum;
	int i=0;
	pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	u_int netmask;
/////////	char packet_filter[] = "ip and udp";
	char packet_filter[] = "ip";
	struct bpf_program fcode;
	
#ifdef _WIN32
	/* Load Npcap and its functions. */
	if (!LoadNpcapDlls())
	{
		fprintf(stderr, "Couldn't load Npcap\n");
		exit(1);
	}
#endif

	/* Retrieve the device list */
	if(pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}
	
	/* Print the list */
	for(d=alldevs; d; d=d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	if(i==0)
	{
		printf("\nNo interfaces found! Make sure Npcap is installed.\n");
		return -1;
	}
	
	printf("Enter the interface number (1-%d):",i);
	scanf("%d", &inum);
	
	/* Check if the user specified a valid adapter */
	if(inum < 1 || inum > i)
	{
		printf("\nAdapter number out of range.\n");
		
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* Jump to the selected adapter */
	for(d=alldevs, i=0; i< inum-1 ;d=d->next, i++);
	
	/* Open the adapter */
	if ((adhandle= pcap_open_live(d->name,	// name of the device
							 65536,			// portion of the packet to capture. 
											// 65536 grants that the whole packet will be captured on all the MACs.
							 1,				// promiscuous mode (nonzero means promiscuous)
							 1000,			// read timeout
							 errbuf			// error buffer
							 )) == NULL)
	{
		fprintf(stderr,"\nUnable to open the adapter: %s\n", errbuf);
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}
	
	/* Check the link layer. We support only Ethernet for simplicity. */
	auto pdl = pcap_datalink(adhandle);
	printf("\n*** pcap_datalink %d\n", pdl);
	if(pdl != DLT_EN10MB)
	{
		fprintf(stderr,"\nThis program works only on Ethernet networks.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}
	
	if(d->addresses != NULL)
		/* Retrieve the mask of the first address of the interface */
		netmask=((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		/* If the interface is without addresses we suppose to be in a C class network */
		netmask=0xffffff; 


	//compile the filter
	if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) <0 )
	{
		fprintf(stderr,"\nUnable to compile the packet filter. Check the syntax.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}
	
	//set the filter
	if (pcap_setfilter(adhandle, &fcode)<0)
	{
		fprintf(stderr,"\nError setting the filter.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}
	
	printf("\nlistening on %s...\n", d->description);
	
	/* At this point, we don't need any more the device list. Free it */
	pcap_freealldevs(alldevs);
	
	/* start the capture */
	pcap_loop(adhandle, 0, packet_handler, NULL);
	
	return 0;
}

/* Callback function invoked by libpcap for every incoming packet */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	struct tm *ltime;
	char timestr[16];
	///////// ip_header *ih;
	//////////////// udp_header *uh;
	u_int ip_len;
	u_short sport,dport;
	time_t local_tv_sec;

	/*
	 * unused parameter
	 */
	(VOID)(param);

	/* convert the timestamp to readable format */
	local_tv_sec = header->ts.tv_sec;
	ltime=localtime(&local_tv_sec);
	strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);

	/* retireve the position of the ip header */

	vlan_eth_header* eth = (vlan_eth_header*) pkt_data;

	int eth_len = 14; // default length of ethernet header

	if (ntohs(eth->vlan_tag) == 0x8100) { // VLAN 802.1Q)
		eth_len = 18;
        uint16_t inner_ethertype = ntohs(*(uint16_t*)(pkt_data + 16));
        if (inner_ethertype == 0x8100 || inner_ethertype == 0x88A8) { // Q-in-Q
            eth_len = 22;
        }
	}

	ip_header *ih = (ip_header *) (pkt_data +
		eth_len); //length of ethernet header

	/* retireve the position of the udp header */
	ip_len = (ih->ver_ihl & 0xf) * 4;
	/////// uh = (udp_header *) ((u_char*)ih + ip_len);

	char plen[32];
	sprintf(plen, "%d(%u %d %d)", header->len,  ntohs
															(ih->tlen), ip_len, eth_len);

	/* print timestamp and length of the packet */
	printf("%s.%.6d len:%-14s ", timestr, header->ts.tv_usec, plen);

	char proto[128] = { 0 };
	char src_port[32] = { 0 };
	char dst_port[32] = { 0 };

	switch (ih->proto) {
		case 1: {
			icmp_header *ich = (icmp_header *) ((u_char*)ih + ip_len);
			sprintf(proto, "%s (%d/%d %d %x %x)", "icmp", ich->type, ich->code, ntohs(ich->id), ih->identification, ih->flags_fo);
			break;
		}
		case 6: {
			tcp_header *th = (tcp_header *) ((u_char*)ih + ip_len);
			sprintf(proto, "%s", "tcp");
			sprintf(src_port, "%d", ntohs(th->source_port));
			sprintf(dst_port, "%d", ntohs(th->dest_port));
			break;
		}
		case 17: {
			udp_header *uh = (udp_header *) ((u_char*)ih + ip_len);
			sprintf(proto, "%s", "udp");
			sprintf(src_port, "%d", ntohs(uh->sport));
			sprintf(dst_port, "%d", ntohs(uh->dport));
			break;
		}
		default:
			sprintf(proto, "proto %d", ih->proto);
			break;
	}

	/* convert from network byte order to host byte order */
	////// sport = ntohs( uh->sport );
	////// dport = ntohs( uh->dport );

	/* print ip addresses and udp ports */
	printf("%3d.%3d.%3d.%3d: %5s -> %3d.%3d.%3d.%3d: %5s %s\n",
		ih->saddr.byte1,
		ih->saddr.byte2,
		ih->saddr.byte3,
		ih->saddr.byte4,
		src_port,
		ih->daddr.byte1,
		ih->daddr.byte2,
		ih->daddr.byte3,
		ih->daddr.byte4,
		dst_port,
		proto);
}
