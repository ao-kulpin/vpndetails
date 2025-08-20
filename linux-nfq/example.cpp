//  sudo iptables -A INPUT  -j NFQUEUE --queue-num 0

#include <errno.h>
 #include <stdio.h>
 #include <stdlib.h>
 #include <unistd.h>
 #include <string.h>
 #include <time.h>
 #include <arpa/inet.h>
 
 #include <libmnl/libmnl.h>
 #include <linux/netfilter.h>
 #include <linux/netfilter/nfnetlink.h>
 
 #include <linux/types.h>
 #include <linux/netfilter/nfnetlink_queue.h>
 
 #include <libnetfilter_queue/libnetfilter_queue.h>
 
 /* only for NFQA_CT, not needed otherwise: */
 #include <linux/netfilter/nfnetlink_conntrack.h>

 #define ETH_HLEN 14 // Длина заголовка Ethernet

struct IPHeader{
    u_char	ver_ihl;		// Version (4 bits) + Internet header length (4 bits)
    u_char	tos;			// Type of service
    u_short totalLen;		// Total length
    u_short identification; // Identification
    u_short flags_fo;		// Flags (3 bits) + Fragment offset (13 bits)
    u_char	ttl;			// Time to live
    u_char	proto;			// Protocol
    u_short checksum;		// Header checksum
    u_int	srcAddr;        // Source address
    u_int	destAddr;       // Destination address
    /////// u_int	op_pad;			// Option + Padding

    void     updateChecksum();
    unsigned size () const  { return (ver_ihl & 0xF) * 4; }
};


 
static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              struct nfq_data *nfa, void *data) {
    static int count = 0;
    ++ count;
    nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
    if (ph) {
        u_int32_t id = ntohl(ph->packet_id);

        unsigned char *payload = nullptr;
        int payload_len = nfq_get_payload(nfa, &payload);
    
        if (payload_len > 0) {
            auto* iph = (IPHeader*)(payload); // + ETH_HLEN);

            printf("\nPacket %d\n", count);
            printf("\t ver: %d proto: %d totalLen: %d\n", iph->ver_ihl >> 4, iph->proto, ntohs(iph->totalLen));

            char sa_buf[INET_ADDRSTRLEN];
            char da_buf[INET_ADDRSTRLEN];
            in_addr addr;
            addr.s_addr = iph->srcAddr;
            inet_ntop(AF_INET, &addr, sa_buf, sizeof sa_buf);
            addr.s_addr = iph->destAddr;
            inet_ntop(AF_INET, &addr, da_buf, sizeof da_buf);

            printf("\t address: %08X(%s) -> %08X(%s)\n", ntohl(iph->srcAddr), sa_buf, ntohl(iph->destAddr), da_buf);


            return nfq_set_verdict(qh, id, iph->proto == 1 ? NF_DROP : NF_ACCEPT, 0, NULL);
        }
    }
    return 0;
}

int main() {
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    int fd;
    char buf[4096] __attribute__ ((aligned));

    h = nfq_open();
    if (!h) {
        perror("nfq_open()");
        exit(1);
    }

    if (nfq_unbind_pf(h, AF_INET) < 0) {
        perror("nfq_unbind_pf()");
        exit(1);
    }

    if (nfq_bind_pf(h, AF_INET) < 0) {
        perror("nfq_bind_pf()");
        exit(1);
    }

    qh = nfq_create_queue(h, 0, &cb, NULL);
    if (!qh) {
        perror("nfq_create_queue()");
        exit(1);
    }

    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        perror("nfq_set_mode()");
        exit(1);
    }

    fd = nfq_fd(h);

    while (1) {
        static int count = 0;
        printf("recv(%d) %d...\n", fd, ++count);
        int rv = recv(fd, buf, sizeof(buf), 0);
        nfq_handle_packet(h, buf, rv);
    }

    nfq_destroy_queue(qh);
    nfq_close(h);

    return 0;
}
