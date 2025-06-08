#ifndef PROTOCOL_H
#define PROTOCOL_H

#ifdef _WIN32

#include <winsock2.h>

#endif // _WIN32

#include <QVector>

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

struct UDPHeader {
    u_short sport;			// Source port
    u_short dport;			// Destination port
    u_short len;			// Datagram length
    u_short checksum;		// Checksum
    void    updateChecksum(const IPHeader& ipHeader);
};

struct TCPHeader {
    u_short  sport;			// Source port
    u_short  dport;			// Destination port
    u_int    seq;           // Sequence Number
    u_int    ackSeq;        // Acknowledgement Number (meaningful when ACK bit set)

    u_char  res:4;         // Reserved (should be zero)
    u_char  doff:4;         // Data offset
    u_char  fin:1;          // FIN flag (finished - end of data)
    u_char  syn:1;          // SYN flag (synchronize - initiate a connection)
    u_char  rst:1;          // RST flag (reset the connection)
    u_char  psh:1;          // PSH flag (push - send data immediately)
    u_char  ack:1;          // ACK flag (acknowledgment of received data)
    u_char  urg:1;          // URG flag (urgent data)
    u_char  ece:1;          // ECE flag (ECN-Echo, for congestion control)
    u_char  cwr:1;          // CWR flag (Congestion Window Reduced)

    u_short window;         //  Window size (size of the receive window)
    u_short checksum;       // Checksum for error-checking
    u_short urgPtr;         // Urgent pointer (indicates end of urgent data, if any)

    void    updateChecksum(const IPHeader& ipHeader);
};

class IPPacket {
public:
    IPPacket(const u_char* _data, unsigned _size);
    IPPacket(const IPPacket& _ipp);

    IPPacket& operator= (const IPPacket& _ipp);

    unsigned   size() const { return mData.size(); }
    const u_char*
               data() const { return mData.data(); }
    u_char*    data()       { return mData.data(); }
    IPHeader*  header()     { return reinterpret_cast<IPHeader*>(mData.data()); }
    const IPHeader* header() const
                            { return reinterpret_cast<const IPHeader*>(mData.data()); }
    UDPHeader* udpHeader()  { return reinterpret_cast<UDPHeader*>(
                                        mData.data() + header()->size()); }
    const UDPHeader* udpHeader() const
                            { return reinterpret_cast<const UDPHeader*>(
                                mData.data() + header()->size()); }
    TCPHeader* tcpHeader()  { return reinterpret_cast<TCPHeader*>(
                                        mData.data() + header()->size()); }
    const TCPHeader* tcpHeader()  const
                            { return reinterpret_cast<const TCPHeader*>(
                                mData.data() + header()->size()); }
    void       updateChecksum();

private:
    QVector<u_char> mData;
};

class EthernetHeader {
public:
    static const int QTag    = 0x8100;
    static const int STag    = 0x88A8;
    static const int TypeIP4 = 0x800;
    u_char      destMac[6] = {0};
    u_char      srcMac[6]  = {0};
    u_short     type       = 0;
    unsigned    size() const;
};

struct VlanHeader {
    u_short     tpid;  // Tag Protocol Identifier (usualy 0x8100)
    u_short     tci;   // Tag Control Information
};

class EthernetVlan1: public EthernetHeader {
public:
    VlanHeader  vlan1;
};

class EthernetVlan2: public EthernetVlan1 {
public:
    VlanHeader  vlan2;
};

class EthernetFrame {
public:
    EthernetFrame(const EthernetHeader& _eh, const IPPacket& _ipp);

    const u_char*
                data() const { return mData.data(); }
    u_char*     data()       { return mData.data(); }

    unsigned ethSize() const    { return mEthSize; }
    unsigned ippSize() const    { return mIPPSize; }
    unsigned size() const       { return mEthSize + mIPPSize; }

private:
    unsigned mEthSize = 0;
    unsigned mIPPSize = 0;
    QVector<u_char> mData;
};

class CheckSumCalculator {
public:
    void        put(const void* _segment, unsigned _size);
    u_short     getSum();
private:
    u_int       mSum = 0;
    u_short     mLastByte = 0;
    bool        mKeepLast = false;
};

class VpnOp {                       // VPN Operations
public:
    static const u_short
        None = 0,                   // no operation
        ClientHello = 1,            // First request of a client to the server
        ServerHello = 2,            // First answer from the sever
        IPPacket    = 3;            // A packet from/to client/server
};

class VpnFlag {                     // Flags of VPN Operations
public:
    static const u_short
        None      = 0,              // no flag
        Encrypted = 1;              // data is encrypted
};

const u_int VpnSignature = 0x01234567;

struct VpnHeader {
    u_int       sign  = htonl(VpnSignature);
    u_short     op    = htons(VpnOp::None);
    u_short     flags = htons(VpnFlag::None);
};

struct VpnClientHello {
    u_int       sign  = htonl(VpnSignature);
    u_short     op    = htons(VpnOp::ClientHello);
    u_short     flags = htons(VpnFlag::None);
};

struct VpnServerHello {
    u_int       sign       = htonl(VpnSignature);
    u_short     op         = htons(VpnOp::ServerHello);
    u_short     flags      = htons(VpnFlag::None);
    u_int       clientId   = 0;
    u_int       encryptKey = 0;
};

struct VpnIPPacket {
    u_int       sign       = htonl(VpnSignature);
    u_short     op         = htons(VpnOp::IPPacket);
    u_short     flags      = htons(VpnFlag::None);
    u_int       clientId   = 0;
    uint        dataSize   = 0;
    u_char      data[0];
};

#endif // PROTOCOL_H
