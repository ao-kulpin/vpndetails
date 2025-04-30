#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <winsock2.h>
#include <windows.h>

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
    u_int	op_pad;			// Option + Padding

    void    calcCheckSum();
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

#endif // PROTOCOL_H
