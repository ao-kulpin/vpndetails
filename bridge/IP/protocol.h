#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <winsock2.h>
#include <windows.h>

#include <QVector>

struct IPHeader{
    u_char	ver_ihl;		// Version (4 bits) + Internet header length (4 bits)
    u_char	tos;			// Type of service
    u_short tlen;			// Total length
    u_short identification; // Identification
    u_short flags_fo;		// Flags (3 bits) + Fragment offset (13 bits)
    u_char	ttl;			// Time to live
    u_char	proto;			// Protocol
    u_short crc;			// Header checksum
    u_int	saddr;		// Source address
    u_int	daddr;		// Destination address
    u_int	op_pad;			// Option + Padding
};

class IPPacket {
public:
    IPPacket(const u_char* _data, unsigned _size);
    IPPacket(const IPPacket& _ipp);

    IPPacket& operator= (const IPPacket& _ipp);

    unsigned   size() const { return mData.size(); }
    u_char*    data()       { return mData.data(); }
    IPHeader*  header()     { return reinterpret_cast<IPHeader*>(mData.data()); }

private:
    QVector<u_char> mData;
};

#endif // PROTOCOL_H
