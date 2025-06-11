#ifdef _WIN32

#include <winsock2.h>
#include <windows.h>

#endif // _WIN32

#include "protocol.h"

struct PPseudoHeader{
    u_int   srcAddr;
    u_int   destAddr;
    u_char  zero = 0;       // always 0
    u_char	proto = 17;		// Protocol
    u_short len;			// Datagram length
};

void CheckSumCalculator::put(const void* _segment, unsigned _size) {
    if (mKeepLast) {
        const u_char* byteSeg = reinterpret_cast<const u_char*>(_segment);
        u_short first = (mLastByte << 8) | *byteSeg;
        mSum += first;
        mKeepLast = false;
        _segment = byteSeg + 1;
        --_size;
    }

    const u_short *ptr = reinterpret_cast<const u_short*>(_segment);

    for (; _size > 1; _size -= sizeof(u_short))
        mSum += ntohs(*ptr++);

    if (_size == 1) {
        mLastByte = *reinterpret_cast<const u_char*>(ptr);
        mKeepLast = true;
    }
}

u_short CheckSumCalculator::getSum() {
    if (mKeepLast) {
        mSum += ntohs(mLastByte);
        mKeepLast = false;
    }

    u_int sum = mSum;

    while(sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    return static_cast<u_short>(~sum);
}

void IPHeader::updateChecksum() {
    checksum = 0;
    CheckSumCalculator calc;
    calc.put(this, size());
    checksum = htons(calc.getSum());
}

void UDPHeader::updateChecksum(const IPHeader& ipHeader) {
    checksum = 0;

    PPseudoHeader uph;
    uph.srcAddr     = ipHeader.srcAddr;
    uph.destAddr    = ipHeader.destAddr;
    uph.zero        = 0;
    uph.proto       = ipHeader.proto;
    uph.len         = len;

    CheckSumCalculator calc;
    calc.put(&uph, sizeof uph);
    calc.put(this, ntohs(len));

    checksum = htons(calc.getSum());
}

void TCPHeader::updateChecksum(const IPHeader& ipHeader) {
    checksum = 0;

    u_int tcpSize = ntohs(ipHeader.totalLen) - ipHeader.size();

    PPseudoHeader uph;
    uph.srcAddr     = ipHeader.srcAddr;
    uph.destAddr    = ipHeader.destAddr;
    uph.zero        = 0;
    uph.proto       = ipHeader.proto;
    uph.len         = htons(tcpSize);

    CheckSumCalculator calc;
    calc.put(&uph, sizeof uph);
    calc.put(this, tcpSize);

    checksum = htons(calc.getSum());
}


IPPacket::IPPacket(const u_char* _data, unsigned _size) :
    mData(_size)
{
    memcpy(mData.data(), _data, _size);
}

IPPacket::IPPacket(const IPPacket& _ipp) :
    mData(_ipp.mData)
{}

IPPacket& IPPacket::operator= (const IPPacket& _ipp) {
    mData = _ipp.mData;
    return *this;
}

void IPPacket::updateChecksum() {
    auto* iph = header();
    iph->updateChecksum();
    switch (iph->proto) {
    case IPPROTO_UDP:
        udpHeader()->updateChecksum(*iph);
        break;

    case IPPROTO_TCP:
        tcpHeader()->updateChecksum(*iph);
        break;

    default:
        break;
    }
}


unsigned EthernetHeader::size() const {
    if (ntohs(type) == QTag) {
        const auto* vlan1 = reinterpret_cast<const EthernetVlan1*>(this);

        switch(ntohs(vlan1->vlan1.tci)) {
        case QTag:
        case STag:
            return sizeof (EthernetVlan2);
        default:
            return sizeof (EthernetVlan1);
        }
    }
    else
        return sizeof(EthernetHeader);
}

EthernetFrame::EthernetFrame(const EthernetHeader& _eh,
                             const IPPacket& _ipp) :
    mEthSize(_eh.size()),
    mIPPSize(_ipp.size()),
    mData(mEthSize + mIPPSize) {

    memcpy(mData.data(), &_eh, mEthSize);
    memcpy(mData.data() + mEthSize, _ipp.data(), mIPPSize);
}
