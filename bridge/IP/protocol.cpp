#include "protocol.h"

static
u_short calcCheckSum(void *b, int len) {
    u_short *buf = reinterpret_cast<u_short*>(b);
    unsigned int sum = 0;

    for (sum = 0; len > 1; len -= 2)
        sum += *buf++;

    if (len == 1)
        sum += *(unsigned char *)buf;

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return ~sum;
}

void IPHeader::calcCheckSum() {
    checksum = 0;
    checksum = ::calcCheckSum(this, (ver_ihl & 0xF) * 4);
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
