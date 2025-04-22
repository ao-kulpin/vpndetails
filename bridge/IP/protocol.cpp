#include "protocol.h"

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
