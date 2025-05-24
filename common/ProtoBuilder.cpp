#include "ProtoBuilder.h"

VpnIPPacketPtr ProtoBuilder::composeIPacket (const IPPacket& _packet, u_int clientId, u_int *_size) {
    auto* iph = _packet.header();

    static VpnIPPacket pattern;
    const u_int sendSize = sizeof(VpnIPPacket) + _packet.size();

    VpnIPPacketPtr vip((VpnIPPacket*) new u_char[sendSize]);

    memcpy(vip.get(), &pattern, sizeof pattern);
    vip->clientId = htonl(clientId);
    vip->dataSize = htonl(_packet.size());
    memcpy(vip->data, _packet.data(), _packet.size());

    if (_size)
        *_size = sendSize;

    return vip;
}

IPPacketPtr ProtoBuilder::decomposeIPacket (const VpnIPPacket& _vpacket) {
  return std::make_unique<IPPacket>(_vpacket.data, ntohl(_vpacket.dataSize));
}
