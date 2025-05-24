#ifndef PROTOBUILDER_H
#define PROTOBUILDER_H

#include <memory>

#include "protocol.h"

using IPPacketPtr = std::unique_ptr<IPPacket>;
using VpnIPPacketPtr = std::unique_ptr<VpnIPPacket>;

class ProtoBuilder {
public:
    static VpnIPPacketPtr composeIPacket   (const IPPacket& _packet, u_int _clientId, u_int *_size = nullptr);
    static IPPacketPtr    decomposeIPacket (const VpnIPPacket& _vpacket);
};

#endif // PROTOBUILDER_H
