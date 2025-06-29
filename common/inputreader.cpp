#include "inputreader.h"
#include "killer.h"
#include "ProtoBuilder.h"

InputReader::InputReader(unsigned _ringBufSize) :
    mRingBuf(_ringBufSize) {
}

bool InputReader::takeInput(const u_char* _data, unsigned _len) {
    if (!mRingBuf.write(_data, _len))
        return false;
    auto ringBufState = mRingBuf.getReadState();

    Killer stateRestorer ([&] {
        mRingBuf.setReadState(ringBufState);
    });

    while (true) {
        ringBufState = mRingBuf.getReadState();

        u_char requestBuf[PeerRequestSize];

        if (!mRingBuf.read(requestBuf, sizeof(VpnHeader)))
            return true;

        auto* vph = (VpnHeader*) requestBuf;
        if (ntohl(vph->sign) != VpnSignature) {
            printf("*** Wrong signature (%08lx) is receved\n", ntohl(vph->sign));
            return true;
        }

        uchar* headerEnd = requestBuf + sizeof(VpnHeader);

        switch(htons(vph->op)) {

            case VpnOp::ClientHello:
                break;

            case VpnOp::ServerHello: {
                if (!mRingBuf.read(headerEnd,
                                   sizeof(VpnServerHello) - sizeof(VpnHeader)))
                    return true;

                break;
            }

            case VpnOp::IPPacket: {
                if (!mRingBuf.read(headerEnd,
                                   sizeof(VpnIPPacket) - sizeof(VpnHeader)))
                    return true;

                auto* ipp = (VpnIPPacket*) requestBuf;

                if (!mRingBuf.read(ipp->data, ipp->dataSize))
                    return true;

                break;
            }

            default:
                printf("*** Unknown peer request (%d)\n", htons(vph->op));
                return false;
        }
        emit peerReqest(vph);
    }

}



