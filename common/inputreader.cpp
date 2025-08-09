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
        printf("+++ setReadState(%d)\n", ringBufState);
        mRingBuf.setReadState(ringBufState);
    });

printf("+++ InputReader::takeInput() 1\n");
    while (true) {
        ringBufState = mRingBuf.getReadState();

        u_char requestBuf[PeerRequestSize];

        if (!mRingBuf.read(requestBuf, sizeof(VpnHeader)))
            return true;

        printf("+++ InputReader::takeInput() 2\n");

        auto* vph = (VpnHeader*) requestBuf;
        if (ntohl(vph->sign) != VpnSignature) {
            printf("*** Wrong signature (%08x) is receved\n", ntohl(vph->sign));
            return true;
        }

        uchar* headerEnd = requestBuf + sizeof(VpnHeader);
    printf("+++ InputReader::takeInput() 3 op=%d\n", ntohs(vph->op));

        switch(ntohs(vph->op)) {

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

                if (!mRingBuf.read(ipp->data, ntohl(ipp->dataSize)))
                    return true;

                break;
            }

            default:
                printf("*** Unknown peer request (%d)\n", htons(vph->op));
                return false;
        }
        printf("+++ Emit PeerRequest !!!\n");
        emit peerRequest(vph);
    }

}



