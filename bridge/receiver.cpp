
#include "receiver.h"
#include "BridgeData.h"

Receiver::Receiver() {}

void Receiver::run() {
    auto readEvent = WinTunLib::getReadWaitEvent(bdata.session);

    while(true) {
        DWORD packetSize = 0;
        BYTE* packet = WinTunLib::receivePacket(bdata.session, &packetSize);
        if (packet) {
            printf("Packed is received size:%ld\n", packetSize);
            WinTunLib::releaseReceivePacket(bdata.session, packet);

        }
        else {
            switch (GetLastError())
            {
            case ERROR_NO_MORE_ITEMS:
                DWORD wres = WaitForSingleObject(readEvent, INFINITE);
                switch (wres) {
                case WAIT_OBJECT_0:
                    continue;
                default:
                    printf("\nError: Receiver fails\n");
                    return;
                }
            }
        }
    }

}
