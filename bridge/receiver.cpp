
#include "receiver.h"
#include "BridgeData.h"

VirtReceiver::VirtReceiver() {}

void VirtReceiver::run() {
    HANDLE events[] = {bdata.quitEvent, WinTunLib::getReadWaitEvent(bdata.session)};

    int packetCount = 0;
    while(!bdata.haveQuit) {
        DWORD packetSize = 0;
        BYTE* packet = WinTunLib::receivePacket(bdata.session, &packetSize);
        if (packet) {
            if (++packetCount % 50 == 0)
                printf("%d packets received\n", packetCount);

            bdata.virtReceiveQueue.push(std::make_unique<IPPacket>(packet, packetSize));

            WinTunLib::releaseReceivePacket(bdata.session, packet);

        }
        else {
            switch (GetLastError())
            {
            case ERROR_NO_MORE_ITEMS:
                DWORD wres = WaitForMultipleObjects(2, events, FALSE, INFINITE);
                switch (wres) {
                case WAIT_OBJECT_0:
                case WAIT_OBJECT_0 + 1:
                    continue;
                default:
                    printf("\nError: Receiver fails\n");
                    return;
                }
            }
        }
    }
    printf("Receiver thread edned (%d packets handled)\n", packetCount);
}
