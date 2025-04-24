#include "receiver.h"
#include "BridgeData.h"
#include <QMutexLocker>

#include <pcap.h>

VirtReceiver::VirtReceiver() {}

static void wakeSender() {
    if (bdata.virtReceiveMutex.tryLock(200)) {
        bdata.virtReceiveWC.wakeAll();
        bdata.virtReceiveMutex.unlock();
    }
}

void VirtReceiver::run() {
    HANDLE events[] = {bdata.quitEvent, WinTunLib::getReadWaitEvent(bdata.session)};

    int packetCount = 0;
    while(!bdata.haveQuit) {
        DWORD packetSize = 0;
        BYTE* packet = WinTunLib::receivePacket(bdata.session, &packetSize);
        if (packet) {
            {
                QMutexLocker vrl (&bdata.virtReceiveMutex);

                if (++packetCount % 50 == 0)
                    printf("%d packets received\n", packetCount);

                bdata.virtReceiveQueue.push(std::make_unique<IPPacket>(packet, packetSize));
                bdata.virtReceiveWC.wakeAll();
            }

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
    wakeSender();
}

void getMacAddress(u_char *mac , struct in_addr destip)
{
    DWORD ret;
    struct in_addr srcip;
    ULONG MacAddr[2];
    ULONG PhyAddrLen = 6;  /* default to length of six bytes */

    srcip.s_addr=0;

    //Send an arp packet
    ret = SendArp(destip , srcip , MacAddr , &PhyAddrLen);

    //Prepare the mac address
    if(PhyAddrLen)
    {
        BYTE *bMacAddr = (BYTE *) & MacAddr;
        for (int i = 0; i < (int) PhyAddrLen; i++)
        {
            mac[i] = (char)bMacAddr[i];
        }
    }
}


void RealSender::run() {
    int packetCount = 0;

    while (true) {
        auto& inputQueue = bdata.virtReceiveQueue;
        auto& inputWC = bdata.virtReceiveWC;
        auto& mutex = bdata.virtReceiveMutex;
        auto& haveQuit = bdata.haveQuit;

        QMutexLocker vrl (&mutex);

        while (!haveQuit && inputQueue.empty())
            inputWC.wait(&mutex);

        if (haveQuit)
            break; // end of thread

        IPPacket packet (*inputQueue.front());

        inputQueue.pop();

        if (++packetCount % 50 == 0)
            printf("%d packets sent\n", packetCount);
    }

    printf("Sender thread edned (%d packets handled)\n", packetCount);
}

bool RealSender::openAdapter() {
    /* Retrieve the device list */
    pcap_if_t *alldevs = nullptr;
    char errbuf[PCAP_ERRBUF_SIZE+1];

    if(pcap_findalldevs(&alldevs, errbuf) == -1) {
        printf("pcap_findalldevs fails: %s\n", errbuf);
        return false;
    }

    QString realIp = bdata.realAdapterIP.toString();
    QString devName;
    bool found = false;
    u_char mac[6] = {0};
    for (auto* dev = alldevs; !found && dev; dev = dev->next) {
        for (auto* ap = dev->addresses; !found && ap; ap = ap->next) {
            if(ap->addr->sa_family == AF_INET && realIp == ap->addr->sa_data) {
                devName = dev->name;
                found = true;
            }
        }

    }

    return true;
}

