#include "receiver.h"
#include "BridgeData.h"
#include "killer.h"
#include "adapteraddr.h"

#include <QMutexLocker>
#include <iphlpapi.h>
#include <QtEndian>

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

    if (pcap_init(PCAP_CHAR_ENC_LOCAL, errbuf)) {
        printf("pcap_init fails: %s\n", errbuf);
        return false;
    }

    if(pcap_findalldevs(&alldevs, errbuf) == -1) {
        printf("pcap_findalldevs fails: %s\n", errbuf);
        return false;
    }

    Killer adk ([&] {
        pcap_freealldevs(alldevs);
    });

    const IPAddr   realIp    = qToBigEndian(bdata.realAdapterIP.toIPv4Address());
    const QString realIpStr = bdata.realAdapterIP.toString();
    printf("+++ realIp: %s %08lX\n", realIpStr.toUtf8().constData(), realIp);

    QString devName;
    bool found = false;
    u_char mac[6] = {0};
    for (auto* dev = alldevs; !found && dev; dev = dev->next) {
        for (auto* ap = dev->addresses; !found && ap; ap = ap->next) {
            ULONG ip4 = ((sockaddr_in*) ap->addr)->sin_addr.S_un.S_addr;
            if(ap->addr->sa_family == AF_INET && realIp == ip4) {
                devName = dev->name;

                AdapterAddr::getMacAddress(realIp, mAdaptMac);
                auto& m = mAdaptMac;
                /////////printf("+++ mac: %02x %02x %02x %02x %02x %02x\n", m[0], m[1], m[2], m[3], m[4], m[5]);

                AdapterAddr::getGatewayIP(realIp, &mGatewayIP);
                ///// printf("+++ gatewayIP:%08X\n", mGatewayIP);

                AdapterAddr::getGatewayMacAddress(mGatewayIP, mGatewayMac);

                auto& gm = mGatewayMac;
                ///////printf("+++ gateway mac: %02x %02x %02x %02x %02x %02x\n", gm[0], gm[1], gm[2], gm[3], gm[4], gm[5]);
                found = true;
            }
        }
    }

    if (! found) {
        printf("Real adapter is not found\n");
        return false;
    }

    mPcapHandle = pcap_open_live(devName.toUtf8().constData(), // name of the device
                             0,     // portion of the packet to capture. 0 == no capture.
                             0,     // non-promiscuous mode
                             1000,	// read timeout
                             errbuf	// error buffer
                                 );
    if (!mPcapHandle) {
        printf("pcap_open_live fails: %s\n", errbuf);
        return false;
    }
    return true;
}

void RealSender::closeAdapter() {
    if  (mPcapHandle) {
        pcap_close(mPcapHandle);
        mPcapHandle = nullptr;
    }
}

