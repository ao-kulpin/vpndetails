#include "receiver.h"
#include "BridgeData.h"
#include "killer.h"
#include "adapteraddr.h"

#include <QMutexLocker>
#include <iphlpapi.h>

VirtReceiver::VirtReceiver() {}

void VirtReceiver::wakeSender() {
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
    printf("Virtual Receiver thread edned (%d packets handled)\n", packetCount);
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

        vrl.unlock();

        updatePacket(packet);
        static int fail = 0;
        static int succ = 0;
        if (!send(packet))
            printf ("+++ send() fails %d\n", ++fail);
        ///else
        ///    printf ("+++ send() succedes %d\n", ++succ);
    }

    printf("Real Sender thread edned (%d packets handled)\n", packetCount);
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

    const IPAddr   realIp    = htonl(bdata.realAdapterIP.toIPv4Address());
    const QString realIpStr = bdata.realAdapterIP.toString();
    /////// printf("+++ realIp: %s %08lX\n", realIpStr.toUtf8().constData(), realIp);

    QString devName;
    bool found = false;
    u_char mac[6] = {0};
    for (auto* dev = alldevs; !found && dev; dev = dev->next) {
        for (auto* ap = dev->addresses; !found && ap; ap = ap->next) {
            IPAddr ip4 = ((sockaddr_in*) ap->addr)->sin_addr.S_un.S_addr;
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

                // Fill Ethernet header

                memcpy(mEthHeader.destMac, mGatewayMac, sizeof mGatewayMac);
                memcpy(mEthHeader.srcMac, mAdaptMac, sizeof mAdaptMac);
                mEthHeader.type = htons(EthernetHeader::TypeIP4);

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

bool RealSender::send(const IPPacket& _packet) {
    EthernetFrame eframe(mEthHeader, _packet);

    return pcap_sendpacket(mPcapHandle, eframe.data(), eframe.size()) == 0;
}

static
void headPrint(IPHeader* header, char* outBuf) {
    char src_s[INET_ADDRSTRLEN];
    char dest_s[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, (void*) &header->srcAddr, src_s, sizeof src_s);
    inet_ntop(AF_INET, (void*) &header->destAddr, dest_s, sizeof dest_s);

    sprintf(outBuf, "%s->%s (%d)", src_s, dest_s, header->proto);
}

void RealSender::updatePacket(IPPacket& _packet) {
    IPHeader* header = _packet.header();
    char buf[128];
    headPrint(header, buf);

    if (header->srcAddr == htonl(bdata.virtAdapterIP.toIPv4Address())) {
        header->srcAddr = htonl(bdata.realAdapterIP.toIPv4Address());
        if (header->proto == IPPROTO_UDP) {
            auto* udp = _packet.udpHeader();
            if (udp->dport == htons(53)) {
                printf("+++ udp->calcCheckSum() port: %d len: %d hs: %d\n", ntohs(udp->sport), ntohs(udp->len), header->size());
                /////// udp->sport = htons(63780);
                int cs = ntohs(udp->checksum);
                ///udp->calcCheckSum(*header);
                printf("+++ checkSum %04x -> %04x\n", cs, ntohs(udp->checksum));/////////
            }
        }
        /////header->calcCheckSum();
        _packet.updateChecksum();

        ////////// printf("+++ Good IP: %s\n", buf);
    }
    else {
        printf("+++ Invalid source IP: %s\n", buf);
    }
}

/// static
void realReceiveHandler(u_char *param, const pcap_pkthdr *header, const u_char *pkt_data) {
    reinterpret_cast<RealReceiver*>(param)->pcapHandler(header, pkt_data);
}

void RealReceiver::pcapHandler(const pcap_pkthdr *header, const u_char *pkt_data){
    //////////printf("+++ RealReceiver::pcapHandler() 1\n");
    while(bdata.haveQuit) {
        pcap_breakloop(mPcapHandle);
        return;
    }

    const auto* eh  = reinterpret_cast<const EthernetHeader*> (pkt_data);
    const auto* iph = reinterpret_cast<const IPHeader*> (pkt_data + eh->size());

    /////////printf("+++ RealReceiver::pcapHandler() 2\n");
    QMutexLocker vrl (&bdata.realReceiveMutex);
    /////printf("+++ RealReceiver::pcapHandler() 3\n");

    if (++mPacketCount % 50 == 0)
        printf("%d real packets received\n", mPacketCount);

    bdata.realReceiveQueue.push(std::make_unique<IPPacket>((const u_char*) iph, ntohs(iph->totalLen)));
    bdata.realReceiveWC.wakeAll();
}

void RealReceiver::wakeSender() {
    if (bdata.realReceiveMutex.tryLock(200)) {
        bdata.realReceiveWC.wakeAll();
        bdata.realReceiveMutex.unlock();
    }
}

void RealReceiver::run() {
printf("+++ RealReceiver starts\n");
    pcap_if_t *alldevs = nullptr;
    char errbuf[PCAP_ERRBUF_SIZE+1] = {0};

    if(pcap_findalldevs(&alldevs, errbuf) == -1) {
        printf("RealReceiver: pcap_findalldevs fails: %s\n", errbuf);
        return;
    }

    Killer adk ([&] {
        pcap_freealldevs(alldevs);
    });

    const IPAddr realIp  = htonl(bdata.realAdapterIP.toIPv4Address());
    bool found = false;
    for (auto* dev = alldevs; !found && dev; dev = dev->next) {
        for (auto* ap = dev->addresses; !found && ap; ap = ap->next) {
            IPAddr ip4 = ((sockaddr_in*) ap->addr)->sin_addr.S_un.S_addr;
            if(ap->addr->sa_family == AF_INET && realIp == ip4) {
                mPcapHandle = pcap_open_live(dev->name,         // name of the device
                                          65536,			// portion of the packet to capture.
                                                            // 65536 grants that the whole packet will be captured on all the MACs.
                                          1,				// promiscuous mode (nonzero means promiscuous)
                                          1000,             // read timeout
                                          errbuf			// error buffer
                                          );
printf("pcap_open_live(%p) succeed\n", mPcapHandle);
                found = true;
            }
        }
    }

    if(!found || !mPcapHandle) {
        printf("RealReceiver: can't open adapter: %s\n", errbuf);
        return;
    }

    pcap_loop(mPcapHandle, 0, realReceiveHandler, reinterpret_cast<u_char*>(this));

    pcap_close(mPcapHandle);
    mPcapHandle = nullptr;

    wakeSender();

    printf("Real Receiver thread edned (%d packets handled)\n", mPacketCount);
}

void VirtSender::run() {
    int packetCount = 0;

    while (true) {
        auto& inputQueue = bdata.realReceiveQueue;
        auto& inputWC = bdata.realReceiveWC;
        auto& mutex = bdata.realReceiveMutex;
        auto& haveQuit = bdata.haveQuit;

        QMutexLocker vsl (&mutex);

        while (!haveQuit && inputQueue.empty())
            inputWC.wait(&mutex);

        if (haveQuit)
            break; // end of thread

        IPPacket packet (*inputQueue.front());

        inputQueue.pop();
        vsl.unlock();

        if (updatePacket(packet)) {
            send(packet);

            if (++packetCount % 50 == 0)
                printf("%d real packets sent\n", packetCount);
        }
    }
    printf("Virtual Sender thread edned (%d packets handled)\n", packetCount);
}

bool VirtSender::updatePacket(IPPacket& _packet) {
    IPHeader* header = _packet.header();
    char buf[128];
    headPrint(header, buf);

    if (header->destAddr == htonl(bdata.realAdapterIP.toIPv4Address())) {
        header->destAddr = htonl(bdata.virtAdapterIP.toIPv4Address());
        _packet.updateChecksum();
        printf("+++ VirtSender: Good destination IP: %s\n", buf);
        return true;
    }
    else {
        ////////printf("+++ VirtSender: Invalid destination IP: %s\n", buf);
        return false;
    }
}

bool VirtSender::send(const IPPacket& _packet) {
    auto& session = bdata.session;
    BYTE* winTunPacket = WinTunLib::allocateSendPacket(session, _packet.size());

    if (!winTunPacket)
        return false;

    memcpy(winTunPacket, _packet.data(), _packet.size());

    WinTunLib::sendPacket(session, winTunPacket);
    return true;
}






