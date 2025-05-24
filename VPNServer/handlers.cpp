#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>

#include <QCoreApplication>
#include <QTcpSocket>

#include <iphlpapi.h>

#include "handlers.h"
#include "protocol.h"
#include "ServerData.h"
#include "killer.h"
#include "adapteraddr.h"
#include "ProtoBuilder.h"

#include <pcap.h>

ClientSocket::ClientSocket(QTcpSocket* _socket, u_int clientId, QObject *parent) :
    QObject(parent),
    mSocket(_socket),
    mClientId(clientId)
{
    connect(mSocket.get(), &QTcpSocket::readyRead, this,
            &ClientSocket::onReadyRead, Qt::DirectConnection);
}

void ClientSocket::onReadyRead() {
    printf("ClientSocket::onReadyRead()\n");
    QByteArray clientData = mSocket->readAll();
    char* start  = clientData.data();
    auto* record = start;
    while (record - start < clientData.size()) {
        const auto* vhead = reinterpret_cast<const VpnHeader*>(record);
        if (ntohl(vhead->sign) != VpnSignature) {
            printf("*** ClientHandler::onReadyRead() failed with wrong signature: %08X\n",
                   vhead->sign);
            return;
        }
        switch(ntohs(vhead->op)) {
        case VpnOp::ClientHello: {
            printf("+++ ClientHello received\n");

            VpnServerHello shello;
            shello.clientId = htonl(mClientId);
            mSocket->write((const char*) &shello, sizeof shello);

            record += sizeof(VpnClientHello);
            break;
        }
        case VpnOp::IPPacket: {
            auto* vip = (VpnIPPacket*) record;
            printf("+++ VpnIPPacket received: client=%lu size=%lu\n",
                   ntohl(vip->clientId), ntohl(vip->dataSize));

            auto packet = ProtoBuilder::decomposeIPacket(*vip);

            if (updatePacket(*packet)) {
              // put packet into queue

              QMutexLocker crl (&sdata.clientReceiveMutex);
              sdata.clientReceiveQueue.push(std::move(packet));
              sdata.clientReceiveWC.wakeAll();
            }

            record += sizeof(VpnIPPacket) + ntohl(vip->dataSize);
            break;
        }
        default:
            printf("*** ClientSocket::onReadyRead() failed with wrong operator: %d\n",
                   vhead->op);
            return;
        }
    }
}

bool ClientSocket::updatePacket (IPPacket& _packet) {
    auto* iph = _packet.header();

    if (iph->srcAddr != htonl(virtAdapterIP.toIPv4Address())) {
        char src_s[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, (void*) &iph->srcAddr, src_s, sizeof src_s);
        printf("+++ Incorrect srcAddr: %s", src_s);
        return false;
    }

    iph->srcAddr = htonl(sdata.realAdapterIP.toIPv4Address());

    switch(iph->proto) {
    case IPPROTO_UDP: {
        auto* uph = _packet.udpHeader();
        auto sport = uph->sport;
        uph->sport = getServerPort(sport);
    }
    break;

    case IPPROTO_TCP: {
        auto* tch = _packet.tcpHeader();
        auto sport = tch->sport;
        tch->sport = getServerPort(sport);
    }
    break;

    default:
        break;
    }

    _packet.updateChecksum();
    return true;
}

u_short ClientSocket::getServerPort(u_short clientPort) {
    PortKey pk;
    pk.clientId = mClientId;
    pk.clientIp = virtAdapterIP.toIPv4Address();
    pk.clientPort = clientPort;

    if (sdata.clientPortMap.count(pk))
      return sdata.clientPortMap[pk].serverPort;
    else {
      // Allocate a new port

      PortInfo pi;
      pi.clientId   = pk.clientId;
      pi.clientIp   = pk.clientIp;
      pi.clientPort = pk.clientPort;

      pi.serverPort = sdata.portProvider.get();

      sdata.clientPortMap[pk] = pi;
      sdata.serverPortMap[pi.serverPort] = pi;

      return pi.serverPort;
    }
}

void ClientSocket::takeFromReceiver(IPPacket& _packet) {
    // works inside Realreceiver thread
    QMutexLocker rql(&mReceiveMutex);
    mReceiveQueue.push(std::make_unique<IPPacket>(_packet));
    wakeClient();
}

bool ClientSocket::event(QEvent *event) {
  if (event->type() == ClientReceiveEvent::EventType) {
        sendReceivedPackets();
        return true;
    }
    return QObject::event(event);
}

void ClientSocket::sendReceivedPackets() {
    auto& inputQueue = mReceiveQueue;
    auto& mutex = mReceiveMutex;
    auto& haveQuit = sdata.haveQuit;

    if (haveQuit)
        return;

    while (true) {
        QMutexLocker rql (&mutex);

        if (inputQueue.empty())
            return;

        IPPacket packet (*inputQueue.front());
        inputQueue.pop();

        rql.unlock();

        sendPacket(packet);
    }
}

void ClientSocket::sendPacket(const IPPacket& _packet) {
    u_int sendSize = 0;
    auto vip = ProtoBuilder::composeIPacket(_packet, mClientId, &sendSize);
    mSocket->write((const char*) vip.get(), sendSize);
}

void ClientSocket::wakeClient() {
    QCoreApplication::postEvent(this, new ClientReceiveEvent);
}



void RealSender::run() {
    int packetCount = 0;

    while (true) {
        auto& inputQueue = sdata.clientReceiveQueue;
        auto& inputWC    = sdata.clientReceiveWC;
        auto& mutex      = sdata.clientReceiveMutex;
        auto& haveQuit   = sdata.haveQuit;

        QMutexLocker vrl (&mutex);

        while (!haveQuit && inputQueue.empty())
            inputWC.wait(&mutex);

        if (haveQuit)
            break; // end of thread

        IPPacket packet (*inputQueue.front());
        inputQueue.pop();

        vrl.unlock();

        /////updatePacket(packet);
        static int fail = 0;
        static int succ = 0;
        if (send(packet)) {
          if (++packetCount % 50 == 0)
            printf("Real Sender: %d packets sent\n", packetCount);
        }
        else
          printf ("+++ send() fails %d\n", ++fail);
    }

    printf("Real Sender: thread edned (%d packets handled)\n", packetCount);
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

    const IPAddr   realIp    = htonl(sdata.realAdapterIP.toIPv4Address());
    const QString realIpStr = sdata.realAdapterIP.toString();
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
                /////////("+++ mac: %02x %02x %02x %02x %02x %02x\n", m[0], m[1], m[2], m[3], m[4], m[5]);

                AdapterAddr::getGatewayIP(realIp, &mGatewayIP);
                ///// ("+++ gatewayIP:%08X\n", mGatewayIP);

                AdapterAddr::getGatewayMacAddress(mGatewayIP, mGatewayMac);

                auto& gm = mGatewayMac;
                ///////("+++ gateway mac: %02x %02x %02x %02x %02x %02x\n", gm[0], gm[1], gm[2], gm[3], gm[4], gm[5]);

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

void realReceiveHandler(u_char *param, const pcap_pkthdr *header, const u_char *pkt_data) {
    reinterpret_cast<RealReceiver*>(param)->pcapHandler(header, pkt_data);
}

void RealReceiver::pcapHandler(const pcap_pkthdr *header, const u_char *pkt_data){
    //////////printf("+++ RealReceiver::pcapHandler() 1\n");
    while(sdata.haveQuit) {
        pcap_breakloop(mPcapHandle);
        return;
    }

    const auto* eh  = reinterpret_cast<const EthernetHeader*> (pkt_data);
    const auto* iph = reinterpret_cast<const IPHeader*> (pkt_data + eh->size());

    /////////printf("+++ RealReceiver::pcapHandler() 2\n");
    /////printf("+++ RealReceiver::pcapHandler() 3\n");

    if (++mPacketCount % 50 == 0)
        printf("RealReceiver: %d real received\n", mPacketCount);

    IPPacket packet((const u_char*) iph, ntohs(iph->totalLen));

    auto* targetClient = findTargetClient(packet);
    if (targetClient)
        targetClient->takeFromReceiver(packet);
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

    const IPAddr realIp  = htonl(sdata.realAdapterIP.toIPv4Address());
    bool found = false;
    for (auto* dev = alldevs; !found && dev; dev = dev->next) {
        for (auto* ap = dev->addresses; !found && ap; ap = ap->next) {
            IPAddr ip4 = ((sockaddr_in*) ap->addr)->sin_addr.S_un.S_addr;
            if(ap->addr->sa_family == AF_INET && realIp == ip4) {
                mPcapHandle = pcap_open_live(dev->name,         // name of the device
                                             65536,			// portion of the packet to capture.
                                             // 65536 grants that the whole packet will be captured on all the MACs.
                                             0,				// promiscuous mode (nonzero means promiscuous)
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

    printf("Real Receiver thread edned (%d packets handled)\n", mPacketCount);
}

ClientSocket* RealReceiver::findTargetClient(const IPPacket& _packet) {
    auto* iph = _packet.header();

    if (iph->destAddr != htonl(sdata.realAdapterIP.toIPv4Address()))
        return nullptr;

    int destPort = -1;
    switch(iph->proto) {
    case IPPROTO_UDP:
        destPort = _packet.udpHeader()->dport;
        break;

    case IPPROTO_TCP:
        destPort = _packet.tcpHeader()->dport;
        break;

    default:
        break;
    }

    if (destPort != -1 && sdata.serverPortMap.count(destPort)) {
        auto clientId = sdata.serverPortMap[destPort].clientId;

        assert(sdata.socketMap.count(clientId));

        return sdata.socketMap[clientId];
    }

    return nullptr;
}

bool operator < (const PortKey& lhs, const PortKey& rhs) {
    if (lhs.clientPort == rhs.clientPort) {
        if (lhs.clientId == rhs.clientId)
            return lhs.clientIp < rhs.clientIp;
        else
            return lhs.clientId < rhs.clientId;
    }
    else
        return lhs.clientPort < rhs.clientPort;
}

u_short PortProvider::get() {
    if (mPort >= PortMax)
        mPort = PortMin;
    return ++mPort;
}

