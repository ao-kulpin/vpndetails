#ifdef _WIN32

#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>

#endif // _WIN32

#include <QCoreApplication>
#include <QTcpSocket>

#include "handlers.h"
#include "protocol.h"
#include "ServerData.h"
#include "killer.h"
#include "adapteraddr.h"
#include "ProtoBuilder.h"

#include <pcap.h>

static
    void headPrint(const IPHeader* header, char* outBuf) {
    char src_s[INET_ADDRSTRLEN];
    char dest_s[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, (void*) &header->srcAddr, src_s, sizeof src_s);
    inet_ntop(AF_INET, (void*) &header->destAddr, dest_s, sizeof dest_s);

    sprintf(outBuf, "%s->%s (%d) len=%d", src_s, dest_s, header->proto, ntohs(header->totalLen));
}

ClientSocket::ClientSocket(QTcpSocket* _socket, u_int clientId, QObject *parent) :
    QObject(parent),
    mSocket(_socket),
    mClientId(clientId)
{
    printf("\n+++ ClientSocket::ClientSocket raw ptr=%p smart ptr=%p !!!\n\n",
           _socket, mSocket.get());
    connect(mSocket.get(), &QTcpSocket::readyRead, this,
            &ClientSocket::onReadyRead); //, Qt::DirectConnection);

    connect(mSocket.get(), &QTcpSocket::errorOccurred, this, &ClientSocket::onError);
    connect(mSocket.get(), &QTcpSocket::disconnected, this, &ClientSocket::onDisconnected);


    onReadyRead(); // first segment of data, if any
}

void ClientSocket::onReadyRead() {
    const auto ba = mSocket->bytesAvailable();
    printf("ClientSocket::onReadyRead(%lld)\n", ba);
    if (ba <= 0)
        return;

    ++ sdata.serverTimer;
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
            static int count = 0;
            ///if (++ count % 10 == 0)
            ///    printf("+++ %d VpnIPPacket received: client=%lu size=%lu\n", count,
            ///       ntohl(vip->clientId), ntohl(vip->dataSize));

            auto packet = ProtoBuilder::decomposeIPacket(*vip);

            if (updateClientPacket(*packet)) {
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
void ClientSocket::onError(QAbstractSocket::SocketError socketError) {
    printf("\n*** ClientSocket: Signal Error=%d state=%d !!!\n\n", int(socketError),
           int(mSocket->state()));
}

void ClientSocket::onDisconnected() {
    printf("\n*** ClientSocket: Signal Disconnected state=%d !!!\n\n",
           int(mSocket->state()));
}


bool ClientSocket::updateClientPacket (IPPacket& _packet) {
    auto* iph = _packet.header();

    if (iph->srcAddr != htonl(virtAdapterIP.toIPv4Address())) {
        char src_s[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, (void*) &iph->srcAddr, src_s, sizeof src_s);
        printf("+++ Incorrect srcAddr: %s\n", src_s);
        return false;
    }

    iph->srcAddr = htonl(sdata.realAdapterIP.toIPv4Address());

    switch(iph->proto) {
    case IPPROTO_UDP: {
        auto* uph = _packet.udpHeader();
        auto sport = ntohs(uph->sport);
        uph->sport = htons(getServerPort(sport));
    }
    break;

    case IPPROTO_TCP: {
        auto* tch = _packet.tcpHeader();
        auto sport = ntohs(tch->sport);
        tch->sport = htons(getServerPort(sport));
    }
    break;

    default: {
        // any protocol

        auto& rmap = sdata.requestMap;
        ClientRequestKey crk;
        crk.destIp = ntohl(iph->destAddr);
        crk.proto = iph->proto;

        ClientRequestVector* crv = nullptr;

        if(rmap.count(crk))
          crv = rmap[crk].get();
        else {
            crv = new ClientRequestVector;
            rmap[crk] = std::unique_ptr<ClientRequestVector>(crv);
        }

        assert(crv);

        auto rinfo = std::find_if(crv->begin(), crv->end(),
                     [&](const auto& elem)->bool {
                         return elem.clientId == mClientId;
                      }
        );

        if (rinfo == crv->end()) {
            ClientRequestInfo newElem;
            newElem.clientId = mClientId;
            crv->push_back(newElem);
            rinfo = crv->end() - 1;
        }

        assert(rinfo != crv->end());
        rinfo->clientTime = sdata.serverTimer;

    }
    break;
    }

    _packet.updateChecksum();
    return true;
}

u_short ClientSocket::getClientPort(u_short serverPort) {
    auto& portMap = sdata.serverPortMap;
    if (portMap.count(serverPort))
        return portMap[serverPort].clientPort;
    else
        return 0;
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

    ///printf("+++ ClientSocket::takeFromReceiver()\n");
    QMutexLocker rql(&mReceiveMutex);
    mReceiveQueue.push(std::make_unique<IPPacket>(_packet));
    wakeClient();
}

bool ClientSocket::event(QEvent *event) {
  if (event->type() == ClientReceiveEvent::EventType) {
        ++ sdata.serverTimer;
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

        if (updateServerPacket(packet))
          sendServerPacket(packet);
    }
}

bool ClientSocket::updateServerPacket (IPPacket& _packet) {
    IPHeader* iph = _packet.header();
    iph->destAddr = htonl(virtAdapterIP.toIPv4Address());

    switch(iph->proto) {
    case IPPROTO_UDP: {
        auto* uph = _packet.udpHeader();
        auto dport = ntohs(uph->dport);
        uph->dport = htons(getClientPort(dport));
        ////uph->updateChecksum(*iph);
    }
    break;

    case IPPROTO_TCP: {
        auto* tch = _packet.tcpHeader();
        auto dport = ntohs(tch->dport);
        tch->dport = htons(getClientPort(dport));
        ///////////tch->updateChecksum(*iph);
    }
    break;

    default:
    break;
    }

    _packet.updateChecksum();

    return true;
}

void ClientSocket::sendServerPacket(const IPPacket& _packet) {
    u_int sentSize = 0;
    auto vip = ProtoBuilder::composeIPacket(_packet, mClientId, &sentSize);
    mSocket->write((const char*) vip.get(), sentSize);
    ++mSentServerPackCount;
    const auto totalLen = ntohs(_packet.header()->totalLen);
    mSentServerPackSize += totalLen;
    if (mSentServerPackCount % 100 == 0) {
      printf("*** Sent to Cliend: id:%u, pakets:%u total size:%llu MB\n",
             mClientId, mSentServerPackCount, mSentServerPackSize >> 20);
    }
}

void ClientSocket::wakeClient() {
    QCoreApplication::postEvent(this, new ClientReceiveEvent);
}

QHostAddress ClientSocket::localAddress() {
    return mSocket ? mSocket->localAddress() : QHostAddress::Null;
}




void RealSender::run() {
    u_int   packetCount = 0;
    u_int64 packetSize = 0;

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
          ++packetCount;
          packetSize += ntohs(packet.header()->totalLen);
          if (packetCount % 100 == 0)
            printf("Real Sender: packets: %u size: %llu MB\n", packetCount, packetSize >> 20);
        }
        else
          printf ("+++ send() fails %d\n", ++fail);
    }

    printf("Real Sender: thread edned (sent %d packets, %llu MB)\n", packetCount, packetSize >> 20);
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

    const IP4Addr realIp    = sdata.realAdapterIP.toIPv4Address();
    const auto    netRealIp = htonl(realIp);
    const QString realIpStr = sdata.realAdapterIP.toString();
    /////// printf("+++ realIp: %s %08lX\n", realIpStr.toUtf8().constData(), realIp);

    QString devName;
    bool found = false;
    u_char mac[6] = {0};
    for (auto* dev = alldevs; !found && dev; dev = dev->next) {
        for (auto* ap = dev->addresses; !found && ap; ap = ap->next) {
#ifdef _WIN32
            IP4Addr netIp4 = ((sockaddr_in*) ap->addr)->sin_addr.S_un.S_addr;
#else
            IP4Addr netIp4 = ((sockaddr_in*) ap->addr)->sin_addr.s_addr;
#endif
            if(ap->addr->sa_family == AF_INET && netRealIp == netIp4) {
                devName = dev->name;

                AdapterAddr::getMacAddress(realIp, mAdaptMac);
                auto& m = mAdaptMac;
                printf("+++ mac: %02x %02x %02x %02x %02x %02x\n", m[0], m[1], m[2], m[3], m[4], m[5]);

                AdapterAddr::getGatewayIP(realIp, &mGatewayIP);
                printf ("+++ gatewayIP: %08lX\n", mGatewayIP);

                AdapterAddr::getGatewayMacAddress(realIp, mGatewayIP, mGatewayMac);

                auto& gm = mGatewayMac;
                printf("+++ gateway mac: %02x %02x %02x %02x %02x %02x\n", gm[0], gm[1], gm[2], gm[3], gm[4], gm[5]);

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
    while(sdata.haveQuit) {
        pcap_breakloop(mPcapHandle);
        return;
    }

    const auto* eh  = reinterpret_cast<const EthernetHeader*> (pkt_data);
    const auto* iph = reinterpret_cast<const IPHeader*> (pkt_data + eh->size());

    if((iph->ver_ihl >> 4) != 4)
        // take only IPv4 packets
        return;

    ++mPacketCount;
    const auto totalLen = ntohs(iph->totalLen);
    mPacketSize += totalLen;
    if (mPacketCount % 100 == 0)
      printf("Real Receiver: packets: %u size: %llu MB\n", mPacketCount, mPacketSize >> 20);

    IPPacket packet((const u_char*) iph, totalLen);

    auto* targetClient = findTargetClient(packet);
    if (targetClient)
        targetClient->takeFromReceiver(packet);
}

void RealReceiver::run() {
    pcap_if_t *alldevs = nullptr;
    char errbuf[PCAP_ERRBUF_SIZE+1] = {0};

    if(pcap_findalldevs(&alldevs, errbuf) == -1) {
        printf("RealReceiver: pcap_findalldevs fails: %s\n", errbuf);
        return;
    }

    Killer adk ([&] {
        pcap_freealldevs(alldevs);
    });

    const IP4Addr netRealIp  = htonl(sdata.realAdapterIP.toIPv4Address());
    bool found = false;
    for (auto* dev = alldevs; !found && dev; dev = dev->next) {
        for (auto* ap = dev->addresses; !found && ap; ap = ap->next) {
#ifdef _WIN32
            IP4Addr ip4 = ((sockaddr_in*) ap->addr)->sin_addr.S_un.S_addr;
#else
            IP4Addr ip4 = ((sockaddr_in*) ap->addr)->sin_addr.s_addr;
#endif
            if(ap->addr->sa_family == AF_INET && netRealIp == ip4) {
                mPcapHandle = pcap_open_live(dev->name,         // name of the device
                                             65536,			// portion of the packet to capture.
                                             // 65536 grants that the whole packet will be captured on all the MACs.
                                             0,				// promiscuous mode (nonzero means promiscuous)
                                             1000,             // read timeout
                                             errbuf			// error buffer
                                             );
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

    printf("Real Receiver thread edned (read %d packets, %llu MB)\n", mPacketCount, mPacketSize >> 20);
}

ClientSocket* RealReceiver::findTargetClient(const IPPacket& _packet) {
    auto* iph = _packet.header();

    if (iph->destAddr != htonl(sdata.realAdapterIP.toIPv4Address()))
        return nullptr;

    int destPort = -1;
    switch(iph->proto) {
    case IPPROTO_UDP:
        destPort = ntohs(_packet.udpHeader()->dport);
        break;

    case IPPROTO_TCP:
        destPort = ntohs(_packet.tcpHeader()->dport);
        break;

    default:
        break;
    }

    if (destPort != -1 && sdata.serverPortMap.count(destPort)) {
        auto& pi = sdata.serverPortMap[destPort];

        assert(sdata.socketMap.count(pi.clientId));

        return sdata.socketMap[pi.clientId];
    } else {
        // any protocol

        auto& rmap = sdata.requestMap;
        ClientRequestKey crk;
        crk.destIp = ntohl(iph->srcAddr);
        crk.proto = iph->proto;

        if (rmap.count(crk)) {
          auto* requestVector = rmap[crk].get();

          if (requestVector->size() != 1)
              printf("+++ Request Vector size %zu\n", requestVector->size());

          auto& lastRequest = requestVector->back();
          lastRequest.serverTime = sdata.serverTimer;

          return sdata.socketMap[lastRequest.clientId];
        }
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

bool operator < (const ClientRequestKey& lhs, const ClientRequestKey& rhs) {
    return lhs.destIp == rhs.destIp ? lhs.proto < rhs.proto
                                    : lhs.destIp < rhs.destIp;
}


u_short PortProvider::get() {
    if (mPort >= PortMax)
        mPort = PortMin;
    return ++mPort;
}

