#include <QCoreApplication>

#include "handlers.h"
#include "ProtoBuilder.h"

#include "ClientData.h"

VPNSocket::VPNSocket(QObject *parent) :
    QObject(parent),
    mInputReader(cdata.ringBufSize)
{
    mTcpSocket.reset(new QTcpSocket(this));
    connect(&mInputReader, &InputReader::peerReqest, this, &VPNSocket::onPeerRequest);
    connect(mTcpSocket.get(), &QTcpSocket::connected, this, &VPNSocket::onConnected);
    connect(mTcpSocket.get(), &QTcpSocket::readyRead, this, &VPNSocket::onReadyRead);
    connect(mTcpSocket.get(), &QTcpSocket::errorOccurred, this, &VPNSocket::onError);
    connect(mTcpSocket.get(), &QTcpSocket::disconnected, this, &VPNSocket::onDisconnected);
}

bool VPNSocket::connectToServer(const QString& _ip, u_int _port, const QHostAddress& _adapter) {
    if (!mTcpSocket->bind(_adapter)) {
        printf("*** bond() failed: %s\n", mTcpSocket->errorString().toStdString().c_str());
        return false;
    }
    mTcpSocket->connectToHost(_ip, _port);
    if (mTcpSocket->waitForConnected(cdata.connectTime)) {
        return true;
    }
    else
        return false;
}


void VPNSocket::onConnected() {
    printf("+++ Send ClientHello\n");

    VpnClientHello vch;

    for (int i = 0; i < 100; ++i) {
        auto rc = mTcpSocket->write((const char*) &vch, sizeof vch);
        auto f = mTcpSocket->flush();
        printf("+++ %d) socket->write %lld(%d)\n", i, rc, int(f));
    }
}

void VPNSocket::onPeerRequest(const VpnHeader* _request) {
    printf("+++ VPNSocket::onPeerRequest()\n");
    switch (ntohs(_request->op)) {
        case VpnOp::ServerHello: {
            auto* shello = (const VpnServerHello*) _request;
            cdata.clientId = ntohl(shello->clientId);
            printf("*** ServerHello received, clientId=%d\n", cdata.clientId);

            break;
        }

        case VpnOp::IPPacket: {
            auto* vip = (const VpnIPPacket*) _request;
            u_int dataSize = ntohl(vip->dataSize);
            printf("+++ VpnIPPacket received: client=%lu size=%u\n",
                   ntohl(vip->clientId), dataSize);

            putToServerQueue(ProtoBuilder::decomposeIPacket(*vip));

            break;
        }
        default:
            printf("*** VPNSocket::onPeerRequest() failed with unknown op: %d\n",
                   ntohs(_request->op));
    }

}

void VPNSocket::onReadyRead() {
    const auto ba = mTcpSocket->bytesAvailable();
    printf("+++ VPNSocket::onReadyRead(%lld)\n", ba);

    if (ba <= 0)
        return;

    auto vpnData = mTcpSocket->readAll();
    auto* dataPtr  = (const u_char*) vpnData.data();
    mInputReader.takeInput(dataPtr, vpnData.size());
}

bool VPNSocket::event(QEvent *event) {
    if (event->type() == VirtReceiveEvent::EventType) {

        static int eventCount = 0;
        ////if (++eventCount % 50 == 0)
        ////    printf("+++ %d VirtReceiveEvent! %p\n", eventCount, QThread::currentThread());

        sendReceivedVirtPackets();
        return true;
    }
    return QObject::event(event);
}

void VPNSocket::sendReceivedVirtPackets() {
    //// printf("+++ VPNSocket::sendReceivedVirtPackets()\n");
    auto& inputQueue = cdata.virtReceiveQueue;
    auto& mutex = cdata.virtReceiveMutex;
    auto& haveQuit = cdata.haveQuit;

    if (haveQuit)
        return;

    while (true) {
        QMutexLocker vrl (&mutex);

        if (inputQueue.empty())
            return;

        IPPacket packet (*inputQueue.front());
        inputQueue.pop();

        vrl.unlock();

        sendVirtPacket(packet);
    }
}

QHostAddress VPNSocket::localAddress() {
    return mTcpSocket ? mTcpSocket->localAddress() : QHostAddress::Null;
}

QHostAddress VPNSocket::peerAddress() {
    return mTcpSocket ? mTcpSocket->peerAddress() : QHostAddress::Null;
}

u_short VPNSocket::peerPort() {
    return mTcpSocket ? mTcpSocket->peerPort() : 0;
}



void VPNSocket::sendVirtPacket(const IPPacket& _packet) {
    printf("+++ VPNSocket::sendVirtPacket 1  packet %p thread %p\n",
           &_packet, QThread::currentThread());

    u_int sendSize = 0;
    auto vip = ProtoBuilder::composeIPacket(_packet, cdata.clientId, &sendSize);
    mTcpSocket->write((const char*) vip.get(), sendSize);
    mTcpSocket->flush();
}

void VPNSocket::putToServerQueue(IPPacketPtr _packet) {
    auto& queue = cdata.serverReceiveQueue;
    auto& mutex = cdata.serverReceiveMutex;
    auto& wc = cdata.serverReceiveWC;

    QMutexLocker qul(&mutex);
    queue.push(std::move(_packet));
    wc.wakeAll();
}

void VPNSocket::onError(QAbstractSocket::SocketError socketError) {
    printf("\n*** Signal Error=%d state=%d !!!\n\n", int(socketError),
           int(mTcpSocket->state()));
}

void VPNSocket::onDisconnected() {
    printf("\n*** Signal Disconnected state=%d !!!\n\n",
           int(mTcpSocket->state()));
}

VirtReceiver::VirtReceiver() {}

void VirtReceiver::run() {
    HANDLE events[] = {cdata.quitEvent, WinTunLib::getReadWaitEvent(cdata.session)};

    u_int packetCount = 0;
    u_int64 packetTotalSize = 0;
    while(!cdata.haveQuit) {
        DWORD packetSize = 0;
        BYTE* packet = WinTunLib::receivePacket(cdata.session, &packetSize);
        if (packet) {
            {
                auto* iph = (IPHeader*) packet;
                printf("+++ VirtReceiver::run() 1  packet %p thread %p proto %d src %s dst %s\n",
                       packet,
                       QThread::currentThread(),
                       iph->proto,
                       QHostAddress(ntohl(iph->srcAddr))
                           .toString().toStdString().c_str(),
                       QHostAddress(ntohl(iph->destAddr))
                           .toString().toStdString().c_str());

                QMutexLocker vrl (&cdata.virtReceiveMutex);

                cdata.virtReceiveQueue.push(std::make_unique<IPPacket>(packet, packetSize));

                ++packetCount;
                packetTotalSize += ntohs(((IPHeader*) packet)->totalLen);
                if (packetCount % 100 == 0)
                    printf("Virtual Receiver: packets: %u size: %llu MB\n", packetCount, packetTotalSize >> 20);

                WinTunLib::releaseReceivePacket(cdata.session, packet);

                printf("+++ VirtReceiver::run() 2  packet %p thread %p proto %d src %s dst %s\n",
                       packet,
                       QThread::currentThread(),
                       iph->proto,
                       QHostAddress(ntohl(iph->srcAddr))
                           .toString().toStdString().c_str(),
                       QHostAddress(ntohl(iph->destAddr))
                           .toString().toStdString().c_str());
            }
            wakeSender();
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

    printf("Virtual Receiver thread edned (read %d packets, %llu MB)\n", packetCount, packetTotalSize >> 20);
    wakeSender();
}

void VirtReceiver::wakeSender() {
    QCoreApplication::postEvent(cdata.vpnSocket, new VirtReceiveEvent);
}

void VirtSender::run() {
    u_int packetCount = 0;
    u_int64 packetSize = 0;

    while (true) {
        auto& inputQueue = cdata.serverReceiveQueue;
        auto& inputWC = cdata.serverReceiveWC;
        auto& mutex = cdata.serverReceiveMutex;
        auto& haveQuit = cdata.haveQuit;

        QMutexLocker vsl (&mutex);

        while (!haveQuit && inputQueue.empty())
            inputWC.wait(&mutex);

        if (haveQuit)
            break; // end of thread

        IPPacket packet (*inputQueue.front());

        inputQueue.pop();
        vsl.unlock();

        if (updatePacket(packet)) {
            if (send(packet)) {
                ++packetCount;
                packetSize += ntohs(packet.header()->totalLen);
                if (packetCount % 100 == 0)
                    printf("Virtual Sender: packets: %u size: %llu MB\n", packetCount, packetSize >> 20);
            } else {
                static int failCount = 0;
                printf ("+++ VirtSender:send() fails %d\n", ++failCount);
            }
        }
    }

    printf("Virtual Sender: thread edned (sent %d packets, %llu MB)\n", packetCount, packetSize >> 20);
}

bool VirtSender::updatePacket(IPPacket& _packet) {
    return true;
}

bool VirtSender::send(const IPPacket& _packet) {
    auto& session = cdata.session;
    BYTE* winTunPacket = WinTunLib::allocateSendPacket(session, _packet.size());

    if (!winTunPacket)
        return false;

    memcpy(winTunPacket, _packet.data(), _packet.size());

    WinTunLib::sendPacket(session, winTunPacket);

    auto* iph = _packet.header();
    printf("+++ VirtSender::send() thread %p proto %d src %s dst %s\n",
           QThread::currentThread(),
           iph->proto,
           QHostAddress(ntohl(iph->srcAddr))
               .toString().toStdString().c_str(),
           QHostAddress(ntohl(iph->destAddr))
               .toString().toStdString().c_str());


    return true;
}


