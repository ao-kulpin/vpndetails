#include <QCoreApplication>

#include "handlers.h"
#include "ProtoBuilder.h"

#include "ClientData.h"

VPNSocket::VPNSocket(QObject *parent) :
    QObject(parent)
{
    mTcpSocket.reset(new QTcpSocket(this));
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

void VPNSocket::onReadyRead() {
    const auto ba = mTcpSocket->bytesAvailable();
    printf("+++ VPNSocket::onReadyRead(%lld)\n", ba);

    if (ba <= 0)
        return;

    QByteArray vpnData = mTcpSocket->readAll();
    char* start  = vpnData.data();
    auto* record = start;
    while (record - start < vpnData.size()) {
        const auto* vhead = reinterpret_cast<const VpnHeader*>(record);
        if (ntohl(vhead->sign) != VpnSignature) {
            printf("*** VPNSocket::onReadyRead() failed with wrong signature: %08X\n",
                   vhead->sign);
            return;
        }

        switch(ntohs(vhead->op)) {

        case VpnOp::ServerHello: {
            auto* shello = reinterpret_cast<const VpnServerHello*>(record);
            cdata.clientId = ntohl(shello->clientId);
            printf("*** ServerHello received, clientId=%d\n", cdata.clientId);

            record += sizeof (VpnServerHello);
            break;
        }

        case VpnOp::IPPacket: {
            auto* vip = (VpnIPPacket*) record;
            u_int dataSize = ntohl(vip->dataSize);
            printf("+++ VpnIPPacket received: client=%lu size=%u\n",
                   ntohl(vip->clientId), dataSize);

            putToServerQueue(ProtoBuilder::decomposeIPacket(*vip));

            record += sizeof(VpnIPPacket) + dataSize;
            break;
        }

        default:
            printf("*** VPNSocket::onReadyRead() failed with wrong operator: %d\n",
                   vhead->op);
            return;
        }
    }
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
                QMutexLocker vrl (&cdata.virtReceiveMutex);

                cdata.virtReceiveQueue.push(std::make_unique<IPPacket>(packet, packetSize));
                ///cdata.virtReceiveWC.wakeAll();
                wakeSender();

                ++packetCount;
                packetTotalSize += ntohs(((IPHeader*) packet)->totalLen);
                if (packetCount % 100 == 0)
                    printf("Virtual Receiver: packets: %u size: %llu MB\n", packetCount, packetTotalSize >> 20);
            }

            WinTunLib::releaseReceivePacket(cdata.session, packet);
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
    return true;
}


