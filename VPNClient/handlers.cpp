#include <QCoreApplication>

#include "handlers.h"
#include "ProtoBuilder.h"

VPNSocket::VPNSocket(QObject *parent) :
    QObject(parent)
{
    mTcpSocket.reset(new QTcpSocket(this));
    connect(mTcpSocket.get(), &QTcpSocket::connected, this, &VPNSocket::onConnected);
    connect(mTcpSocket.get(), &QTcpSocket::readyRead, this, &VPNSocket::onReadyRead);
}

bool VPNSocket::connectToServer(const QString& _ip, u_int _port, const QHostAddress& _adapter) {
    mTcpSocket->bind(_adapter);
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
/////////    for(int i = 0; i < 5; ++i)
        mTcpSocket->write((const char*) &vch, sizeof vch);
}

void VPNSocket::onReadyRead() {
    printf("VPNSocket::onReadyRead()\n");
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
        if (++eventCount % 50 == 0)
            printf("+++ %d VirtReceiveEvent! %p\n", eventCount, QThread::currentThread());

        sendReceivedPackets();
        return true;
    }
    return QObject::event(event);
}

void VPNSocket::sendReceivedPackets() {
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

        sendPacket(packet);
    }
}

void VPNSocket::sendPacket(const IPPacket& _packet) {
    u_int sendSize = 0;
    auto vip = ProtoBuilder::composeIPacket(_packet, cdata.clientId, &sendSize);
    mTcpSocket->write((const char*) vip.get(), sendSize);
}

VirtReceiver::VirtReceiver() {}

void VirtReceiver::run() {
    HANDLE events[] = {cdata.quitEvent, WinTunLib::getReadWaitEvent(cdata.session)};

    int packetCount = 0;
    while(!cdata.haveQuit) {
        DWORD packetSize = 0;
        BYTE* packet = WinTunLib::receivePacket(cdata.session, &packetSize);
        if (packet) {
            {
                QMutexLocker vrl (&cdata.virtReceiveMutex);

                if (++packetCount % 50 == 0)
                    printf("VirtReceiver: %d packets received %p\n", packetCount, QThread::currentThread());

                cdata.virtReceiveQueue.push(std::make_unique<IPPacket>(packet, packetSize));
                ///cdata.virtReceiveWC.wakeAll();
                wakeSender();
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
    printf("Virtual Receiver thread edned (%d packets handled)\n", packetCount);
    wakeSender();
}

void VirtReceiver::wakeSender() {
    QCoreApplication::postEvent(cdata.vpnSocket, new VirtReceiveEvent);
}


