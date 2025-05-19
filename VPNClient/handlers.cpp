#include "handlers.h"
#include "protocol.h"

VPNSocket::VPNSocket(QObject *parent) :
    QObject(parent)
{
    mTcpSocket.reset(new QTcpSocket(this));
    connect(mTcpSocket.get(), &QTcpSocket::connected, this, &VPNSocket::onConnected);
    connect(mTcpSocket.get(), &QTcpSocket::readyRead, this, &VPNSocket::onReadyRead);

}

bool VPNSocket::connectToServer(const QString& _ip, u_int _port) {
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
