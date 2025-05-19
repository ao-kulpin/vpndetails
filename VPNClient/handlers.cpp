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
    for(int i = 0; i < 5; ++i)
        mTcpSocket->write((const char*) &vch, sizeof vch);
}

void VPNSocket::onReadyRead() {

}
