#include "handlers.h"

VPNSocket::VPNSocket(QObject *parent) :
    QObject(parent)
{
    mTcpSocket.reset(new QTcpSocket(this));
    connect(mTcpSocket.get(), &QTcpSocket::connected, this, &VPNSocket::onConnected);
    connect(mTcpSocket.get(), &QTcpSocket::readyRead, this, &VPNSocket::onReadyRead);

}

bool VPNSocket::connectToServer(const QString& _ip, u_int _port) {
    mTcpSocket->connectToHost(_ip, _port);
    return mTcpSocket->waitForConnected(cdata.connectTime);
}


void VPNSocket::onConnected() {

}

void VPNSocket::onReadyRead() {

}
