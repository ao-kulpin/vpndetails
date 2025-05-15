#include "handlers.h"

VPNSocket::VPNSocket(QObject *parent) :
    QObject(parent)
{
    mTcpSocket.reset(new QTcpSocket(this));
    connect(mTcpSocket.get(), &QTcpSocket::connected, this, &VPNSocket::onConnected);
    connect(mTcpSocket.get(), &QTcpSocket::readyRead, this, &VPNSocket::onReadyRead);

}

void VPNSocket::onConnected() {

}

void VPNSocket::onReadyRead() {

}
