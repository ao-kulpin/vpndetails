#include <QTcpSocket>
#include "handlers.h"

ClientHandler::ClientHandler(qintptr socketDescriptor, u_int clientID, QObject *parent) :
    QThread(parent),
    mClientID(clientID),
    mSocketDescriptor(socketDescriptor)
{}

void ClientHandler::run() {
    mSocket.reset (new QTcpSocket());
    if (!mSocket->setSocketDescriptor(mSocketDescriptor)) {
      printf("setSocketDescriptor() failed\n");
      return;
    }
    connect(mSocket.get(), &QTcpSocket::readyRead, this, &ClientHandler::onReadyRead);

    exec();
}

void ClientHandler::onReadyRead() {

}
