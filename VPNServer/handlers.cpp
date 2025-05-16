#include <QTcpSocket>

#include "handlers.h"
#include "protocol.h"

ClientHandler::ClientHandler(qintptr socketDescriptor, u_int clientId, QObject *parent) :
    QThread(parent),
    mClientId(clientId),
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
        case VpnOp::ClientHello:
            printf("+++ ClientHello received\n");
            VpnServerHello shello;
            shello.clientId = htonl(mClientId);
            mSocket->write((const char*) &shello, sizeof shello);

            record += sizeof(VpnClientHello);
            break;


        }
    }

}
