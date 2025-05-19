#include <QTcpSocket>

#include "handlers.h"
#include "protocol.h"

ClientSocket::ClientSocket(QTcpSocket* _socket, u_int clientId, QObject *parent) :
    QObject(parent),
    mSocket(_socket),
    mClientId(clientId)
{
    connect(mSocket.get(), &QTcpSocket::readyRead, this,
            &ClientSocket::onReadyRead, Qt::DirectConnection);

}

void ClientSocket::onReadyRead() {
    printf("ClientHandler::onReadyRead()\n");
    printf("ClientHandler::onReadyRead() thread %p\n", QThread::currentThread());
//#if 0
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
//////            mSocket->write((const char*) &shello, sizeof shello);

            record += sizeof(VpnClientHello);
            break;
        }
        default:
            printf("*** ClientHandler::onReadyRead() failed with wrong operator: %d\n",
                   vhead->op);
            return;
        }
    }
//#endif
}
