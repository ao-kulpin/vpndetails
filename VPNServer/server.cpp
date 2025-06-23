#include "server.h"
#include "ServerData.h"
#include "handlers.h"

Server::Server(QObject *parent) : QTcpServer(parent) {
    connect(this, &QTcpServer::newConnection, this, &Server::onNewConnection);
    connect(this, &QTcpServer::acceptError, this, &Server::onAcceptError);
    /// connect(this, &QObject::destroyed, this, &Server::onDestroyed);
    connect(this, &QTcpServer::pendingConnectionAvailable, this, &Server::onPendingConnectionAvailable);
}

void Server::onNewConnection() {
    auto* npc = nextPendingConnection();
    printf("Client connected from %s state: %d proto: %d...\n",
           npc->peerAddress().toString().toStdString().c_str(),
           npc->state(),
           npc->peerAddress().protocol());
    printf("Local address: %s\n",
           npc->localAddress().toString().toStdString().c_str());
    auto *sock = new ClientSocket(npc, ++sdata.clientCount);
    sdata.socketMap[sock->clientId()] = sock;
}

void Server::onAcceptError(QAbstractSocket::SocketError socketError) {
    printf("QTcpServer::acceptError(%d) !!!\n\n", socketError);
}

void Server::onDestroyed(QObject *obj) {
    printf("QTcpServer::destroyed(%p) !!!\n\n", obj);
}

void Server::onPendingConnectionAvailable() {
    printf("QTcpServer::pendingConnectionAvailable !!!\n\n");
}
