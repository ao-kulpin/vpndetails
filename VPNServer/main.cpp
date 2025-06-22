#if _WIN32

#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>

#endif // _WIN32

#include <QCoreApplication>
#include <QTcpServer>
#include <QTcpSocket>

#include <csignal>

#include "ServerData.h"
#include "handlers.h"
#include "killer.h"
#include "adapteraddr.h"

ServerData sdata; // common data of the application

#ifdef _WIN32

std::unique_ptr<IP_ADAPTER_ADDRESSES> AdapterAddr::mAdaptList;

#endif // _WIN32

#ifdef __linux__

ifaddrs* AdapterAddr::mAdaptList = nullptr;

#endif // __linux__

void signalHandler(int signum) {
    printf("\nTerminated by user\n");
    sdata.haveQuit = true;

    if (sdata.clientReceiveMutex.tryLock(200)) {
        sdata.clientReceiveWC.wakeAll();
        sdata.clientReceiveMutex.unlock();
    }

    QCoreApplication::quit();
}

class Server : public QTcpServer
{
    Q_OBJECT
public:
    Server(QObject *parent = nullptr) : QTcpServer(parent) {
        connect(this, &QTcpServer::newConnection, this, &Server::onNewConnection);
        connect(this, &QTcpServer::acceptError, this, &Server::onAcceptError);
        /// connect(this, &QObject::destroyed, this, &Server::onDestroyed);
        connect(this, &QTcpServer::pendingConnectionAvailable, this, &Server::onPendingConnectionAvailable);
    }

private slots:
    void onNewConnection() {
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

    void onAcceptError(QAbstractSocket::SocketError socketError) {
        printf("QTcpServer::acceptError(%d) !!!\n\n", socketError);
    }

    void onDestroyed(QObject *obj) {
        printf("QTcpServer::destroyed(%p) !!!\n\n", obj);
    }

    void onPendingConnectionAvailable() {
        printf("QTcpServer::pendingConnectionAvailable !!!\n\n");
    }
};

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);

    if (argc > 1)
        sdata.serverPort = strtol(argv[1], 0, 10);

    Server server;
    ///std::unique_ptr<Server> server (std::make_unique<Server>());

///    if (!server.listen(QHostAddress::Any, sdata.serverPort)) {
    if (!server.listen(QHostAddress::AnyIPv4, sdata.serverPort)) {
        printf("Server can't start: %s\n", server.errorString().toLocal8Bit().constData());
        return 1;
    }

    printf("Server is litening port %d\n", sdata.serverPort);
//#if 0

    RealSender rsender;
    if (rsender.openAdapter())
        printf("Real adapter %s is open\n", sdata.realAdapterIP.toString().toStdString().c_str());
    else {
        printf("Can't open real adapter\n");
        return 1;
    }

    Killer rsk ( [&] {
        rsender.wait();
        rsender.closeAdapter();
        printf("Real sender is ended\n");
    });

    RealReceiver rreceiver;
    Killer rrck ([&]{
        rreceiver.wait();
        printf("Real receiver is ended\n");
    });
//#endif

    printf("Waiting for Ctrl-C ...\n\n");

    std::signal(SIGINT, signalHandler);

    rsender.start();
    rreceiver.start();

    return a.exec();
}

#include "main.moc"
